/*
FILE PATH: tests/chaos/harness/bytestore.go

Bytestore environment-variable plumbing. The chaos harness
reuses the same SeaweedFS / S3 instance the soak provisions
(via scripts/run-soak.sh) — provisioning a fresh bytestore per
chaos test would multiply test wall-time and Docker resource
footprint without adding signal. Instead, every chaos test
gets a unique key PREFIX inside the shared bucket so writes
don't collide across runs.

ENV CONTRACT

The harness reads three groups of env vars at construction time
and translates them to the LEDGER_BYTE_STORE_* env vars the
ledger binary consumes:

  ATTESTA_SOAK_BYTESTORE_BACKEND  → LEDGER_BYTE_STORE_BACKEND
  ATTESTA_TEST_S3_BUCKET          → LEDGER_BYTE_STORE_S3_BUCKET
  ATTESTA_TEST_S3_ENDPOINT        → LEDGER_BYTE_STORE_S3_ENDPOINT
  ATTESTA_TEST_S3_ACCESS_KEY      → LEDGER_BYTE_STORE_S3_ACCESS_KEY
  ATTESTA_TEST_S3_SECRET_KEY      → LEDGER_BYTE_STORE_S3_SECRET_KEY
  ATTESTA_TEST_S3_REGION          → LEDGER_BYTE_STORE_S3_REGION
  ATTESTA_TEST_S3_PATH_STYLE      → LEDGER_BYTE_STORE_S3_PATH_STYLE

When the backend isn't supported (or env is missing) the test
is t.Skip'd — the chaos suite is opt-in infrastructure-
dependent.

PER-TEST PREFIX ISOLATION

The PREFIX env var (LEDGER_BYTE_STORE_PREFIX) is set to
"chaos/<pid>/<unix-nano>" per harness instance. Every chaos
test writes to its own subtree of the shared bucket so
parallel runs (and successive runs against the same bucket)
never collide on the same key. The bucket itself is NOT
cleaned up between runs — operational task, not chaos-test
correctness concern.

GCS NOT SUPPORTED

The soak supports both `gcs` and `s3` backends; the chaos
harness only wires `s3` (which works for SeaweedFS, MinIO,
real AWS, and Cloudflare R2). Real GCS spawn-from-test would
need credential plumbing the chaos harness deliberately
doesn't replicate; tests requesting `gcs` are t.Skip'd with a
clear message.
*/
package harness

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// bytestorePrefix returns the per-harness key prefix. Used by
// the main Harness type to scope every blob write into a
// unique subtree.
func bytestorePrefix() string {
	return fmt.Sprintf("chaos/%d/%d", os.Getpid(), time.Now().UnixNano())
}

// bytestoreEnv returns the LEDGER_BYTE_STORE_* env-var slice
// the subprocess ledger should receive. Pulls source values
// from ATTESTA_SOAK_BYTESTORE_BACKEND + ATTESTA_TEST_S3_*.
// On missing required vars, t.Skip — the chaos harness is
// infrastructure-dependent by design.
func bytestoreEnv(t *testing.T) []string {
	t.Helper()
	backend := os.Getenv("ATTESTA_SOAK_BYTESTORE_BACKEND")
	if backend == "" {
		backend = os.Getenv("LEDGER_BYTE_STORE_BACKEND")
	}
	switch backend {
	case "s3":
		return buildS3Env(t)
	case "gcs":
		t.Skipf("chaos harness doesn't wire GCS backend (set ATTESTA_SOAK_BYTESTORE_BACKEND=s3)")
		return nil
	default:
		t.Skipf("chaos harness needs ATTESTA_SOAK_BYTESTORE_BACKEND=s3 (got %q)", backend)
		return nil
	}
}

// buildS3Env constructs the S3-flavoured env slice. Required
// values produce a t.Skip; optional values are appended only
// when present so the binary's default (empty → AWS SDK
// credential chain) kicks in for omitted fields.
func buildS3Env(t *testing.T) []string {
	t.Helper()
	bucket := requireEnvVar(t, "ATTESTA_TEST_S3_BUCKET")
	endpoint := os.Getenv("ATTESTA_TEST_S3_ENDPOINT")
	access := os.Getenv("ATTESTA_TEST_S3_ACCESS_KEY")
	secret := os.Getenv("ATTESTA_TEST_S3_SECRET_KEY")
	region := os.Getenv("ATTESTA_TEST_S3_REGION")
	pathStyle := os.Getenv("ATTESTA_TEST_S3_PATH_STYLE")

	out := []string{
		"LEDGER_BYTE_STORE_BACKEND=s3",
		"LEDGER_BYTE_STORE_S3_BUCKET=" + bucket,
	}
	if endpoint != "" {
		out = append(out, "LEDGER_BYTE_STORE_S3_ENDPOINT="+endpoint)
	}
	if access != "" {
		out = append(out, "LEDGER_BYTE_STORE_S3_ACCESS_KEY="+access)
	}
	if secret != "" {
		out = append(out, "LEDGER_BYTE_STORE_S3_SECRET_KEY="+secret)
	}
	if region != "" {
		out = append(out, "LEDGER_BYTE_STORE_S3_REGION="+region)
	}
	if pathStyle == "true" || pathStyle == "1" {
		out = append(out, "LEDGER_BYTE_STORE_S3_PATH_STYLE=true")
	}
	return out
}

// requireEnvVar reads name from the environment. If empty,
// t.Skip is called with an informative message.
func requireEnvVar(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("chaos harness needs %s", name)
	}
	return v
}
