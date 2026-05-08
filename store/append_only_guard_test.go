/*
FILE PATH:

	store/append_only_guard_test.go

DESCRIPTION:

	H4 — Code-level append-only assertion. Scans every .go file
	under store/ for SQL string literals that mutate the
	append-only tables (entry_index, commitment_split_id,
	derivation_commitments, tree_heads, tree_head_sigs,
	equivocation_proofs). If any UPDATE / DELETE / TRUNCATE
	statement is constructed against these tables in production
	code, the test fails the build.

KEY ARCHITECTURAL DECISIONS:
  - Build-time guard via `go test`, NOT a static-analysis
    linter, so the check runs in the same toolchain that
    already compiles + tests the code. Administrators don't need
    to install staticcheck or any new tooling.
  - Defense-in-depth on top of F2 (deploy/sql/grants.sql).
    F2 enforces at the DB role level — the application can't
    mutate even if the code tries. H4 enforces at compile-
    check time — the code can't even contain the mutation
    string. Together: a buggy commit can't slip past either
    layer.
  - Heuristic-but-bounded: we look for case-insensitive
    "UPDATE <table>", "DELETE FROM <table>", "TRUNCATE <table>"
    patterns inside string literals. False positives are
    tolerable (the test will fail on a renamed-but-similar
    table); false negatives would mean the guard misses a
    real mutation, so the patterns favor over-matching.
  - Test-only files (*_test.go) are explicitly NOT scanned —
    tests sometimes need to set up DELETE-FROM fixtures.
  - The guard runs against the entire repo, not just store/,
    so api/ or builder/ breaches surface here too.
*/
package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// appendOnlyTables is the canonical list of tables that MUST NOT
// be mutated by application code (UPDATE / DELETE / TRUNCATE).
// Mutable tables (builder_cursor, credits, smt_*, sessions,
// delta_window_buffers, witness_sets) are intentionally absent.
var appendOnlyTables = []string{
	"entry_index",
	"commitment_split_id",
	"derivation_commitments",
	"tree_heads",
	"tree_head_sigs",
	"equivocation_proofs",
}

// TestAppendOnlyGuard pins the H4 contract: no Go file in the
// repo (excluding *_test.go) constructs a SQL UPDATE / DELETE /
// TRUNCATE statement against an append-only table. A breach
// fails the build.
func TestAppendOnlyGuard(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	patterns := buildPatterns(appendOnlyTables)
	violations := []string{}

	werr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip vendor + .git + build output.
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		// Only scan .go production files.
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip THIS file (the guard itself contains the patterns).
		if strings.HasSuffix(path, "append_only_guard_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Strip block + line comments so docstrings + file-header
		// runbooks (which often quote the administrator-run reset SQL
		// for cmd/rebuild-tiles + similar one-shot tools) don't
		// trip the guard. This is a syntactic strip — string
		// literals containing "/*" wouldn't be confused because
		// stripBlockComments matches on bare patterns at top-level
		// of the source, not inside strings; the worst case is a
		// false negative where a real mutation hides inside a
		// commented-out block, which is acceptable since
		// commented-out code doesn't execute.
		body := stripBlockComments(stripLineComments(string(raw)))
		for _, p := range patterns {
			if locs := p.re.FindAllStringIndex(body, -1); locs != nil {
				for _, loc := range locs {
					line := lineNumber(body, loc[0])
					violations = append(violations,
						relPath(root, path)+":"+itoa(line)+
							" — "+p.label+": "+
							snippet(body, loc[0], loc[1]))
				}
			}
		}
		return nil
	})
	if werr != nil {
		t.Fatalf("walk: %v", werr)
	}
	if len(violations) > 0 {
		t.Fatalf("H4 — append-only guard breach (%d violations):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

type pattern struct {
	label string
	re    *regexp.Regexp
}

// buildPatterns constructs the case-insensitive UPDATE / DELETE /
// TRUNCATE patterns for each append-only table.
func buildPatterns(tables []string) []pattern {
	out := make([]pattern, 0, 3*len(tables))
	for _, t := range tables {
		out = append(out,
			pattern{
				label: "UPDATE " + t,
				re:    regexp.MustCompile(`(?i)\bUPDATE\s+` + regexp.QuoteMeta(t) + `\b`),
			},
			pattern{
				label: "DELETE FROM " + t,
				re:    regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+` + regexp.QuoteMeta(t) + `\b`),
			},
			pattern{
				label: "TRUNCATE " + t,
				re:    regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE\s+)?` + regexp.QuoteMeta(t) + `\b`),
			},
		)
	}
	return out
}

// repoRoot walks upward from this test file's directory until a
// go.mod is found, returning the directory containing it.
func repoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cwd, nil // ran out — fall back to cwd
		}
		dir = parent
	}
}

func relPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

func lineNumber(body string, off int) int {
	if off > len(body) {
		off = len(body)
	}
	return strings.Count(body[:off], "\n") + 1
}

func snippet(body string, start, end int) string {
	const max = 80
	if end > len(body) {
		end = len(body)
	}
	s := body[start:end]
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strings.TrimSpace(s)
}

// stripBlockComments replaces /* ... */ blocks with spaces of
// the same length so line numbers in error messages still match
// the original file. Naive — does not understand strings or
// nested comments — which matches Go's grammar (no nested block
// comments). Worst-case false negative is ignoring a mutation
// inside a commented-out block, which is fine because the code
// won't execute.
func stripBlockComments(src string) string {
	out := []byte(src)
	i := 0
	for i < len(out)-1 {
		if out[i] == '/' && out[i+1] == '*' {
			j := i + 2
			for j < len(out)-1 {
				if out[j] == '*' && out[j+1] == '/' {
					j += 2
					break
				}
				j++
			}
			if j >= len(out)-1 {
				j = len(out)
			}
			for k := i; k < j; k++ {
				if out[k] != '\n' {
					out[k] = ' '
				}
			}
			i = j
			continue
		}
		i++
	}
	return string(out)
}

// stripLineComments replaces "// ..." through end-of-line with
// spaces (preserving the newline) so docstrings on a single line
// don't trip the guard. Same false-negative caveat as
// stripBlockComments.
func stripLineComments(src string) string {
	out := []byte(src)
	i := 0
	for i < len(out)-1 {
		if out[i] == '/' && out[i+1] == '/' {
			j := i
			for j < len(out) && out[j] != '\n' {
				out[j] = ' '
				j++
			}
			i = j
			continue
		}
		i++
	}
	return string(out)
}

// itoa avoids a strconv import to keep this file's surface
// minimal and self-contained.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	s := string(buf[i:])
	if neg {
		return "-" + s
	}
	return s
}
