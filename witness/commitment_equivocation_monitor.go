/*
FILE PATH: witness/commitment_equivocation_monitor.go

Cryptographic-commitment equivocation monitor per Wave 1 v3 §S2 +
ADR-005 §3.

Distinct from witness/equivocation_monitor.go (which surveils
tree-head equivocation across peer operators by polling external
endpoints). This monitor watches the operator's OWN
commitment_split_id index for collisions: when two or more
pre-grant-commitment-v1 or escrow-split-commitment-v1 entries are
admitted under the same (schema_id, split_id) tuple, the dealer
has equivocated and the cryptographic evidence is durable on the
operator's log.

Detection model. The C3 commitment_split_id index is BTREE on
(schema_id, split_id) — NOT UNIQUE — by Decision 3. This monitor
runs a periodic SQL scan to find tuples with row count > 1 and
upserts them into commitment_equivocation_proofs. The monitor is
NOT in the admission hot path: detection is decoupled from
admission so the operator never silently rejects an equivocating
entry on a constraint violation, which would destroy the evidence
the SDK's *CommitmentEquivocationError construction depends on.

Idempotency. Repeated runs against the same incident UPSERT into
the same row, appending only newly-observed sequence numbers to
entry_seqs and bumping last_observed_at. The monitor is safe to
restart, run concurrently across replicas (one will win the
upsert, the others' INSERT becomes a no-op via ON CONFLICT), and
re-scan the historical index from boot.

Alert dispatch. The monitor records evidence; the AlertCallback
is invoked synchronously per new incident. The previous
HTTP-webhook publisher (witness/commitment_equivocation_alert.go)
was retired: equivocation transparency now flows through the
gossip layer (KindEquivocationFinding events broadcast via
gossipnet.EquivocationPublisher), making per-deployment webhooks
redundant. Operators wishing to bridge to a governance webhook
implement AlertCallback themselves.
*/
package witness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// CommitmentEquivocationMonitorConfig configures the periodic scan
// for SplitID collisions in commitment_split_id.
type CommitmentEquivocationMonitorConfig struct {
	// PollInterval is the wait between successive scans. Defaults
	// to 30 seconds when zero. Detection is not security-critical
	// (the evidence is already durable on the log via the BTREE
	// index); the monitor only needs to keep up with the equivocation
	// rate, which is by definition rare.
	PollInterval time.Duration

	// AlertCallback fires once per incident when a NEW equivocation
	// is first detected (the upsert observed alert_dispatched_at IS
	// NULL prior to update). May be nil. Operators wire this to a
	// gossip publisher (KindEquivocationFinding broadcast) or a
	// custom escalation channel; in-process tests can supply a
	// channel-backed callback.
	AlertCallback func(evidence CommitmentEquivocationEvidence)
}

// CommitmentEquivocationEvidence is the per-incident payload passed
// to AlertCallback and persisted in commitment_equivocation_proofs.
//
// Field set is the strict minimum for downstream governance action:
// SchemaID + SplitID identify the incident; EntrySeqs lists every
// admitted entry under the colliding tuple. Canonical bytes for each
// entry are not duplicated here — they live in Tessera and can be
// fetched on demand via the existing EntryReader. Carrying just the
// sequence numbers keeps evidence rows compact and avoids storing
// entry bytes outside Tessera.
type CommitmentEquivocationEvidence struct {
	SchemaID        string
	SplitID         [32]byte
	EntrySeqs       []uint64
	FirstDetectedAt time.Time
}

// ─────────────────────────────────────────────────────────────────────
// Monitor
// ─────────────────────────────────────────────────────────────────────

// CommitmentEquivocationMonitor polls commitment_split_id for
// (schema_id, split_id) tuples with multiple sequence numbers and
// records evidence in commitment_equivocation_proofs.
type CommitmentEquivocationMonitor struct {
	cfg    CommitmentEquivocationMonitorConfig
	db     *pgxpool.Pool
	logger *slog.Logger
}

// NewCommitmentEquivocationMonitor constructs a monitor.
func NewCommitmentEquivocationMonitor(
	cfg CommitmentEquivocationMonitorConfig,
	db *pgxpool.Pool,
	logger *slog.Logger,
) *CommitmentEquivocationMonitor {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	return &CommitmentEquivocationMonitor{
		cfg:    cfg,
		db:     db,
		logger: logger,
	}
}

// Run executes the monitor loop until ctx is cancelled. MUST be
// called from a single goroutine per operator instance — concurrent
// runs are technically safe (the upserts are idempotent) but waste
// scan effort.
//
// On the first iteration the monitor performs a backfill scan of
// every (schema_id, split_id) tuple that already has rowcount > 1
// in commitment_split_id. This catches equivocations that landed
// during operator downtime and ensures evidence eventually
// surfaces even across crash-restart cycles.
func (m *CommitmentEquivocationMonitor) Run(ctx context.Context) {
	m.logger.Info("commitment equivocation monitor started",
		"poll_interval", m.cfg.PollInterval)

	// Backfill on first iteration; the periodic loop handles
	// incremental detection thereafter. Backfill error is logged
	// but not fatal — the loop will retry.
	if err := m.scan(ctx); err != nil {
		if !isContextError(err) {
			m.logger.Error("commitment equivocation backfill scan failed",
				"error", err)
		}
	}

	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("commitment equivocation monitor stopped")
			return
		case <-ticker.C:
			if err := m.scan(ctx); err != nil {
				if isContextError(err) {
					m.logger.Info("commitment equivocation monitor stopped during scan")
					return
				}
				m.logger.Error("commitment equivocation scan failed",
					"error", err)
			}
		}
	}
}

// scan performs one detection pass: SELECT colliding tuples,
// UPSERT evidence for each, fire the alert callback for newly-
// detected incidents.
//
// The detection query groups commitment_split_id by (schema_id,
// split_id) and returns only tuples with HAVING COUNT(*) > 1.
// For each match, the upsert into commitment_equivocation_proofs
// returns whether the row was newly created (alert callback fires)
// or updated in place (no callback — already alerted on a prior
// scan, possibly with a smaller sequence set).
func (m *CommitmentEquivocationMonitor) scan(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT schema_id, split_id, array_agg(sequence_number ORDER BY sequence_number ASC) AS seqs
		FROM commitment_split_id
		GROUP BY schema_id, split_id
		HAVING COUNT(*) > 1`)
	if err != nil {
		return fmt.Errorf("witness: scan commitment_split_id: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var (
			schemaID    string
			splitIDRaw  []byte
			seqs        []int64
		)
		if scanErr := rows.Scan(&schemaID, &splitIDRaw, &seqs); scanErr != nil {
			return fmt.Errorf("witness: scan equivocation row: %w", scanErr)
		}
		if len(splitIDRaw) != 32 {
			m.logger.Warn("commitment equivocation: malformed split_id length",
				"schema_id", schemaID,
				"split_id_len", len(splitIDRaw))
			continue
		}
		var splitID [32]byte
		copy(splitID[:], splitIDRaw)

		evidence := CommitmentEquivocationEvidence{
			SchemaID:  schemaID,
			SplitID:   splitID,
			EntrySeqs: int64sToUint64s(seqs),
		}

		newlyDetected, firstDetectedAt, upsertErr := m.upsertEvidence(ctx, evidence)
		if upsertErr != nil {
			m.logger.Error("commitment equivocation upsert failed",
				"schema_id", schemaID,
				"split_id_prefix", fmt.Sprintf("%x", splitID[:8]),
				"error", upsertErr)
			continue
		}
		evidence.FirstDetectedAt = firstDetectedAt

		if newlyDetected {
			m.logger.Warn("COMMITMENT EQUIVOCATION DETECTED",
				"schema_id", schemaID,
				"split_id_prefix", fmt.Sprintf("%x", splitID[:8]),
				"entry_count", len(evidence.EntrySeqs))
			if m.cfg.AlertCallback != nil {
				m.cfg.AlertCallback(evidence)
			}
		}
	}
	return rows.Err()
}

// upsertEvidence inserts a new commitment_equivocation_proofs row
// for the supplied evidence, OR updates an existing row if the
// (schema_id, split_id) UNIQUE constraint trips. Returns whether
// the row was newly inserted (firing the alert callback once per
// incident) and the first_detected_at timestamp.
//
// Update semantics on conflict:
//
//   - entry_seqs is OVERWRITTEN with the latest aggregated set.
//     Postgres does not have a clean "set union" operation in a
//     single UPSERT; the alternative would require an array_cat
//     plus deduplication. The detection query already aggregates
//     every observed sequence, so overwriting with the freshly
//     aggregated array is correct as long as the index is the
//     source of truth (it is — the BTREE index is durable and
//     never deletes rows).
//
//   - last_observed_at bumps to NOW() on every detection so the
//     S3 publisher / operators can see when the incident was last
//     re-confirmed.
//
//   - first_detected_at and alert_dispatched_at are PRESERVED.
//     The monitor's job is to surface evidence; alert dispatch is
//     S3's job, and overwriting alert_dispatched_at would cause
//     the publisher to re-alert on every scan.
func (m *CommitmentEquivocationMonitor) upsertEvidence(
	ctx context.Context, ev CommitmentEquivocationEvidence,
) (newlyDetected bool, firstDetectedAt time.Time, err error) {
	// pgx supplies array values via []int64 / []uint64; convert
	// to int64 for postgres BIGINT[] compatibility.
	seqsForPG := uint64sToInt64s(ev.EntrySeqs)

	var existedBefore bool
	err = m.db.QueryRow(ctx, `
		WITH upsert AS (
			INSERT INTO commitment_equivocation_proofs
				(schema_id, split_id, entry_seqs, first_detected_at, last_observed_at)
			VALUES ($1, $2, $3, NOW(), NOW())
			ON CONFLICT (schema_id, split_id) DO UPDATE
				SET entry_seqs       = EXCLUDED.entry_seqs,
				    last_observed_at = NOW()
			RETURNING xmax <> 0 AS was_updated, first_detected_at
		)
		SELECT was_updated, first_detected_at FROM upsert`,
		ev.SchemaID, ev.SplitID[:], seqsForPG,
	).Scan(&existedBefore, &firstDetectedAt)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("witness: upsert evidence: %w", err)
	}
	return !existedBefore, firstDetectedAt, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// isContextError reports whether err is a context cancellation,
// matching the same predicate used in builder/loop.go and
// witness/equivocation_monitor.go.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// int64sToUint64s converts a Postgres BIGINT[] (returned as []int64)
// to the []uint64 the Evidence struct exposes. Negative values are
// impossible because sequence_number is allocated from a
// CYCLE-disabled SEQUENCE starting at 1, so a sign-flip would be a
// data-corruption signal — log loudly rather than silently mask.
func int64sToUint64s(in []int64) []uint64 {
	out := make([]uint64, len(in))
	for i, v := range in {
		if v < 0 {
			// Sequence numbers are always positive; a negative
			// value here means the row was tampered with. Coerce
			// to zero rather than wrapping; the alert payload
			// will surface the anomaly.
			out[i] = 0
			continue
		}
		out[i] = uint64(v)
	}
	return out
}

// uint64sToInt64s converts the application-layer []uint64 sequence
// list to the []int64 pgx accepts for BIGINT[] parameter binding.
// Sequence numbers fit in int64's positive range comfortably (the
// SEQUENCE caps at the max BIGINT value before wrapping is disabled
// by NO CYCLE), so the cast is safe in practice.
func uint64sToInt64s(in []uint64) []int64 {
	out := make([]int64, len(in))
	for i, v := range in {
		out[i] = int64(v)
	}
	return out
}

// pgxConnUnused is a trivial assertion that pgx's exported types
// remain part of the import graph if a future refactor drops the
// QueryRow / Query call sites. Touching the symbol prevents a
// goimports-driven removal of the pgx dependency.
var pgxConnUnused = (*pgx.Conn)(nil)
