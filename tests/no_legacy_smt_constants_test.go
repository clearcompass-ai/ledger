// Package tests — no_legacy_smt_constants_test.go is a structural
// guard: it walks every .go and .sql file in the ledger module and
// asserts none of them hard-code constants from the v0.2.0 depth-256
// SMT shape.
//
// THE BUG THIS PREVENTS
// ─────────────────────
// Two test fixtures used to reset smt_root_state.current_root to the
// v0.2.0 depth-256 empty-tree hash `876422b7…10e88a`. After the
// migration to v0.3.0 Jellyfish/Patricia (empty-tree hash
// `e3b0c4…b855`), those fixtures still wrote the dead v0.2.0 value
// over the row migration 0003 just installed. The builder loop then
// started from a root that pointed at a node not present in
// jellyfish_nodes, every batch's PostgresNodeStore.Get returned
// "missing node", every atomic commit failed, and the 100K soak
// finished with leaf_count=0.
//
// HOW THIS TEST GUARDS AGAINST RECURRENCE
// ───────────────────────────────────────
// Three patterns trigger a failure:
//
//   1. The literal depth-256 empty-tree hash hex appears anywhere
//      under tests/, cmd/, store/, builder/, api/ — except in
//      historical-context documentation under docs/ and the legacy
//      migration 0002 which intentionally seeds the value before
//      0003 overwrites it.
//
//   2. References to v0.2.0 SDK symbols that should not exist
//      under v0.3.0: TreeDepth, DefaultHash, smt.NodeCache,
//      InMemoryNodeCache, OverlayNodeCache, PostgresNodeCache,
//      NewInMemoryNodeCache, NewOverlayNodeCache, NewPostgresNodeCache,
//      MaterializeToInMemory, Materializable.
//
//   3. The dropped `smt_nodes` table name appears in any active
//      code path — the v0.3.0 schema renames it to jellyfish_nodes.
//
// When the SDK eventually moves to v0.4.0 with another shape change,
// extend the deny-list rather than re-litigate the lesson.
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyEmptyHashHex is the v0.2.0 depth-256 empty-tree hash in lower
// hex. Migration 0003 overwrites smt_root_state.current_root from
// this value to smt.EmptyHash. Any production or test code that
// re-installs this literal is a bug.
const legacyEmptyHashHex = "876422b7697ae7c337e2ee7727feb3db474adf7be1cf04b6b5857d82d610e88a"

// legacySymbols are v0.2.0 SDK identifiers gone in v0.3.0. Their
// appearance in Go source under non-allowlisted paths is a port-
// regression and must fail the test.
var legacySymbols = []string{
	"smt.NodeCache",
	"smt.InMemoryNodeCache",
	"smt.OverlayNodeCache",
	"smt.NewInMemoryNodeCache",
	"smt.NewOverlayNodeCache",
	"smt.DefaultHash",
	"smt.TreeDepth",
	"store.PostgresNodeCache",
	"store.NewPostgresNodeCache",
	"MaterializeToInMemory",
	"Materializable",
}

// allowedHashSites are paths permitted to reference the legacy hex
// for historical reasons: the migration that intentionally seeds it
// (overwritten by 0003) and the migration 0003 file itself
// (documents the constant change). Anything else is a bug.
var allowedHashSites = []string{
	filepath.Join("store", "migrations", "0002_smt_root_state.sql"),
	filepath.Join("store", "migrations", "0003_jellyfish_smt.sql"),
}

// allowedSymbolSites are paths permitted to mention the legacy symbol
// names — comments / CHANGELOG-style documentation only.
var allowedSymbolSites = []string{
	filepath.Join("api", "proofs.go"),                  // doc comment explaining why liveTree is gone
	filepath.Join("cmd", "ledger-reader", "main.go"),   // comment noting v0.2.0 → v0.3.0 rename
	filepath.Join("store", "smt_state.go"),             // self-reference (PostgresNodeStore replaces PostgresNodeCache)
	filepath.Join("docs", "production_readiness.md"),   // history table
	filepath.Join("tests", "no_legacy_smt_constants_test.go"), // this file
}

// TestNoLegacyEmptyHashLiteral fails if any file outside the
// allowlist contains the v0.2.0 depth-256 empty-tree hex.
func TestNoLegacyEmptyHashLiteral(t *testing.T) {
	root := moduleRoot(t)
	var violations []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasSuffix(path, "/.git") || strings.Contains(path, "/.run/") || strings.Contains(path, "/vendor/") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !isCodeOrSQL(rel) {
			return nil
		}
		for _, allowed := range allowedHashSites {
			if rel == allowed {
				return nil
			}
		}
		// Allow the literal inside this regression test (it's the
		// reference value used to detect the bad pattern).
		if rel == filepath.Join("tests", "no_legacy_smt_constants_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := strings.ToLower(string(body))
		if strings.Contains(text, legacyEmptyHashHex) {
			violations = append(violations, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("v0.2.0 depth-256 empty-tree hash literal must not appear outside the allowlist.\n"+
			"Found in %d file(s):\n  - %s\n"+
			"Fix: use smt.EmptyHash (v0.3.0) instead of the literal. See cleanTables in tests/helpers_test.go for the pattern.",
			len(violations), strings.Join(violations, "\n  - "))
	}
}

// TestNoLegacySymbols fails if any .go file outside the allowlist
// references a removed v0.2.0 SDK identifier.
func TestNoLegacySymbols(t *testing.T) {
	root := moduleRoot(t)
	type hit struct{ rel, sym, snippet string }
	var hits []hit
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasSuffix(path, "/.git") || strings.Contains(path, "/.run/") || strings.Contains(path, "/vendor/") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !strings.HasSuffix(rel, ".go") {
			return nil
		}
		for _, allowed := range allowedSymbolSites {
			if rel == allowed {
				return nil
			}
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		for _, sym := range legacySymbols {
			if idx := strings.Index(text, sym); idx >= 0 {
				// Skip comment lines — narrow heuristic: if the
				// occurrence sits in a line whose first
				// non-whitespace character is `/` or `*`, ignore.
				lineStart := strings.LastIndex(text[:idx], "\n") + 1
				lineEnd := strings.Index(text[idx:], "\n")
				if lineEnd < 0 {
					lineEnd = len(text)
				} else {
					lineEnd += idx
				}
				line := text[lineStart:lineEnd]
				trimmed := strings.TrimLeft(line, " \t")
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				hits = append(hits, hit{rel: rel, sym: sym, snippet: strings.TrimSpace(line)})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) > 0 {
		var msg strings.Builder
		msg.WriteString("legacy v0.2.0 SDK symbol(s) must not appear in active code paths.\n")
		for _, h := range hits {
			msg.WriteString("  " + h.rel + ": " + h.sym + "  →  " + h.snippet + "\n")
		}
		msg.WriteString("Fix: replace with the v0.3.0 equivalent.\n" +
			"  smt.NodeCache               → smt.NodeStore\n" +
			"  smt.InMemoryNodeCache       → smt.InMemoryNodeStore\n" +
			"  smt.OverlayNodeCache        → smt.OverlayNodeStore\n" +
			"  smt.NewInMemoryNodeCache    → smt.NewInMemoryNodeStore\n" +
			"  smt.NewOverlayNodeCache     → smt.NewOverlayNodeStore\n" +
			"  smt.DefaultHash(depth)      → smt.EmptyHash (constant)\n" +
			"  smt.TreeDepth               → (removed; no depth in path-compressed trie)\n" +
			"  store.PostgresNodeCache     → store.PostgresNodeStore\n" +
			"  store.NewPostgresNodeCache  → store.NewPostgresNodeStore\n" +
			"  MaterializeToInMemory       → (removed; v0.3.0 Tree.Root is incremental)\n" +
			"  Materializable              → (removed; v0.3.0 SDK reads PostgresLeafStore natively)\n")
		t.Fatal(msg.String())
	}
}

// TestNoSmtNodesTable fails if any active code path still names the
// dropped `smt_nodes` table. Migration 0003 drops it and creates
// `jellyfish_nodes` in its place.
func TestNoSmtNodesTable(t *testing.T) {
	root := moduleRoot(t)
	allowed := map[string]bool{
		filepath.Join("store", "migrations", "0001_initial.sql"):    true, // original definition
		filepath.Join("store", "migrations", "0003_jellyfish_smt.sql"): true, // DROP TABLE smt_nodes
		filepath.Join("tests", "no_legacy_smt_constants_test.go"):     true, // this file
		filepath.Join("docs", "production_readiness.md"):              true, // history table
	}
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasSuffix(path, "/.git") || strings.Contains(path, "/.run/") || strings.Contains(path, "/vendor/") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !isCodeOrSQL(rel) {
			return nil
		}
		if allowed[rel] {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Quote-delimited or table-statement contexts; bare word
		// match is too noisy because of comments.
		text := string(body)
		patterns := []string{
			`"smt_nodes"`,
			"`smt_nodes`",
			"FROM smt_nodes",
			"INTO smt_nodes",
			"TABLE smt_nodes",
			"UPDATE smt_nodes",
			"DELETE FROM smt_nodes",
		}
		for _, p := range patterns {
			if strings.Contains(text, p) {
				hits = append(hits, rel+" → "+p)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) > 0 {
		t.Fatalf("the dropped table `smt_nodes` is still referenced.\n"+
			"Found in %d file(s):\n  - %s\n"+
			"Fix: replace with `jellyfish_nodes` (the v0.3.0 content-addressed node table).",
			len(hits), strings.Join(hits, "\n  - "))
	}
}

// moduleRoot returns the absolute path of the ledger module root —
// the directory containing go.mod. We rely on tests running from
// either the module root or any subdirectory under it.
func moduleRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getcwd: %v", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod walking up from %s", cwd)
		}
		dir = parent
	}
}

func isCodeOrSQL(rel string) bool {
	return strings.HasSuffix(rel, ".go") ||
		strings.HasSuffix(rel, ".sql") ||
		strings.HasSuffix(rel, ".yaml") ||
		strings.HasSuffix(rel, ".yml")
}
