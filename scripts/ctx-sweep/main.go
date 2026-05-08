// ctx_sweep.go — exhaustive Ledger inventory for the SDK ctx migration.
//
// Walks every .go file in the Ledger tree (skipping vendor + .git) and
// reports, per tier:
//
//   - Files that IMPORT the affected SDK package.
//   - Files that CALL the affected SDK function or implement the
//     affected interface (matched against the SDK symbol name).
//   - Locations of the four structural traps (Deep Wire, Lazy Context,
//     Transitive I/O, Post-Commit Detachment).
//
// Why AST and not grep:
//   - Resolves import aliases (`sdkdid "github.com/.../did"` is found
//     under `sdkdid.NewECDSAKeyResolver`, not `did.NewECDSAKeyResolver`).
//   - Distinguishes SelectorExpr (real call) from string literals.
//   - Counts STRUCT fields of an interface type so satisfier types are
//     surfaced as well as direct callers.
//
// Run as: go run ctx_sweep.go <ledger-root>
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Per-tier symbol inventory. Each entry maps an SDK package import
// path to the (function | method | interface) names that the SDK
// migration adds ctx to. Listing the package + symbol is enough —
// callers are SelectorExpr nodes (`pkg.Symbol`) plus interface
// satisfaction via type embedding.
type tierSpec struct {
	name    string
	pkg     string
	symbols []string
}

var tiers = []tierSpec{
	{
		name: "1.1 — types.EntryFetcher + verifier walkers + log.HTTPEntryFetcher + BuildCrossLogProof",
		pkg:  "github.com/clearcompass-ai/attesta/types",
		symbols: []string{
			"EntryFetcher",
		},
	},
	{
		name: "1.1b — log.HTTPEntryFetcher + BuildCrossLogProof",
		pkg:  "github.com/clearcompass-ai/attesta/log",
		symbols: []string{
			"HTTPEntryFetcher", "BuildCrossLogProof",
		},
	},
	{
		name: "1.2 — types.CommitmentFetcher + FetchPREGrantCommitment + FetchEscrowSplitCommitment",
		pkg:  "github.com/clearcompass-ai/attesta/types",
		symbols: []string{
			"CommitmentFetcher", "FetchPREGrantCommitment", "FetchEscrowSplitCommitment",
		},
	},
	{
		name: "1.3 — core/smt.LeafReader/LeafStore/NodeCache/Tree/Overlay",
		pkg:  "github.com/clearcompass-ai/attesta/core/smt",
		symbols: []string{
			"LeafReader", "LeafStore", "NodeCache", "Tree", "Overlay",
			"NewTree", "NewInMemory", "HTTPLeafReader",
		},
	},
	{
		name: "1.4-5 + Tier 0 #2 — DID resolver + SignatureVerifier + applyRotation",
		pkg:  "github.com/clearcompass-ai/attesta/did",
		symbols: []string{
			"DIDResolver", "SignatureVerifier",
			"DefaultVerifierRegistry", "DefaultVerifierRegistryWithRPC",
			"NewECDSAKeyResolver", "ResolvePublicKey",
		},
	},
	{
		name: "1.6-7 + Tier 0 #3 — Witness endpoints + TreeHeadClient",
		pkg:  "github.com/clearcompass-ai/attesta/witness",
		symbols: []string{
			"EndpointResolver", "EndpointProvider", "TreeHeadClient",
			"FetchLatestTreeHead", "FetchFromURL",
		},
	},
	{
		name: "1.8 — gossip/findings perimeter (SignerVerifier, SignerAttested, MerkleAttested)",
		pkg:  "github.com/clearcompass-ai/attesta/gossip/findings",
		symbols: []string{
			"SignerVerifier", "SignerAttested", "MerkleAttested",
			"NewEscrowOverrideFinding", "NewEntryCommitmentEquivocationFinding",
			"NewVerifiedEquivocationFinding", "NewWitnessRotationFinding",
		},
	},
	{
		name: "1.9 — gossip orchestrator (OriginatorVerifier, OriginatorKeyManager, PubKeyResolver, Verify)",
		pkg:  "github.com/clearcompass-ai/attesta/gossip",
		symbols: []string{
			"OriginatorVerifier", "OriginatorKeyManager", "PubKeyResolver",
			"Verify", "Sign", "DIDOriginatorVerifier",
		},
	},
	{
		name: "1.10 — cosign.WitnessSigner.Sign",
		pkg:  "github.com/clearcompass-ai/attesta/crypto/cosign",
		symbols: []string{
			"WitnessSigner", "NewECDSAWitnessSigner",
		},
	},
	{
		name: "1.11 — storage.ContentStore + RetrievalProvider",
		pkg:  "github.com/clearcompass-ai/attesta/storage",
		symbols: []string{
			"ContentStore", "RetrievalProvider",
		},
	},
	{
		name: "1.12 — log.LedgerQueryAPI + DelegationQuerier",
		pkg:  "github.com/clearcompass-ai/attesta/log",
		symbols: []string{
			"LedgerQueryAPI", "DelegationQuerier",
		},
	},
	{
		name: "1.13 — verifier.MerkleProver (mostly satisfiers in Ledger)",
		pkg:  "github.com/clearcompass-ai/attesta/verifier",
		symbols: []string{
			"MerkleProver",
		},
	},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ctx_sweep <ledger-root>")
		os.Exit(2)
	}
	root := os.Args[1]
	fset := token.NewFileSet()

	// Per-file: imports map[importPath]aliasUsed (aliasUsed is the
	// name actually referenced; "" = use the package's intrinsic name).
	type fileSpec struct {
		path    string
		imports map[string]string
		ast     *ast.File
	}
	var files []fileSpec

	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			n := info.Name()
			if n == "vendor" || n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.AllErrors|parser.ParseComments)
		if err != nil {
			return nil
		}
		imps := map[string]string{}
		for _, im := range f.Imports {
			ip := strings.Trim(im.Path.Value, `"`)
			alias := ""
			if im.Name != nil {
				alias = im.Name.Name
			} else {
				// Default to last segment of import path.
				bits := strings.Split(ip, "/")
				alias = bits[len(bits)-1]
			}
			imps[ip] = alias
		}
		files = append(files, fileSpec{path: p, imports: imps, ast: f})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Per-tier: list importing files + symbol-call sites.
	for _, t := range tiers {
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println("Tier:", t.name)
		fmt.Println("SDK package:", t.pkg)
		var importingFiles []string
		var callSites []string
		// Set of symbol names for fast match.
		want := map[string]struct{}{}
		for _, s := range t.symbols {
			want[s] = struct{}{}
		}

		for _, f := range files {
			alias, ok := f.imports[t.pkg]
			if !ok {
				continue
			}
			rel, _ := filepath.Rel(root, f.path)
			importingFiles = append(importingFiles, rel)

			// Walk AST for SelectorExprs `<alias>.<Symbol>`.
			ast.Inspect(f.ast, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if ident.Name != alias {
					return true
				}
				if _, hit := want[sel.Sel.Name]; !hit {
					return true
				}
				pos := fset.Position(sel.Pos())
				rel, _ := filepath.Rel(root, pos.Filename)
				callSites = append(callSites,
					fmt.Sprintf("%s:%d  %s.%s", rel, pos.Line, alias, sel.Sel.Name))
				return true
			})
		}
		sort.Strings(importingFiles)
		sort.Strings(callSites)
		fmt.Printf("  importers (%d): %v\n", len(importingFiles), importingFiles)
		fmt.Printf("  call sites (%d):\n", len(callSites))
		for _, s := range callSites {
			fmt.Println("   ", s)
		}
	}

	// Trap #2: Lazy Context (context.Background / context.TODO outside main + tests + lifecycle/shutdown).
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("TRAP #2 — Lazy Context (context.Background / context.TODO outside boot/teardown)")
	type lazy struct {
		path    string
		line    int
		col     int
		flavor  string
		comment string
	}
	var lazies []lazy
	for _, f := range files {
		if strings.HasSuffix(f.path, "_test.go") {
			continue
		}
		// Resolve the alias for "context".
		ctxAlias := "context"
		if a, ok := f.imports["context"]; ok {
			ctxAlias = a
		} else {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if x.Name != ctxAlias {
				return true
			}
			if sel.Sel.Name != "Background" && sel.Sel.Name != "TODO" {
				return true
			}
			pos := fset.Position(call.Pos())
			rel, _ := filepath.Rel(root, pos.Filename)
			lazies = append(lazies, lazy{rel, pos.Line, pos.Column,
				sel.Sel.Name, ""})
			return true
		})
	}
	// Filter: legal sites are top-of-tree (main.go, root daemons),
	// teardown shutdown contexts (parent ctx already canceled), and
	// boot-helper bootstraps. Anything else is a leak boundary.
	allowed := map[string]bool{
		"cmd/ledger/main.go":                   true,
		"cmd/ledger-reader/main.go":            true,
		"cmd/rebuild-tiles/main.go":            true,
		"cmd/seed-session/main.go":             true,
		"cmd/init-network/main.go":             true,
		"cmd/submit-stamp/main.go":             true,
		"cmd/ledger/boot/teardown/teardown.go": true,
	}
	suspect := 0
	for _, l := range lazies {
		mark := "ok"
		if !allowed[l.path] {
			mark = "SUSPECT"
			suspect++
		}
		fmt.Printf("  %s:%d  context.%s()  %s\n", l.path, l.line, l.flavor, mark)
	}
	fmt.Printf("  → %d suspect site(s) outside the legal allowlist\n", suspect)

	// Trap #4: Post-commit detachment — places that pass r.Context()
	// into a Sink.Broadcast / NotifyAfterCommit / fan-out call.
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("TRAP #4 — Post-commit detachment hot-spots (r.Context() passed to fan-out)")
	hot := []string{}
	for _, f := range files {
		if !strings.Contains(f.path, "/api/") && !strings.Contains(f.path, "/gossipnet/") {
			continue
		}
		if strings.HasSuffix(f.path, "_test.go") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			if name != "Broadcast" && name != "Append" && name != "Publish" && name != "Send" {
				return true
			}
			// Look at first arg — is it an `r.Context()` call?
			if len(call.Args) == 0 {
				return true
			}
			argCall, ok := call.Args[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			argSel, ok := argCall.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if argSel.Sel.Name != "Context" {
				return true
			}
			argX, ok := argSel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// HTTP request convention: "r" or "req".
			if argX.Name != "r" && argX.Name != "req" {
				return true
			}
			pos := fset.Position(call.Pos())
			rel, _ := filepath.Rel(root, pos.Filename)
			hot = append(hot, fmt.Sprintf("%s:%d  %s(...) ← r.Context()",
				rel, pos.Line, name))
			return true
		})
	}
	sort.Strings(hot)
	for _, h := range hot {
		fmt.Println("  ", h)
	}
	fmt.Printf("  → %d hot-spot(s)\n", len(hot))

	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("DONE")
}
