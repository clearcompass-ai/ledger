// ctx-contract-check — bidirectional AST + type-checker validation
// of every SDK interface contract against every Ledger candidate
// satisfier.
//
// FILE PATH:
//
//	scripts/ctx-contract-check/main.go
//
// WHAT THIS DOES (and what the older scripts/ctx-sweep does NOT):
//
//   - Loads the SDK and the Ledger via golang.org/x/tools/go/packages
//     with the FULL Go type checker (NeedTypes | NeedTypesInfo). No
//     hardcoded symbol lists, no string matching, no grep.
//
//   - Enumerates every exported interface in every SDK package
//     (github.com/clearcompass-ai/attesta/...) by walking the package
//     scope and selecting *types.TypeName whose underlying type is
//     *types.Interface.
//
//   - Enumerates every named type in every Ledger package
//     (github.com/clearcompass-ai/ledger/...).
//
//   - For each (SDK interface, Ledger type) pair, asks the Go type
//     checker:
//
//     types.Implements(T, I)  → does T fully implement I right now?
//     types.MissingMethod(T, I, true)
//     → if not, which method is missing or
//     has the wrong signature?
//
//     types.Implements is the SAME function `go build` invokes when
//     it decides whether `var _ I = (*T)(nil)` compiles. There is no
//     more authoritative validator than this in Go.
//
//   - Reports three classes per interface:
//
//     ✓ Satisfiers          — types that fully implement (current
//     state; will need to update as SDK
//     adds ctx).
//     ⚠ Almost-satisfiers   — types whose method set OVERLAPS with
//     the interface (≥ 1 method by name)
//     but DOESN'T fully implement. These
//     are migration-in-progress: SDK
//     contract drifted, Ledger satisfier
//     hasn't caught up yet. Prints the
//     structural diff (SDK sig vs Ledger
//     sig) per offending method.
//     (silent on types with zero overlap — they're not candidates.)
//
// USAGE:
//
//	go run ./scripts/ctx-contract-check .
//
// EXIT CODE:
//
//	0  no almost-satisfiers (every Ledger candidate fully aligns with
//	   the SDK interfaces it intends to implement).
//	1  one or more structural mismatches (the SDK has changed; Ledger
//	   needs updating).
//
// LIMITATIONS:
//
//   - Reports types with method-name overlap that aren't intended
//     to satisfy the interface (e.g., a Ledger type happens to have
//     a method called "Close" but isn't a connection). Filter by
//     reading the report and ignoring obvious false-positives.
//
//   - Doesn't track call-site mismatches (Ledger calls SDK function
//     with wrong args). Those are caught by `go build` directly —
//     this tool's value is PRE-build interface-shape validation
//     against an SDK whose .go files are already on disk.
package main

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	sdkPathPrefix    = "github.com/clearcompass-ai/attesta/"
	ledgerPathPrefix = "github.com/clearcompass-ai/ledger"
)

type satReport struct {
	typeName string
	pkgPath  string
	pos      token.Position
}

type methodStatus struct {
	name      string
	sdkSig    string
	ledgerSig string // empty if Ledger lacks the method
	state     string // "match", "wrong-sig", "missing"
}

type almostReport struct {
	typeName string
	pkgPath  string
	pos      token.Position
	methods  []methodStatus // one entry per SDK interface method
	matched  int            // number of methods that match exactly
	wrongSig int            // number of methods with wrong signature
	missing  int            // number of methods absent from Ledger
}

type ifaceReport struct {
	ifacePkg  string
	ifaceName string
	ifacePos  token.Position
	iface     *types.Interface

	satisfiers       []satReport
	almostSatisfiers []almostReport
}

func main() {
	verbose := flag.Bool("v", false, "print packages even with no satisfiers")
	showAll := flag.Bool("all", false,
		"include almost-satisfiers where the Ledger lacks the method entirely "+
			"(naming coincidence). Default: only show wrong-SIGNATURE mismatches "+
			"— these are the real migration targets.")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctx-contract-check [-v] [-all] <ledger-root>")
		os.Exit(2)
	}
	dir := flag.Arg(0)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedDeps | packages.NeedImports,
		Dir: dir,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(2)
	}
	if errs := packages.PrintErrors(pkgs); errs > 0 {
		fmt.Fprintf(os.Stderr, "load: %d errors (continuing with partial type info)\n", errs)
	}

	// Walk the dependency closure: classify each loaded package as SDK,
	// Ledger, or neither.
	var sdkPkgs, ledgerPkgs []*packages.Package
	seen := map[string]bool{}
	var collect func(*packages.Package)
	collect = func(p *packages.Package) {
		if p == nil || seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		switch {
		case strings.HasPrefix(p.PkgPath, sdkPathPrefix):
			sdkPkgs = append(sdkPkgs, p)
		case p.PkgPath == ledgerPathPrefix || strings.HasPrefix(p.PkgPath, ledgerPathPrefix+"/"):
			ledgerPkgs = append(ledgerPkgs, p)
		}
		for _, imp := range p.Imports {
			collect(imp)
		}
	}
	for _, p := range pkgs {
		collect(p)
	}

	if len(pkgs) == 0 || pkgs[0].Fset == nil {
		fmt.Fprintln(os.Stderr, "no packages loaded")
		os.Exit(2)
	}
	fset := pkgs[0].Fset

	// Enumerate SDK interfaces.
	var ifaces []*ifaceReport
	for _, p := range sdkPkgs {
		if p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			tn, ok := obj.(*types.TypeName)
			if !ok || !tn.Exported() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			iface, ok := named.Underlying().(*types.Interface)
			if !ok {
				continue
			}
			if iface.NumMethods() == 0 {
				continue // marker / empty interface — skip
			}
			ifaces = append(ifaces, &ifaceReport{
				ifacePkg:  p.PkgPath,
				ifaceName: name,
				ifacePos:  fset.Position(tn.Pos()),
				iface:     iface,
			})
		}
	}

	// For each SDK interface, scan every Ledger named type for
	// satisfaction (or near-satisfaction).
	for _, sif := range ifaces {
		ifaceMethodNames := map[string]bool{}
		for j := 0; j < sif.iface.NumMethods(); j++ {
			ifaceMethodNames[sif.iface.Method(j).Name()] = true
		}

		for _, p := range ledgerPkgs {
			if p.Types == nil {
				continue
			}
			// Anti-noise filter: a candidate Ledger package can only
			// be an INTENTIONAL satisfier of an SDK interface if it
			// imports the interface's package (directly or
			// transitively via the type system). The cheap check is
			// a direct import; this rules out a lot of name-collision
			// false positives where unrelated types share method
			// names like Get/Close/Set.
			if !packageDirectlyImports(p, sif.ifacePkg) {
				continue
			}
			scope := p.Types.Scope()
			for _, name := range scope.Names() {
				obj := scope.Lookup(name)
				tn, ok := obj.(*types.TypeName)
				if !ok {
					continue
				}
				named, ok := tn.Type().(*types.Named)
				if !ok {
					continue
				}
				// Skip type aliases and interface types — we only
				// want concrete satisfier candidates.
				if _, isIface := named.Underlying().(*types.Interface); isIface {
					continue
				}

				vT := types.Type(named)
				ptrT := types.Type(types.NewPointer(named))

				// Full satisfier check (try value + pointer receivers).
				if types.Implements(vT, sif.iface) || types.Implements(ptrT, sif.iface) {
					sif.satisfiers = append(sif.satisfiers, satReport{
						typeName: name,
						pkgPath:  p.PkgPath,
						pos:      fset.Position(tn.Pos()),
					})
					continue
				}

				// Not a full satisfier — measure overlap.
				if !hasMethodNameOverlap(named, ifaceMethodNames) {
					continue
				}

				// Confirm at least one method-set check fails;
				// otherwise the type would have been classified as a
				// satisfier above. (We've already returned at the
				// `types.Implements` branch when it does fully
				// implement; this is a guard for races between the
				// two type-check passes.)
				if m, _ := types.MissingMethod(ptrT, sif.iface, true); m == nil {
					continue
				}

				// Walk every method on the SDK interface; categorize
				// the Ledger type's contribution per method. Both
				// sides go through sigString so the "func" prefix is
				// stripped consistently before comparison.
				ar := almostReport{
					typeName: name,
					pkgPath:  p.PkgPath,
					pos:      fset.Position(tn.Pos()),
				}
				for j := 0; j < sif.iface.NumMethods(); j++ {
					im := sif.iface.Method(j)
					sdkSig := sigString(im.Type())
					ledgerSigRaw := lookupLedgerMethodSig(named, im.Name())
					var ledgerSig string
					if ledgerSigRaw != "" {
						ledgerSig = sigString(typeFromString(ledgerSigRaw))
					}
					st := methodStatus{
						name:      im.Name(),
						sdkSig:    sdkSig,
						ledgerSig: ledgerSig,
					}
					switch ledgerSig {
					case "":
						st.state = "missing"
						ar.missing++
					case sdkSig:
						st.state = "match"
						ar.matched++
					default:
						st.state = "wrong-sig"
						ar.wrongSig++
					}
					ar.methods = append(ar.methods, st)
				}
				sif.almostSatisfiers = append(sif.almostSatisfiers, ar)
			}
		}
	}

	// Sort interfaces by package + name for stable output.
	sort.Slice(ifaces, func(i, j int) bool {
		if ifaces[i].ifacePkg != ifaces[j].ifacePkg {
			return ifaces[i].ifacePkg < ifaces[j].ifacePkg
		}
		return ifaces[i].ifaceName < ifaces[j].ifaceName
	})

	// Report.
	fmt.Printf("Loaded: %d SDK packages, %d Ledger packages\n", len(sdkPkgs), len(ledgerPkgs))
	fmt.Printf("Found:  %d exported SDK interfaces with ≥ 1 method\n\n", len(ifaces))

	// Pre-filter pass to compute the right summary numbers.
	type prefilterCount struct {
		sat, almost int
	}
	pre := make([]prefilterCount, len(ifaces))
	for i, sif := range ifaces {
		pre[i].sat = len(sif.satisfiers)
		for _, a := range sif.almostSatisfiers {
			if a.wrongSig > 0 || *showAll {
				pre[i].almost++
			}
		}
	}

	totalSat, totalAlmost, ifacesWithHits := 0, 0, 0
	for i, sif := range ifaces {
		if pre[i].sat == 0 && pre[i].almost == 0 {
			if !*verbose {
				continue
			}
		}
		ifacesWithHits++
		totalSat += pre[i].sat
		totalAlmost += pre[i].almost

		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("SDK interface: %s.%s\n", sif.ifacePkg, sif.ifaceName)
		fmt.Printf("  declared at: %s\n", relPos(sif.ifacePos, dir))
		fmt.Println("  contract:")
		// Sort methods by name for stability.
		methods := make([]*types.Func, sif.iface.NumMethods())
		for j := range methods {
			methods[j] = sif.iface.Method(j)
		}
		sort.Slice(methods, func(i, j int) bool { return methods[i].Name() < methods[j].Name() })
		for _, m := range methods {
			fmt.Printf("    %s%s\n", m.Name(), sigString(m.Type()))
		}

		if len(sif.satisfiers) > 0 {
			sort.Slice(sif.satisfiers, func(i, j int) bool {
				return sif.satisfiers[i].pkgPath+sif.satisfiers[i].typeName <
					sif.satisfiers[j].pkgPath+sif.satisfiers[j].typeName
			})
			fmt.Printf("\n  ✓ Ledger satisfiers (%d):\n", len(sif.satisfiers))
			for _, s := range sif.satisfiers {
				fmt.Printf("    %s.%s   (%s)\n",
					trimPkgPath(s.pkgPath), s.typeName, relPos(s.pos, dir))
			}
		}

		// Filter almost-satisfiers per -all flag. The default cuts
		// types whose only contact with the interface is missing
		// methods (zero overlap with wrong-sig); -all relaxes to
		// any candidate the heuristic considered.
		filtered := sif.almostSatisfiers[:0]
		for _, a := range sif.almostSatisfiers {
			if a.wrongSig > 0 || *showAll {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) > 0 {
			sort.Slice(filtered, func(i, j int) bool {
				return filtered[i].pkgPath+filtered[i].typeName <
					filtered[j].pkgPath+filtered[j].typeName
			})
			label := "wrong-signature on at least one method"
			if *showAll {
				label = "any method-name overlap"
			}
			fmt.Printf("\n  ⚠ ALMOST-satisfiers (%d) — %s:\n",
				len(filtered), label)
			for _, a := range filtered {
				ifaceN := len(a.methods)
				fmt.Printf("    %s.%s   (%s)\n",
					trimPkgPath(a.pkgPath), a.typeName, relPos(a.pos, dir))
				fmt.Printf("        coverage: %d match · %d wrong-sig · %d missing  (of %d)\n",
					a.matched, a.wrongSig, a.missing, ifaceN)
				for _, m := range a.methods {
					var glyph string
					switch m.state {
					case "match":
						glyph = "✓"
					case "wrong-sig":
						glyph = "⚠"
					case "missing":
						glyph = "✗"
					}
					switch m.state {
					case "match":
						fmt.Printf("        %s %s%s\n", glyph, m.name, m.sdkSig)
					case "wrong-sig":
						fmt.Printf("        %s %s\n", glyph, m.name)
						fmt.Printf("            SDK    : %s%s\n", m.name, m.sdkSig)
						fmt.Printf("            Ledger : %s%s\n", m.name, m.ledgerSig)
					case "missing":
						fmt.Printf("        %s %s%s   (Ledger lacks this method)\n", glyph, m.name, m.sdkSig)
					}
				}
			}
		}
		// Update the per-iface count for the summary.
		sif.almostSatisfiers = filtered
	}

	fmt.Println("\n════════════════════════════════════════════════════════════")
	fmt.Printf("Summary\n")
	fmt.Printf("  SDK interfaces with ≥ 1 Ledger relation : %d\n", ifacesWithHits)
	fmt.Printf("  Ledger types that FULLY satisfy           : %d\n", totalSat)
	fmt.Printf("  Ledger types that ALMOST satisfy          : %d\n", totalAlmost)
	if totalAlmost > 0 {
		fmt.Println()
		fmt.Println("✗ Migration mismatches detected — Ledger satisfier method signatures")
		fmt.Println("  diverge from the SDK interface they overlap with. Each ⚠ block above")
		fmt.Println("  is a target. Reconcile the signature, or delete the candidate type.")
		os.Exit(1)
	}
	fmt.Println("\n✓ No structural mismatches. Every Ledger candidate aligns with the SDK.")
}

// packageDirectlyImports reports whether p imports the package at
// importPath. Used to suppress name-collision noise from Ledger
// packages that aren't aware of the SDK interface at all.
func packageDirectlyImports(p *packages.Package, importPath string) bool {
	for path := range p.Imports {
		if path == importPath {
			return true
		}
	}
	return false
}

// hasMethodNameOverlap reports whether the named type (or its
// pointer) has at least one method whose name appears in want. Used
// to avoid printing "almost satisfier" entries for types that happen
// to share zero method names with the interface (those aren't
// candidates).
func hasMethodNameOverlap(named *types.Named, want map[string]bool) bool {
	for _, t := range []types.Type{types.Type(named), types.NewPointer(named)} {
		ms := types.NewMethodSet(t)
		for j := 0; j < ms.Len(); j++ {
			if want[ms.At(j).Obj().Name()] {
				return true
			}
		}
	}
	return false
}

// lookupLedgerMethodSig returns the Ledger type's signature for
// `methodName` as a *types.Signature.String() value. Returns "" if
// the type doesn't have that method (i.e., missing entirely).
func lookupLedgerMethodSig(named *types.Named, methodName string) string {
	for _, t := range []types.Type{types.Type(named), types.NewPointer(named)} {
		ms := types.NewMethodSet(t)
		for j := 0; j < ms.Len(); j++ {
			sel := ms.At(j)
			if sel.Obj().Name() == methodName {
				return sel.Obj().Type().String()
			}
		}
	}
	return ""
}

// sigString renders a *types.Signature without the leading "func"
// keyword, so output reads like `(ctx Context) error` rather than
// `func(ctx Context) error`.
func sigString(t types.Type) string {
	s := t.String()
	if strings.HasPrefix(s, "func") {
		return s[len("func"):]
	}
	return s
}

// typeFromString is a no-op helper used only to satisfy sigString's
// types.Type input when we already have a string. Used for the
// pretty-printed Ledger sig.
func typeFromString(s string) types.Type {
	return stringType{s: s}
}

type stringType struct {
	s string
}

func (st stringType) Underlying() types.Type { return st }
func (st stringType) String() string         { return st.s }

func trimPkgPath(p string) string {
	return strings.TrimPrefix(p, "github.com/clearcompass-ai/")
}

// relPos converts an absolute file path inside a token.Position to a
// path relative to dir, for shorter, copy-pasteable output.
func relPos(p token.Position, dir string) string {
	file := p.Filename
	if strings.HasPrefix(file, dir+"/") {
		file = strings.TrimPrefix(file, dir+"/")
	}
	if p.Line > 0 {
		return fmt.Sprintf("%s:%d", file, p.Line)
	}
	return file
}
