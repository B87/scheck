package llm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Build is the only constructor of a provider: no other function in the
// package reads a registered factory, and no exported function calls
// Build, so scripts/depcheck.sh's pin on references to llm.Build holds
// who builds one (AGENTS.md, "nothing was sent to the makers of scheck").
func TestBuildIsTheOnlyConstructor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "Build" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if x.Sel.Name == "factory" {
						t.Errorf("%s: %s reads a factory; only Build may", fset.Position(x.Pos()), fn.Name.Name)
					}
				case *ast.Ident:
					if x.Name == "Build" && fn.Name.IsExported() {
						t.Errorf("%s: exported %s refers to Build", fset.Position(x.Pos()), fn.Name.Name)
					}
				}
				return true
			})
		}
	}
}
