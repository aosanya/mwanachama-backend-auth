package mwanachamaauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// domainWords are words that mean something in one domain and nothing in
// another. This module must run a clinic's front desk and a library's reader
// accounts without a line changing, so none of them may appear in an
// identifier here. A reader from a different domain would not recognise them.
var domainWords = []string{
	"member", "agency", "chapter", "sector", "archetype", "wakala",
	"mwanachama", "citizen", "constituency", "ward", "sacco", "chama",
}

// A struct tag is a presentation choice, not an identifier: the wire name
// member_id is kept deliberately so the HTTP contract the gateway and
// wakala-api already publish does not move, and the same goes for the
// /members/ path segments in the declared operations. The column underneath
// is subject_id, which is what this test protects.
func TestNoDomainWordInAnIdentifier(t *testing.T) {
	for _, dir := range []string{".", "models", "routes"} {
		t.Run(dir, func(t *testing.T) {
			for _, path := range goFilesIn(t, dir) {
				checkIdentifiers(t, path)
			}
		})
	}
}

func goFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}

func checkIdentifiers(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	// The package clause and the import aliases carry the module's own name,
	// which the module path fixes and which is not a claim about any domain.
	exempt := map[string]bool{file.Name.Name: true}
	for _, imp := range file.Imports {
		if imp.Name != nil {
			exempt[imp.Name.Name] = true
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if exempt[id.Name] {
			return true
		}
		lower := strings.ToLower(id.Name)
		for _, word := range domainWords {
			if strings.Contains(lower, word) {
				t.Errorf("%s: the identifier %q carries the domain word %q; this module names no domain",
					fset.Position(id.Pos()), id.Name, word)
			}
		}
		return true
	})
}

// A stored enum value outlives a rename, which is the worst version of this
// failure: the Go constant can be corrected in one commit and every row
// written before it still says the old word.
func TestNoDomainWordInAStoredEnumValue(t *testing.T) {
	b, err := mwanachamaauth.Blueprint()
	if err != nil {
		t.Fatalf("Blueprint: %v", err)
	}
	for _, o := range b.Objects {
		for _, f := range o.Fields {
			for _, v := range f.Values {
				lower := strings.ToLower(v)
				for _, word := range domainWords {
					if strings.Contains(lower, word) {
						t.Errorf("%s.%s declares the stored value %q, which carries the domain word %q; a stored value outlives a rename",
							o.Role, f.Name, v, word)
					}
				}
			}
		}
	}
}

// The action ids are a vocabulary other repos grant against, so a domain word
// in one of them would be granted by name across every instance.
func TestNoDomainWordInAnActionID(t *testing.T) {
	s, err := mwanachamaauth.OperationSpec()
	if err != nil {
		t.Fatalf("OperationSpec: %v", err)
	}
	for name, op := range s.Operations {
		lower := strings.ToLower(op.Action)
		for _, word := range domainWords {
			if strings.Contains(lower, word) {
				t.Errorf("operation %q declares the action %q, which carries the domain word %q",
					name, op.Action, word)
			}
		}
	}
}
