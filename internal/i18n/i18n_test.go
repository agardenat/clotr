package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestLanguages(t *testing.T) {
	defer func() { ui, report, uiSet = "en", "en", false }()
	SetReport("fr")
	if N(1, "step") != "1 step" || N(3, "step") != "3 steps" || T("waiting", "t1") != "waiting for t1" || R("evidence.title") != "Annexe — preuves citées" {
		t.Fatal("rapport fr : l'interface doit rester en anglais")
	}
	SetUI("fr")
	SetReport("auto")
	if N(0, "finding") != "0 constat" || N(2, "tool call") != "2 appels d'outils" || T("step.n", 4) != "étape 4" || R("evidence.title") != "Appendix — cited evidence" {
		t.Fatal("interface fr, rapport auto")
	}
	DefaultUI("en")
	if UI() != "fr" {
		t.Fatal("ui_language de la config ne doit pas écraser --ui-lang")
	}
	if err := E("cli.err.turn_results", 3, Key("llm.request_timeout")); err.Error() != "tour 3 sans résultats enregistrés : request_timeout dépassé" {
		t.Fatal(err)
	}
}

var verb = regexp.MustCompile(`%(?:\[(\d+)\])?[-+# 0]*\d*(?:\.\d+)?[a-zA-Z%]`)

func verbs(s string) []string {
	var out []string
	for _, m := range verb.FindAllStringSubmatch(s, -1) {
		if !strings.HasSuffix(m[0], "%") {
			out = append(out, m[0][len(m[0])-1:]+m[1])
		}
	}
	return out
}

func arity(s string) int {
	n := 0
	for _, m := range verb.FindAllStringSubmatch(s, -1) {
		switch {
		case strings.HasSuffix(m[0], "%"):
		case m[1] != "":
			i, _ := strconv.Atoi(m[1])
			n = max(n, i)
		default:
			n++
		}
	}
	return n
}

func TestCatalog(t *testing.T) {
	for name, cat := range map[string]map[string]msg{"msgs": msgs, "reportMsgs": reportMsgs, "plurals": plurals} {
		for k, m := range cat {
			if m.en == "" || m.fr == "" {
				t.Errorf("%s %s : traduction manquante", name, k)
			}
			if a, b := verbs(m.en), verbs(m.fr); !slices.Equal(a, b) {
				t.Errorf("%s %s : verbes différents en %v / fr %v", name, k, a, b)
			}
		}
	}
}

func TestCallSites(t *testing.T) {
	used := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "internal/i18n/") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "i18n" {
				return true
			}
			if sel.Sel.Name == "N" {
				if lit, ok := call.Args[1].(*ast.BasicLit); ok {
					k, _ := strconv.Unquote(lit.Value)
					used[k] = true
					if _, found := plurals[k]; !found {
						t.Errorf("%s : pluriel %q absent du catalogue", fset.Position(lit.Pos()), k)
					}
				}
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				if b, ok := call.Args[0].(*ast.BinaryExpr); ok {
					if l, ok := b.X.(*ast.BasicLit); ok {
						p, _ := strconv.Unquote(l.Value)
						for k := range msgs {
							if strings.HasPrefix(k, p) {
								used[k] = true
							}
						}
					}
				}
				return true
			}
			key, _ := strconv.Unquote(lit.Value)
			used[key] = true
			pos := fset.Position(lit.Pos())
			var m msg
			var found bool
			switch sel.Sel.Name {
			case "T", "E", "Key":
				m, found = msgs[key]
			case "R", "All":
				m, found = reportMsgs[key]
			default:
				return true
			}
			if !found {
				t.Errorf("%s : clé %q absente du catalogue", pos, key)
				return true
			}
			if sel.Sel.Name == "Key" || call.Ellipsis.IsValid() {
				return true
			}
			if want, got := arity(m.en), len(call.Args)-1; want != got {
				t.Errorf("%s : %q attend %d argument(s), %d fourni(s)", pos, key, want, got)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, cat := range []map[string]msg{msgs, reportMsgs, plurals} {
		for k := range cat {
			if !used[k] {
				t.Errorf("clé %q inutilisée", k)
			}
		}
	}
}
