package report

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestModel(t *testing.T) {
	def, err := Model(ModeDefault, nil)
	if err != nil || !strings.HasPrefix(def, "Sinon, format Markdown:") || !strings.HasSuffix(def, "« Vérification ».\n") {
		t.Fatalf("modèle par défaut: %v\n%s", err, def)
	}
	cve, err := Model(ModeCVE, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range []string{"verdict", "fiche", "positives", "unknown", "negatives"} {
		if !strings.Contains(cve, "{{cve.<ID>."+block+"}}") {
			t.Fatalf("bloc %s absent du modèle CVE", block)
		}
	}
	if _, err := Model("incident", nil); err == nil {
		t.Fatal("mode inconnu accepté")
	}
	path := filepath.Join(t.TempDir(), "cve.md")
	if err := os.WriteFile(path, []byte("modèle local\r\n{{cve.<ID>.verdict}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Model(ModeCVE, map[string]string{ModeCVE: path}); err != nil || got != "modèle local\n{{cve.<ID>.verdict}}" {
		t.Fatalf("surcharge: %q %v", got, err)
	}
	if _, err := Model(ModeCVE, map[string]string{ModeCVE: path + ".absent"}); err == nil {
		t.Fatal("modèle absent accepté")
	}
}

func TestFill(t *testing.T) {
	blocks := map[string]string{
		"cve.CVE-1.verdict":   "🚨 1",
		"cve.CVE-1.positives": "| a |",
		"cve.CVE-1.negatives": "neg",
		"cve.CVE-1.unknown":   "",
	}
	order := []string{"cve.CVE-1.verdict", "cve.CVE-1.positives", "cve.CVE-1.unknown", "cve.CVE-1.negatives"}
	md := "# CVE-1\n\n## 1. Verdict\n\n{{ cve.cve-1.verdict }}\n\n<!-- consigne\nsur deux lignes -->\n\n\n\n- **Touché**\n\n## 3\n\n{{cve.CVE-1.positives}}\n{{cve.CVE-1.positives}}\n{{cve.CVE-9.verdict}}\n"
	got, missing := Fill(md, blocks, order, "Données CVE")
	if !slices.Equal(missing, []string{"cve.CVE-1.negatives"}) {
		t.Fatalf("manquants: %v", missing)
	}
	for _, want := range []string{"## 1. Verdict\n\n🚨 1\n\n- **Touché**", "| a |\n", "---\n\n## Données CVE\n\nneg\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q absent de\n%s", want, got)
		}
	}
	if strings.Contains(got, "{{") || strings.Contains(got, "consigne") || strings.Count(got, "| a |") != 1 || strings.Contains(got, "\n\n\n") {
		t.Fatalf("rendu:\n%s", got)
	}
}
