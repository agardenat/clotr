package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agardenat/clotr/internal/session"
)

func TestResolveExport(t *testing.T) {
	cases := []struct {
		name, flag, output string
		json               bool
		format, path, md   string
		err                bool
	}{
		{"rien", "", "", false, "", "", "", false},
		{"markdown", "", "r.md", false, "", "", "r.md", false},
		{"flag seul", "pdf", "", false, "pdf", "", "", false},
		{"flag + markdown", "docx", "r.md", false, "docx", "", "r.md", false},
		{"-o docx", "", "r.DOCX", false, "docx", "r.DOCX", "", false},
		{"-o pdf + flag", "pdf", "r.pdf", false, "pdf", "r.pdf", "", false},
		{"incohérent", "pdf", "r.docx", false, "", "", "", true},
		{"format inconnu", "odt", "", false, "", "", "", true},
		{"json vers docx", "", "r.docx", true, "", "", "", true},
	}
	for _, c := range cases {
		o := &options{exportFmt: c.flag, output: c.output, json: c.json}
		err := o.resolveExport()
		if (err != nil) != c.err {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !c.err && (o.exportFmt != c.format || o.exportPath != c.path || o.output != c.md) {
			t.Errorf("%s: format=%q path=%q output=%q", c.name, o.exportFmt, o.exportPath, o.output)
		}
	}
}

func TestReportLanguage(t *testing.T) {
	for _, c := range []struct{ lang, md, want string }{
		{"en", "le service est arrêté", "en"},
		{"auto", "Le service est arrêté dans la nuit, aucun impact pour les utilisateurs.", "fr"},
		{"auto", "The service is stopped and there was no impact on the users of this cluster.", "en"},
		{"", "", "fr"},
		{"auto", "Le service est arrêté dans la nuit.\n\n```\nThe service is stopped and there is no data for the users of this cluster and the file is not on the host\n```\n", "fr"},
	} {
		if got := reportLanguage(c.lang, c.md); got != c.want {
			t.Errorf("%q %q: %s", c.lang, c.md, got)
		}
	}
}

func TestExportTitle(t *testing.T) {
	if got := exportTitle("intro\n# Titre du rapport\n## A", "demande"); got != "Titre du rapport" {
		t.Fatalf("H1: %q", got)
	}
	if got := exportTitle("## A\ntexte", "  analyse   du cluster "); got != "analyse du cluster" {
		t.Fatalf("demande: %q", got)
	}
}

func TestImagePath(t *testing.T) {
	for _, c := range []struct {
		src    string
		nested bool
		want   bool
	}{
		{"schema.png", false, true},
		{"img/schema.png", false, false},
		{"img/schema.png", true, true},
		{"./img/schema.png", true, true},
		{"../schema.png", true, false},
		{"img/../../schema.png", true, false},
		{"/etc/schema.png", true, false},
		{"https://example.org/a.png", true, false},
		{".hidden.png", false, false},
	} {
		if got := imagePath(c.src, c.nested); got != c.want {
			t.Errorf("imagePath(%q, %v) = %v", c.src, c.nested, got)
		}
	}
}

func TestCVEReportTitle(t *testing.T) {
	ids := []string{"CVE-2026-11111", "CVE-2026-22222"}
	if got := cveReportTitle("fr", ids); got != "Rapport CVE-2026-11111, CVE-2026-22222" {
		t.Fatalf("fr: %q", got)
	}
	if got := cveReportTitle("en", ids); got != "Report CVE-2026-11111, CVE-2026-22222" {
		t.Fatalf("en: %q", got)
	}
}

const recapSource = `# CVE-2026-11111 — openjdk

## 3. Actifs positifs

**🚨 vm-a** (hôte, RHEL 9)

- **Trouvé** : openjdk 17.0.1 [E010]
- **Exposition** : **exposée** : port 8443 publié [E012]

## 6. Plan d'action

1. **vm-a**
   - Pourquoi positif : openjdk 17.0.1, dans la plage touchée < 17.0.9 [E010]
   - Mitigation immédiate : filtrer le port 8443
   - Correctif définitif : openjdk 17.0.9
`

func TestWriteRecapCopiesToWorkingDir(t *testing.T) {
	s, err := session.Create(t.TempDir(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.NewTurn("CVE-2026-11111"); err != nil {
		t.Fatal(err)
	}
	s.Turns[0].CVE, s.Turns[0].Clients = []string{"CVE-2026-11111"}, []string{"gnr"}
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeRecap(&options{}, s, 1, recapSource)
	kept, err := os.ReadFile(s.RecapPath(1, "md"))
	if err != nil {
		t.Fatalf("récapitulatif absent de la session : %v", err)
	}
	local, err := os.ReadFile(filepath.Join(cwd, s.Turns[0].RecapName()+".md"))
	if err != nil {
		t.Fatalf("récapitulatif absent du répertoire courant : %v", err)
	}
	if len(kept) == 0 || string(local) != string(kept) {
		t.Fatalf("copie différente :\n%s\n---\n%s", local, kept)
	}
}

func TestWriteRecapIgnoresOtherModes(t *testing.T) {
	s, err := session.Create(t.TempDir(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.NewTurn("incident"); err != nil {
		t.Fatal(err)
	}
	s.Turns[0].Clients = []string{"gnr"}
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeRecap(&options{}, s, 1, recapSource)
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Fatalf("fichiers écrits hors mode CVE : %v", entries)
	}
}
