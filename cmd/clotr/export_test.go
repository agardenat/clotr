package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/export"
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
	s.Turns[0].CVE, s.Turns[0].Clients = []string{"CVE-2026-11111"}, []string{"acme"}
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeRecap(&options{}, nil, s, 1, recapSource)
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
	s.Turns[0].Clients = []string{"acme"}
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeRecap(&options{}, nil, s, 1, recapSource)
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Fatalf("fichiers écrits hors mode CVE : %v", entries)
	}
}

func TestScopedTitle(t *testing.T) {
	for _, c := range []struct {
		title    string
		projects []string
		want     string
	}{
		{"CVE-2026-114938 — openjdk", []string{"P-1"}, "P-1 · CVE-2026-114938 — openjdk"},
		{"Rapport CVE-2026-1, CVE-2026-2", []string{"P-A", "P-B"}, "P-A, P-B · Rapport CVE-2026-1, CVE-2026-2"},
		{"DAT P-1", []string{"P-1"}, "DAT P-1"},
		{"Rapport", nil, "Rapport"},
		{"", []string{"P-A"}, "P-A"},
	} {
		if got := scopedTitle(c.title, c.projects); got != c.want {
			t.Errorf("scopedTitle(%q, %v) = %q, attendu %q", c.title, c.projects, got, c.want)
		}
	}
}

func TestScopeFromAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	line := `{"kind":"instances_scope","offered":["web-acme","db-acme"],"clients":["acme"],"projects":{"acme":["P-2"]}}` + "\n"
	if err := os.WriteFile(path, []byte(`{"kind":"other"}`+"\n"+line), 0o600); err != nil {
		t.Fatal(err)
	}
	instances := []config.Instance{{Name: "web-acme", Project: "P-1"}, {Name: "db-acme"}, {Name: "web-globex", Project: "P-3"}}
	clients, projects := scopeFromAudit(path, instances)
	if strings.Join(clients, ",") != "acme" || strings.Join(projects, ",") != "P-1,P-2" {
		t.Fatalf("clients %v, projets %v", clients, projects)
	}
	if _, projects := scopeFromAudit(path, nil); strings.Join(projects, ",") != "P-2" {
		t.Fatalf("sans configuration : %v", projects)
	}
}

func TestDocumentProjects(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{{Name: "acme", Label: "ACME CORP", Projects: []config.Project{{Name: "P-1", Label: "Alpha"}}}, {Name: "globex", Projects: []config.Project{{Name: "P-2"}}}}}
	got := documentProjects(cfg, []string{"P-1", "P-2", "P-3"})
	if len(got) != 3 || got[0].Label != "Alpha" || got[0].Client != "acme" || got[0].ClientLabel != "ACME CORP" || got[1].Label != "" || got[1].Client != "globex" || got[2].Name != "P-3" || got[2].Client != "" {
		t.Fatalf("projets : %+v", got)
	}
	if got := documentProjects(nil, []string{"P-1"}); len(got) != 1 || got[0].Label != "" {
		t.Fatalf("sans configuration : %+v", got)
	}
}

func TestClientNames(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{
		{Name: "acme", Label: "ACME Corp", Projects: []config.Project{{Name: "P-1", Label: "Alpha"}, {Name: "P-2"}}},
		{Name: "globex", Projects: []config.Project{{Name: "P-3"}}},
	}}
	turn := session.Turn{Clients: []string{"acme"}, Projects: []string{"P-1", "P-2", "P-3"}}
	if got := strings.Join(clientNames(cfg, turn), ","); got != "Alpha,ACME Corp,globex" {
		t.Fatalf("noms : %q", got)
	}
	if got := strings.Join(clientNames(nil, turn), ","); got != "acme" {
		t.Fatalf("sans configuration : %q", got)
	}
}

const recordDoc = `
def render(doc):
    body = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:body></w:document>' % xml.escape("|".join([doc.title, doc.audience, doc.request, doc.session] + [p.name for p in doc.projects]))
    return zip.write({"[Content_Types].xml": "<Types/>", "word/document.xml": body})
`

func TestExportReportAddsClientRecap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.yaml"), []byte("name: doc\nkind: document\nscript: doc.star\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc.star"), []byte(recordDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Templates: config.TemplatesConf{Dir: dir},
		Export:    config.ReportExport{Template: "doc"},
		Clients:   []config.Client{{Name: "acme", Label: "ACME Société", Projects: []config.Project{{Name: "P-1"}}}},
	}
	s, err := session.Create(t.TempDir(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.NewTurn("CVE-2026-11111 sur acme"); err != nil {
		t.Fatal(err)
	}
	s.Turns[0].CVE, s.Turns[0].Clients, s.Turns[0].Projects = []string{"CVE-2026-11111"}, []string{"acme"}, []string{"P-1"}
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := exportReport(t.Context(), &options{exportFmt: "docx"}, cfg, s, 1, recapSource); err != nil {
		t.Fatal(err)
	}
	turn := s.Turns[0]
	name := "ACME-SOCIETE_CVE-2026-11111_RECAP_" + turn.Time.Local().Format("20060102")
	for _, p := range []string{filepath.Join(cwd, turn.ReportName()+".docx"), filepath.Join(cwd, name+".docx"), filepath.Join(s.TurnDir(1), name+".docx")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("export absent : %v", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(cwd, name+".docx"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := export.Read("docx", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Text; !strings.Contains(got, "Récapitulatif CVE-2026-11111|client|||P-1") {
		t.Fatalf("document client : %q", got)
	}
}
