package export

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"fmt"
	"html"
	"strings"
	"testing"
)

const report = `# Rapport de test

## Constats

### Vue

Le service **alpha** redémarre en boucle depuis 08:00 [E001].

- Mémoire du pod limitée à 512 Mi [E002]
- Voir [la documentation](https://example.com/doc) pour les limites

| Composant | État |
|---|---|
| alpha-worker | CrashLoopBackOff |

` + "```" + `
OOMKilled: container alpha exceeded memory limit
` + "```" + `
`

func docx(t *testing.T, paras ...string) []byte {
	t.Helper()
	var body strings.Builder
	for _, p := range paras {
		style := ""
		if h, ok := strings.CutPrefix(p, "# "); ok {
			p, style = h, `<w:pPr><w:pStyle w:val="T1"/></w:pPr>`
		}
		fmt.Fprintf(&body, `<w:p>%s<w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, style, html.EscapeString(p))
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"[Content_Types].xml": `<Types/>`,
		"word/document.xml":   `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`,
		"word/styles.xml":     `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:styleId="T1"><w:name w:val="heading 1"/></w:style><w:style w:styleId="Body"><w:name w:val="Body"/></w:style></w:styles>`,
		"word/footer1.xml":    `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:instrText>PAGE</w:instrText></w:r></w:p></w:ftr>`,
	} {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pdf(t *testing.T, content string) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte(content))
	_ = zw.Close()
	a := make([]byte, ascii85.MaxEncodedLen(z.Len()))
	a = a[:ascii85.Encode(a, z.Bytes())]
	return []byte(fmt.Sprintf("%%PDF-1.4\n4 0 obj\n<< /Filter [ /ASCII85Decode /FlateDecode ] /Length %d >>\nstream\n%s~>endstream\nendobj\n%%%%EOF\n", len(a)+2, a))
}

var full = []string{
	"# Rapport de test", "# Constats", "# Vue",
	"Le service alpha redémarre en boucle depuis 08:00 [E001].",
	"Mémoire du pod limitée à 512 Mi [E002]",
	"Voir la documentation (https://example.com/doc) pour les limites",
	"Composant", "État", "alpha-worker", "CrashLoopBackOff",
	"OOMKilled: container alpha exceeded memory limit",
}

func TestSegments(t *testing.T) {
	var got []string
	for _, s := range Segments(report) {
		if s.Heading {
			got = append(got, "# "+s.Text)
		} else {
			got = append(got, s.Text)
		}
	}
	want := []string{"# Rapport de test", "# Constats", "# Vue", "Le service alpha redémarre en boucle depuis 08:00 [E001].", "Mémoire du pod limitée à 512 Mi [E002]", "Voir la documentation pour les limites", "Composant", "alpha-worker", "CrashLoopBackOff", "OOMKilled: container alpha exceeded memory limit"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("segments:\n%q\nwant\n%q", got, want)
	}
}

func read(t *testing.T, format string, data []byte) Doc {
	t.Helper()
	d, err := Read(format, data)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDocxComplete(t *testing.T) {
	d := read(t, "docx", docx(t, full...))
	if strings.Contains(d.Text, "PAGE") {
		t.Fatalf("field code read as text: %q", d.Text)
	}
	if strings.Join(d.Headings, "|") != "Rapport de test|Constats|Vue" {
		t.Fatalf("headings: %q", d.Headings)
	}
	if r := Compare(report, d); !r.Checked || r.Issues() > 0 {
		t.Fatalf("%+v", r)
	}
}

func TestDocxMissing(t *testing.T) {
	paras := append([]string{}, full...)
	paras[3] = "Le service alpha redémarre souvent [E001]."
	r := Compare(report, read(t, "docx", docx(t, paras...)))
	if !r.Checked || r.Issues() != 1 || len(r.Missing) != 1 || !strings.Contains(r.Missing[0], "08:00") {
		t.Fatalf("%+v", r)
	}
}

func TestDocxMoved(t *testing.T) {
	paras := append([]string{}, full...)
	paras[3], paras[4] = paras[4], paras[3]
	r := Compare(report, read(t, "docx", docx(t, paras...)))
	if r.Issues() != 1 || len(r.Moved) != 1 || !strings.Contains(r.Moved[0], "Mémoire") {
		t.Fatalf("%+v", r)
	}
}

func TestDocxFlatHeadingAndArtifacts(t *testing.T) {
	paras := append([]string{}, full...)
	paras[1], paras[2] = "Constats", "Vue"
	paras[4] = `- Mémoire du pod **limitée** à 512 Mi [E002]\nfin`
	r := Compare(report, read(t, "docx", docx(t, paras...)))
	if strings.Join(r.Flat, "|") != "Constats|Vue" || strings.Join(r.Artifacts, " ") != `\n ** "- " en début de ligne` || len(r.Missing)+len(r.Moved) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPageBreakInsideParagraph(t *testing.T) {
	paras := append([]string{}, full...)
	paras[3] = "Le service alpha redémarre en boucle"
	paras = append(paras[:4], append([]string{"Rapport de test — page 2", "depuis 08:00 [E001]."}, paras[4:]...)...)
	if r := Compare(report, read(t, "docx", docx(t, paras...))); r.Issues() > 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPDF(t *testing.T) {
	var cs strings.Builder
	cs.WriteString("q 1 0 0 1 62 757 cm\n")
	for _, p := range full {
		p = strings.TrimPrefix(p, "# ")
		p = strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`, "é", `\351`, "É", `\311`, "à", `\340`).Replace(p)
		fmt.Fprintf(&cs, "BT /F1 11 Tf 12 TL (%s) Tj T* ET\n", p)
	}
	cs.WriteString("BT [(Fin) -250 <2064> ] TJ ET\nQ\n")
	d := read(t, "pdf", pdf(t, cs.String()))
	if !strings.Contains(d.Text, "redémarre") || !strings.Contains(d.Text, "Fin d") || d.Headings != nil {
		t.Fatalf("doc=%+v", d)
	}
	if r := Compare(report, d); !r.Checked || r.Issues() > 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPDFUnreadable(t *testing.T) {
	if r := Compare(report, read(t, "pdf", pdf(t, "BT <0012003400560078> Tj ET"))); r.Checked {
		t.Fatal("unreadable text must not be reported as checked")
	}
}

func TestNotFormat(t *testing.T) {
	if _, err := Read("docx", []byte("%PDF-1.4")); err == nil {
		t.Fatal("pdf accepted as docx")
	}
	if _, err := Read("pdf", docx(t, "x")); err == nil {
		t.Fatal("docx accepted as pdf")
	}
}

func TestShortCodeLines(t *testing.T) {
	md := "# Rapport de test\n\n## Preuves\n\n```\n# E001\ntâche: t1\nsortie complète de la commande\n```\n"
	r := Compare(md, read(t, "docx", docx(t, "# Rapport de test", "# Preuves", "Preuve :\n# E001\ntâche: t1\nsortie complète de la commande")))
	if !r.Checked || r.Issues() > 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSegmentsKeepInlinePlaceholder(t *testing.T) {
	segs := Segments("# T\n\n## S\n\n| Identité | Portée |\n|---|---|\n| app_<env>_id (une par cluster) | groupe |\n\nLigne un<br>ligne deux.\n")
	var texts []string
	for _, s := range segs {
		texts = append(texts, s.Text)
	}
	joined := strings.Join(texts, "|")
	if !strings.Contains(joined, "app_<env>_id (une par cluster)") || !strings.Contains(joined, "Ligne un ligne deux.") {
		t.Fatalf("segments : %q", texts)
	}
}
