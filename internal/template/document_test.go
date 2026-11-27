package template

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const docYAML = "name: doc\nkind: document\nscript: x.star\n"

func renderDoc(t *testing.T, star string, assets map[string][]byte, in DocumentInput) ([]byte, error) {
	t.Helper()
	tpl := writeTemplate(t, docYAML, star)
	for name, data := range assets {
		if err := os.WriteFile(filepath.Join(filepath.Dir(tpl.Source), name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inst, err := NewInstance("doc", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	return inst.RenderDocument(context.Background(), in)
}

func TestMarkdownBlocks(t *testing.T) {
	md := "> REQ-1\n\n# Titre\n\n## 1. Synthèse\n\nTexte **gras** et *italique*, `code` et [lien](https://example.com/a)  \nligne 2 \\*littéral\\* 2.4.71-1~deb12u1, 13 1~deb13u1.\n\n- un\n  - deux\n3. trois\n\n| A | B |\n|:--|--:|\n| x | **y** |\n\n```sh\nls -l\n```\n\n---\n\n![schéma](img/a.png)\n"
	star := `
def render(doc):
    out = []
    for b in markdown.blocks(doc.markdown):
        d = {"type": b.type}
        if hasattr(b, "text"):
            d["text"] = b.text
        if hasattr(b, "level"):
            d["level"] = b.level
        if hasattr(b, "marker") and b.marker:
            d["marker"] = b.marker
        if hasattr(b, "runs"):
            d["runs"] = [[r.text, r.bold, r.italic, r.code, r.url, r.br] for r in b.runs]
        if b.type == "table":
            d["header"] = [c.text for c in b.header]
            d["rows"] = [[c.text for c in r] for r in b.rows]
            d["align"] = b.align
        if b.type == "code":
            d["lang"] = b.lang
        if b.type == "image":
            d["src"] = b.src
            d["alt"] = b.alt
        out.append(d)
    return json.encode(out)
`
	data, err := renderDoc(t, star, nil, DocumentInput{Markdown: md})
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, b := range got {
		types = append(types, b["type"].(string))
	}
	if strings.Join(types, " ") != "quote heading heading para bullet bullet numbered table code rule image" {
		t.Fatalf("types: %v", types)
	}
	if got[0]["text"] != "REQ-1" || got[0]["level"] != 1.0 {
		t.Fatalf("quote: %v", got[0])
	}
	if got[2]["text"] != "1. Synthèse" || got[2]["level"] != 2.0 {
		t.Fatalf("heading: %v", got[2])
	}
	if got[3]["text"] != "Texte gras et italique, code et lien\nligne 2 *littéral* 2.4.71-1~deb12u1, 13 1~deb13u1." {
		t.Fatalf("para text: %q", got[3]["text"])
	}
	runs, _ := json.Marshal(got[3]["runs"])
	want := `[["Texte ",false,false,false,"",false],["gras",true,false,false,"",false],[" et ",false,false,false,"",false],["italique",false,true,false,"",false],[", ",false,false,false,"",false],["code",false,false,true,"",false],[" et ",false,false,false,"",false],["lien",false,false,false,"https://example.com/a",false],["",false,false,false,"",true],["ligne 2 *littéral* 2.4.71-1~deb12u1, 13 1~deb13u1.",false,false,false,"",false]]`
	if string(runs) != want {
		t.Fatalf("runs:\n%s\nwant\n%s", runs, want)
	}
	if got[4]["level"] != 1.0 || got[5]["level"] != 2.0 || got[6]["marker"] != "3." {
		t.Fatalf("lists: %v %v %v", got[4], got[5], got[6])
	}
	tbl, _ := json.Marshal([]any{got[7]["header"], got[7]["rows"], got[7]["align"]})
	if string(tbl) != `[["A","B"],[["x","y"]],["left","right"]]` {
		t.Fatalf("table: %s", tbl)
	}
	if got[8]["text"] != "ls -l" || got[8]["lang"] != "sh" {
		t.Fatalf("code: %v", got[8])
	}
	if got[10]["src"] != "img/a.png" || got[10]["alt"] != "schéma" {
		t.Fatalf("image: %v", got[10])
	}
}

func TestMarkdownListOrder(t *testing.T) {
	md := "- **A.** Intro :\n  - a1 ;\n  - a2.\n\n  Suite de A.\n\n  ```sh\n  ls\n  ```\n- B.\n\n1. Un.\n\n   Suite de un.\n"
	star := `
def render(doc):
    return json.encode([[b.type, getattr(b, "text", ""), getattr(b, "level", 0), getattr(b, "indent", 0), getattr(b, "item", "")] for b in markdown.blocks(doc.markdown)])
`
	data, err := renderDoc(t, star, nil, DocumentInput{Markdown: md})
	if err != nil {
		t.Fatal(err)
	}
	want := `[["bullet","A. Intro :",1,0,""],["bullet","a1 ;",2,0,""],["bullet","a2.",2,0,""],["para","Suite de A.",0,1,"bullet"],["code","ls",0,0,""],["bullet","B.",1,0,""],["numbered","Un.\nSuite de un.",1,0,""]]`
	if string(data) != want {
		t.Fatalf("blocs :\n%s\nattendu\n%s", data, want)
	}
}

func testZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "word/document.xml"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(files[name]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func unzip(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestDocumentXMLZip(t *testing.T) {
	base := testZip(t, map[string]string{
		"[Content_Types].xml": `<Types/>`,
		"word/document.xml":   `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Couverture</w:t></w:r></w:p><w:p w:rsidR="1"><w:r><w:t>À supprimer</w:t></w:r></w:p><w:sectPr/></w:body></w:document>`,
	})
	star := `
def render(doc):
    files = zip.read(asset("base.zip"))
    root = xml.parse(files["word/document.xml"])
    body = root.find("w:body")
    first = body.children[0]
    for p in body.findall("w:p[@w:rsidR]"):
        p.remove()
    paras = xml.fragment("".join(['<w:p><w:pPr><w:pStyle w:val="H1"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>' % xml.escape(b.text) for b in markdown.blocks(doc.markdown)]))
    first.add_next(paras)
    tail = xml.element("w:p", {"w:id": "fin"}, None)
    body.find("w:sectPr").add_prev(tail)
    if first.index() != 0 or tail.index() != len(body.children) - 2:
        fail("index")
    if body.find("w:p[@w:id='fin']") != tail:
        fail("find")
    files["word/document.xml"] = xml.encode(root)
    files["extra.txt"] = doc.title + "|" + doc.mode + "|" + doc.params.get("x", "-")
    return zip.write(files)
`
	data, err := renderDoc(t, star, map[string][]byte{"base.zip": base}, DocumentInput{Markdown: "# A & B\n\nC < D\n", Title: "T", Mode: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	files := unzip(t, data)
	doc := files["word/document.xml"]
	if !strings.HasPrefix(doc, xmlDeclaration) || strings.Contains(doc, "supprimer") {
		t.Fatalf("document:\n%s", doc)
	}
	order := []string{"Couverture", "A &amp; B", "C &lt; D", `w:id="fin"`, "<w:sectPr/>"}
	at := 0
	for _, s := range order {
		i := strings.Index(doc[at:], s)
		if i < 0 {
			t.Fatalf("%q missing or out of order in:\n%s", s, doc)
		}
		at += i
	}
	if files["extra.txt"] != "T|incident|-" || files["[Content_Types].xml"] != "<Types/>" {
		t.Fatalf("files: %q", files)
	}
}

func TestDocumentRules(t *testing.T) {
	for name, c := range map[string]struct{ yaml, star, want string }{
		"sans render":   {docYAML, "def other():\n    pass\n", "render"},
		"réseau":        {docYAML, "def render(doc):\n    return http.get('x')\n", "http"},
		"outils":        {docYAML + "tools: [{kind: dns_resolve}]\n", "def render(doc):\n    return b''\n", "kind document"},
		"fichiers":      {docYAML + "files: [/etc/hosts]\n", "def render(doc):\n    return b''\n", "kind document"},
		"sans script":   {"name: doc\nkind: document\ntargets: [{kind: a}]\n", "", "script"},
		"kind inconnu":  {"name: doc\nkind: report\nscript: x.star\n", "def render(doc):\n    return b''\n", "document"},
		"résultat":      {docYAML, "def render(doc):\n    return 1\n", "bytes"},
		"asset hors":    {docYAML, "def render(doc):\n    return asset('../x.yaml')\n", "asset"},
		"asset absent":  {docYAML, "def render(doc):\n    return asset('absent.docx')\n", "absent.docx"},
		"asset caché":   {docYAML, "def render(doc):\n    return asset('.git')\n", "asset"},
		"élément cycle": {docYAML, "def render(doc):\n    a = xml.element('a')\n    b = xml.element('b')\n    a.append(b)\n    b.append(a)\n    return b''\n", "itself"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if c.star != "" {
				_ = os.WriteFile(filepath.Join(dir, "x.star"), []byte(c.star), 0o600)
			}
			p := filepath.Join(dir, "x.yaml")
			_ = os.WriteFile(p, []byte(c.yaml), 0o600)
			tpl, err := Parse([]byte(c.yaml), p)
			if err == nil {
				var in *Instance
				if in, err = NewInstance("doc", tpl, nil); err == nil {
					_, err = in.RenderDocument(context.Background(), DocumentInput{})
				}
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error with %q, got %v", c.want, err)
			}
		})
	}
}

func TestDocumentConnectors(t *testing.T) {
	yaml := docYAML + "connectors:\n  store:\n    driver: mcp\n    server: store\n  files:\n    driver: http\n    base_url: https://files.example.com\n    methods: [GET]\n"
	tpl := writeTemplate(t, yaml, "def render(doc):\n    return mcp.call('store', 'make', {}) or http.request('files', 'GET', '/x')\n")
	if _, err := NewInstance("doc", tpl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentSpecial(t *testing.T) {
	tpl := writeTemplate(t, docYAML, "def render(doc):\n    return b''\n")
	if !tpl.Document() || !tpl.Special() {
		t.Fatal("document template must be special")
	}
}

func TestDocumentProjects(t *testing.T) {
	star := "def render(doc):\n    return json.encode([[p.name, p.label, p.client, p.client_label] for p in doc.projects])\n"
	data, err := renderDoc(t, star, nil, DocumentInput{Projects: []DocumentProject{{Name: "P-1", Label: "Alpha", Client: "acme", ClientLabel: "ACME"}, {Name: "P-2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `[["P-1","Alpha","acme","ACME"],["P-2","","",""]]` {
		t.Fatalf("projets : %s", data)
	}
}
