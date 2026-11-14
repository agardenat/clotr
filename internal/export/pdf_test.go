package export

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"
)

func minimalDocx(t *testing.T, paras ...string) []byte {
	t.Helper()
	var body strings.Builder
	for _, p := range paras {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, content string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(f.content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPDFConversion(t *testing.T) {
	if _, err := Office(); err != nil {
		t.Skip("LibreOffice absent")
	}
	data, err := PDF(context.Background(), minimalDocx(t, "Rapport de conversion"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("not a PDF: %q", data[:min(len(data), 16)])
	}
}

func TestFileURL(t *testing.T) {
	if got := fileURL("/tmp/a b/profile"); got != "file:///tmp/a%20b/profile" {
		t.Fatal(got)
	}
}
