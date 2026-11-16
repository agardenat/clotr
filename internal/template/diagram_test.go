package template

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const diagramYAML = `name: draw
kind: diagram
description: schéma par un serveur MCP
script: draw.star
params:
  url: {type: string, default: "https://diagrams.example.com/mcp"}
connectors:
  srv:
    driver: mcp
    url: "{{.url}}"
`

const diagramStar = `def reference(cloud):
    return mcp.call("srv", "capabilities", {"cloud": cloud}).data

def shapes(query, cloud):
    return mcp.call("srv", "search", {"query": query, "cloud": cloud}).text

def render(spec, cloud):
    r = mcp.call("srv", "create", {"spec": spec, "cloud": cloud, "inline_images": True})
    if r.error:
        fail(r.text)
    d = r.data
    return {"drawio": d["drawio"], "png": d["images"][0]["data_base64"], "warnings": d["warnings"]}
`

const diagramTest = `def mock(call):
    if call.tool == "capabilities":
        return {"cloud": call.args["cloud"], "groups": ["vpc"]}
    if call.tool == "search":
        return struct(text = "type: vm")
    return {"drawio": "<mxfile/>", "images": [{"data_base64": "cG5n"}], "warnings": [] if call.args["spec"]["nodes"] else ["aucun nœud"]}

def test_render():
    i = template.instance(mcp = mock)
    assert.contains(i.diagram_reference("azure"), "vpc")
    assert.eq(i.diagram_shapes("vm", "azure"), "type: vm")
    r = i.diagram_render({"groups": [], "nodes": [{"id": "a"}], "edges": []}, "azure")
    assert.eq(r.png, b"png")
    assert.eq(r.warnings, [])
    assert.eq(i.diagram_render({"nodes": []}, "azure").warnings, ["aucun nœud"])
`

func TestDiagramTemplate(t *testing.T) {
	dir := t.TempDir()
	for n, c := range map[string]string{"draw.yaml": diagramYAML, "draw.star": diagramStar, "draw_test.star": diagramTest} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(dir)
	if err != nil || len(s.Warnings) > 0 {
		t.Fatalf("%v %v", err, s.Warnings)
	}
	tpl, _ := s.Get("draw")
	if !tpl.Diagram() || !tpl.Special() || !tpl.External() {
		t.Fatalf("kind %q", tpl.Kind)
	}
	var out bytes.Buffer
	passed, failed, err := RunTests(context.Background(), tpl, &out)
	if err != nil || failed != 0 || passed != 1 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
	in, err := NewInstance("diagram", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.MCPServers(); len(got) != 1 {
		t.Fatalf("serveurs : %v", got)
	}
	in.MCP = func(context.Context, string) (MCPCaller, error) { return diagramCaller{}, nil }
	r, err := in.DiagramRender(context.Background(), "azure", map[string]any{"nodes": []any{"a"}})
	if err != nil || string(r.PNG) != "png" || string(r.Drawio) != "<mxfile/>" || len(r.Warnings) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

type diagramCaller struct{}

func (diagramCaller) CallTool(_ context.Context, _ string, _ map[string]any) (*MCPResult, error) {
	b, _ := json.Marshal(map[string]any{"drawio": "<mxfile/>", "images": []any{map[string]any{"data_base64": base64.StdEncoding.EncodeToString([]byte("png"))}}, "warnings": []any{}})
	return &MCPResult{Text: string(b), Data: b}, nil
}

func TestDiagramKindRejectsTools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "d.star"), []byte("def render(spec, cloud):\n    return {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "d.yaml")
	for _, y := range []string{
		"name: d\nkind: diagram\nscript: d.star\ntools: [{kind: inventory}]\n",
		"name: d\nkind: diagram\nscript: d.star\nconnectors: {s: {driver: ssh, host: h}}\n",
	} {
		if _, err := Parse([]byte(y), src); err == nil || !strings.Contains(err.Error(), "diagram") {
			t.Fatalf("%q : %v", y, err)
		}
	}
}

func TestDocumentImages(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 40, 20))); err != nil {
		t.Fatal(err)
	}
	star := `
def render(doc):
    im = doc.images["architecture.png"]
    return "%s %dx%d %d" % (im.format, im.width, im.height, len(im.data))
`
	out, err := renderDoc(t, star, nil, DocumentInput{Markdown: "![x](architecture.png)", Images: map[string]Image{"architecture.png": {Data: buf.Bytes(), Format: "png", Width: 40, Height: 20}}})
	if err != nil || !strings.HasPrefix(string(out), "png 40x20 ") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestHarnessRenderImagesBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 3, 5))); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"d.yaml":      "name: d\nkind: document\nscript: d.star\n",
		"d.star":      "def render(doc):\n    im = doc.images[\"a.png\"]\n    return \"%s %dx%d\" % (im.format, im.width, im.height)\n",
		"d_test.star": "def test_images():\n    out = template.instance().render(markdown = \"![x](a.png)\", images = {\"a.png\": base64.decode(\"" + base64.StdEncoding.EncodeToString(buf.Bytes()) + "\")})\n    assert.eq(out, b\"png 3x5\")\n",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := s.Get("d")
	var out bytes.Buffer
	if passed, failed, err := RunTests(context.Background(), tpl, &out); err != nil || failed != 0 || passed != 1 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
}
