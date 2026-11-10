package template

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mcpTplYAML = `name: repo
version: 1
description: dépôt lu par un serveur MCP
script: repo.star
params:
  server: {type: string, default: gl}
connectors:
  gl:
    driver: mcp
    when: "{{if .server}}true{{end}}"
    server: "{{.server}}"
targets: [{kind: iac, name: x}]
`

const mcpTplStar = `def read(args):
    r = mcp.call("gl", "get_repository_file", {"project_id": "g/p", "file_path": args["path"]})
    if r.error:
        return "erreur: " + r.text
    return r.data["content"]

tool(name = "read", description = "lit un fichier", schema = {"type": "object", "properties": {"path": {"type": "string"}}}, fn = read)
`

const mcpTplTest = `def mock(call):
    if call.args["file_path"] == "absent":
        return struct(text = "404 File Not Found", error = True)
    return {"content": "kind: Kustomization\n", "path": call.args["file_path"]}

def test_call():
    i = template.instance(mcp = mock)
    assert.eq(i.call("read", {"path": "a.yaml"}), "kind: Kustomization\n")
    assert.eq(i.call("read", {"path": "absent"}), "erreur: 404 File Not Found")
    calls = i.mcp_calls()
    assert.eq(len(calls), 2)
    assert.eq(calls[0]["server"], "gl")
    assert.eq(calls[0]["tool"], "get_repository_file")
    assert.eq(calls[0]["args"]["project_id"], "g/p")

def test_no_mock():
    i = template.instance()
    assert.contains(i.error("read", {"path": "a.yaml"}), "mcp mock")
`

func writeMCPTemplate(t *testing.T) *Template {
	t.Helper()
	dir := t.TempDir()
	for n, c := range map[string]string{"repo.yaml": mcpTplYAML, "repo.star": mcpTplStar, "repo_test.star": mcpTplTest} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(dir)
	if err != nil || len(s.Warnings) > 0 {
		t.Fatalf("%v %v", err, s.Warnings)
	}
	tpl, ok := s.Get("repo")
	if !ok {
		t.Fatal("template repo absent")
	}
	return tpl
}

func TestMCPConnectorHarness(t *testing.T) {
	tpl := writeMCPTemplate(t)
	var out bytes.Buffer
	passed, failed, err := RunTests(context.Background(), tpl, &out)
	if err != nil || failed != 0 || passed != 2 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
}

type fakeCaller struct {
	server string
	calls  []string
	err    error
}

func (f *fakeCaller) CallTool(_ context.Context, tool string, args map[string]any) (*MCPResult, error) {
	f.calls = append(f.calls, f.server+"/"+tool+"/"+args["file_path"].(string))
	if f.err != nil {
		return nil, f.err
	}
	b, _ := json.Marshal(map[string]any{"content": "v: 1\n"})
	return &MCPResult{Text: string(b), Data: b}, nil
}

func TestMCPConnectorRuntime(t *testing.T) {
	tpl := writeMCPTemplate(t)
	in, err := NewInstance("r", tpl, map[string]any{"server": "gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.MCPServers(); len(got) != 1 || got[0] != "gitlab" {
		t.Fatalf("serveurs: %v", got)
	}
	var audits []map[string]any
	in.Audit = func(kind string, f map[string]any) {
		if kind == "mcp_call" {
			audits = append(audits, f)
		}
	}
	tools := instanceTools(t, in)
	if _, err := tools["read"](map[string]any{"path": "a.yaml"}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("sans serveur connecté: %v", err)
	}
	fc := &fakeCaller{}
	in.MCP = func(_ context.Context, server string) (MCPCaller, error) {
		fc.server = server
		return fc, nil
	}
	out, err := tools["read"](map[string]any{"path": "a.yaml"})
	if err != nil || !strings.Contains(out, "v: 1") {
		t.Fatalf("lecture: %q %v", out, err)
	}
	if len(fc.calls) != 1 || fc.calls[0] != "gitlab/get_repository_file/a.yaml" {
		t.Fatalf("appels: %v", fc.calls)
	}
	fc.err = errors.New("tool not exposed")
	if _, err := tools["read"](map[string]any{"path": "b.yaml"}); err == nil || !strings.Contains(err.Error(), "not exposed") {
		t.Fatalf("erreur du serveur: %v", err)
	}
	if len(audits) != 2 || audits[0]["server"] != "gitlab" || audits[0]["remote_tool"] != "get_repository_file" || audits[1]["error"] == nil {
		t.Fatalf("audit: %v", audits)
	}
	off, err := NewInstance("r", tpl, map[string]any{"server": ""})
	if err != nil || len(off.MCPServers()) != 0 {
		t.Fatalf("connecteur désactivé par when: %v %v", off.MCPServers(), err)
	}
}

func TestMCPConnectorValidation(t *testing.T) {
	base := "name: x\ntargets: [{kind: a}]\n"
	if _, err := Parse([]byte(base+"connectors: {c: {driver: mcp, server: s, url: x}}\n"), "x.yaml"); err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("option inconnue: %v", err)
	}
	tpl, err := Parse([]byte(base+"connectors: {c: {driver: mcp}}\n"), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), "server") {
		t.Fatalf("server absent: %v", err)
	}
}
