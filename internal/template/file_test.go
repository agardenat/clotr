package template

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/creds"
)

const fileScript = `
def list(a):
    r = file.list(a["path"], depth = a.get("depth", 1))
    return {"truncated": r.truncated, "entries": ["%s %s" % (e["type"], e["path"]) for e in r.entries]}

def read(a):
    return file.read(a["path"])

def exists(a):
    return file.exists(a["path"])

tool(name = "list", description = "d", schema = {"type": "object"}, fn = list)
tool(name = "read", description = "d", schema = {"type": "object"}, fn = read)
tool(name = "exists", description = "d", schema = {"type": "object"}, fn = exists)

def discover(ctx):
    return {"targets": [{"name": "a", "kind": "a"}]}
`

func instanceTools(t *testing.T, in *Instance) map[string]func(any) (string, error) {
	t.Helper()
	out := map[string]func(any) (string, error){}
	for _, tl := range in.Tools() {
		out[strings.TrimPrefix(tl.Name(), in.Name+"_")] = func(a any) (string, error) {
			raw, _ := json.Marshal(a)
			return tl.Call(context.Background(), raw)
		}
	}
	return out
}

func TestFileDirectories(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	outside := filepath.Join(base, "outside.txt")
	for p, content := range map[string]string{
		filepath.Join(root, "a.yaml"):        "a: 1\n",
		filepath.Join(root, "sub", "b.yaml"): "b: 2\n",
		outside:                              "secret\n",
	} {
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(content), 0o600)
	}
	os.Symlink(outside, filepath.Join(root, "escape.txt"))
	os.Symlink(filepath.Join(root, "a.yaml"), filepath.Join(root, "inner.txt"))
	tpl := writeTemplate(t, "name: x\nscript: x.star\nparams:\n  root: {type: path}\n  single: {type: path}\nfiles: [\"{{.root}}/**\", \"{{.single}}\"]\n", fileScript)
	in, err := NewInstance("i", tpl, map[string]any{"root": root, "single": outside})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	call := instanceTools(t, in)
	list := func(depth int) []string {
		t.Helper()
		out, err := call["list"](map[string]any{"path": root, "depth": depth})
		if err != nil {
			t.Fatal(err)
		}
		var r struct{ Entries []string }
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		return r.Entries
	}
	entries := list(1)
	for _, want := range []string{"file " + filepath.Join(root, "a.yaml"), "dir " + filepath.Join(root, "sub"), "link " + filepath.Join(root, "escape.txt")} {
		if !slices.Contains(entries, want) {
			t.Fatalf("list sans %q : %v", want, entries)
		}
	}
	if slices.Contains(entries, "file "+filepath.Join(root, "sub", "b.yaml")) {
		t.Fatalf("profondeur 1 dépassée : %v", entries)
	}
	if entries := list(2); !slices.Contains(entries, "file "+filepath.Join(root, "sub", "b.yaml")) {
		t.Fatalf("profondeur 2 : %v", entries)
	}
	if out, err := call["read"](map[string]any{"path": filepath.Join(root, "sub", "b.yaml")}); err != nil || out != "b: 2\n" {
		t.Fatalf("lecture : %q %v", out, err)
	}
	if out, err := call["read"](map[string]any{"path": filepath.Join(root, "inner.txt")}); err != nil || out != "a: 1\n" {
		t.Fatalf("lien interne : %q %v", out, err)
	}
	if _, err := call["read"](map[string]any{"path": filepath.Join(root, "escape.txt")}); err == nil || !strings.Contains(err.Error(), "leaves the declared directory") {
		t.Fatalf("lien sortant : %v", err)
	}
	if _, err := call["read"](map[string]any{"path": root + "/../outside.txt"}); err == nil || !strings.Contains(err.Error(), "is not declared") {
		t.Fatalf("remontée : %v", err)
	}
	if _, err := call["list"](map[string]any{"path": outside}); err == nil || !strings.Contains(err.Error(), "not inside a directory") {
		t.Fatalf("list d'un fichier seul : %v", err)
	}
	if out, err := call["read"](map[string]any{"path": outside}); err != nil || out != "secret\n" {
		t.Fatalf("fichier déclaré seul : %q %v", out, err)
	}
	if out, err := call["exists"](map[string]any{"path": filepath.Join(root, "absent.yaml")}); err != nil || out != "false" {
		t.Fatalf("exists absent : %q %v", out, err)
	}
	if _, err := NewInstance("i", tpl, map[string]any{"root": "relative", "single": outside}); err == nil {
		t.Fatal("répertoire relatif accepté")
	}
}

func TestHTTPHeaderAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Header.Get("PRIVATE-TOKEN") + "|" + r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	yaml := `name: x
script: x.star
params:
  url: {type: url}
  env: {type: string, default: ""}
  vault: {type: string, default: ""}
connectors:
  api:
    driver: http
    base_url: "{{.url}}"
    auth: {header: %s, password_env: "{{.env}}", password_vault: "{{.vault}}"}
`
	star := `
tool(name = "get", description = "d", schema = {"type": "object"}, fn = lambda a: http.request("api", "GET", "/x").body)

def discover(ctx):
    return {"targets": [{"name": "a", "kind": "a"}]}
`
	read := creds.ReadVault
	creds.ReadVault = func(_ context.Context, ref string) (string, error) {
		if ref == "kv/team/forge#token" {
			return "from-vault", nil
		}
		return "", errors.New("absent")
	}
	t.Cleanup(func() { creds.ReadVault = read })
	t.Setenv("T_TOKEN", "from-env")
	for _, c := range []struct {
		name, header string
		params       map[string]any
		want         string
	}{
		{"env", "PRIVATE-TOKEN", map[string]any{"env": "T_TOKEN"}, "from-env|"},
		{"vault", "PRIVATE-TOKEN", map[string]any{"vault": "kv/team/forge#token"}, "from-vault|"},
		{"bearer", "Authorization, scheme: Bearer", map[string]any{"env": "T_TOKEN"}, "|Bearer from-env"},
	} {
		tpl := writeTemplate(t, strings.Replace(yaml, "%s", c.header, 1), star)
		c.params["url"] = srv.URL
		in, err := NewInstance("hdr-"+c.name, tpl, c.params)
		if err != nil {
			t.Fatal(err)
		}
		if err := in.Prepare(context.Background()); err != nil {
			t.Fatalf("%s : %v", c.name, err)
		}
		if out, err := instanceTools(t, in)["get"](map[string]any{}); err != nil || out != c.want {
			t.Fatalf("%s : %q %v", c.name, out, err)
		}
	}
	for _, bad := range []string{
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {scheme: Bearer}}\n",
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {header: X-Token, user_env: U}}\n",
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  s: {driver: ssh, auth: {header: X-Token}}\n",
	} {
		if _, err := Parse([]byte(bad), "x.yaml"); err == nil {
			t.Fatalf("accepté : %s", bad)
		}
	}
}

func TestConnectorWhen(t *testing.T) {
	y := "name: x\ntargets: [{kind: a}]\nparams: {url: {type: string, default: \"\"}}\ntools: [{kind: inventory}]\nconnectors:\n  api: {driver: http, when: \"{{if .url}}true{{end}}\", base_url: \"{{.url}}\", auth: {header: X-Token, password_env: NONE_SET}}\n"
	tpl, err := Parse([]byte(y), filepath.Join(t.TempDir(), "x.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInstance("when-off", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.https) != 0 {
		t.Fatalf("connecteur créé malgré when : %v", in.https)
	}
	if err := in.Prepare(context.Background()); err != nil {
		t.Fatalf("identifiants demandés pour un connecteur absent : %v", err)
	}
	if in, err = NewInstance("when-on", tpl, map[string]any{"url": "https://forge.example.com"}); err != nil || in.https["api"] == nil {
		t.Fatalf("connecteur attendu : %v", err)
	}
}
