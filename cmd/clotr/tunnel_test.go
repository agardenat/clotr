package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/template"
)

func TestRenderTunnel(t *testing.T) {
	cl := config.Client{Name: "acme", Vars: map[string]string{"cmp": "CMP-0000"}, Projects: []config.Project{{Name: "PRJ-0000"}}}
	tc, err := renderTunnel(config.Tunnel{Hops: []string{"10.0.0.1"}, PasswordVault: "kv/{{.cmp}}/{{.project}}/adm"}, clientVars(cl, "PRJ-0000"))
	if err != nil || tc.PasswordVault != "kv/CMP-0000/PRJ-0000/adm" || tc.Hops[0] != "10.0.0.1" {
		t.Fatalf("rendu: %+v %v", tc, err)
	}
	if _, err := renderTunnel(config.Tunnel{Hops: []string{"x"}, PasswordVault: "kv/{{.project}}"}, clientVars(cl, "")); err == nil {
		t.Fatal("variable inconnue acceptée")
	}
}

func TestInstanceParamsPrecedence(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.star"), []byte("tool(name = 'r', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1)\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("name: x\nscript: x.star\nparams:\n  kubeconfig: {type: string, default: ~/.kube/config}\n  proxy_url: {type: string, default: \"\"}\n  timeout: {type: string, default: 30s}\n  user: {type: string, default: \"\"}\n"), 0o600)
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("x")
	cfg := &config.Config{
		Params: map[string]any{"kubeconfig": "~/.kube/all", "timeout": "10s", "user": "global", "unknown": "ignoré"},
		Clients: []config.Client{{Name: "acme", Params: map[string]any{"timeout": "20s", "user": "client"}, Projects: []config.Project{{
			Name: "PRJ-0000", Params: map[string]any{"proxy_url": "{{.tunnel_url}}", "user": "projet"},
		}}}},
	}
	in, err := newInstance(cfg, config.Instance{Name: "i", Template: "x", Client: "acme", Project: "PRJ-0000", Params: map[string]any{"user": "instance"}}, tpl, access.Read, "socks5h://127.0.0.1:41234")
	if err != nil {
		t.Fatal(err)
	}
	p := in.Params()
	want := map[string]string{"kubeconfig": "~/.kube/all", "timeout": "20s", "proxy_url": "socks5h://127.0.0.1:41234", "user": "instance"}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, attendu %s", k, p[k], v)
		}
	}
	solo, err := newInstance(cfg, config.Instance{Name: "solo", Template: "x"}, tpl, access.Read, "")
	if err != nil || solo.Params()["kubeconfig"] != "~/.kube/all" || solo.Params()["user"] != "global" {
		t.Fatalf("instance hors client : %v %v", solo.Params(), err)
	}
}
