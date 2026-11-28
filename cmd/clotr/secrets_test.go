package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
)

func TestRegisterSecretSourcesDisabled(t *testing.T) {
	creds.ResetSecretSources()
	t.Cleanup(creds.ResetSecretSources)
	off := false
	cfg := &config.Config{Secrets: []config.SecretSource{{Name: "store", Template: "x", Enabled: &off}}}
	registerSecretSources(cfg, func(msg string) { t.Errorf("avertissement inattendu : %s", msg) })
	_, err := creds.ReadVault(context.Background(), "store:1#password")
	if err == nil || !strings.Contains(err.Error(), "store") || !strings.Contains(err.Error(), "enabled: false") {
		t.Fatalf("source désactivée : %v", err)
	}
}

func TestSecretsCheck(t *testing.T) {
	dir := t.TempDir()
	tpl := "name: acme\ntargets: [{kind: k, name: lake}]\ntools: [{kind: inventory}]\nconnectors:\n  api: {driver: http, base_url: \"http://127.0.0.1:1\", auth: {user_env: CHK_USER, password_env: CHK_PASS}}\n"
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	conf := "providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + dir + "}\ninstances:\n  - {name: lab, template: acme}\n  - {name: off, template: acme, enabled: false}\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHK_USER", "")
	t.Setenv("CHK_PASS", "")
	o := &options{config: path, ctx: context.Background(), noStartup: true}
	var out strings.Builder
	err := cmdSecretsCheck(context.Background(), o, nil, &out)
	if err == nil || !strings.Contains(out.String(), "KO  lab") || strings.Contains(out.String(), "off") {
		t.Fatalf("identifiants à saisir : %v\n%s", err, out.String())
	}
	t.Setenv("CHK_USER", "u")
	t.Setenv("CHK_PASS", "p")
	out.Reset()
	if err := cmdSecretsCheck(context.Background(), o, []string{"lab"}, &out); err != nil || !strings.Contains(out.String(), "ok  lab") {
		t.Fatalf("identifiants en variables : %v\n%s", err, out.String())
	}
	if err := cmdSecretsCheck(context.Background(), o, []string{"inconnue"}, &out); err == nil || !strings.Contains(err.Error(), "inconnue") {
		t.Fatalf("cible inconnue : %v", err)
	}
}

func TestSecretsCheckTunnelURL(t *testing.T) {
	dir := t.TempDir()
	tpl := "name: acme\ntargets: [{kind: k, name: lake}]\ntools: [{kind: inventory}]\nparams:\n  proxy_url: {type: string, default: \"\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "clients"), 0o700); err != nil {
		t.Fatal(err)
	}
	cl := "name: north\ntunnel: {hops: [10.0.0.1], port: 41999, user: ops, key_path: /dev/null}\ninstances:\n  - {name: lab, template: acme, params: {proxy_url: \"{{.tunnel_url}}\"}}\n"
	if err := os.WriteFile(filepath.Join(dir, "clients", "north.yaml"), []byte(cl), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	conf := "providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + dir + "}\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := cmdSecretsCheck(context.Background(), &options{config: path, ctx: context.Background(), noStartup: true}, []string{"north"}, &out); err != nil || !strings.Contains(out.String(), "ok  lab") {
		t.Fatalf("instance derrière tunnel : %v\n%s", err, out.String())
	}
}
