package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "config.yaml")
}

const sharedConfig = `providers:
  - name: a
    base_url: http://a/v1
    max_concurrency: 2
  - name: b
    base_url: http://b/v1
language: fr
params:
  kubeconfig: /shared/kube
  region: eu
limits:
  max_steps: 50
  stall_steps: 4
`

func TestLocalOverlayConfig(t *testing.T) {
	path := writeTree(t, map[string]string{
		"config.yaml": sharedConfig,
		"local/config.yaml": `providers:
  - name: a
    max_concurrency: 8
  - !remove {name: b}
  - name: c
    base_url: http://c/v1
language: en
ui_language: fr
params:
  kubeconfig: ~/.kube/mine
  region: ~
limits:
  max_steps: 70
`,
	})
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 2 || c.Providers[0].Name != "a" || c.Providers[0].BaseURL != "http://a/v1" || c.Providers[0].MaxConcurrency != 8 || c.Providers[1].Name != "c" {
		t.Fatalf("providers: %+v", c.Providers)
	}
	if c.Language != "en" || c.Limits.MaxSteps != 70 || *c.Limits.StallSteps != 4 {
		t.Fatalf("language/limits: %s %+v", c.Language, c.Limits)
	}
	if _, ok := c.Params["region"]; ok || c.Params["kubeconfig"] != "~/.kube/mine" {
		t.Fatalf("params: %+v", c.Params)
	}
	if got := PeekUILanguage(path); got != "fr" {
		t.Fatalf("ui_language: %q", got)
	}
}

func TestLocalOverlayClients(t *testing.T) {
	path := writeTree(t, map[string]string{
		"config.yaml": "providers:\n  - name: a\n    base_url: http://a/v1\n",
		"clients/acme.yaml": `name: acme
params:
  ssh_user: svc
projects:
  - name: data
    instances:
      - name: acme-vm
        template: ssh-host
        params: {host: vm1, port: 22}
      - name: acme-old
        template: ssh-host
`,
		"local/clients/acme.yaml": `projects:
  - name: data
    instances:
      - name: acme-vm
        params: {port: 2222}
      - name: acme-old
        enabled: false
`,
		"local/clients/perso.yaml": "name: perso\ninstances:\n  - name: perso-vm\n    template: ssh-host\n",
	})
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Instance{}
	for _, in := range c.Instances {
		got[in.Name] = in
	}
	vm := got["acme-vm"]
	if vm.Template != "ssh-host" || vm.Params["host"] != "vm1" || vm.Params["port"] != 2222 || vm.Project != "data" {
		t.Fatalf("acme-vm: %+v", vm)
	}
	if got["acme-old"].IsEnabled() {
		t.Fatal("acme-old devrait être désactivée")
	}
	if got["perso-vm"].Client != "perso" || len(c.Clients) != 2 {
		t.Fatalf("client local: %+v", c.Clients)
	}
}

func TestLocalOverlayErrors(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"clé inconnue":      {map[string]string{"local/config.yaml": "unknown: 1\n"}, filepath.Join("local", "config.yaml")},
		"résultat invalide": {map[string]string{"local/config.yaml": "providers:\n  - name: a\n    base_url: nope\n"}, "local"},
		"client inconnu":    {map[string]string{"clients/acme.yaml": "name: acme\n", "local/clients/acme.yaml": "nope: 1\n"}, filepath.Join("local", "clients", "acme.yaml")},
	}
	for name, tc := range cases {
		files := map[string]string{"config.yaml": sharedConfig}
		for k, v := range tc.files {
			files[k] = v
		}
		_, err := Load(writeTree(t, files))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLocalOverlayEmpty(t *testing.T) {
	c, err := Load(writeTree(t, map[string]string{"config.yaml": sharedConfig, "local/config.yaml": "# rien\n"}))
	if err != nil || len(c.Providers) != 2 {
		t.Fatalf("%v %+v", err, c)
	}
}
