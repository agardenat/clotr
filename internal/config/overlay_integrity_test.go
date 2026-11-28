package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/integrity"
)

func TestOverlayRestrictedWhenIntegrityActive(t *testing.T) {
	defer integrity.SetActive(true)()
	dir := t.TempDir()
	cases := []struct {
		name, body string
		client     bool
		bad        string
	}{
		{name: "allowed config", body: "ui_language: fr\nmcp:\n  - name: gw\n    servers:\n      - alias: files\n        auth: oauth\n        enabled: true\nsecrets:\n  - name: s\n    template: t\n    params: {user: u}\ninstances:\n  - name: i\n    template: t\n    params: {host: h}\n"},
		{name: "allowed client", client: true, body: "name: acme\ncontext: c\ninstances:\n  - name: i\n    template: t\nprojects:\n  - name: p\n    instances:\n      - name: j\n        params: {a: b}\n"},
		{name: "provider rate", body: "providers:\n  - name: x\n    max_requests_per_minute: 60\n"},
		{name: "providers", body: "providers:\n  - name: x\n    base_url: http://x\n", bad: "providers.base_url"},
		{name: "provider key", body: "providers:\n  - name: x\n    api_key: k\n", bad: "providers.api_key"},
		{name: "provider remove", body: "providers:\n  - !remove {name: x}\n", bad: "providers.!remove"},
		{name: "templates", body: "templates:\n  dir: /tmp/x\n", bad: "templates"},
		{name: "startup", body: "startup: ~\n", bad: "startup"},
		{name: "instance commands", body: "instances:\n  - name: i\n    commands: {allow: [rm]}\n", bad: "instances.commands"},
		{name: "instance shell", body: "instances:\n  - name: i\n    shell: {command: [sh]}\n", bad: "instances.shell"},
		{name: "mcp command", body: "mcp:\n  - name: m\n    command: /bin/sh\n", bad: "mcp.command"},
		{name: "mcp alias allow", body: "mcp:\n  - name: m\n    servers:\n      - alias: a\n        allow: [send]\n", bad: "mcp.servers.allow"},
		{name: "client access", client: true, body: "name: acme\naccess: create\n", bad: "access"},
		{name: "client tunnel", client: true, body: "name: acme\ntunnel: {hops: [h]}\n", bad: "tunnel"},
		{name: "project ssh_paths", client: true, body: "name: acme\nprojects:\n  - name: p\n    instances:\n      - name: i\n        ssh_paths: {allow: [/]}\n", bad: "projects.instances.ssh_paths"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+".yaml")
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if c.client {
				_, err = readOverlay(p, &Client{})
			} else {
				_, err = readOverlay(p, &Config{})
			}
			if c.bad == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !integrity.IsError(err) || !strings.Contains(err.Error(), c.bad) {
				t.Fatalf("expected refusal of %s, got %v", c.bad, err)
			}
		})
	}
}

func TestOverlayFreeWhenIntegrityInactive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("providers:\n  - name: x\n    base_url: http://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOverlay(p, &Config{}); err != nil {
		t.Fatal(err)
	}
}

func TestOverlayProviderRateMerged(t *testing.T) {
	path := writeTree(t, map[string]string{
		"config.yaml":       sharedConfig,
		"local/config.yaml": "providers:\n  - name: a\n    max_requests_per_minute: 60\n",
	})
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 2 || c.Providers[0].MaxRequestsPerMinute != 60 || c.Providers[0].BaseURL != "http://a/v1" || c.Providers[0].MaxConcurrency != 2 {
		t.Fatalf("providers: %+v", c.Providers)
	}
}
