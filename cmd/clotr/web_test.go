package main

import (
	"errors"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
)

func TestResolveWeb(t *testing.T) {
	creds.OpenTTY = func() (*creds.Console, error) { return nil, errors.New("pas de terminal") }
	off := false
	cases := []struct {
		name         string
		policy, flag string
		mcp, model   string
		disabled     bool
		confidential bool
		excluded     bool
		want         bool
		target       string
		err          bool
	}{
		{"sans serveur", "allow", "", "", "", false, false, false, false, "", false},
		{"allow", "allow", "", "search", "", false, false, false, true, "search", false},
		{"deny", "deny", "", "search", "", false, false, false, false, "", false},
		{"ask sans terminal", "ask", "", "search", "", false, false, false, false, "", false},
		{"flag yes", "deny", "yes", "search", "", false, false, false, true, "search", false},
		{"flag no", "allow", "no", "search", "", false, false, false, false, "", false},
		{"confidentielle", "allow", "", "search", "", false, true, false, false, "", false},
		{"confidentielle + yes", "allow", "yes", "search", "", false, true, false, false, "", true},
		{"flag invalide", "allow", "peut-être", "search", "", false, false, false, false, "", true},
		{"exclu", "allow", "", "search", "", false, false, true, false, "", false},
		{"exclu + yes", "allow", "yes", "search", "", false, false, true, false, "", true},
		{"modèle seul", "allow", "", "", "go/haiku", false, false, false, true, "go/haiku", false},
		{"modèle, deny", "deny", "", "", "go/haiku", false, false, false, false, "", false},
		{"modèle confidentielle", "allow", "", "", "go/haiku", false, true, false, false, "", false},
		{"MCP prioritaire", "allow", "", "search", "go/haiku", false, false, false, true, "search", false},
		{"MCP exclu, modèle", "allow", "", "search", "go/haiku", false, false, true, true, "go/haiku", false},
		{"MCP désactivé, modèle", "allow", "", "search", "go/haiku", true, false, false, true, "go/haiku", false},
		{"MCP désactivé sans modèle", "allow", "yes", "search", "", true, false, false, false, "", false},
	}
	for _, c := range cases {
		cfg := &config.Config{WebSearch: config.WebSearch{Policy: c.policy, MCP: c.mcp, Model: c.model}}
		if c.mcp != "" {
			m := config.MCPServer{Name: c.mcp}
			if c.disabled {
				m.Enabled = &off
			}
			cfg.MCP = []config.MCPServer{m}
		}
		var exclude []string
		if c.excluded {
			exclude = []string{"mcp_search"}
		}
		got, why, err := resolveWeb(cfg, &options{web: c.flag, exclude: exclude}, c.confidential)
		if got != c.want || (err != nil) != c.err || (got && why != c.target) {
			t.Errorf("%s: %v %q %v", c.name, got, why, err)
		}
	}
}
