package main

import (
	"errors"
	"strings"
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
		got, why, err := resolveWeb(cfg, &options{web: c.flag, exclude: exclude}, c.confidential, nil)
		if got != c.want || (err != nil) != c.err || (got && why != c.target) {
			t.Errorf("%s: %v %q %v", c.name, got, why, err)
		}
	}
}

func TestResolveWebClients(t *testing.T) {
	creds.OpenTTY = func() (*creds.Console, error) { return nil, errors.New("pas de terminal") }
	base := func() *config.Config {
		return &config.Config{
			WebSearch:  config.WebSearch{Policy: "allow", MCP: "search"},
			MCP:        []config.MCPServer{{Name: "search"}},
			Providers:  []config.Provider{{Name: "souv", Sovereign: true}, {Name: "ext"}},
			Compliance: map[string]config.Compliance{"regulated": {Confidential: true}},
		}
	}
	reg := func(name, web string) config.Client {
		return config.Client{Name: name, Compliance: "regulated", WebSearch: web}
	}
	plain := func(name, web string) config.Client { return config.Client{Name: name, WebSearch: web} }
	cases := []struct {
		name         string
		flag         string
		model        bool
		provider     string
		confidential bool
		clients      []config.Client
		want         bool
		err          bool
	}{
		{"confidentielle sans client", "", false, "", true, nil, false, false},
		{"confidentielle client sans réglage, politique allow", "", false, "", true, []config.Client{reg("a", "")}, true, false},
		{"confidentielle client sans réglage, politique deny", "", false, "", true, []config.Client{reg("a", "")}, false, false},
		{"confidentielle client deny, politique allow", "", false, "", true, []config.Client{reg("a", "deny")}, false, false},
		{"confidentielle client allow", "", false, "", true, []config.Client{reg("a", "allow")}, true, false},
		{"confidentielle client allow + yes", "yes", false, "", true, []config.Client{reg("a", "allow")}, true, false},
		{"confidentielle client ask sans terminal", "", false, "", true, []config.Client{reg("a", "ask")}, false, false},
		{"confidentielle client deny + yes", "yes", false, "", true, []config.Client{reg("a", "deny")}, false, true},
		{"confidentielle un client sans réglage", "", false, "", true, []config.Client{reg("a", "allow"), reg("b", "")}, true, false},
		{"confidentielle un client deny", "", false, "", true, []config.Client{reg("a", "allow"), reg("b", "deny")}, false, false},
		{"confidentielle client non réglementé seul", "", false, "", true, []config.Client{plain("a", "allow")}, false, false},
		{"confidentielle modèle souverain", "", true, "souv", true, []config.Client{reg("a", "allow")}, true, false},
		{"confidentielle modèle non souverain", "", true, "ext", true, []config.Client{reg("a", "allow")}, false, false},
		{"client deny", "", false, "", false, []config.Client{plain("a", "deny")}, false, false},
		{"client deny + yes", "yes", false, "", false, []config.Client{plain("a", "deny")}, true, false},
		{"client ask sans terminal", "", false, "", false, []config.Client{plain("a", "ask"), plain("b", "allow")}, false, false},
		{"client allow, politique deny", "", false, "", false, []config.Client{plain("a", "allow")}, true, false},
	}
	for _, c := range cases {
		cfg := base()
		if strings.HasSuffix(c.name, "politique deny") {
			cfg.WebSearch.Policy = "deny"
		}
		if c.model {
			cfg.WebSearch = config.WebSearch{Policy: "allow", Model: c.provider + "/m", API: "messages"}
			cfg.MCP = nil
		}
		got, why, err := resolveWeb(cfg, &options{web: c.flag}, c.confidential, c.clients)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%s: %v %q %v", c.name, got, why, err)
		}
	}
}
