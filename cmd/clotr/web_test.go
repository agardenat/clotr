package main

import (
	"errors"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
)

func TestResolveWeb(t *testing.T) {
	creds.OpenTTY = func() (*creds.Console, error) { return nil, errors.New("pas de terminal") }
	cfg := &config.Config{WebSearch: config.WebSearch{Policy: "ask", MCP: "search"}}
	cases := []struct {
		name         string
		policy, flag string
		mcp          string
		confidential bool
		excluded     bool
		want         bool
		err          bool
	}{
		{"sans serveur", "allow", "", "", false, false, false, false},
		{"allow", "allow", "", "search", false, false, true, false},
		{"deny", "deny", "", "search", false, false, false, false},
		{"ask sans terminal", "ask", "", "search", false, false, false, false},
		{"flag yes", "deny", "yes", "search", false, false, true, false},
		{"flag no", "allow", "no", "search", false, false, false, false},
		{"confidentielle", "allow", "", "search", true, false, false, false},
		{"confidentielle + yes", "allow", "yes", "search", true, false, false, true},
		{"flag invalide", "allow", "peut-être", "search", false, false, false, true},
		{"exclu", "allow", "", "search", false, true, false, false},
		{"exclu + yes", "allow", "yes", "search", false, true, false, true},
	}
	for _, c := range cases {
		cfg.WebSearch.Policy, cfg.WebSearch.MCP = c.policy, c.mcp
		var exclude []string
		if c.excluded {
			exclude = []string{"mcp_search"}
		}
		got, _, err := resolveWeb(cfg, &options{web: c.flag, exclude: exclude}, c.confidential)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%s: %v %v", c.name, got, err)
		}
	}
}
