package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMCPServersExpansion(t *testing.T) {
	y := `providers:
  - {name: a, base_url: http://x/v1}
mcp:
  - name: gw
    url: "https://gw.example/api/v1/{alias}/mcp"
    headers: {x-api-key: "${GW_KEY}"}
    deny: ["*delete*"]
    enabled: false
    servers:
      - {alias: wiki}
      - {alias: web_search, name: web, allow: [web_search-search], enabled: true}
      - {alias: mail_me, auth: oauth, timeout: 2m, headers: {x-extra: "1"}}
  - name: hub
    url: "https://hub.example/mcp/"
    servers:
      - {alias: tickets, allow: ["tickets-get_*"]}
  - name: solo
    url: "https://solo.example/mcp"
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range c.MCP {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, []string{"wiki", "web", "mail-me", "tickets", "solo"}) {
		t.Fatalf("entrées: %v", names)
	}
	wiki, web, mail, tickets := c.MCP[0], c.MCP[1], c.MCP[2], c.MCP[3]
	if wiki.URL != "https://gw.example/api/v1/wiki/mcp" || wiki.Headers["x-api-key"] != "${GW_KEY}" || wiki.Headers[MCPSelectHeader] != "" || wiki.IsEnabled() || !slices.Equal(wiki.Deny, []string{"*delete*"}) || wiki.Transport != "http" {
		t.Fatalf("wiki: %+v", wiki)
	}
	if web.URL != "https://gw.example/api/v1/web_search/mcp" || !web.IsEnabled() || !slices.Equal(web.Allow, []string{"web_search-search"}) {
		t.Fatalf("web: %+v", web)
	}
	if mail.Auth != MCPAuthOAuth || mail.Timeout.Duration != 2*time.Minute || mail.Headers["x-extra"] != "1" || mail.Headers["x-api-key"] != "${GW_KEY}" || wiki.Headers["x-extra"] != "" {
		t.Fatalf("mail: %+v", mail)
	}
	if tickets.URL != "https://hub.example/mcp/" || tickets.Headers[MCPSelectHeader] != "tickets" || !tickets.IsEnabled() {
		t.Fatalf("tickets: %+v", tickets)
	}
	for _, c := range []struct{ y, want string }{
		{"mcp:\n  - {name: g, command: x, servers: [{alias: a}]}\n", "servers"},
		{"mcp:\n  - {name: g, url: \"https://x/{alias}\", servers: [{name: b}]}\n", "alias"},
		{"mcp:\n  - {name: g, url: \"https://x/{alias}\", servers: [{alias: a}, {alias: a}]}\n", "dup"},
		{"mcp:\n  - {name: g, url: \"https://x/{alias}\", servers: [{alias: a, allowed: [x]}]}\n", "allowed"},
	} {
		if _, err := Parse([]byte(c.y)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s : %v", c.y, err)
		}
	}
}
