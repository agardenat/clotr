package main

import (
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestToolFilter(t *testing.T) {
	cases := []struct {
		name          string
		only, exclude []string
		prefix        string
		on, want      bool
	}{
		{"sans filtre", nil, nil, "mcp_docs", true, true},
		{"sans filtre, coupé", nil, nil, "mcp_docs", false, false},
		{"-t mcp, coupé", []string{"mcp"}, nil, "mcp_docs", false, false},
		{"-t mcp", []string{"mcp"}, nil, "mcp_docs", true, true},
		{"-t nommé, coupé", []string{"mcp_docs"}, nil, "mcp_docs", false, true},
		{"-t nommé avec _", []string{"mcp_docs_"}, nil, "mcp_docs", false, true},
		{"-t autre", []string{"fs"}, nil, "mcp_docs", true, false},
		{"instance nommée, coupée", []string{"lab"}, nil, "lab", false, true},
		{"-x nommé", nil, []string{"mcp_docs"}, "mcp_docs", true, false},
		{"-x groupe", nil, []string{"mcp"}, "mcp_docs", true, false},
		{"-x autre", nil, []string{"mcp_wiki"}, "mcp_docs", true, true},
		{"-x prioritaire sur -t", []string{"mcp_docs"}, []string{"mcp_docs"}, "mcp_docs", false, false},
		{"-x instance", []string{"lab", "fs"}, []string{"lab"}, "lab", true, false},
	}
	for _, c := range cases {
		if got := (toolFilter{only: c.only, exclude: c.exclude}).active(c.prefix, c.on); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestCheckToolGroups(t *testing.T) {
	cfg := &config.Config{MCP: []config.MCPServer{{Name: "tickets"}}, Instances: []config.Instance{{Name: "lab"}}}
	for _, ok := range [][]string{{"fs"}, {"mcp"}, {"mcp_tickets"}, {"mcp_tickets_"}, {"lab*"}, {"evidence", "memory"}} {
		if err := checkToolGroups(cfg, ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	if err := checkToolGroups(cfg, nil, []string{"tickets"}); err == nil || !strings.Contains(err.Error(), "mcp_tickets") {
		t.Errorf("suggestion attendue: %v", err)
	}
	if err := checkToolGroups(cfg, []string{"inconnu"}); err == nil {
		t.Error("groupe inconnu accepté")
	}
}
