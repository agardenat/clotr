package main

import (
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestProviderGatesByHost(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := &config.Config{Providers: []config.Provider{
		{Name: "gw", BaseURL: "https://gateway.example.test/v1", MaxRequestsPerMinute: 30},
		{Name: "other", BaseURL: "https://llm.example.test/v1"},
	}}
	gate := providerGates(cfg)
	a := gate(config.MCPServer{Name: "docs", URL: "https://Gateway.example.test/api/v1/docs/mcp"})
	b := gate(config.MCPServer{Name: "search", URL: "https://gateway.example.test/api/v1/search/mcp"})
	if a == nil || a != b {
		t.Fatalf("même fournisseur attendu : %p %p", a, b)
	}
	if gate(config.MCPServer{Name: "local", Command: "server"}) != nil || gate(config.MCPServer{URL: "https://mcp.example.test/x"}) != nil {
		t.Fatal("serveur hors fournisseur rattaché")
	}
}
