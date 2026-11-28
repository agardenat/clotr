package main

import (
	"net/url"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/llm"
)

func providerGates(cfg *config.Config) func(config.MCPServer) *llm.Gate {
	hosts := map[string]config.Provider{}
	for _, p := range cfg.Providers {
		if h := urlHost(p.BaseURL); h != "" {
			if _, seen := hosts[h]; !seen {
				hosts[h] = p
			}
		}
	}
	var mu sync.Mutex
	gates := map[string]*llm.Gate{}
	return func(m config.MCPServer) *llm.Gate {
		p, ok := hosts[urlHost(m.URL)]
		if !ok {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if g := gates[p.Name]; g != nil {
			return g
		}
		g := llm.SharedGate(p.MaxRequestsPerMinute, p.Name)
		gates[p.Name] = g
		return g
	}
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
