package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLimitFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("providers:\n  - {name: p, base_url: http://x}\nlimits: {max_agents: 6, max_steps: 100}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(&options{config: path, maxAgents: 1, maxTasks: 2})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxAgents != 1 || cfg.Limits.MaxTasks != 2 || cfg.Limits.MaxSteps != 100 {
		t.Fatalf("limites: %+v", cfg.Limits)
	}
	if _, err := loadConfig(&options{config: path, maxSteps: -1}); err == nil {
		t.Fatal("--max-steps négatif accepté")
	}
	if (&options{direct: directAuto}).directRole() != "" || (&options{direct: "analyst"}).directRole() != "analyst" {
		t.Fatal("rôle direct")
	}
}
