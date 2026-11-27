package main

import (
	"context"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
)

func TestRegisterSecretSourcesDisabled(t *testing.T) {
	creds.ResetSecretSources()
	t.Cleanup(creds.ResetSecretSources)
	off := false
	cfg := &config.Config{Secrets: []config.SecretSource{{Name: "store", Template: "x", Enabled: &off}}}
	registerSecretSources(cfg, func(msg string) { t.Errorf("avertissement inattendu : %s", msg) })
	_, err := creds.ReadVault(context.Background(), "store:1#password")
	if err == nil || !strings.Contains(err.Error(), "store") || !strings.Contains(err.Error(), "enabled: false") {
		t.Fatalf("source désactivée : %v", err)
	}
}
