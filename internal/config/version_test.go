package config

import (
	"strings"
	"testing"
)

func withVersion(t *testing.T, v string) {
	t.Helper()
	old := Version
	Version = v
	t.Cleanup(func() { Version = old })
}

func TestRequireVersion(t *testing.T) {
	withVersion(t, "v0.72.0")
	for _, ok := range []string{"", "0.72.0", "v0.71.9", "0.9.0", "0.72.0 "} {
		if err := RequireVersion("config", ok, ""); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, ko := range []string{"0.72.1", "0.73.0", "1.0.0"} {
		err := RequireVersion("config", ko, "relancer le script d'installation")
		if err == nil || !strings.Contains(err.Error(), ">= "+ko) || !strings.Contains(err.Error(), "0.72.0") || !strings.Contains(err.Error(), "relancer le script") {
			t.Errorf("%q: %v", ko, err)
		}
	}
	if err := RequireVersion("config", "0.72", ""); err == nil || !strings.Contains(err.Error(), "X.Y.Z") {
		t.Errorf("format: %v", err)
	}
	for _, dev := range []string{"dev", "v0.71.1-dirty", "v0.71.1-3-gabcdef0"} {
		withVersion(t, dev)
		if err := RequireVersion("config", "9.0.0", ""); err != nil {
			t.Errorf("%s: %v", dev, err)
		}
	}
}

func TestConfigMinVersionBeforeUnknownFields(t *testing.T) {
	withVersion(t, "0.71.1")
	_, err := Parse([]byte("min_version: 0.72.0\nupdate_hint: \"mettre à jour : curl …\"\nnouvelle_cle: 1\n"))
	if err == nil || !strings.Contains(err.Error(), ">= 0.72.0") || !strings.Contains(err.Error(), "0.71.1") || !strings.Contains(err.Error(), "curl") {
		t.Fatalf("%v", err)
	}
	withVersion(t, "0.72.0")
	if _, err := Parse([]byte("min_version: 0.72.0\nupdate_hint: x\nproviders:\n  - {name: a, base_url: http://x/v1}\n")); err != nil {
		t.Fatal(err)
	}
}
