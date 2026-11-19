package main

import (
	"slices"
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestRolesBySpeed(t *testing.T) {
	cfg := &config.Config{Roles: map[string]config.Role{
		"planner":   {Tier: "deep"},
		"analyst":   {Tier: "balanced"},
		"collector": {Tier: "fast"},
	}}
	if got := rolesBySpeed(cfg); !slices.Equal(got, []string{"collector", "analyst", "planner"}) {
		t.Fatalf("rolesBySpeed = %q", got)
	}
}

func TestModeWord(t *testing.T) {
	cases := []struct {
		o    options
		want string
	}{
		{options{cveFlag: "CVE-2026-11111"}, "cve"},
		{options{datVariant: "clean"}, "dat"},
		{options{incident: true}, "incident"},
		{options{}, ""},
	}
	for _, c := range cases {
		if got := c.o.modeWord(); got != c.want {
			t.Errorf("modeWord = %q, want %q", got, c.want)
		}
	}
}

func TestThinkFree(t *testing.T) {
	if got := topicWord.FindString(thinkFree("<think>réfléchir</think>\n Kerberos.")); got != "Kerberos" {
		t.Fatalf("got %q", got)
	}
}
