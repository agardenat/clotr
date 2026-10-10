package router

import (
	"fmt"
	"testing"

	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
)

func setup(t *testing.T) (*config.Config, *catalog.Catalog) {
	cfg, err := config.Parse([]byte(`
providers:
  - {name: p1, base_url: http://a}
  - {name: p2, base_url: http://b}
roles:
  planner: {tier: deep}
  collector: {tier: fast, tools: true}
  analyst: {tier: balanced, tools: true, min_context: 64000}
  synthesizer: {tier: deep}
`))
	if err != nil {
		t.Fatal(err)
	}
	cat := &catalog.Catalog{Models: []catalog.ModelInfo{
		{Provider: "p1", ID: "small", Tier: "fast", Context: 32000, Tools: true},
		{Provider: "p1", ID: "notools", Tier: "fast", Context: 32000},
		{Provider: "p2", ID: "mid", Tier: "balanced", Context: 128000, Tools: true},
		{Provider: "p1", ID: "big", Tier: "deep", Context: 200000, Tools: true},
		{Provider: "p2", ID: "big2", Tier: "deep", Context: 200000, Tools: true, Priority: 5},
	}}
	return cfg, cat
}

func refs(ms []catalog.ModelInfo) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Ref())
	}
	return out
}

func TestCandidates(t *testing.T) {
	cfg, cat := setup(t)
	r, err := New(cfg, cat, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"collector": {"p1/small", "p2/mid", "p2/big2", "p1/big"},
		"analyst":   {"p2/mid", "p2/big2", "p1/big"},
		"planner":   {"p2/big2", "p1/big"},
	}
	for role, want := range cases {
		got, err := r.Candidates(role)
		if err != nil {
			t.Fatal(err)
		}
		if g := refs(got); len(g) != len(want) || func() bool {
			for i := range g {
				if g[i] != want[i] {
					return true
				}
			}
			return false
		}() {
			t.Errorf("%s: %v, attendu %v", role, g, want)
		}
	}
}

func TestOverrideAndErrors(t *testing.T) {
	cfg, cat := setup(t)
	r, err := New(cfg, cat, map[string]string{"collector": "p2/custom/model"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.Candidates("collector")
	if len(got) != 1 || got[0].Ref() != "p2/custom/model" {
		t.Fatalf("override: %v", refs(got))
	}
	if _, err := New(cfg, cat, map[string]string{"collector": "nope/x"}, ""); err == nil {
		t.Error("provider inconnu accepté")
	}
	cfg.Roles["analyst"] = config.Role{Tier: "deep", Tools: true, MinContext: 1000000}
	if _, err := r.Candidates("analyst"); err == nil {
		t.Error("rôle insatisfiable accepté")
	}
}

func TestWeightAndSovereign(t *testing.T) {
	cfg, err := config.Parse([]byte(`
providers:
  - {name: cloud, base_url: http://a}
  - {name: sov, base_url: http://b, weight: 20, sovereign: true}
roles:
  planner: {tier: deep}
  collector: {tier: fast, tools: true}
  strict: {tier: fast, tools: true, sovereign: require}
  synthesizer: {tier: deep}
`))
	if err != nil {
		t.Fatal(err)
	}
	cat := &catalog.Catalog{Models: []catalog.ModelInfo{
		{Provider: "cloud", ID: "haiku", Tier: "fast", Tools: true, Priority: 10},
		{Provider: "cloud", ID: "sonnet", Tier: "balanced", Tools: true},
		{Provider: "sov", ID: "chat", Tier: "fast", Tools: true, Weight: 20, Sovereign: true},
		{Provider: "sov", ID: "oss", Tier: "balanced", Tools: true, Weight: 20, Sovereign: true},
	}}
	check := func(policy, role string, want ...string) {
		t.Helper()
		r, err := New(cfg, cat, nil, policy)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Candidates(role)
		if err != nil {
			t.Fatal(err)
		}
		if g := refs(got); fmt.Sprint(g) != fmt.Sprint(want) {
			t.Errorf("policy=%q role=%s: %v, attendu %v", policy, role, g, want)
		}
	}
	check("", "collector", "sov/chat", "cloud/haiku", "sov/oss", "cloud/sonnet")
	check("prefer", "collector", "sov/chat", "sov/oss", "cloud/haiku", "cloud/sonnet")
	check("require", "collector", "sov/chat", "sov/oss")
	check("", "strict", "sov/chat", "sov/oss")
	check("any", "strict", "sov/chat", "cloud/haiku", "sov/oss", "cloud/sonnet")
	if _, err := New(cfg, cat, nil, "maybe"); err == nil {
		t.Error("politique invalide acceptée")
	}
	r, _ := New(cfg, cat, map[string]string{"strict": "cloud/haiku"}, "")
	if _, err := r.Candidates("strict"); err == nil {
		t.Error("override non souverain accepté sous require")
	}
}
