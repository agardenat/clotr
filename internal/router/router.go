package router

import (
	"fmt"
	"sort"

	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
)

type Router struct {
	cfg       *config.Config
	cat       *catalog.Catalog
	overrides map[string]catalog.ModelInfo
	order     map[string]int
	sovereign string
}

func New(cfg *config.Config, cat *catalog.Catalog, overrides map[string]string, sovereign string) (*Router, error) {
	if sovereign != "" && !config.ValidSovereignPolicy(sovereign) {
		return nil, fmt.Errorf("--sovereign %q invalide (any|prefer|require)", sovereign)
	}
	r := &Router{cfg: cfg, cat: cat, overrides: map[string]catalog.ModelInfo{}, order: map[string]int{}, sovereign: sovereign}
	for i, p := range cfg.Providers {
		r.order[p.Name] = i
	}
	for role, ref := range overrides {
		rc, ok := cfg.Roles[role]
		if !ok {
			return nil, fmt.Errorf("--model %s=%s: rôle inconnu", role, ref)
		}
		if m, ok := cat.Find(ref); ok {
			r.overrides[role] = m
			continue
		}
		prov, id, ok := catalog.SplitRef(ref)
		if !ok {
			return nil, fmt.Errorf("--model %s=%s: format attendu provider/model", role, ref)
		}
		p, ok := cfg.Provider(prov)
		if !ok {
			return nil, fmt.Errorf("--model %s=%s: provider %q inconnu", role, ref, prov)
		}
		r.overrides[role] = catalog.ModelInfo{Provider: prov, ID: id, Tier: rc.Tier, Tools: rc.Tools, Context: rc.MinContext, Sovereign: p.Sovereign, Weight: p.Weight, Source: "override"}
	}
	return r, nil
}

func (r *Router) Policy(role string) string {
	if r.sovereign != "" {
		return r.sovereign
	}
	if rc, ok := r.cfg.Roles[role]; ok && rc.Sovereign != "" {
		return rc.Sovereign
	}
	return r.cfg.Routing.Sovereign
}

func (r *Router) Candidates(role string) ([]catalog.ModelInfo, error) {
	rc, ok := r.cfg.Roles[role]
	if !ok {
		return nil, fmt.Errorf("rôle %q inconnu", role)
	}
	policy := r.Policy(role)
	if m, ok := r.overrides[role]; ok {
		if policy == "require" && !m.Sovereign {
			return nil, fmt.Errorf("rôle %s: modèle forcé %s non souverain alors que sovereign=require", role, m.Ref())
		}
		return []catalog.ModelInfo{m}, nil
	}
	want := config.TierRank(rc.Tier)
	var out []catalog.ModelInfo
	for _, m := range r.cat.Models {
		if config.TierRank(m.Tier) < want {
			continue
		}
		if rc.Tools && !m.Tools {
			continue
		}
		if rc.MinContext > 0 && m.Context < rc.MinContext {
			continue
		}
		if policy == "require" && !m.Sovereign {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("aucun modèle ne satisfait le rôle %q (tier>=%s, tools=%t, min_context=%d, sovereign=%s) : ajuster profiles ou roles", role, rc.Tier, rc.Tools, rc.MinContext, policy)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if policy == "prefer" && a.Sovereign != b.Sovereign {
			return a.Sovereign
		}
		if ta, tb := config.TierRank(a.Tier), config.TierRank(b.Tier); ta != tb {
			return ta < tb
		}
		if sa, sb := a.Score(), b.Score(); sa != sb {
			return sa > sb
		}
		if r.order[a.Provider] != r.order[b.Provider] {
			return r.order[a.Provider] < r.order[b.Provider]
		}
		return a.ID < b.ID
	})
	return out, nil
}
