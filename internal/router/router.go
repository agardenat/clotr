package router

import (
	"sort"

	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
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
		return nil, i18n.E("router.sovereign", sovereign)
	}
	r := &Router{cfg: cfg, cat: cat, overrides: map[string]catalog.ModelInfo{}, order: map[string]int{}, sovereign: sovereign}
	for i, p := range cfg.Providers {
		r.order[p.Name] = i
	}
	for role, ref := range overrides {
		rc, ok := cfg.Roles[role]
		if !ok {
			return nil, i18n.E("router.model_role", role, ref)
		}
		if m, ok := cat.Find(ref); ok {
			r.overrides[role] = m
			continue
		}
		prov, id, ok := catalog.SplitRef(ref)
		if !ok {
			return nil, i18n.E("router.model_format", role, ref)
		}
		p, ok := cfg.Provider(prov)
		if !ok {
			return nil, i18n.E("router.model_provider", role, ref, prov)
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
		return nil, i18n.E("router.role", role)
	}
	policy := r.Policy(role)
	if m, ok := r.overrides[role]; ok {
		if policy == "require" && !m.Sovereign {
			return nil, i18n.E("router.forced_foreign", role, m.Ref())
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
		return nil, i18n.E("router.no_model", role, rc.Tier, rc.Tools, rc.MinContext, policy)
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
