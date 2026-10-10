package budget

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/llm"
)

type Status struct {
	Provider string  `json:"provider"`
	Spend    float64 `json:"spend"`
	Max      float64 `json:"max_budget"`
	HasMax   bool    `json:"has_max"`
	Duration string  `json:"budget_duration,omitempty"`
	ResetAt  string  `json:"budget_reset_at,omitempty"`
	Error    string  `json:"error,omitempty"`
}

func (s Status) Remaining() float64 {
	return s.Max - s.Spend
}

func root(baseURL string) string {
	if r, ok := strings.CutSuffix(baseURL, "/v1"); ok {
		return r
	}
	return baseURL
}

func Fetch(ctx context.Context, hc *http.Client, p config.Provider) Status {
	st := Status{Provider: p.Name}
	path := p.Budget.InfoPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, root(p.BaseURL)+path, nil)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	if key := p.APIKey(); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		st.Error = fmt.Sprintf("GET %s: HTTP %d: %s", path, resp.StatusCode, httpx.Snippet(body, 200))
		return st
	}
	var out struct {
		Info struct {
			Spend          float64  `json:"spend"`
			MaxBudget      *float64 `json:"max_budget"`
			BudgetDuration string   `json:"budget_duration"`
			BudgetResetAt  string   `json:"budget_reset_at"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		st.Error = fmt.Sprintf("GET %s: réponse invalide: %v", path, err)
		return st
	}
	st.Spend = out.Info.Spend
	if out.Info.MaxBudget != nil {
		st.Max, st.HasMax = *out.Info.MaxBudget, true
	}
	st.Duration, st.ResetAt = out.Info.BudgetDuration, out.Info.BudgetResetAt
	return st
}

func FetchAll(ctx context.Context, hc *http.Client, cfg *config.Config, only ...string) []Status {
	var provs []config.Provider
	for _, p := range cfg.Providers {
		if !p.Budget.Limited() {
			continue
		}
		if len(only) > 0 && !contains(only, p.Name) {
			continue
		}
		provs = append(provs, p)
	}
	out := make([]Status, len(provs))
	var wg sync.WaitGroup
	for i, p := range provs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = Fetch(ctx, hc, p)
		}()
	}
	wg.Wait()
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type account struct {
	cfg       *config.Budget
	runCost   float64
	calls     int
	reported  bool
	estimated bool
	viaInfo   bool
	baseline  float64
	hasBase   bool
	spend     float64
	max       float64
	hasKey    bool
	exhausted string
}

type Tracker struct {
	mu       sync.Mutex
	accounts map[string]*account
}

func NewTracker(cfg *config.Config) *Tracker {
	t := &Tracker{accounts: map[string]*account{}}
	for _, p := range cfg.Providers {
		t.accounts[p.Name] = &account{cfg: p.Budget}
	}
	return t
}

func (t *Tracker) Seed(statuses []Status) []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var excluded []string
	for _, s := range statuses {
		a, ok := t.accounts[s.Provider]
		if !ok || s.Error != "" || !s.HasMax {
			continue
		}
		a.spend, a.max, a.hasKey = s.Spend, s.Max, true
		a.baseline, a.hasBase = s.Spend, true
		if reason := a.check(); reason != "" {
			a.exhausted = reason
			excluded = append(excluded, fmt.Sprintf("%s écarté: %s", s.Provider, reason))
		}
	}
	return excluded
}

func (a *account) check() string {
	if !a.cfg.Limited() {
		return ""
	}
	if a.hasKey && a.cfg.MinRemaining > 0 && a.max-a.spend < a.cfg.MinRemaining {
		return fmt.Sprintf("budget restant %.4f $ < min_remaining %.2f $ (dépensé %.4f / %.2f $)", a.max-a.spend, a.cfg.MinRemaining, a.spend, a.max)
	}
	if a.cfg.MaxRunCost > 0 && a.runCost >= a.cfg.MaxRunCost {
		return fmt.Sprintf("coût du run %.4f $ >= max_run_cost %.2f $", a.runCost, a.cfg.MaxRunCost)
	}
	return ""
}

func (t *Tracker) Record(provider string, c llm.Cost) string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.accounts[provider]
	if !ok {
		return ""
	}
	a.calls++
	if c.Reported {
		a.runCost += c.Response
		a.reported = true
		a.estimated = a.estimated || c.Estimated
	}
	if c.HasKey {
		a.spend, a.max, a.hasKey = max(a.spend, c.KeySpend), c.KeyMax, true
	} else if a.hasKey {
		a.spend += c.Response
	}
	if a.exhausted != "" {
		return ""
	}
	if reason := a.check(); reason != "" {
		a.exhausted = reason
		return reason
	}
	return ""
}

type Exhaustion struct {
	Provider string
	Reason   string
}

func (t *Tracker) Refresh(statuses []Status) []Exhaustion {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Exhaustion
	for _, s := range statuses {
		a, ok := t.accounts[s.Provider]
		if !ok || s.Error != "" || !s.HasMax {
			continue
		}
		a.spend, a.max, a.hasKey = s.Spend, s.Max, true
		if a.hasBase && !a.reported {
			a.runCost = max(s.Spend-a.baseline, 0)
			a.viaInfo = true
		}
		if a.exhausted != "" {
			continue
		}
		if reason := a.check(); reason != "" {
			a.exhausted = reason
			out = append(out, Exhaustion{Provider: s.Provider, Reason: reason})
		}
	}
	return out
}

func (t *Tracker) Used() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for name, a := range t.accounts {
		if a.calls > 0 && a.cfg.Limited() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (t *Tracker) Exhausted(provider string) string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if a, ok := t.accounts[provider]; ok {
		return a.exhausted
	}
	return ""
}

type Line struct {
	Provider  string  `json:"provider"`
	Calls     int     `json:"calls"`
	RunCost   float64 `json:"run_cost"`
	KeySpend  float64 `json:"key_spend,omitempty"`
	KeyMax    float64 `json:"key_max_budget,omitempty"`
	HasKey    bool    `json:"has_key_budget"`
	Reported  bool    `json:"cost_reported"`
	Estimated bool    `json:"cost_estimated,omitempty"`
	Unlimited bool    `json:"unlimited,omitempty"`
	Exhausted string  `json:"exhausted,omitempty"`
}

func (t *Tracker) Summary() []Line {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Line
	for name, a := range t.accounts {
		if a.calls == 0 && a.exhausted == "" {
			continue
		}
		unlimited := a.cfg != nil && a.cfg.Unlimited
		out = append(out, Line{Provider: name, Calls: a.calls, RunCost: a.runCost, KeySpend: a.spend, KeyMax: a.max, HasKey: a.hasKey && !unlimited, Unlimited: unlimited, Exhausted: a.exhausted, Reported: a.reported || a.viaInfo, Estimated: a.estimated})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

func (l Line) String() string {
	calls := i18n.N(l.Calls, "call")
	s := i18n.T("cost.run", l.Provider, calls, l.RunCost)
	if l.Estimated {
		s = i18n.T("cost.estimated", l.Provider, calls, l.RunCost)
	}
	if !l.Reported {
		s = i18n.T("cost.unreported", l.Provider, calls)
	}
	if l.HasKey {
		s += i18n.T("cost.key", l.KeySpend, l.KeyMax, l.KeyMax-l.KeySpend)
	}
	if l.Unlimited {
		s += i18n.T("cost.unlimited")
	}
	if l.Exhausted != "" {
		s += i18n.T("cost.dropped", l.Exhausted)
	}
	return s
}
