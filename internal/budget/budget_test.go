package budget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/llm"
)

func cfg(t *testing.T, url string) *config.Config {
	c, err := config.Parse([]byte(`
providers:
  - {name: lite, base_url: ` + url + `/v1, api_key: k, budget: {min_remaining: 1, max_run_cost: 0.5}}
  - {name: free, base_url: http://x, budget: unlimited}
  - {name: none, base_url: http://z}
`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/key/info" || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{"key":"x","info":{"spend":49.5,"max_budget":50,"budget_duration":"30d","budget_reset_at":"2026-11-01T00:00:00+00:00"}}`))
	}))
	defer srv.Close()
	c := cfg(t, srv.URL)
	st := FetchAll(context.Background(), srv.Client(), c)
	if len(st) != 1 || st[0].Error != "" || st[0].Remaining() != 0.5 || st[0].Duration != "30d" {
		t.Fatalf("%+v", st)
	}
	tr := NewTracker(c)
	ex := tr.Seed(st)
	if len(ex) != 1 || tr.Exhausted("lite") == "" || tr.Exhausted("free") != "" {
		t.Fatalf("seed: %v", ex)
	}
}

func TestRecord(t *testing.T) {
	c := cfg(t, "http://x")
	tr := NewTracker(c)
	if r := tr.Record("lite", llm.Cost{Reported: true, Response: 0.2, KeySpend: 10, KeyMax: 50, HasKey: true}); r != "" {
		t.Fatalf("écarté trop tôt: %s", r)
	}
	if r := tr.Record("lite", llm.Cost{Reported: true, Response: 0.31}); !strings.Contains(r, "max_run_cost") {
		t.Fatalf("max_run_cost non déclenché: %q", r)
	}
	tr2 := NewTracker(c)
	if r := tr2.Record("lite", llm.Cost{Reported: true, Response: 0.01, KeySpend: 49.2, KeyMax: 50, HasKey: true}); !strings.Contains(r, "min_remaining") {
		t.Fatalf("min_remaining non déclenché: %q", r)
	}
	if r := tr2.Record("free", llm.Cost{Response: 100}); r != "" {
		t.Fatalf("provider sans budget écarté: %q", r)
	}
	sum := tr.Summary()
	if c.Providers[1].BudgetStatus() != "illimité" || c.Providers[2].BudgetStatus() != "non déclaré" || c.Providers[0].BudgetStatus() != "limité" {
		t.Fatal("statuts de budget")
	}
	if len(sum) != 1 || sum[0].Calls != 2 || sum[0].RunCost < 0.509 || sum[0].Exhausted == "" {
		t.Fatalf("summary: %+v", sum)
	}
	if !strings.Contains(sum[0].String(), "run cost") {
		t.Errorf("ligne: %s", sum[0].String())
	}
	tr3 := NewTracker(c)
	tr3.Record("none", llm.Cost{})
	if l := tr3.Summary(); len(l) != 1 || !strings.Contains(l[0].String(), "not reported") {
		t.Errorf("coût non communiqué: %+v", l)
	}
	var nilT *Tracker
	if nilT.Exhausted("x") != "" || nilT.Record("x", llm.Cost{}) != "" {
		t.Fatal("tracker nil")
	}
}

func TestInvalidBudget(t *testing.T) {
	if _, err := config.Parse([]byte("providers:\n  - {name: a, base_url: http://x, budget: maybe}\n")); err == nil || !strings.Contains(err.Error(), "unlimited") {
		t.Fatalf("err=%v", err)
	}
}

func TestRefreshFromInfo(t *testing.T) {
	c := cfg(t, "http://x")
	tr := NewTracker(c)
	tr.Seed([]Status{{Provider: "lite", Spend: 10, Max: 50, HasMax: true}})
	tr.Record("lite", llm.Cost{KeySpend: 10, KeyMax: 50, HasKey: true})
	if u := tr.Used(); len(u) != 1 || u[0] != "lite" {
		t.Fatalf("used: %v", u)
	}
	if ex := tr.Refresh([]Status{{Provider: "lite", Spend: 10.2, Max: 50, HasMax: true}}); len(ex) != 0 {
		t.Fatalf("écarté trop tôt: %v", ex)
	}
	l := tr.Summary()[0]
	if !l.Reported || l.RunCost < 0.19 || l.RunCost > 0.21 {
		t.Fatalf("coût via /key/info: %+v", l)
	}
	ex := tr.Refresh([]Status{{Provider: "lite", Spend: 10.6, Max: 50, HasMax: true}})
	if len(ex) != 1 || !strings.Contains(ex[0].Reason, "max_run_cost") || tr.Exhausted("lite") == "" {
		t.Fatalf("max_run_cost via /key/info: %v", ex)
	}
	if ex := tr.Refresh([]Status{{Provider: "lite", Spend: 10.7, Max: 50, HasMax: true}}); len(ex) != 0 {
		t.Fatal("écartement signalé deux fois")
	}
}
