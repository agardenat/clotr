package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/testutil"
	"github.com/agardenat/clotr/internal/tools"
)

func registry(concurrent *int32, peak *int32) *tools.Registry {
	r := tools.NewRegistry(1000)
	r.Add(testutil.FakeTool{ToolName: "k8s_list", Fn: func(ctx context.Context, args json.RawMessage) (string, error) {
		n := atomic.AddInt32(concurrent, 1)
		for {
			p := atomic.LoadInt32(peak)
			if n <= p || atomic.CompareAndSwapInt32(peak, p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(concurrent, -1)
		return "pods: " + string(args), nil
	}})
	return r
}

func runner(chat llm.Chatter, reg *tools.Registry) *Runner {
	return &Runner{Chat: chat, Tools: reg, Audit: audit.Nop(), Events: progress.Nop{}, MaxSteps: 3, Attempts: 2, Backoff: time.Millisecond}
}

var models = []catalog.ModelInfo{{Provider: "p", ID: "a"}, {Provider: "p", ID: "b"}}

func TestToolLoopParallel(t *testing.T) {
	var cur, peak int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		last := req.Messages[len(req.Messages)-1]
		if last.Role == "user" {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"}), testutil.Call("k8s_list<|channel|>commentary", map[string]string{"ns": "b"}), testutil.Call("rm_rf", nil)), nil
		}
		return testutil.Reply("<think>hmm</think>{\"findings\":[\"ok\"]}"), nil
	}}
	out, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models})
	if err != nil {
		t.Fatal(err)
	}
	if out.Content != `{"findings":["ok"]}` || out.ToolCalls != 3 || out.Model != "p/a" {
		t.Fatalf("%+v", out)
	}
	if peak < 2 {
		t.Errorf("tool calls non parallèles (pic %d)", peak)
	}
	msgs := chat.Calls[1].Messages
	tc := msgs[2].ToolCalls
	if tc[0].ID == "" || msgs[3].ToolCallID != tc[0].ID || !strings.Contains(msgs[3].Content, `"ns":"a"`) {
		t.Fatalf("messages outils: %+v", msgs)
	}
	if tc[1].Function.Name != "k8s_list" || !strings.Contains(msgs[4].Content, `"ns":"b"`) {
		t.Fatalf("nom d'outil non nettoyé: %q → %q", tc[1].Function.Name, msgs[4].Content)
	}
	if !strings.Contains(msgs[5].Content, "ERREUR") {
		t.Errorf("outil hors scope non refusé: %q", msgs[5].Content)
	}
}

func TestFallback(t *testing.T) {
	var cur, peak int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if req.Model == "a" {
			return nil, &llm.APIError{Status: 429}
		}
		return testutil.Reply("done"), nil
	}}
	out, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "t", Candidates: models})
	if err != nil || out.Model != "p/b" || len(chat.Calls) != 3 {
		t.Fatalf("out=%+v err=%v calls=%d", out, err, len(chat.Calls))
	}
}

func TestFailoverWrapsAroundAndRetriesRound(t *testing.T) {
	var cur, peak int32
	var n atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		call := n.Add(1)
		switch {
		case req.Model == "a" && call <= 2:
			return nil, &llm.APIError{Status: 429}
		case req.Model == "b" && call <= 4:
			return testutil.Reply("", testutil.Call("k8s_list", nil)), nil
		case req.Model == "b":
			return nil, &llm.APIError{Status: 429}
		case req.Model == "a" && call <= 6:
			return nil, &llm.APIError{Status: 503}
		}
		return testutil.Reply("fini"), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.MaxSteps = 5
	r.Attempts = 1
	r.RoundPause = time.Millisecond
	out, err := r.Run(context.Background(), Spec{TaskID: "t", Tools: []string{"k8s_list"}, Candidates: models})
	if err != nil || out.Content != "fini" || out.Model != "p/a" {
		t.Fatalf("out=%+v err=%v appels=%d", out, err, n.Load())
	}
}

func TestNoFailoverOnAuth(t *testing.T) {
	var cur, peak int32
	chat := &testutil.FakeChat{Fn: func(context.Context, string, llm.Request) (*llm.Response, error) {
		return nil, &llm.APIError{Status: 401}
	}}
	_, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "t", Candidates: models})
	if err == nil || len(chat.Calls) != 1 {
		t.Fatalf("err=%v calls=%d", err, len(chat.Calls))
	}
}

func TestMaxSteps(t *testing.T) {
	var cur, peak int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Tools) == 0 {
			return testutil.Reply("conclusion"), nil
		}
		return testutil.Reply("", testutil.Call("k8s_list", nil)), nil
	}}
	out, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "t", Tools: []string{"k8s_list"}, Candidates: models})
	if err != nil || out.Content != "conclusion" || len(chat.Calls) != 4 {
		t.Fatalf("out=%+v err=%v calls=%d", out, err, len(chat.Calls))
	}
	last := chat.Calls[3]
	if len(last.Tools) != 0 || !strings.Contains(last.Messages[len(last.Messages)-1].Content, "Limite") {
		t.Fatal("dernier appel devrait être sans outils avec consigne de conclusion")
	}
}

func TestQuotaRetriedEachRun(t *testing.T) {
	var cur, peak int32
	var calls atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if req.Model == "a" {
			calls.Add(1)
			return nil, &llm.APIError{Status: 429, Body: "INSUFFICIENT QUOTA"}
		}
		return testutil.Reply("done"), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	for i := 0; i < 3; i++ {
		out, err := r.Run(context.Background(), Spec{TaskID: "t", Candidates: models})
		if err != nil || out.Model != "p/b" {
			t.Fatalf("run %d: %+v %v", i, out, err)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("modèle en 429 appelé %d fois, attendu 6 (2 tentatives x 3 runs, jamais écarté)", calls.Load())
	}
}

func TestNotFoundDownForRun(t *testing.T) {
	var cur, peak int32
	var calls atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if req.Model == "a" {
			calls.Add(1)
			return nil, &llm.APIError{Status: 404, Body: "model not found"}
		}
		return testutil.Reply("done"), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	for i := 0; i < 3; i++ {
		if _, err := r.Run(context.Background(), Spec{TaskID: "t", Candidates: models}); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("modèle 404 appelé %d fois, attendu 1", calls.Load())
	}
}

func TestBudgetExhaustion(t *testing.T) {
	cfg, err := config.Parse([]byte("providers:\n  - {name: p, base_url: http://x, budget: {max_run_cost: 0.1}}\n  - {name: q, base_url: http://y}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, provider string, req llm.Request) (*llm.Response, error) {
		r := testutil.Reply("ok " + provider)
		if provider == "p" {
			calls.Add(1)
			r.Cost = llm.Cost{Reported: true, Response: 0.06}
		}
		return r, nil
	}}
	var cur, peak int32
	run := runner(chat, registry(&cur, &peak))
	run.Budget = budget.NewTracker(cfg)
	cands := []catalog.ModelInfo{{Provider: "p", ID: "a"}, {Provider: "q", ID: "b"}}
	var models []string
	for i := 0; i < 3; i++ {
		out, err := run.Run(context.Background(), Spec{TaskID: "t", Candidates: cands})
		if err != nil {
			t.Fatal(err)
		}
		models = append(models, out.Model)
	}
	if strings.Join(models, ",") != "p/a,p/a,q/b" || calls.Load() != 2 {
		t.Fatalf("modèles %v, appels p=%d", models, calls.Load())
	}
	_, err = run.Run(context.Background(), Spec{TaskID: "t", Candidates: cands[:1]})
	if err == nil || !strings.Contains(err.Error(), "aucun modèle disponible") {
		t.Fatalf("err=%v", err)
	}
}

type recBoundary struct {
	out, in atomic.Int32
}

func (b *recBoundary) Outbound(_ catalog.ModelInfo, msgs []llm.Message) []llm.Message {
	b.out.Add(1)
	cp := append([]llm.Message(nil), msgs...)
	cp[len(cp)-1].Content = "ANON"
	return cp
}

func (b *recBoundary) Inbound(_ catalog.ModelInfo, msg llm.Message) llm.Message {
	b.in.Add(1)
	msg.Content = strings.ReplaceAll(msg.Content, "TOKEN", "réel")
	return msg
}

func TestBoundaryOnlyForNonSovereign(t *testing.T) {
	var cur, peak int32
	var seen []string
	var mu sync.Mutex
	chat := &testutil.FakeChat{Fn: func(_ context.Context, provider string, req llm.Request) (*llm.Response, error) {
		mu.Lock()
		seen = append(seen, provider+":"+req.Messages[len(req.Messages)-1].Content)
		mu.Unlock()
		return testutil.Reply("valeur TOKEN"), nil
	}}
	b := &recBoundary{}
	r := runner(chat, registry(&cur, &peak))
	r.Boundary = b
	out, _ := r.Run(context.Background(), Spec{TaskID: "t", User: "secret", Candidates: []catalog.ModelInfo{{Provider: "sov", ID: "a", Sovereign: true}}})
	if out.Content != "valeur TOKEN" || b.out.Load() != 0 || !out.Sovereign {
		t.Fatalf("souverain: %+v out=%d", out, b.out.Load())
	}
	out, _ = r.Run(context.Background(), Spec{TaskID: "t", User: "secret", Candidates: []catalog.ModelInfo{{Provider: "ext", ID: "b"}}})
	if out.Content != "valeur réel" || b.out.Load() != 1 || b.in.Load() != 1 || out.Sovereign {
		t.Fatalf("non souverain: %+v", out)
	}
	if seen[0] != "sov:secret" || seen[1] != "ext:ANON" {
		t.Fatalf("messages envoyés: %v", seen)
	}
}

func TestCostEstimatedFromUsage(t *testing.T) {
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: http://x, budget: {max_run_cost: 1}}\n"))
	chat := &testutil.FakeChat{Fn: func(context.Context, string, llm.Request) (*llm.Response, error) {
		r := testutil.Reply("ok")
		r.Usage = llm.Usage{PromptTokens: 1000, CompletionTokens: 100}
		return r, nil
	}}
	var cur, peak int32
	run := runner(chat, registry(&cur, &peak))
	run.Budget = budget.NewTracker(cfg)
	out, err := run.Run(context.Background(), Spec{TaskID: "t", Candidates: []catalog.ModelInfo{{Provider: "p", ID: "a", InputCost: 1e-6, OutputCost: 1e-5}}})
	if err != nil || out.Cost < 0.00199 || out.Cost > 0.00201 {
		t.Fatalf("coût estimé: %v %v", out.Cost, err)
	}
	if l := run.Budget.Summary(); len(l) != 1 || !l[0].Estimated || !strings.Contains(l[0].String(), "~0.0020") {
		t.Fatalf("résumé: %+v", l)
	}
}

func TestConcludeBeforeDeadline(t *testing.T) {
	var cur, peak int32
	var finalSeen atomic.Bool
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Tools) == 0 {
			finalSeen.Store(strings.Contains(req.Messages[len(req.Messages)-1].Content, "Temps presque écoulé"))
			return testutil.Reply(`{"findings":["partiel"],"gaps":["reste"]}`), nil
		}
		return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.MaxSteps = 50
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := r.Run(ctx, Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models, Deadline: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Limited || out.Steps != 2 || !finalSeen.Load() {
		t.Fatalf("conclusion anticipée absente: %+v", out)
	}
}

func TestConcludeAnticipatesStepDuration(t *testing.T) {
	var cur, peak int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Tools) == 0 {
			return testutil.Reply(`{"findings":["partiel"]}`), nil
		}
		time.Sleep(100 * time.Millisecond)
		return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.MaxSteps = 50
	out, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models, Deadline: time.Now().Add(150 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Limited || out.Steps != 2 {
		t.Fatalf("une étape qui dépasserait le délai a été lancée: %+v", out)
	}
}

func TestEvidencePrefix(t *testing.T) {
	var cur, peak int32
	var seen string
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		last := req.Messages[len(req.Messages)-1]
		if last.Role == "user" {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
		}
		seen = last.Content
		return testutil.Reply(`{"findings":["ok [E001]"]}`), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.Evidence = evidence.Open(t.TempDir(), 1)
	if _, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(seen, "[E001] pods:") || r.Evidence.Len() != 1 {
		t.Fatalf("sortie d'outil: %q", seen)
	}
}

func TestEvidenceKeepsFullOutput(t *testing.T) {
	full := strings.Repeat("ligne\n", 300) + "StandardNVADSA10v5Family"
	reg := tools.NewRegistry(1000)
	reg.Add(testutil.FakeTool{ToolName: "az_get", Fn: func(context.Context, json.RawMessage) (string, error) { return full, nil }})
	var seen string
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		last := req.Messages[len(req.Messages)-1]
		if last.Role == "user" {
			return testutil.Reply("", testutil.Call("az_get", map[string]string{"id": "x"})), nil
		}
		seen = last.Content
		return testutil.Reply(`{"findings":["ok [E001]"]}`), nil
	}}
	r := runner(chat, reg)
	dir := t.TempDir()
	r.Evidence = evidence.Open(dir, 1)
	if _, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"az_get"}, Candidates: models}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seen, "StandardNVADSA10v5Family") || !strings.Contains(seen, "evidence_read id=E001") {
		t.Fatalf("sortie vue par le modèle: %q", seen)
	}
	data, err := os.ReadFile(filepath.Join(dir, "E001.txt"))
	if err != nil || !strings.HasSuffix(string(data), full) {
		t.Fatalf("preuve tronquée: %v", err)
	}
}

func TestInboxDeliveredAtNextStep(t *testing.T) {
	var cur, peak int32
	var got []string
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		last := req.Messages[len(req.Messages)-1]
		if len(req.Messages) == 2 {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
		}
		got = append(got, last.Content)
		return testutil.Reply(`{"findings":["ok [E001]"]}`), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.Evidence = evidence.Open(t.TempDir(), 1)
	calls := 0
	r.Inbox = func(c tools.Caller) string {
		calls++
		if c.Task != "t1" || c.Model != "p/a" {
			t.Errorf("lecteur: %+v", c)
		}
		if calls == 1 {
			return "- t9 : [cause établie] AllocationFailed [E001]"
		}
		return ""
	}
	if _, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(got) != 1 || !strings.Contains(got[0], "AllocationFailed") || !strings.Contains(got[0], "Ne refais pas leur collecte") {
		t.Fatalf("boîte de réception: %d appels, %q", calls, got)
	}
}

func TestConcludeNowEndsTask(t *testing.T) {
	var cur, peak int32
	var r *Runner
	var final llm.Request
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Messages) == 2 {
			r.ConcludeNow()
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
		}
		final = req
		return testutil.Reply(`{"findings":["ok [E001]"]}`), nil
	}}
	r = runner(chat, registry(&cur, &peak))
	r.MaxSteps = 10
	r.Evidence = evidence.Open(t.TempDir(), 1)
	out, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models})
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Tools) != 0 || !strings.Contains(final.Messages[len(final.Messages)-1].Content, "conclure maintenant") || !out.Limited || out.Limit != "interrupted" || out.Steps != 2 {
		t.Fatalf("conclusion: tools=%d limit=%q steps=%d", len(final.Tools), out.Limit, out.Steps)
	}
}

func TestReachedEndsTaskWithoutLimit(t *testing.T) {
	var cur, peak int32
	var final llm.Request
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Messages) == 2 {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"ns": "a"})), nil
		}
		final = req
		return testutil.Reply(`{"findings":["ok [E001]"]}`), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.MaxSteps = 10
	r.Evidence = evidence.Open(t.TempDir(), 1)
	out, err := r.Run(context.Background(), Spec{TaskID: "t0", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models, Reached: func() string { return "objectif atteint, conclus" }})
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Tools) != 0 || final.Messages[len(final.Messages)-1].Content != "objectif atteint, conclus" || out.Limited || out.Steps != 2 {
		t.Fatalf("fin sur objectif: tools=%d limited=%v steps=%d", len(final.Tools), out.Limited, out.Steps)
	}
}

func TestResumeTruncatedAnswer(t *testing.T) {
	var calls atomic.Int32
	var maxTokens atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		maxTokens.Store(int32(req.MaxTokens))
		resp := testutil.Reply(`{"findings":["début`)
		if calls.Add(1) == 2 {
			last := req.Messages[len(req.Messages)-1]
			if !strings.Contains(last.Content, "coupée") || req.Messages[len(req.Messages)-2].Role != "assistant" {
				t.Errorf("relance: %+v", last)
			}
			return testutil.Reply(` et fin"]}`), nil
		}
		resp.Choices[0].FinishReason = "length"
		return resp, nil
	}}
	var cur, peak int32
	r := runner(chat, registry(&cur, &peak))
	cands := []catalog.ModelInfo{{Provider: "p", ID: "m", MaxOutput: 64000}}
	out, err := r.Run(context.Background(), Spec{TaskID: "synthesizer", System: "s", User: "u", Candidates: cands})
	if err != nil {
		t.Fatal(err)
	}
	if out.Content != `{"findings":["début et fin"]}` || calls.Load() != 2 || maxTokens.Load() != maxOutputTokens {
		t.Fatalf("reprise: %q, %d appels, max_tokens %d", out.Content, calls.Load(), maxTokens.Load())
	}
}

func TestSwitchModelWhenOutputExhausted(t *testing.T) {
	var models []string
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		models = append(models, req.Model)
		if req.Model == "thinker" {
			resp := testutil.Reply("<think>long raisonnement</think>")
			resp.Choices[0].FinishReason = "length"
			return resp, nil
		}
		return testutil.Reply("# Rapport"), nil
	}}
	var cur, peak int32
	r := runner(chat, registry(&cur, &peak))
	cands := []catalog.ModelInfo{{Provider: "p", ID: "thinker", MaxOutput: 16384}, {Provider: "p", ID: "writer", MaxOutput: 16384}}
	out, err := r.Run(context.Background(), Spec{TaskID: "synthesizer", System: "s", User: "u", Candidates: cands})
	if err != nil {
		t.Fatal(err)
	}
	if out.Content != "# Rapport" || strings.Join(models, ",") != "thinker,writer" || out.Model != "p/writer" {
		t.Fatalf("bascule: %q, modèles %v, %s", out.Content, models, out.Model)
	}
}

func TestHistoryCompactionAndNotes(t *testing.T) {
	reg := tools.NewRegistry(100000)
	reg.Add(testutil.FakeTool{ToolName: "big", Fn: func(context.Context, json.RawMessage) (string, error) {
		return strings.Repeat("ligne de log très longue\n", 400), nil
	}})
	var seen [][]llm.Message
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		seen = append(seen, append([]llm.Message(nil), req.Messages...))
		if len(req.Tools) == 0 {
			return testutil.Reply(`{"findings":["ok"]}`), nil
		}
		return testutil.Reply("", testutil.Call("big", nil)), nil
	}}
	r := runner(chat, reg)
	r.MaxSteps = 4
	r.KeepSteps, r.ToolChars = 2, 300
	r.Evidence = evidence.Open(t.TempDir(), 1)
	r.ConcludeNotes = func(task string) string { return "- note de " + task }
	if _, err := r.Run(context.Background(), Spec{TaskID: "t1", System: "s", User: "u", Tools: []string{"big"}, Candidates: models}); err != nil {
		t.Fatal(err)
	}
	last := seen[len(seen)-1]
	first, recent := last[3].Content, last[len(last)-2].Content
	if !strings.HasPrefix(first, "[E001] ") || !strings.Contains(first, "evidence_read id=E001") || len(first) > 500 {
		t.Errorf("sortie ancienne non raccourcie (%d car.): %.120q", len(first), first)
	}
	if strings.Contains(recent, "raccourcie") {
		t.Errorf("sortie récente raccourcie")
	}
	if c := last[len(last)-1].Content; !strings.Contains(c, "Limite") || !strings.Contains(c, "note de t1") {
		t.Errorf("conclusion sans notes: %q", c)
	}
}

func TestEmptyFinalAnswerRetried(t *testing.T) {
	var n atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if n.Add(1) == 1 {
			return testutil.Reply(""), nil
		}
		if !strings.Contains(req.Messages[len(req.Messages)-1].Content, "aucun texte") {
			t.Errorf("relance sans consigne: %+v", req.Messages[len(req.Messages)-1])
		}
		return testutil.Reply(`{"findings":["ok"]}`), nil
	}}
	var cur, peak int32
	out, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "t", System: "s", User: "u", Candidates: models})
	if err != nil || out.Content != `{"findings":["ok"]}` || n.Load() != 2 {
		t.Fatalf("out=%+v err=%v appels=%d", out, err, n.Load())
	}
}

func TestStallEndsTaskWithoutProgress(t *testing.T) {
	var cur, peak int32
	var n atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if len(req.Tools) == 0 {
			return testutil.Reply(`{"findings":["fin"]}`), nil
		}
		if n.Add(1) <= 3 {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]any{"ns": fmt.Sprint(n.Load())})), nil
		}
		return testutil.Reply("", testutil.Call("k8s_list", map[string]any{"ns": "3"})), nil
	}}
	r := runner(chat, registry(&cur, &peak))
	r.MaxSteps, r.StallSteps = 100, 2
	out, err := r.Run(context.Background(), Spec{TaskID: "t", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models})
	if err != nil || out.Limit != "stall" || out.Steps != 6 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCheckRejectsThenAccepts(t *testing.T) {
	var cur, peak int32
	var n atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if n.Add(1) == 1 {
			return testutil.Reply(`{"verdicts":[{"n":1}`), nil
		}
		if !strings.Contains(req.Messages[len(req.Messages)-1].Content, "manque") {
			t.Errorf("relance sans le problème: %+v", req.Messages[len(req.Messages)-1])
		}
		return testutil.Reply(`ok complet`), nil
	}}
	check := func(c string) string {
		if c != "ok complet" {
			return "il manque des verdicts"
		}
		return ""
	}
	out, err := runner(chat, registry(&cur, &peak)).Run(context.Background(), Spec{TaskID: "v", System: "s", User: "u", Candidates: models, Check: check})
	if err != nil || out.Content != "ok complet" || n.Load() != 2 {
		t.Fatalf("out=%+v err=%v appels=%d", out, err, n.Load())
	}
}

func TestLiveText(t *testing.T) {
	var calls atomic.Int32
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if calls.Add(1) == 1 {
			req.OnContent("je regarde")
			return testutil.Reply("je regarde", testutil.Call("k8s_list", map[string]string{"r": "pods"})), nil
		}
		for _, d := range []string{"<think>calcul", "</think>## Ré", "ponse"} {
			req.OnContent(d)
		}
		return testutil.Reply("<think>calcul</think>## Réponse"), nil
	}}
	var cur, peak int32
	var mu sync.Mutex
	var shown []string
	r := runner(chat, registry(&cur, &peak))
	out, err := r.Run(context.Background(), Spec{TaskID: "direct", System: "s", User: "u", Tools: []string{"k8s_list"}, Candidates: models[:1], OnText: func(s string) {
		mu.Lock()
		shown = append(shown, s)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", "je regarde", "", "", "## Ré", "## Réponse"}
	if out.Content != "## Réponse" || strings.Join(shown, "|") != strings.Join(want, "|") {
		t.Fatalf("texte affiché: %q (réponse %q)", shown, out.Content)
	}
}

func TestLeakedToolCalls(t *testing.T) {
	defs := []llm.ToolDef{{Type: "function", Function: llm.FunctionDef{Name: "prod_get"}}}
	content := "<|start|>assistant<|channel|>commentary to=functions.prod_get{\n  \"target\": \"cm\",\n  \"query\": {\"view\": \"full\"}\n}<|call|>"
	calls := leakedToolCalls(content, defs)
	if len(calls) != 1 || calls[0].Function.Name != "prod_get" || !strings.Contains(calls[0].Function.Arguments, `"view": "full"`) {
		t.Fatalf("%+v", calls)
	}
	if got := leakedToolCalls("commentary to=functions.inconnu{\"a\":1}<|call|>", defs); len(got) != 0 {
		t.Fatalf("outil inconnu converti: %+v", got)
	}
	if got := leakedToolCalls(`{"findings":["to=functions.prod_get est cité"]}`, defs); len(got) != 0 {
		t.Fatalf("texte de constat converti: %+v", got)
	}
}

func TestOutputExhaustedWithoutAlternativeFailsFast(t *testing.T) {
	var models []string
	chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		models = append(models, req.Model)
		resp := testutil.Reply("<think>long raisonnement</think>")
		resp.Choices[0].FinishReason = "length"
		resp.Usage.CompletionTokens = 16384
		return resp, nil
	}}
	var cur, peak int32
	r := runner(chat, registry(&cur, &peak))
	for _, cands := range [][]catalog.ModelInfo{
		{{Provider: "p", ID: "thinker", MaxOutput: 16384}},
		{{Provider: "p", ID: "thinker", MaxOutput: 16384}, {Provider: "p", ID: "other", MaxOutput: 16384}},
	} {
		models = nil
		_, err := r.Run(context.Background(), Spec{TaskID: "synthesizer", System: "s", User: "u", Candidates: cands})
		if err == nil || !strings.Contains(err.Error(), "16384 tokens") {
			t.Fatalf("%d candidats : erreur attendue, %v", len(cands), err)
		}
		if len(models) != len(cands) {
			t.Fatalf("%d candidats : appels %v, un par modèle attendu", len(cands), models)
		}
	}
}

func TestPersistentRetryOnTransientErrors(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		var calls atomic.Int32
		chat := &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
			if calls.Add(1) <= 7 {
				return nil, &llm.APIError{Status: 429, Body: "INSUFFICIENT QUOTA"}
			}
			return testutil.Reply("# Rapport"), nil
		}}
		r := runner(chat, tools.NewRegistry(100))
		r.Attempts, r.RoundPause = 1, time.Millisecond
		r.Persistent = func(p string) bool { return persistent && p == "sov" }
		out, err := r.Run(context.Background(), Spec{TaskID: "synthesizer", System: "s", User: "u", Candidates: []catalog.ModelInfo{{Provider: "sov", ID: "m"}}})
		switch {
		case persistent && (err != nil || out.Content != "# Rapport" || calls.Load() != 8):
			t.Fatalf("persistent_retry : %v %q, %d appels", err, out.Content, calls.Load())
		case !persistent && (err == nil || calls.Load() != 2):
			t.Fatalf("sans persistent_retry : 2 tours attendus, %v, %d appels", err, calls.Load())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	chat := &testutil.FakeChat{Fn: func(context.Context, string, llm.Request) (*llm.Response, error) {
		cancel()
		return nil, &llm.APIError{Status: 503}
	}}
	r := runner(chat, tools.NewRegistry(100))
	r.RoundPause, r.Persistent = time.Hour, func(string) bool { return true }
	if _, err := r.Run(ctx, Spec{TaskID: "t", System: "s", User: "u", Candidates: models}); !errors.Is(err, context.Canceled) {
		t.Fatalf("interruption pendant la pause: %v", err)
	}
}
