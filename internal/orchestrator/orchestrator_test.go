package orchestrator

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/router"
	"github.com/agardenat/clotr/internal/testutil"
	"github.com/agardenat/clotr/internal/tools"
)

var taskID = regexp.MustCompile(`Ta tâche \(([^)]+)\)`)

const workDelay = 150 * time.Millisecond

type timeline struct {
	mu    sync.Mutex
	start map[string]time.Time
	end   map[string]time.Time
	input map[string]string
}

func newOrch(t *testing.T, plans []string, fail map[string]bool) (*Orchestrator, *timeline) {
	cfg, err := config.Parse([]byte(`
providers:
  - {name: p, base_url: http://x}
roles:
  planner: {tier: deep}
  collector: {tier: fast, tools: true}
  thinker: {tier: balanced}
  synthesizer: {tier: deep}
limits: {max_agents: 8, max_tasks: 5}
`))
	if err != nil {
		t.Fatal(err)
	}
	cat := &catalog.Catalog{Models: []catalog.ModelInfo{
		{Provider: "p", ID: "small", Tier: "fast", Tools: true},
		{Provider: "p", ID: "big", Tier: "deep", Tools: true},
	}}
	rt, _ := router.New(cfg, cat, nil, "")
	reg := tools.NewRegistry(1000)
	reg.Add(testutil.FakeTool{ToolName: "k8s_list", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }})
	reg.Add(testutil.FakeTool{ToolName: "fs_read", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }})
	tl := &timeline{start: map[string]time.Time{}, end: map[string]time.Time{}, input: map[string]string{}}
	var planIdx int
	var pmu sync.Mutex
	chat := &testutil.FakeChat{Fn: func(ctx context.Context, _ string, req llm.Request) (*llm.Response, error) {
		sys := req.Messages[0].Content
		user := req.Messages[1].Content
		switch {
		case strings.Contains(sys, "planificateur"):
			pmu.Lock()
			defer pmu.Unlock()
			p := plans[min(planIdx, len(plans)-1)]
			planIdx++
			return testutil.Reply(p), nil
		case strings.Contains(sys, "réponse finale"):
			return testutil.Reply("# Rapport"), nil
		}
		id := taskID.FindStringSubmatch(user)[1]
		tl.mu.Lock()
		tl.start[id] = time.Now()
		tl.input[id] = user
		tl.mu.Unlock()
		select {
		case <-time.After(workDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		tl.mu.Lock()
		tl.end[id] = time.Now()
		tl.mu.Unlock()
		if fail[id] {
			return nil, &llm.APIError{Status: 401, Body: "denied"}
		}
		return testutil.Reply(`{"findings":["[INFO] ` + id + ` vu"],"evidence":["e"],"gaps":[]}`), nil
	}}
	runner := &agent.Runner{Chat: chat, Tools: reg, Audit: audit.Nop(), Events: progress.Nop{}, MaxSteps: 3, Attempts: 1}
	mem := memory.NewStore()
	reg.Add(mem.Tools()...)
	return &Orchestrator{Cfg: cfg, Router: rt, Runner: runner, Tools: reg, Audit: audit.Nop(), Events: progress.Nop{}, Memory: mem}, tl
}

const dagPlan = "```json\n" + `{"tasks":[
 {"id":"t1","role":"collector","goal":"g1","tools":["k8s"]},
 {"id":"t2","role":"collector","goal":"g2","tools":["k8s_list"]},
 {"id":"t3","role":"collector","goal":"g3"},
 {"id":"t4","role":"thinker","goal":"g4","depends_on":["t1","t2"]}
]}` + "\n```"

func TestParallelDAG(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	t0 := time.Now()
	rep, err := o.Run(context.Background(), "analyse")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(t0)
	if elapsed > 3*workDelay {
		t.Errorf("exécution non parallèle: %v", elapsed)
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		if tl.start[id].Sub(t0) > workDelay/2 {
			t.Errorf("%s démarré tardivement", id)
		}
	}
	if tl.start["t4"].Before(tl.end["t1"]) || tl.start["t4"].Before(tl.end["t2"]) {
		t.Error("t4 démarré avant ses dépendances")
	}
	if !strings.Contains(tl.input["t4"], "t1 vu") || !strings.Contains(tl.input["t4"], "t2 vu") {
		t.Errorf("résultats des dépendances absents: %s", tl.input["t4"])
	}
	if rep.Markdown != "# Rapport" || len(rep.Results) != 4 {
		t.Fatalf("%+v", rep)
	}
	if got := strings.Join(rep.Plan.Tasks[1].Tools, ","); got != "k8s_list,memory_write,memory_search" {
		t.Errorf("outils mémoire non ajoutés: %s", got)
	}
	if st := o.Memory.Stats(); st.Entries != 4 {
		t.Errorf("constats non versés en mémoire: %+v", st)
	}
	if got := strings.Join(rep.Plan.Tasks[2].Tools, ","); got != "k8s_list,fs_read,memory_write,memory_search" {
		t.Errorf("outils par défaut: %s", got)
	}
	if rep.Results[0].Model != "p/small" || rep.Results[3].Model != "p/big" {
		t.Errorf("routage: %s %s", rep.Results[0].Model, rep.Results[3].Model)
	}
}

func TestFailureIsolation(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, map[string]bool{"t2": true})
	rep, err := o.Run(context.Background(), "analyse")
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range rep.Results {
		status[r.TaskID] = r.Status
	}
	if status["t2"] != "failed" || status["t1"] != "ok" || status["t3"] != "ok" || status["t4"] != "ok" {
		t.Fatalf("statuts: %v", status)
	}
	if rep.Markdown == "" {
		t.Fatal("synthèse absente")
	}
}

func TestPlanRetryAndValidation(t *testing.T) {
	o, _ := newOrch(t, []string{"pas de json", `{"tasks":[{"id":"t1","role":"collector","goal":"g"}]}`}, nil)
	p, err := o.Plan(context.Background(), "x")
	if err != nil || len(p.Tasks) != 1 {
		t.Fatalf("retry: %v %+v", err, p)
	}
	cases := map[string]string{
		`{"tasks":[]}`: "aucune tâche",
		`{"tasks":[{"id":"a","role":"planner","goal":"g"}]}`:                                                                                  "rôle",
		`{"tasks":[{"id":"a","role":"collector","goal":"g","tools":["nope"]}]}`:                                                               "outil inconnu",
		`{"tasks":[{"id":"a","role":"thinker","goal":"g","tools":["k8s"]}]}`:                                                                  "n'utilise pas",
		`{"tasks":[{"id":"a","role":"collector","goal":"g","depends_on":["z"]}]}`:                                                             "dépendance",
		`{"tasks":[{"id":"a","role":"collector","goal":"g","depends_on":["b"]},{"id":"b","role":"collector","goal":"g","depends_on":["a"]}]}`: "cycle",
		`{"tasks":[{"id":"a","role":"collector","goal":"g"},{"id":"a","role":"collector","goal":"g"}]}`:                                       "dupliqué",
	}
	for in, want := range cases {
		var p Plan
		if err := ExtractJSON(in, &p); err != nil {
			t.Fatal(err)
		}
		if err := o.Validate(&p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, attendu %q", in, err, want)
		}
	}
}

func TestAllFailed(t *testing.T) {
	o, _ := newOrch(t, []string{`{"tasks":[{"id":"t1","role":"collector","goal":"g"}]}`}, map[string]bool{"t1": true})
	if _, err := o.Run(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "toutes les tâches") {
		t.Fatalf("err=%v", err)
	}
}

func TestCancel(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), workDelay/3)
	defer cancel()
	t0 := time.Now()
	_, err := o.Run(ctx, "x")
	if err == nil || time.Since(t0) > workDelay*2 {
		t.Fatalf("annulation: err=%v durée=%v", err, time.Since(t0))
	}
}

func TestLanguageDirective(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, nil)
	var systems []string
	var mu sync.Mutex
	inner := o.Runner.Chat.(*testutil.FakeChat).Fn
	o.Runner.Chat.(*testutil.FakeChat).Fn = func(ctx context.Context, p string, req llm.Request) (*llm.Response, error) {
		mu.Lock()
		systems = append(systems, req.Messages[0].Content)
		mu.Unlock()
		return inner(ctx, p, req)
	}
	o.Language = "en"
	if _, err := o.Run(context.Background(), "état du cluster"); err != nil {
		t.Fatal(err)
	}
	for _, sys := range systems {
		if !strings.Contains(sys, "in English, whatever the language of the request") {
			t.Fatalf("consigne absente: %.200s", sys)
		}
	}
	o.Language = "auto"
	if !strings.Contains(o.langDirective(), "langue de la demande") {
		t.Fatal("auto")
	}
}

func TestContinuationBeforeDependents(t *testing.T) {
	plan := `{"tasks":[{"id":"t1","role":"collector","goal":"g1","tools":["k8s"]},{"id":"t2","role":"thinker","goal":"analyse","depends_on":["t1"]}]}`
	o, tl := newOrch(t, []string{plan}, nil)
	withToolFirst(o)
	rep, err := o.Run(context.Background(), "analyse")
	if err != nil {
		t.Fatal(err)
	}
	r1 := rep.Results[0]
	if r1.Continuations != 1 || r1.Status != "ok" || r1.Steps < 2 {
		t.Fatalf("suite non exécutée: %+v", r1)
	}
	if tl.start["t2"].Before(tl.end["t1.2"]) {
		t.Error("tâche dépendante démarrée avant la suite")
	}
	if !strings.Contains(tl.input["t1.2"], "Suite de la tâche t1") || !strings.Contains(tl.input["t1.2"], "t1 vu") {
		t.Errorf("entrée de la suite: %s", tl.input["t1.2"])
	}
	if len(rep.Results) != 2 {
		t.Errorf("résultats: %d", len(rep.Results))
	}
	zero := 0
	o2, _ := newOrch(t, []string{plan}, nil)
	withToolFirst(o2)
	o2.Cfg.Limits.Continuations = &zero
	rep2, _ := o2.Run(context.Background(), "analyse")
	if rep2.Results[0].Continuations != 0 {
		t.Error("suite exécutée malgré continuations=0")
	}
	if g := strings.Join(rep2.Results[0].Gaps, "\n"); rep2.Results[0].Limit != "max_steps" || !strings.Contains(g, "investigation incomplète") {
		t.Errorf("arrêt sur limite non signalé: %+v", rep2.Results[0])
	}
}

func withToolFirst(o *Orchestrator) {
	orig := o.Runner.Chat.(*testutil.FakeChat)
	o.Runner.MaxSteps = 1
	o.Runner.Chat = &testutil.FakeChat{Fn: func(ctx context.Context, p string, req llm.Request) (*llm.Response, error) {
		if len(req.Tools) > 0 && len(req.Messages) == 2 && !strings.Contains(req.Messages[0].Content, "planificateur") {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]any{})), nil
		}
		return orig.Fn(ctx, p, req)
	}}
}

func TestSynthInputCompact(t *testing.T) {
	in := synthInput([]Result{{TaskID: "t1", Role: "collector", Status: "ok", Goal: "g", Findings: []string{"[MAJEUR] disque 15 GiB [E012]"}, Evidence: []string{"[E012] prod_cm_events : texte long"}, Gaps: []string{"reste"}, Limited: true, Limit: "agent_timeout"}})
	if strings.Contains(in, "texte long") || !strings.Contains(in, "[E012]") || !strings.Contains(in, "arrêtée par agent_timeout") || !strings.Contains(in, "- reste") {
		t.Fatalf("entrée du synthesizer:\n%s", in)
	}
}

func TestWebToolsAndRule(t *testing.T) {
	o, _ := newOrch(t, nil, nil)
	if !strings.Contains(o.workerPrompt("collector"), "Recherche web non disponible") {
		t.Error("consigne sans recherche web absente")
	}
	o.Tools.Add(testutil.FakeTool{ToolName: "mcp_search_web_search", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }})
	o.WebTools = []string{"mcp_search_web_search"}
	p := Plan{Tasks: []Task{{ID: "a", Role: "collector", Goal: "g", Tools: []string{"k8s_list"}}}}
	if err := o.Validate(&p); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Tasks[0].Tools, "mcp_search_web_search") {
		t.Errorf("outil web non ajouté: %v", p.Tasks[0].Tools)
	}
	if w := o.workerPrompt("collector"); !strings.Contains(w, "Recherche web disponible") || !strings.Contains(w, "identifiant interne") || !strings.Contains(w, "Reste factuel") {
		t.Errorf("consigne web:\n%s", w)
	}
}

func TestExtractJSONRepairsCommonDefects(t *testing.T) {
	in := "{\"findings\":[\"grep -E 'ERROR\\s+Audit' sur C:\\data\",\"ligne 1\nligne 2\"],\"gaps\":[\"tab\there\"]}"
	var p struct {
		Findings []string `json:"findings"`
		Gaps     []string `json:"gaps"`
	}
	if err := ExtractJSON(in, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Findings) != 2 || p.Findings[0] != `grep -E 'ERROR\s+Audit' sur C:\data` || p.Findings[1] != "ligne 1\nligne 2" || p.Gaps[0] != "tab\there" {
		t.Fatalf("réparation: %q %q", p.Findings, p.Gaps)
	}
}

func TestExtractJSONClosesUnterminated(t *testing.T) {
	var p struct {
		Findings []string `json:"findings"`
		Gaps     []string `json:"gaps"`
	}
	for _, in := range []string{`{"findings":["a"],"gaps":["b"]`, `{"findings":["a {x}"],"gaps":["b"]`} {
		if err := ExtractJSON(in, &p); err != nil || len(p.Findings) != 1 || p.Gaps[0] != "b" {
			t.Fatalf("%s: %v %+v", in, err, p)
		}
	}
}

func TestMarkUnproven(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "prod_ssh_disk", `{}`, "/var 77%", nil)
	f := []string{"[MAJEUR] /var à 77 % [" + id + "]", "[MAJEUR] index sur le stockage partagé [#148]", "[INFO] cite une preuve inventée [E999]"}
	if n := markUnproven(ev, f); n != 2 || strings.HasPrefix(f[0], UnprovenTag) || !strings.HasPrefix(f[1], UnprovenTag) || !strings.HasPrefix(f[2], UnprovenTag) {
		t.Fatalf("%d %q", n, f)
	}
	if markUnproven(ev, f) != 0 {
		t.Fatal("double marquage")
	}
}

func TestFlagNoteBackedByEvidence(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "prod_ssh_disk", `{}`, "/var 77%", nil)
	out, n := flagNoteOnlyLines("- /var à 77 % [#290]", ev, map[string]string{"290": "df /var 77 % [" + id + "]"})
	if n != 0 || strings.Contains(out, "⚠") {
		t.Fatalf("note étayée signalée: %s", out)
	}
}

func TestFlagNoteOnlyLines(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "prod_ssh_disk", `{}`, "/var 77%", nil)
	md := "- /var à 77 % [" + id + "]\n- projection en 10 h [#290]\n- valeur notée (mémoire #72)\n- mixte [#290][" + id + "]\n- sans citation"
	out, n := flagNoteOnlyLines(md, ev, map[string]string{"72": "sans preuve"})
	lines := strings.Split(out, "\n")
	if n != 2 || strings.Contains(lines[0], "⚠") || !strings.Contains(lines[1], "⚠") || !strings.Contains(lines[2], "⚠") || strings.Contains(lines[3], "⚠") || strings.Contains(lines[4], "⚠") {
		t.Fatalf("%d\n%s", n, out)
	}
}

func TestVerifyMarksFindings(t *testing.T) {
	o, _ := newOrch(t, nil, nil)
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "prod_ssh_disk", `{}`, "/var 77%", nil)
	o.Runner.Evidence = ev
	o.Tools.Add(ev.Tool(), ev.SearchTool())
	var seen string
	o.Runner.Chat = &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		if !strings.Contains(req.Messages[0].Content, "vérificateur") {
			t.Fatalf("appel inattendu: %s", req.Messages[0].Content[:60])
		}
		seen = req.Messages[1].Content
		return testutil.Reply(`{"verdicts":[{"n":1,"verdict":"confirmé"},{"n":2,"verdict":"non étayé","raison":"aucune mention du stockage partagé dans ` + id + `"}]}`), nil
	}}
	results := []Result{{TaskID: "t1", Status: "ok", Goal: "g", Findings: []string{
		"[MAJEUR] /var à 77 % [" + id + "]",
		"[CRITIQUE] index sur le stockage partagé [" + id + "]",
		"[INFO] détail [" + id + "]",
	}}}
	o.Verify(context.Background(), results)
	f := results[0].Findings
	if !strings.HasPrefix(f[0], "[VÉRIFIÉ] [MAJEUR]") || !strings.HasPrefix(f[1], "[NON ÉTAYÉ : aucune mention du stockage partagé") || !strings.HasPrefix(f[2], "[INFO]") {
		t.Fatalf("verdicts: %q", f)
	}
	if strings.Contains(seen, "[INFO]") || !strings.Contains(seen, "2. [CRITIQUE]") {
		t.Fatalf("entrée du vérificateur: %s", seen)
	}
	if notes := o.Memory.All(); len(notes) == 0 || notes[len(notes)-1].Kind != "verification" {
		t.Fatalf("verdict non enregistré en mémoire: %+v", notes)
	}
}

func TestCheckVerdicts(t *testing.T) {
	if p := checkVerdicts(`{"verdicts":[{"n":1,"verdict":"Confirmée"},{"n":2,"verdict":"partielle","raison":"x"},{"n":3,"verdict":"non etayé"}]}`, 3); p != "" {
		t.Fatalf("variantes refusées: %s", p)
	}
	if p := checkVerdicts(`{"verdicts":[{"n":1,"verdict":"confirmé"},{"n":3,"verdict":"peut-être"}]}`, 3); !strings.Contains(p, "n° 2, 3") || !strings.Contains(p, `3 ("peut-être")`) {
		t.Fatalf("manquants: %s", p)
	}
	if p := checkVerdicts(`{"verdicts":[{"n":1,"verdict":"confirmé" "raison":"x"}]}`, 1); !strings.Contains(p, "JSON valide") {
		t.Fatalf("JSON invalide non signalé: %s", p)
	}
	if p := checkWorker(nil)(`<|channel|>commentary to=functions.prod_get{"path": "/clusters"}<|call|>`); !strings.Contains(p, "ni findings") {
		t.Fatalf("appel d'outil en texte accepté: %q", p)
	}
	if checkWorker(nil)(`{"findings":["a"]`) != "" || checkWorker(nil)("pas de json") == "" {
		t.Fatal("contrôle JSON des sous-agents")
	}
	ev := evidence.Open(t.TempDir(), 2)
	id := ev.Add("t1", "prod_metrics", `{}`, "load_1 0.1", nil)
	check := checkWorker(ev)
	if p := check(`{"findings":["[INFO] charge faible"],"evidence":["[` + id + `] load"]}`); !strings.Contains(p, "1. [INFO] charge faible") {
		t.Fatalf("constat sans citation accepté: %q", p)
	}
	if p := check(`{"findings":["[INFO] charge faible [` + id + `]"],"evidence":[]}`); p != "" {
		t.Fatalf("constat cité refusé: %q", p)
	}
}

func TestDirect(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, nil)
	o.Runner.Evidence = evidence.Open(t.TempDir(), 1)
	var mu sync.Mutex
	var systems []string
	o.Runner.Chat = &testutil.FakeChat{Fn: func(_ context.Context, _ string, req llm.Request) (*llm.Response, error) {
		mu.Lock()
		systems = append(systems, req.Messages[0].Content)
		mu.Unlock()
		if req.Messages[len(req.Messages)-1].Role != "tool" {
			return testutil.Reply("", testutil.Call("k8s_list", map[string]string{"resource": "nodes"})), nil
		}
		req.OnContent("3 nœuds Ready [E001].")
		return testutil.Reply("3 nœuds Ready [E001]."), nil
	}}
	var live []string
	o.OnAnswer = func(s string) { live = append(live, s) }
	rep, err := o.Direct(context.Background(), "combien de nœuds ?", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Plan.Tasks) != 1 || rep.Plan.Tasks[0].Role != "collector" || !slices.Contains(rep.Plan.Tasks[0].Tools, "k8s_list") {
		t.Fatalf("plan: %+v", rep.Plan)
	}
	if !strings.HasPrefix(rep.Markdown, "3 nœuds Ready [E001].") || !strings.Contains(rep.Markdown, "k8s_list") || rep.Results[0].Status != "ok" || rep.Results[0].ToolCalls != 1 {
		t.Fatalf("rapport: %+v\n%s", rep.Results, rep.Markdown)
	}
	if live[len(live)-1] != "3 nœuds Ready [E001]." {
		t.Fatalf("texte en direct: %q", live)
	}
	for _, s := range systems {
		if strings.Contains(s, "planificateur") || !strings.Contains(s, "sans planification") {
			t.Fatalf("prompt: %s", s)
		}
	}
	if r, err := o.DirectRole("thinker"); err != nil || r != "thinker" {
		t.Fatalf("rôle explicite: %s %v", r, err)
	}
	if _, err := o.DirectRole("planner"); err == nil {
		t.Fatal("planner accepté comme rôle direct")
	}
}

func TestPruneSameRoleDeps(t *testing.T) {
	p := &Plan{Tasks: []Task{
		{ID: "t1", Role: "collector"},
		{ID: "t2", Role: "collector", DependsOn: []string{"t1"}},
		{ID: "t3", Role: "analyst", DependsOn: []string{"t1", "t2"}},
	}}
	dropped := pruneSameRoleDeps(p)
	if len(dropped) != 1 || dropped["t2"][0] != "t1" || len(p.Tasks[1].DependsOn) != 0 || len(p.Tasks[2].DependsOn) != 2 || !strings.Contains(p.Tasks[1].Goal, "Les résultats de t1 ne te sont pas transmis") || strings.Contains(p.Tasks[2].Goal, "transmis") {
		t.Fatalf("%v %+v", dropped, p.Tasks)
	}
}
