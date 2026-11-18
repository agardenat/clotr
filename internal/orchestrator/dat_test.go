package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/dat"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/report"
	"github.com/agardenat/clotr/internal/testutil"
)

type fakeRenderer struct{}

func (fakeRenderer) Reference(context.Context, string) (string, error) {
	return `{"groups":"…"}`, nil
}

func (fakeRenderer) Shapes(context.Context, string, string) (string, error) {
	return `{"results":[{"type":"vm"}]}`, nil
}

func (fakeRenderer) Render(_ context.Context, _ string, spec map[string]any) (*dat.Rendered, error) {
	if _, ok := spec["nodes"]; !ok {
		return &dat.Rendered{Warnings: []string{"spec sans nœud"}}, nil
	}
	return &dat.Rendered{Drawio: []byte("<mxfile/>"), PNG: []byte("png")}, nil
}

const datPlan = "```json\n" + `{"tasks":[{"id":"t1","role":"collector","goal":"relevé du cluster","tools":["k8s","diagram_render"]}]}` + "\n```"

func datOrch(t *testing.T, variant string, diagramOnly bool) (*Orchestrator, *timeline, *sync.Map, string) {
	o, tl := newOrch(t, []string{datPlan}, nil)
	o.Tools.Add(testutil.FakeTool{ToolName: "code_tree", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }})
	dir := t.TempDir()
	o.DAT = dat.New(variant, diagramOnly, fakeRenderer{}, audit.Nop())
	o.DAT.Instances, o.DAT.IaCOnes = []string{"k8s", "code"}, []string{"code"}
	o.DAT.Begin(dir)
	o.Tools.Add(o.DAT.Tools()...)
	sections := &sync.Map{}
	base := o.Runner.Chat
	o.Runner.Chat = &testutil.FakeChat{Fn: func(ctx context.Context, p string, req llm.Request) (*llm.Response, error) {
		sys, user := req.Messages[0].Content, req.Messages[1].Content
		switch {
		case strings.Contains(sys, "Rédaction section par section"):
			_, chunk, _ := strings.Cut(user, "Section à rédiger")
			_, chunk, _ = strings.Cut(chunk, ":\n")
			head := ""
			if strings.HasPrefix(chunk, "# ") {
				head, chunk, _ = strings.Cut(chunk, "\n\n")
				head = "# Document d'architecture technique — test\n\n"
			}
			title := report.Heading(chunk)
			sections.Store(title, sys)
			body := "Contenu de " + title
			if strings.Contains(chunk, "{{diagram}}") {
				body = "{{diagram}}\n\n" + body
			}
			return testutil.Reply(head + "## " + title + "\n\n" + body), nil
		case strings.Contains(user, "Ta tâche ("+dat.TaskID+")"):
			if req.Messages[len(req.Messages)-1].Role == "tool" {
				return testutil.Reply(`{"findings":["[INFO] schéma architecture rendu"],"evidence":[],"gaps":[]}`), nil
			}
			spec := map[string]any{"groups": []any{}, "nodes": []any{map[string]any{"id": "vm1", "type": "vm", "label": "VM"}}, "edges": []any{}}
			return testutil.Reply("", testutil.Call(dat.RenderTool, map[string]any{"name": "architecture", "cloud": "azure", "title": "Architecture globale", "spec": spec})), nil
		}
		return base.Chat(ctx, p, req)
	}}
	return o, tl, sections, dir
}

func TestDATModeCoversInstancesDrawsAndWritesBySection(t *testing.T) {
	o, tl, sections, dir := datOrch(t, dat.Drift, false)
	rep, err := o.Run(context.Background(), "DAT du projet test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tl.input["planner"], "Instances du périmètre, toutes à couvrir : k8s, code") {
		t.Fatalf("entrée du planner : %q", tl.input["planner"])
	}
	var covered bool
	for _, task := range rep.Plan.Tasks {
		if slices.Contains(task.Tools, dat.RenderTool) {
			t.Fatalf("outil de schéma donné à une tâche de relevé : %v", task.Tools)
		}
		if slices.Contains(task.Tools, "code_tree") {
			covered = true
		}
	}
	if !covered || len(rep.Plan.Tasks) != 2 {
		t.Fatalf("instance code non couverte : %+v", rep.Plan.Tasks)
	}
	last := rep.Results[len(rep.Results)-1]
	if last.TaskID != dat.TaskID || last.Status != "ok" {
		t.Fatalf("étape schéma : %+v", last)
	}
	for _, f := range []string{"architecture.png", "architecture.drawio", "diagrams.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	sections.Range(func(_, _ any) bool { n++; return true })
	if n != 13 {
		t.Fatalf("%d sections rédigées, 13 attendues en drift", n)
	}
	md := rep.Markdown
	for _, want := range []string{"# Document d'architecture technique — test", "![Figure 1 — Architecture globale](architecture.png)", "## 13. Écarts entre l'IaC et l'état réel", "Contenu de 12. Périmètre non couvert et limites"} {
		if !strings.Contains(md, want) {
			t.Fatalf("rapport sans %q :\n%s", want, md)
		}
	}
	if strings.Contains(md, "variant:") || strings.Contains(md, "{{") {
		t.Fatalf("marqueurs restés dans le rapport :\n%s", md)
	}
	if sys, _ := sections.Load("1. Introduction"); !strings.Contains(sys.(string), dat.DriftMark) {
		t.Fatal("consigne des écarts absente de la synthèse")
	}
	if rule := o.modeRule(); !strings.Contains(rule, "Extraction exhaustive") || !strings.Contains(rule, dat.DriftMark) {
		t.Fatalf("consigne des tâches : %q", rule)
	}
	if o.reportMode() != report.ModeDAT {
		t.Fatal(o.reportMode())
	}
}

func TestDATCleanHasNoDriftSectionNorEvidence(t *testing.T) {
	o, _, sections, _ := datOrch(t, dat.Clean, false)
	rep, err := o.Run(context.Background(), "DAT du projet test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sections.Load("13. Écarts entre l'IaC et l'état réel"); ok || strings.Contains(rep.Markdown, "Écarts") {
		t.Fatalf("section des écarts en variante clean :\n%s", rep.Markdown)
	}
	if o.DAT.CitesEvidence() || strings.Contains(o.DAT.SynthRule(), "Cite les preuves") {
		t.Fatal("la variante clean ne cite pas de preuve")
	}
}

func TestDiagramOnlySingleSynthesis(t *testing.T) {
	o, tl, sections, _ := datOrch(t, dat.IaC, true)
	if _, err := o.Run(context.Background(), "schéma du projet test"); err != nil {
		t.Fatal(err)
	}
	n := 0
	sections.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Fatalf("schéma seul rédigé par sections (%d)", n)
	}
	sys := tl.system["synthesizer"]
	if !strings.Contains(sys, "# Schéma d'architecture — ") || strings.Contains(sys, "Écarts entre") {
		t.Fatalf("modèle du schéma seul : %q", sys)
	}
	if o.reportMode() != report.ModeDiagram {
		t.Fatal(o.reportMode())
	}
}

func TestDATRefineAcceptsEmptyPlan(t *testing.T) {
	o, _, _, _ := datOrch(t, dat.Clean, true)
	first := &Plan{}
	if err := o.validatePlan(first); err != nil || len(first.Tasks) == 0 {
		t.Fatalf("premier tour non couvert : %v %v", first.Tasks, err)
	}
	o.History = "tour 1"
	refine := &Plan{}
	if err := o.validatePlan(refine); err != nil || len(refine.Tasks) != 0 {
		t.Fatalf("affinage : %v %v", refine.Tasks, err)
	}
	if !strings.Contains(o.DAT.PlanRule(), "plan vide") {
		t.Fatal("consigne d'affinage absente")
	}
}

func TestDATFixedPlanSkipsPlanner(t *testing.T) {
	o, tl, _, _ := datOrch(t, dat.Clean, true)
	o.DAT.Units = []dat.Unit{
		{IaC: "code", Instances: []string{"code", "k8s"}, Objects: []string{"k8s/prod"}},
		{Instances: []string{"k8s"}, Except: []string{"prod"}},
	}
	for i := 0; i < 5; i++ {
		o.DAT.Units = append(o.DAT.Units, dat.Unit{Instances: []string{"k8s"}})
	}
	p, err := o.Plan(context.Background(), "schéma")
	if err != nil {
		t.Fatal(err)
	}
	if _, called := tl.input["planner"]; called {
		t.Fatal("planner appelé malgré le plan fixe")
	}
	if len(p.Tasks) != 7 || p.Tasks[0].ID != "t1" || p.Tasks[0].Role != "collector" {
		t.Fatalf("plan : %+v", p.Tasks)
	}
	if g := p.Tasks[0].Goal; !strings.Contains(g, "l'instance IaC code") || !strings.Contains(g, "la cible prod de l'instance k8s") {
		t.Fatalf("objectif t1 : %s", g)
	}
	if g := p.Tasks[1].Goal; !strings.Contains(g, "hors cibles prod") {
		t.Fatalf("objectif t2 : %s", g)
	}
	if !slices.Contains(p.Tasks[0].Tools, "code_tree") || !slices.Contains(p.Tasks[0].Tools, "k8s_list") || slices.Contains(p.Tasks[0].Tools, dat.RenderTool) {
		t.Fatalf("outils t1 : %v", p.Tasks[0].Tools)
	}
	again, _ := o.Plan(context.Background(), "schéma")
	for i := range p.Tasks {
		if again.Tasks[i].Goal != p.Tasks[i].Goal {
			t.Fatal("plan différent d'un appel à l'autre")
		}
	}
	o.History = "tour précédent"
	if _, err := o.Plan(context.Background(), "affiner"); err != nil {
		t.Fatal(err)
	}
	if _, called := tl.input["planner"]; !called {
		t.Fatal("affinage de session : le planner doit décider des faits nouveaux")
	}
}

func TestPrepareToolsBeforeTasks(t *testing.T) {
	o, tl, _, _ := datOrch(t, dat.Clean, true)
	o.DAT.Units = []dat.Unit{{IaC: "code", Instances: []string{"code", "k8s"}}}
	var prepared []string
	var startedBefore bool
	o.PrepareTools = func(_ context.Context, names []string) {
		prepared = names
		_, startedBefore = tl.start["t1"]
	}
	if _, err := o.Run(context.Background(), "schéma"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(prepared, "code_tree") || !slices.Contains(prepared, "k8s_list") {
		t.Fatalf("outils préparés : %v", prepared)
	}
	if startedBefore {
		t.Fatal("identifiants préparés après le démarrage d'une tâche")
	}
}
