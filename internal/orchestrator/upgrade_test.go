package orchestrator

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/report"
	"github.com/agardenat/clotr/internal/testutil"
)

func TestUpgradeReadsDocumentationBeforePlan(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	web := testutil.FakeTool{ToolName: "mcp_web_search", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }}
	o.Tools.Add(web)
	o.WebTools = []string{web.ToolName}
	o.Upgrade = true
	rep, err := o.Run(context.Background(), "mode opératoire de mise à jour du cluster c1 vers 2.0, c2 plus tard")
	if err != nil {
		t.Fatal(err)
	}
	first := rep.Results[0]
	if first.TaskID != procedureID || first.Status != "ok" || len(rep.Results) != 5 {
		t.Fatalf("résultats : %+v", rep.Results)
	}
	if !strings.Contains(tl.input[procedureID], "Documentation de mise à jour, avant toute planification") {
		t.Fatalf("objectif de l'étape : %q", tl.input[procedureID])
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		if tl.start[id].Before(tl.end[procedureID]) {
			t.Errorf("%s démarré avant la lecture de la documentation", id)
		}
		if !strings.Contains(tl.input[id], "procedure vu") {
			t.Errorf("%s : documentation ou consigne absente : %q", id, tl.input[id])
		}
	}
	in := tl.input["planner"]
	if !strings.Contains(in, "Mode opératoire de mise à jour : rien n'est modifié") || !strings.Contains(in, "Résultat de l'étape procedure") || !strings.Contains(in, "procedure vu") {
		t.Fatalf("entrée du planner : %q", in)
	}
	if o.reportMode() != report.ModeUpgrade {
		t.Fatal(o.reportMode())
	}
	if rule := o.modeRule(); !strings.Contains(rule, "Mode opératoire de mise à jour : tu ne modifies rien") {
		t.Fatalf("consigne des tâches : %q", rule)
	}
	if !strings.Contains(tl.input["frame"], "procedure vu") || !strings.Contains(tl.input["synthesizer"], "Cadrage commun du mode opératoire") || !strings.Contains(tl.input["synthesizer"], "Variante retenue : progressive") {
		t.Fatalf("cadrage absent : %q", tl.input["synthesizer"])
	}
	if !strings.Contains(tl.input["synthesizer"], "ne servent pas à l'estimer") {
		t.Fatal("règles de lecture absentes de la rédaction")
	}
	if !strings.Contains(tl.input[procedureID], "Ne mêle jamais deux variantes") {
		t.Fatal("consigne des variantes absente de l'étape procedure")
	}
	if !strings.Contains(rep.Markdown, "# Rapport") || strings.Count(rep.Markdown, "# Rapport") != 11 {
		t.Fatalf("rédaction section par section attendue (11 sections) :\n%s", rep.Markdown)
	}
}

func TestUpgradeProcedureTools(t *testing.T) {
	o, _ := newOrch(t, nil, nil)
	web := testutil.FakeTool{ToolName: "mcp_web_search", Fn: func(context.Context, json.RawMessage) (string, error) { return "ok", nil }}
	o.Tools.Add(web)
	o.WebTools = []string{web.ToolName}
	o.Upgrade = true
	tools := o.procedureTools()
	if !slices.Contains(tools, web.ToolName) || slices.Contains(tools, "k8s_list") || slices.Contains(tools, "fs_read") {
		t.Fatalf("outils de l'étape : %v", tools)
	}
}

func TestUpgradeWithoutWebSkipsProcedure(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	o.Upgrade = true
	rep, err := o.Run(context.Background(), "mise à jour de c1 vers 2.0")
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.TaskID != procedureID || r.Status != "skipped" || len(r.Gaps) == 0 {
		t.Fatalf("étape sans web : %+v", r)
	}
	if _, ran := tl.start[procedureID]; ran {
		t.Fatal("étape procedure lancée sans recherche web")
	}
	if !strings.Contains(tl.input["synthesizer"], "documentation officielle non lue") {
		t.Fatal("limite absente de l'entrée de la synthèse")
	}
}

func TestUpgradePlanReservesProcedureID(t *testing.T) {
	o, _ := newOrch(t, nil, nil)
	o.Upgrade = true
	o.procedure = &Result{TaskID: procedureID, Status: "ok"}
	if err := o.Validate(&Plan{Tasks: []Task{{ID: procedureID, Role: "collector", Goal: "g"}}}); err == nil {
		t.Fatal("id procedure accepté")
	}
	p := &Plan{Tasks: []Task{{ID: "t1", Role: "collector", Goal: "g", DependsOn: []string{procedureID}}}}
	if err := o.Validate(p); err != nil || len(p.Tasks[0].DependsOn) != 0 {
		t.Fatalf("dépendance vers procedure : %v %v", err, p.Tasks[0].DependsOn)
	}
}

func TestUpgradeRefineSkipsProcedureAndAcceptsEmptyPlan(t *testing.T) {
	o, tl := newOrch(t, []string{`{"tasks":[]}`}, nil)
	o.Upgrade = true
	o.History = "Tour 1 : mode opératoire"
	o.WebTools = []string{"mcp_web_search"}
	rep, err := o.Run(context.Background(), "ajoute les durées")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("résultats : %+v", rep.Results)
	}
	if !strings.Contains(tl.input["planner"], "Affinage d'une session") {
		t.Fatalf("entrée du planner : %q", tl.input["planner"])
	}
}
