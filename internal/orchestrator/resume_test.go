package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/pending"
)

func TestResumeRunsApprovedCommands(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	o.Runner.Evidence = evidence.Open(t.TempDir(), 2)
	var called []string
	o.Resume = &Resume{
		From: 1,
		Items: []pending.Item{
			{ID: 1, Kind: pending.KindExec, Instance: "k8s", Tool: "k8s_list", Where: "h1", Argv: []string{"demo-tool", "--state"}, Task: "t3", Status: pending.StatusApproved},
			{ID: 2, Kind: pending.KindExec, Instance: "k8s", Tool: "k8s_list", Where: "h1", Argv: []string{"demo-tool", "--other"}, Task: "t3", Status: pending.StatusRefused},
			{ID: 3, Kind: pending.KindExec, Instance: "k8s", Tool: "k8s_list", Where: "h2", Argv: []string{"demo-missing"}, Task: "t2", Status: pending.StatusApproved},
		},
		Goals: map[string]string{"t3": "état du composant"},
		Roles: map[string]string{"t3": "collector"},
		Call: func(_ context.Context, it pending.Item) (string, error) {
			called = append(called, strings.Join(it.Argv, " "))
			if it.ID == 3 {
				return "", errors.New("demo-missing: not found")
			}
			return "state=degraded", nil
		},
	}
	rep, err := o.Run(context.Background(), "Reprise du tour 1")
	if err != nil {
		t.Fatal(err)
	}
	if tl.input["planner"] != "" {
		t.Fatal("planner appelé pendant une reprise")
	}
	if len(called) != 2 || called[0] != "demo-tool --state" || called[1] != "demo-missing" {
		t.Fatalf("appels : %v", called)
	}
	if len(rep.Plan.Tasks) != 2 || rep.Plan.Tasks[0].ID != "t3" || !strings.Contains(rep.Plan.Tasks[0].Goal, "état du composant") || rep.Plan.Tasks[1].ID != "t2" {
		t.Fatalf("plan : %+v", rep.Plan.Tasks)
	}
	if it := o.Resume.Items[2]; it.Status != pending.StatusFailed || it.Evidence == "" || it.Error == "" {
		t.Fatalf("élément en échec : %+v", it)
	}
	if in := tl.input["t3"]; !strings.Contains(in, "demo-tool --state") || !strings.Contains(in, ResumeID) {
		t.Fatalf("entrée de t3 sans l'étape de reprise : %s", in)
	}
	if !strings.Contains(tl.input["synthesizer"], "Commande refusée par l'utilisateur") {
		t.Fatalf("refus absent de la synthèse : %s", tl.input["synthesizer"])
	}
	if it := o.Resume.Items[0]; it.Status != pending.StatusDone || it.Evidence == "" {
		t.Fatalf("élément exécuté : %+v", it)
	}
	if it := o.Resume.Items[1]; it.Status != pending.StatusRefused {
		t.Fatalf("élément refusé : %+v", it)
	}
}
