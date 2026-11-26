package orchestrator

import (
	"context"
	"github.com/agardenat/clotr/internal/config"
	"strings"
	"testing"
)

func TestMinutesPlanRolesAndRules(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	o.Minutes = true
	rep, err := o.Run(context.Background(), "compte rendu du comité projet acme du 5 novembre")
	if err != nil {
		t.Fatal(err)
	}
	strong, err := o.strongRole()
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range rep.Plan.Tasks {
		if task.Role != strong {
			t.Errorf("%s : rôle %q, attendu %q", task.ID, task.Role, strong)
		}
	}
	if !strings.Contains(tl.input["planner"], "Compte rendu de réunion : le run lit la ou les réunions") {
		t.Fatalf("consigne du planner absente : %q", tl.input["planner"])
	}
	if !strings.Contains(o.modeRule(), "Mode compte rendu de réunion : lis la transcription entière") {
		t.Fatalf("consigne des agents absente : %q", o.modeRule())
	}
	if sys := tl.system["synthesizer"]; !strings.Contains(sys, "rédige le compte rendu de réunion") || !strings.Contains(sys, "## 4. Actions") {
		t.Fatalf("modèle de rapport minutes absent : %q", sys)
	}
}

func TestMinutesRolesUseStrongestWorker(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, nil)
	o.Cfg.Roles["analyst"] = config.Role{Tier: "balanced", Tools: true}
	p := &Plan{Tasks: []Task{{ID: "t1", Role: "collector"}, {ID: "t2", Role: "analyst"}}}
	o.minutesRoles(p)
	if p.Tasks[0].Role != "collector" {
		t.Fatalf("rôles changés hors mode compte rendu : %+v", p.Tasks)
	}
	o.Minutes = true
	o.minutesRoles(p)
	for _, task := range p.Tasks {
		if task.Role != "analyst" {
			t.Errorf("%s : rôle %q, attendu analyst", task.ID, task.Role)
		}
	}
}
