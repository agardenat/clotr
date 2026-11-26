package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/evidence"
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
	if sys := tl.system["synthesizer"]; !strings.Contains(sys, "rédige le compte rendu de réunion") || !strings.Contains(sys, "## 3. Suivi du compte rendu précédent") {
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

func TestMinutesReportWithoutEvidenceByDefault(t *testing.T) {
	o, _ := newOrch(t, nil, nil)
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "teams_transcript", `{}`, "transcription", nil)
	o.Runner.Evidence = ev
	md := "- **Décision** : migration samedi [" + id + "] [00:12:03].\n- Voir [" + id + ", " + id + "] et ([" + id + "]).\n- Rien à citer."
	o.Minutes = true
	got := o.finalize(md)
	want := "- **Décision** : migration samedi [00:12:03].\n- Voir et.\n- Rien à citer."
	if got != want {
		t.Fatalf("compte rendu client :\n%q\nattendu :\n%q", got, want)
	}
	if sys := o.synthesizerSystem(); !strings.Contains(sys, "ne cite aucun identifiant de preuve [Exxx]") {
		t.Fatalf("consigne client absente : %q", sys)
	}
	o.CiteEvidence = true
	got = o.finalize(md)
	if !strings.Contains(got, "["+id+"] [00:12:03]") || !strings.Contains(got, "Annexe") && !strings.Contains(got, "Appendix") {
		t.Fatalf("preuves demandées absentes : %q", got)
	}
	if sys := o.synthesizerSystem(); strings.Contains(sys, "ne cite aucun identifiant de preuve [Exxx]") || !strings.Contains(sys, "Cite les preuves [Exxx]") {
		t.Fatalf("consigne avec preuves : %q", sys)
	}
	o.Minutes, o.CiteEvidence = false, false
	if got := o.finalize(md); !strings.Contains(got, "["+id+"]") {
		t.Fatalf("preuves retirées hors compte rendu : %q", got)
	}
}
