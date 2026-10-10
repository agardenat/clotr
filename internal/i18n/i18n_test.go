package i18n

import "testing"

func TestCatalog(t *testing.T) {
	defer Set("en")
	Set("en")
	if N(1, "step") != "1 step" || N(3, "step") != "3 steps" || T("step.n", 4) != "step 4" || N(0, "entry") != "0 entries" {
		t.Fatal("en")
	}
	Set("fr")
	if N(1, "step") != "1 étape" || N(3, "step") != "3 étapes" || T("step.n", 4) != "étape 4" || N(0, "tâche") != "0 tâche" {
		t.Fatalf("fr: %s %s %s", N(1, "step"), N(3, "step"), T("step.n", 4))
	}
	if N(0, "finding") != "0 constat" || N(2, "tool call") != "2 appels d'outils" || T("waiting", "t1") != "attend t1" {
		t.Fatal("fr pluriels")
	}
	Set("auto")
	if Lang() != "en" {
		t.Fatal("auto doit donner une interface anglaise")
	}
	for k, m := range msgs {
		if m.en == "" || m.fr == "" {
			t.Errorf("traduction manquante: %s", k)
		}
	}
}
