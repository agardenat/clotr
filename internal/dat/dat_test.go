package dat

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/i18n"
)

type renderer struct{ warnings []string }

func (renderer) Reference(context.Context, string) (string, error) { return "ref", nil }
func (renderer) Shapes(context.Context, string, string) (string, error) {
	return "shapes", nil
}
func (r renderer) Render(context.Context, string, map[string]any) (*Rendered, error) {
	return &Rendered{Drawio: []byte("<mxfile/>"), PNG: []byte("png"), Warnings: r.warnings}, nil
}

func call(t *testing.T, s *Store, args map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(args)
	out, err := renderTool{s}.Call(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenderWritesFilesAndRestores(t *testing.T) {
	i18n.SetReport("fr")
	dir := t.TempDir()
	s := New(Drift, false, renderer{warnings: []string{"type inconnu : foo"}}, audit.Nop())
	s.Begin(dir)
	args := map[string]any{"name": "Cloud Azure", "cloud": "Azure", "title": "Réseau", "spec": map[string]any{"nodes": []any{}}}
	if out := call(t, s, args); !strings.Contains(out, "avertissement") {
		t.Fatal(out)
	}
	if s.Rendered() {
		t.Fatal("un schéma avec avertissement n'est pas rendu")
	}
	s.Renderer = renderer{}
	call(t, s, args)
	ds := s.Diagrams()
	if len(ds) != 1 || ds[0].Name != "architecture-cloud-azure" || ds[0].Cloud != "azure" || !ds[0].Clean() {
		t.Fatalf("%+v", ds)
	}
	for _, f := range []string{"architecture-cloud-azure.png", "architecture-cloud-azure.drawio"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	r := New(Drift, false, nil, audit.Nop())
	r.Restore(dir)
	blocks, _ := r.Blocks()
	if blocks["diagram"] != "![Figure 1 — Réseau](architecture-cloud-azure.png)" {
		t.Fatalf("%q", blocks["diagram"])
	}
	if len(r.Tools()) != 0 {
		t.Fatal("outils de schéma sans template de schéma")
	}
}

func TestBlocksWithoutDiagram(t *testing.T) {
	i18n.SetReport("fr")
	s := New(Clean, false, nil, audit.Nop())
	s.Skipped = "Pas de schéma : session confidentielle."
	blocks, _ := s.Blocks()
	if blocks["diagram"] != "*Pas de schéma : session confidentielle.*" {
		t.Fatalf("%q", blocks["diagram"])
	}
}

func TestPlanRuleByVariant(t *testing.T) {
	s := New(IaC, false, nil, audit.Nop())
	s.Instances, s.IaCOnes = []string{"code"}, []string{"code"}
	if r := s.PlanRule(); strings.Contains(r, "instances réelles") || !strings.Contains(r, "toutes à couvrir : code") {
		t.Fatal(r)
	}
	s.Variant = Drift
	if r := s.WorkerRule(); !strings.Contains(r, DriftMark) {
		t.Fatal(r)
	}
	s.Variant = Clean
	if r := s.WorkerRule(); strings.Contains(r, DriftMark) {
		t.Fatal(r)
	}
}

func TestMainDiagramFirst(t *testing.T) {
	s := New(Clean, true, renderer{}, audit.Nop())
	s.Begin(t.TempDir())
	for _, n := range []string{"cdp", "vm", "architecture", "cdp"} {
		call(t, s, map[string]any{"name": n, "cloud": "azure", "title": n, "spec": map[string]any{"nodes": []any{}}})
	}
	var names []string
	for _, d := range s.Diagrams() {
		names = append(names, d.Name)
	}
	if strings.Join(names, " ") != "architecture architecture-cdp architecture-vm" {
		t.Fatal(names)
	}
}

func TestDiagramGoalEntryPoint(t *testing.T) {
	g := New(Clean, true, nil, nil).DiagramGoal()
	if !strings.Contains(g, "relié à chacun de ses points d'entrée") || !strings.Contains(g, "la jumpbox, le bastion ou le rebond pour l'exploitation") || strings.Contains(g, "relié au groupe qu'il atteint, avec") {
		t.Fatalf("consigne des points d'entrée : %s", g)
	}
	for _, gone := range []string{"de préférence deux groupes", "relié une seule fois au groupe qui les contient", "un lien par groupe consommateur"} {
		if strings.Contains(g, gone) {
			t.Fatalf("consigne retirée encore présente : %q", gone)
		}
	}
	if !strings.Contains(g, "Chaque lien repose sur une preuve qui établit ce couple précis") {
		t.Fatal("règle de preuve par lien absente")
	}
}

func TestSynthRuleClientVariant(t *testing.T) {
	clean := New(Clean, false, nil, nil).SynthRule()
	if !strings.Contains(clean, "ne dit pas comment il a été établi") || strings.Contains(clean, "tâches en échec ou arrêtées") {
		t.Fatalf("variante client : %s", clean)
	}
	if drift := New(Drift, false, nil, nil).SynthRule(); strings.Contains(drift, "ne dit pas comment") {
		t.Fatalf("variante drift : %s", drift)
	}
}

func TestUnitGoalChecklist(t *testing.T) {
	s := New(Clean, false, nil, nil)
	g := s.UnitGoal(Unit{Instances: []string{"cloud-a"}, Checklist: []string{"cloud-a : appairages ; passerelles"}})
	if !strings.Contains(g, "À établir avant de conclure") || !strings.Contains(g, "- cloud-a : appairages ; passerelles") {
		t.Fatalf("objectif : %s", g)
	}
	if g := s.UnitGoal(Unit{Instances: []string{"cloud-a"}}); strings.Contains(g, "À établir") {
		t.Fatalf("liste vide annoncée : %s", g)
	}
	d := s.DiagramGoal()
	if !strings.Contains(d, "seuls des éléments interchangeables") || strings.Contains(d, "au-delà de trois ressources de même type") {
		t.Fatal("règle de regroupement des nœuds")
	}
}

func TestDiagramGoalConsistent(t *testing.T) {
	g := New(Clean, true, nil, nil).DiagramGoal()
	for _, want := range []string{"client → serveur", "Chaque lien porte son libellé", "relié à chacun de ses points d'entrée", "green entrée des utilisateurs", "Pas de title dans la spec", "pas l'organisation administrative", "relis la spec contre les preuves", "n'est pas un nœud : son adresse va dans le libellé de ce composant"} {
		if !strings.Contains(g, want) {
			t.Errorf("consigne absente : %q", want)
		}
	}
	for _, gone := range []string{"relié une seule fois", "un point d'entrée se met dans le libellé", "un répartiteur de charge a le type du répartiteur", "une quinzaine au plus par schéma"} {
		if strings.Contains(g, gone) {
			t.Errorf("consigne contradictoire encore présente : %q", gone)
		}
	}
}
