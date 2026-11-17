package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/dat"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
)

func TestResolveDAT(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      options
		variant string
		only    bool
		fails   bool
	}{
		{"sans mode", options{}, "", false, false},
		{"dat drift", options{datFlag: "Drift"}, dat.Drift, false, false},
		{"schéma seul", options{diagramFlag: "iac"}, dat.IaC, true, false},
		{"variante inconnue", options{datFlag: "full"}, "", false, true},
		{"les deux", options{datFlag: "iac", diagramFlag: "iac"}, "", false, true},
		{"avec incident", options{datFlag: "clean", incident: true}, "", false, true},
		{"avec changement", options{datFlag: "clean", change: true}, "", false, true},
		{"avec cve", options{datFlag: "clean", cveFlag: "auto"}, "", false, true},
		{"avec ticket", options{diagramFlag: "clean", ticketFlag: "auto"}, "", false, true},
		{"avec direct", options{datFlag: "clean", direct: directAuto}, "", false, true},
	} {
		o := tc.in
		err := o.resolveDAT()
		if (err != nil) != tc.fails {
			t.Errorf("%s : erreur %v", tc.name, err)
			continue
		}
		if !tc.fails && (o.datVariant != tc.variant || o.diagramOnly != tc.only) {
			t.Errorf("%s : variante %q, schéma seul %v", tc.name, o.datVariant, o.diagramOnly)
		}
	}
}

func TestInheritDATMode(t *testing.T) {
	d := session.Turn{N: 1, Mode: dat.ModeDAT, DAT: dat.Clean}
	g := session.Turn{N: 1, Mode: dat.ModeDiagram, DAT: dat.Drift}
	plain := session.Turn{N: 2}
	incident := session.Turn{N: 3, Mode: template.TicketIncident}
	for _, tc := range []struct {
		name    string
		turns   []session.Turn
		in      options
		variant string
		only    bool
	}{
		{"dat repris", []session.Turn{d, plain}, options{}, dat.Clean, false},
		{"schéma repris", []session.Turn{g}, options{}, dat.Drift, true},
		{"incident plus récent", []session.Turn{d, incident}, options{}, "", false},
		{"variante explicite", []session.Turn{d}, options{datVariant: dat.IaC}, dat.IaC, false},
		{"changement explicite", []session.Turn{d}, options{change: true}, "", false},
	} {
		o := tc.in
		o.inheritMode(&session.Session{Turns: tc.turns})
		if o.datVariant != tc.variant || o.diagramOnly != tc.only {
			t.Errorf("%s : variante %q, schéma seul %v", tc.name, o.datVariant, o.diagramOnly)
		}
	}
}

func TestDATScopeFromAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	data := `{"kind":"run_start","tools":["code_tree","diagram_render"]}
{"kind":"dat_scope","variant":"drift","instances":["code","prod"],"iac":["code"]}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	all, iac := datScopeFromAudit(path)
	if !slices.Equal(all, []string{"code", "prod"}) || !slices.Equal(iac, []string{"code"}) {
		t.Fatalf("%v %v", all, iac)
	}
	if got := toolFilterFromAudit(path); !slices.Equal(got, []string{"code"}) {
		t.Fatalf("filtre de resynthèse : %v", got)
	}
}

func TestReportImages(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 2, 1))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "architecture.png"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	md := "![Figure 1 — Réseau](architecture.png)\n\n![x](../secret.png) ![y](absent.png)"
	got := reportImages(md, dir, false)
	if len(got) != 1 || got["architecture.png"].Width != 2 || got["architecture.png"].Format != "png" {
		t.Fatalf("%+v", got)
	}
}

func TestDATUnits(t *testing.T) {
	cfg := []config.Instance{
		{Name: "k8s-a"}, {Name: "cloud-a"}, {Name: "vm-a"},
		{Name: "flux-prod-a", Describes: config.StringList{"k8s-a/prod"}},
		{Name: "flux-rec-a", Describes: config.StringList{"k8s-a/rec"}},
		{Name: "tf-a", Describes: config.StringList{"cloud-a"}},
		{Name: "tf-nsg-a", Describes: config.StringList{"cloud-a"}},
	}
	all := []string{"k8s-a", "cloud-a", "vm-a", "flux-prod-a", "flux-rec-a", "tf-a", "tf-nsg-a"}
	iac := []string{"flux-prod-a", "flux-rec-a", "tf-a", "tf-nsg-a"}
	units := datUnits(cfg, dat.Clean, all, iac)
	var got []string
	for _, u := range units {
		got = append(got, strings.Join(u.Instances, "+")+"|"+strings.Join(u.Except, ","))
	}
	want := []string{"flux-prod-a+k8s-a|", "flux-rec-a+k8s-a|", "tf-a+cloud-a|", "tf-nsg-a+cloud-a|", "k8s-a|prod,rec", "vm-a|"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("unités :\n%v\nattendu\n%v", got, want)
	}
	units = datUnits(cfg, dat.IaC, iac, iac)
	if len(units) != 4 || len(units[0].Instances) != 1 || len(units[0].Objects) != 0 {
		t.Fatalf("variante iac : %+v", units)
	}
}
