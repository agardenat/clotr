package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"testing"

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
