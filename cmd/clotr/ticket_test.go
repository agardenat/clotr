package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/template"
)

func TestChangeAndTicketIncompatibleModes(t *testing.T) {
	for _, tc := range []struct {
		o    *options
		want string
	}{
		{&options{change: true, incident: true}, "--change"},
		{&options{change: true, panic: true}, "--change"},
		{&options{change: true, cveFlag: "auto"}, "--change"},
		{&options{change: true, direct: directAuto}, "--change"},
		{&options{ticketFlag: "auto", chat: true}, "--ticket"},
		{&options{ticketFlag: "TCK-1", cveFlag: "auto"}, "--ticket"},
		{&options{upgrade: true, change: true}, "--upgrade"},
		{&options{upgrade: true, panic: true}, "--upgrade"},
		{&options{upgrade: true, ticketFlag: "auto"}, "--upgrade"},
		{&options{upgrade: true, datFlag: "clean"}, "--upgrade"},
		{&options{upgrade: true, chat: true}, "--upgrade"},
		{&options{watch: true, incident: true}, "--watch"},
		{&options{watch: true, panic: true}, "--watch"},
		{&options{watch: true, ticketFlag: "auto"}, "--watch"},
		{&options{watch: true, datFlag: "clean"}, "--watch"},
		{&options{watch: true, direct: directAuto}, "--watch"},
		{&options{minutes: true, incident: true}, "--minutes"},
		{&options{minutes: true, upgrade: true}, "--minutes"},
		{&options{minutes: true, watch: true}, "--minutes"},
		{&options{minutes: true, ticketFlag: "auto"}, "--minutes"},
		{&options{minutes: true, datFlag: "clean"}, "--minutes"},
		{&options{minutes: true, chat: true}, "--minutes"},
		{&options{watchFor: time.Minute}, "--watch-for"},
		{&options{watch: true, watchEvery: -time.Second}, "--watch-for"},
	} {
		if err := cmdRun(context.Background(), tc.o, []string{"x"}, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: %v", tc.o, err)
		}
	}
}

func TestChangeFlagAliases(t *testing.T) {
	for _, flag := range []string{"--change", "--demande"} {
		root := newRoot()
		run, _, err := root.Find([]string{"run"})
		if err != nil {
			t.Fatal(err)
		}
		if err := run.ParseFlags([]string{flag, "--ticket"}); err != nil {
			t.Fatal(err)
		}
		if v, _ := run.Flags().GetBool("change"); !v {
			t.Fatalf("%s ne positionne pas le mode change", flag)
		}
		if v, _ := run.Flags().GetString("ticket"); v != "auto" {
			t.Fatalf("--ticket sans valeur: %q", v)
		}
	}
}

func TestWatchFlagAliases(t *testing.T) {
	for _, flag := range []string{"--watch", "--suivi"} {
		run, _, err := newRoot().Find([]string{"run"})
		if err != nil {
			t.Fatal(err)
		}
		if err := run.ParseFlags([]string{flag, "--watch-for", "2m"}); err != nil {
			t.Fatal(err)
		}
		if v, _ := run.Flags().GetBool("watch"); !v {
			t.Fatalf("%s ne positionne pas le mode suivi", flag)
		}
		if d, _ := run.Flags().GetDuration("watch-for"); d != 2*time.Minute {
			t.Fatalf("--watch-for : %s", d)
		}
	}
}

const ticketYAML = `name: tracker
kind: tickets
script: tracker.star
id_pattern: "TCK-[0-9]+"
connectors:
  tk: {driver: mcp, server: tracker}
`

const ticketStar = `def get(id):
    r = mcp.call("tk", "get", {"id": id})
    if not r.data:
        return None
    return r.data

def search(q):
    return []
`

type ticketMCP struct{ kind string }

func (m ticketMCP) CallTool(_ context.Context, _ string, args map[string]any) (*template.MCPResult, error) {
	if args["id"] == "TCK-404" {
		return &template.MCPResult{Text: "{}", Data: []byte("{}")}, nil
	}
	b, _ := json.Marshal(map[string]any{"id": args["id"], "kind": m.kind, "title": "port 443 à ouvrir"})
	return &template.MCPResult{Text: string(b), Data: b}, nil
}

func ticketRuntime(t *testing.T, kind string) *app {
	t.Helper()
	dir := t.TempDir()
	for n, c := range map[string]string{"tracker.yaml": ticketYAML, "tracker.star": ticketStar} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rt := &app{cfg: &config.Config{Templates: config.TemplatesConf{Dir: dir}, Tickets: &config.Tickets{Template: "tracker"}}, audit: audit.Nop()}
	if err := rt.setupTickets(&options{ticketFlag: "auto"}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	rt.ticketSrc.MCP = func(context.Context, string) (template.MCPCaller, error) { return ticketMCP{kind}, nil }
	return rt
}

func TestResolveTicketSwitchesMode(t *testing.T) {
	for _, tc := range []struct {
		kind             string
		in               options
		incident, change bool
	}{
		{"change", options{incident: true, ticketFlag: "auto"}, false, true},
		{"incident", options{change: true, ticketFlag: "TCK-7"}, true, false},
		{"change", options{ticketFlag: "auto"}, false, true},
		{"other", options{ticketFlag: "auto"}, true, false},
		{"other", options{change: true}, false, true},
	} {
		rt := ticketRuntime(t, tc.kind)
		o := tc.in
		o.request = "voir TCK-7"
		if err := rt.resolveTicket(context.Background(), &o, func(string) {}); err != nil {
			t.Fatal(err)
		}
		if rt.mainTicket == nil || rt.mainTicket.ID != "TCK-7" || o.incident != tc.incident || o.change != tc.change {
			t.Fatalf("%s %+v: ticket %+v, incident %v, change %v", tc.kind, tc.in, rt.mainTicket, o.incident, o.change)
		}
	}
}

func TestResolveTicketErrors(t *testing.T) {
	rt := ticketRuntime(t, "incident")
	for _, tc := range []struct {
		o    options
		want string
	}{
		{options{ticketFlag: "auto", request: "pas d'identifiant"}, "TCK-[0-9]+"},
		{options{ticketFlag: "XYZ-1"}, "XYZ-1"},
		{options{ticketFlag: "TCK-404"}, "TCK-404"},
	} {
		o := tc.o
		if err := rt.resolveTicket(context.Background(), &o, func(string) {}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: %v", tc.o, err)
		}
	}
	var warned []string
	o := options{incident: true, request: "voir TCK-404"}
	if err := rt.resolveTicket(context.Background(), &o, func(m string) { warned = append(warned, m) }); err != nil || len(warned) != 1 || rt.mainTicket != nil {
		t.Fatalf("ticket relevé dans la demande et absent: %v %v", err, warned)
	}
	rt2 := &app{cfg: &config.Config{}, audit: audit.Nop()}
	if err := rt2.setupTickets(&options{ticketFlag: "auto"}, func(string) {}); err == nil || !strings.Contains(err.Error(), "tickets") {
		t.Fatalf("sans outil de tickets: %v", err)
	}
	if err := rt2.setupTickets(&options{incident: true}, func(string) {}); err != nil || rt2.ticketSrc != nil {
		t.Fatalf("incident sans outil de tickets: %v", err)
	}
}

func TestUpgradeFlagAliases(t *testing.T) {
	for _, flag := range []string{"--upgrade", "--modop"} {
		root := newRoot()
		run, _, err := root.Find([]string{"run"})
		if err != nil {
			t.Fatal(err)
		}
		if err := run.ParseFlags([]string{flag}); err != nil {
			t.Fatal(err)
		}
		if v, _ := run.Flags().GetBool("upgrade"); !v {
			t.Fatalf("%s ne positionne pas le mode upgrade", flag)
		}
	}
}

func TestMinutesFlagAliases(t *testing.T) {
	for _, flag := range []string{"--minutes", "--cr"} {
		root := newRoot()
		run, _, err := root.Find([]string{"run"})
		if err != nil {
			t.Fatal(err)
		}
		if err := run.ParseFlags([]string{flag}); err != nil {
			t.Fatal(err)
		}
		if v, _ := run.Flags().GetBool("minutes"); !v {
			t.Fatalf("%s ne positionne pas le mode minutes", flag)
		}
	}
}
