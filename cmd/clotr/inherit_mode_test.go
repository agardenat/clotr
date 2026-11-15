package main

import (
	"context"
	"testing"

	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
)

func TestInheritMode(t *testing.T) {
	incident := session.Turn{N: 1, Mode: template.TicketIncident, Ticket: "TCK-1"}
	change := session.Turn{N: 1, Mode: template.TicketChange}
	plain := session.Turn{N: 2}
	cve := session.Turn{N: 3, CVE: []string{"CVE-2024-0001"}}
	for _, tc := range []struct {
		name             string
		turns            []session.Turn
		in               options
		incident, change bool
		ticket           string
	}{
		{"nouvelle session", nil, options{}, false, false, ""},
		{"incident repris", []session.Turn{incident}, options{}, true, false, "TCK-1"},
		{"incident après un tour sans mode", []session.Turn{incident, plain}, options{}, true, false, "TCK-1"},
		{"changement repris", []session.Turn{change}, options{}, false, true, ""},
		{"tour CVE plus récent", []session.Turn{incident, cve}, options{}, false, false, ""},
		{"mode explicite", []session.Turn{incident}, options{change: true}, false, true, ""},
		{"ticket explicite", []session.Turn{incident}, options{ticketFlag: "TCK-9"}, true, false, ""},
		{"chat", []session.Turn{incident}, options{chat: true}, false, false, ""},
		{"direct", []session.Turn{incident}, options{direct: directAuto}, false, false, ""},
	} {
		o := tc.in
		o.inheritMode(&session.Session{Turns: tc.turns})
		if o.incident != tc.incident || o.change != tc.change || o.prevTicket != tc.ticket {
			t.Errorf("%s : incident %v, change %v, ticket %q", tc.name, o.incident, o.change, o.prevTicket)
		}
	}
}

func TestResolveTicketPrevious(t *testing.T) {
	rt := ticketRuntime(t, "incident")
	o := options{incident: true, prevTicket: "TCK-7", request: "relance sans identifiant"}
	if err := rt.resolveTicket(context.Background(), &o, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if rt.mainTicket == nil || rt.mainTicket.ID != "TCK-7" {
		t.Fatalf("ticket %+v", rt.mainTicket)
	}
}
