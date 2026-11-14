package template

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ticketsTplYAML = `name: tracker
kind: tickets
version: 1
description: outil de tickets fictif
script: tracker.star
id_pattern: "TCK-[0-9]{3,6}"
params:
  customer: {type: string, default: ""}
connectors:
  tk:
    driver: mcp
    server: tracker
`

const ticketsTplStar = `KINDS = {"INC": "incident", "CHG": "change"}

def norm(t):
    return {
        "id": t["key"],
        "kind": KINDS.get(t["type"], "other"),
        "title": t["subject"],
        "status": t["status"],
        "customer": t["org"],
        "scope": [t["org"]],
        "description": t.get("body", ""),
        "comments": [{"author": c["by"], "body": c["text"]} for c in t.get("notes", [])],
    }

def get(id):
    r = mcp.call("tk", "get_ticket", {"key": id})
    if r.error:
        fail(r.text)
    if not r.data:
        return None
    return norm(r.data)

def search(q):
    f = q["query"]
    customer = q["customer"] or instance.params["customer"]
    if customer and not q["all_customers"]:
        f += " org:" + customer
    if q["kind"]:
        f += " type:" + {"incident": "INC", "change": "CHG"}[q["kind"]]
    r = mcp.call("tk", "find", {"filter": f, "limit": q["limit"]})
    return [norm(t) for t in r.data["items"]]
`

const ticketsTplTest = `def mock(call):
    if call.tool == "get_ticket":
        if call.args["key"] == "TCK-404":
            return {}
        return {"key": call.args["key"], "type": "CHG", "subject": "ouvrir le port 443", "status": "NEW", "org": "ORG-1", "notes": [{"by": "a", "text": "urgent"}]}
    return {"items": [{"key": "TCK-200", "type": "INC", "subject": "certificat expiré", "status": "CLOSED", "org": "ORG-1"}]}

def test_get():
    i = template.instance(mcp = mock)
    t = i.ticket_get("TCK-123")
    assert.eq(t["kind"], "change")
    assert.eq(t["comments"][0]["body"], "urgent")
    assert.eq(i.ticket_get("TCK-404"), None)

def test_search():
    i = template.instance(mcp = mock, params = {"customer": "ORG-9"})
    r = i.ticket_search(query = "certificat", kind = "incident", limit = 5)
    assert.eq(r[0]["id"], "TCK-200")
    assert.eq(i.mcp_calls()[0]["args"]["filter"], "certificat org:ORG-9 type:INC")
`

func writeTicketsTemplate(t *testing.T) *Template {
	t.Helper()
	dir := t.TempDir()
	for n, c := range map[string]string{"tracker.yaml": ticketsTplYAML, "tracker.star": ticketsTplStar, "tracker_test.star": ticketsTplTest} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(dir)
	if err != nil || len(s.Warnings) > 0 {
		t.Fatalf("%v %v", err, s.Warnings)
	}
	tpl, ok := s.Get("tracker")
	if !ok || !tpl.Tickets() || !tpl.Special() {
		t.Fatal("template tracker absent ou mal typé")
	}
	return tpl
}

func TestTicketsHarness(t *testing.T) {
	tpl := writeTicketsTemplate(t)
	var out bytes.Buffer
	passed, failed, err := RunTests(context.Background(), tpl, &out)
	if err != nil || failed != 0 || passed != 2 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
}

type ticketCaller struct {
	args []map[string]any
}

func (c *ticketCaller) CallTool(_ context.Context, tool string, args map[string]any) (*MCPResult, error) {
	c.args = append(c.args, args)
	var v any
	switch tool {
	case "get_ticket":
		v = map[string]any{"key": args["key"], "type": "INC", "subject": "  api   en erreur ", "status": "NEW", "org": "ORG-1"}
	default:
		v = map[string]any{"items": []any{
			map[string]any{"key": "TCK-1", "type": "INC", "subject": "même ticket", "status": "NEW", "org": "ORG-1"},
			map[string]any{"key": "TCK-7", "type": "XYZ", "subject": "autre", "status": "CLOSED", "org": "ORG-1"},
		}}
	}
	b, _ := json.Marshal(v)
	return &MCPResult{Text: string(b), Data: b}, nil
}

func TestTicketsRuntime(t *testing.T) {
	tpl := writeTicketsTemplate(t)
	in, err := NewInstance("tickets", tpl, map[string]any{"customer": "ORG-1"})
	if err != nil {
		t.Fatal(err)
	}
	c := &ticketCaller{}
	in.MCP = func(context.Context, string) (MCPCaller, error) { return c, nil }
	if got := in.TicketIDs("voir tck-123 et TCK-123, puis TCK-4567 ; pas TCK-12 ni TCK-1234567"); strings.Join(got, ",") != "TCK-123,TCK-4567" {
		t.Fatalf("identifiants: %v", got)
	}
	tk, err := in.TicketGet(context.Background(), "TCK-1")
	if err != nil || tk == nil || tk.Kind != TicketIncident || tk.Title != "api en erreur" || tk.Scope[0] != "ORG-1" {
		t.Fatalf("lecture: %+v %v", tk, err)
	}
	found, err := in.TicketSearch(context.Background(), TicketQuery{Query: "api", Limit: 10, Exclude: "TCK-1"})
	if err != nil || len(found) != 1 || found[0].ID != "TCK-7" || found[0].Kind != TicketOther {
		t.Fatalf("recherche: %+v %v", found, err)
	}
	if c.args[1]["filter"] != "api org:ORG-1" {
		t.Fatalf("filtre: %v", c.args[1])
	}
}

func TestTicketsSpec(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.star"), []byte("def get(id):\n    return None\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "x.yaml")
	for _, tc := range []struct{ yaml, want string }{
		{"name: x\nkind: tickets\nscript: x.star\n", "id_pattern"},
		{"name: x\nkind: tickets\nscript: x.star\nid_pattern: \"(\"\n", "id_pattern"},
		{"name: x\nkind: tickets\nid_pattern: X\ntargets: [{kind: a}]\n", "script"},
		{"name: x\nkind: tickets\nscript: x.star\nid_pattern: X\nconnectors: {s: {driver: local}}\n", "local"},
		{"name: x\ntargets: [{kind: a}]\nid_pattern: X\n", "id_pattern"},
	} {
		if _, err := Parse([]byte(tc.yaml), p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: %v", tc.yaml, err)
		}
	}
	yaml := "name: x\nkind: tickets\nscript: x.star\nid_pattern: X\n"
	tpl, err := Parse([]byte(yaml), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), "search") {
		t.Fatalf("search absent: %v", err)
	}
}
