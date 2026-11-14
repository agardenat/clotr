package ticket

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

type fakeSource struct {
	queries []template.TicketQuery
}

func (f *fakeSource) TicketGet(_ context.Context, id string) (*template.Ticket, error) {
	if id == "TCK-404" {
		return nil, nil
	}
	return &template.Ticket{ID: id, Kind: template.TicketIncident, Title: "disque plein", Status: "CLOSED", Closed: "2026-01-02", Resolution: "purge des journaux, rotation ajoutée"}, nil
}

func (f *fakeSource) TicketSearch(_ context.Context, q template.TicketQuery) ([]template.Ticket, error) {
	f.queries = append(f.queries, q)
	return []template.Ticket{
		{ID: "TCK-20", Kind: template.TicketIncident, Title: "disque plein sur web1", Status: "CLOSED", Resolution: "rotation des journaux"},
		{ID: "TCK-21", Kind: template.TicketIncident, Title: "api lente", Status: "NEW"},
	}, nil
}

type sink struct {
	mu     sync.Mutex
	events []progress.Event
}

func (s *sink) Emit(e progress.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func call(t *testing.T, tl tools.Tool, args string) (string, error) {
	t.Helper()
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: TaskID})
	return tl.Call(ctx, json.RawMessage(args))
}

func byName(s *Store) map[string]tools.Tool {
	out := map[string]tools.Tool{}
	for _, tl := range s.Tools() {
		out[tl.Name()] = tl
	}
	return out
}

func TestToolsAndBlocks(t *testing.T) {
	i18n.SetReport("fr")
	src := &fakeSource{}
	ev := evidence.Open(t.TempDir(), 1)
	s := New(src, ev, audit.Nop())
	events := &sink{}
	s.Events = events
	s.SetMain(&template.Ticket{ID: "TCK-1", Kind: template.TicketIncident, Title: "web1 ne répond plus", Status: "NEW", Customer: "ORG-1", Description: "erreur 502"})
	main := s.Record()
	if main == "" || !ev.Has(main) {
		t.Fatalf("preuve du ticket: %q", main)
	}
	tl := byName(s)
	out, err := call(t, tl[SearchTool], `{"query":"disque plein","state":"closed"}`)
	if err != nil || !strings.Contains(out, "TCK-20") || !strings.Contains(out, "rotation des journaux") {
		t.Fatalf("recherche: %q %v", out, err)
	}
	if q := src.queries[0]; q.Customer != "ORG-1" || q.Exclude != "TCK-1" || q.Limit != 20 || q.State != "closed" {
		t.Fatalf("requête: %+v", q)
	}
	if _, err := call(t, tl[SearchTool], `{"query":"x","all_customers":true,"limit":500}`); err != nil {
		t.Fatal(err)
	}
	if q := src.queries[1]; q.Customer != "" || q.Limit != 50 {
		t.Fatalf("tous clients: %+v", q)
	}
	searched := ev.Add(TaskID, SearchTool, "{}", out, nil)
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-99","relation":"similar","summary":"x","evidence":["`+searched+`"]}`); err == nil || !strings.Contains(err.Error(), "non lu") {
		t.Fatalf("ticket jamais lu accepté: %v", err)
	}
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-1","relation":"similar","summary":"x","evidence":["`+searched+`"]}`); err == nil {
		t.Fatal("ticket de la demande accepté comme ticket lié")
	}
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-20","relation":"current","summary":"x","evidence":["`+searched+`"]}`); err == nil {
		t.Fatal("current accepté alors que la demande a son ticket")
	}
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-20","relation":"similar","summary":"x","evidence":["E999"]}`); err == nil {
		t.Fatal("preuve inconnue acceptée")
	}
	if _, err := call(t, tl[RelatedTool], `{"id":"tck-20","relation":"similar","summary":"même disque plein","resolution":"rotation des journaux","evidence":["`+searched+`"]}`); err != nil {
		t.Fatal(err)
	}
	if out, _ := call(t, tl[RelatedTool], `{"id":"TCK-20","relation":"similar","summary":"y","evidence":["`+searched+`"]}`); !strings.Contains(out, "déjà") {
		t.Fatalf("doublon: %q", out)
	}
	rel := s.Related()
	if len(rel) != 1 || rel[0].ID != "TCK-20" || rel[0].Title != "disque plein sur web1" || rel[0].Evidence[0] != "["+searched+"]" {
		t.Fatalf("tickets liés: %+v", rel)
	}
	if len(events.events) != 1 || events.events[0].Kind != "ticket" || !strings.Contains(events.events[0].Detail, "TCK-20") {
		t.Fatalf("événements: %+v", events.events)
	}
	brief := s.Brief()
	if !strings.Contains(brief, "TCK-1 (incident") || !strings.Contains(brief, "["+main+"]") || !strings.Contains(brief, "TCK-20 (similaire") {
		t.Fatalf("brief: %s", brief)
	}
	blocks, order := s.Blocks()
	if strings.Join(order, ",") != BlockTicket+","+BlockRelated {
		t.Fatalf("ordre: %v", order)
	}
	if !strings.Contains(blocks[BlockTicket], "**Ticket TCK-1**") || !strings.Contains(blocks[BlockTicket], "statut NEW") {
		t.Fatalf("bloc ticket: %s", blocks[BlockTicket])
	}
	if !strings.Contains(blocks[BlockRelated], "| TCK-20 — disque plein sur web1 | similaire |") {
		t.Fatalf("bloc tickets liés: %s", blocks[BlockRelated])
	}
	out, err = call(t, tl[GetTool], `{"id":"TCK-404"}`)
	if err != nil || !strings.Contains(out, "introuvable") {
		t.Fatalf("ticket absent: %q %v", out, err)
	}
}

func TestProbableTicket(t *testing.T) {
	i18n.SetReport("fr")
	ev := evidence.Open(t.TempDir(), 1)
	s := New(&fakeSource{}, ev, audit.Nop())
	tl := byName(s)
	out, err := call(t, tl[SearchTool], `{"query":"api","state":"open","since_days":7}`)
	if err != nil {
		t.Fatal(err)
	}
	id := ev.Add(TaskID, SearchTool, "{}", out, nil)
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-21","relation":"current","summary":"même api lente","evidence":["`+id+`"]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, tl[RelatedTool], `{"id":"TCK-20","relation":"current","summary":"x","evidence":["`+id+`"]}`); err == nil {
		t.Fatal("deux tickets probables acceptés")
	}
	blocks, _ := s.Blocks()
	if !strings.Contains(blocks[BlockTicket], "Ticket probable (à confirmer)") || !strings.Contains(blocks[BlockTicket], "TCK-21") {
		t.Fatalf("bloc ticket probable: %s", blocks[BlockTicket])
	}
	if s.Record() != "" {
		t.Fatal("preuve enregistrée sans ticket")
	}
}

func TestEmpty(t *testing.T) {
	s := New(&fakeSource{}, nil, nil)
	if s.Brief() != "" {
		t.Fatal("brief sans ticket")
	}
	if blocks, order := s.Blocks(); len(blocks)+len(order) != 0 {
		t.Fatal("blocs sans ticket")
	}
}
