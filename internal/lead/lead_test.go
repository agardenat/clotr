package lead

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

type sink struct {
	mu     sync.Mutex
	events []progress.Event
}

func (s *sink) Emit(e progress.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func TestReportAndInbox(t *testing.T) {
	mem := memory.NewStore()
	ev := evidence.Open(t.TempDir(), 1)
	id := ev.Add("t1", "az_activity_log", "{}", "Failed AllocationFailed", nil)
	s := New(mem, ev, audit.Nop())
	events := &sink{}
	s.Events = events
	tool := s.Tool()
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1", Model: "p/m", Sovereign: true})

	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"x","evidence":["E999"],"status":"established"}`)); err == nil || !strings.Contains(err.Error(), "E999") {
		t.Fatalf("preuve inconnue acceptée: %v", err)
	}
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"x","evidence":[],"status":"established"}`)); err == nil {
		t.Fatal("signal sans preuve accepté")
	}
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"x","evidence":["`+id+`"],"status":"sure"}`)); err == nil {
		t.Fatal("status invalide accepté")
	}
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"AllocationFailed : capacité insuffisante","evidence":["[`+id+`]"],"status":"established"}`)); err != nil {
		t.Fatal(err)
	}

	other := tools.WithCaller(context.Background(), tools.Caller{Task: "t2", Sovereign: true})
	if out, err := tool.Call(other, json.RawMessage(`{"summary":"allocationfailed :  capacité insuffisante","evidence":["`+id+`"],"status":"probable"}`)); err != nil || !strings.Contains(out, "déjà signalée par t1") {
		t.Fatalf("doublon: %q %v", out, err)
	}

	leads := s.Leads()
	if len(leads) != 1 || leads[0].Kind != Kind || leads[0].Task != "t1" || leads[0].Content != "[cause établie] AllocationFailed : capacité insuffisante [E001]" {
		t.Fatalf("entrée mémoire: %+v", leads)
	}
	if len(events.events) != 1 || events.events[0].Kind != "lead" || events.events[0].Task != "t1" || !strings.Contains(events.events[0].Detail, "AllocationFailed") {
		t.Fatalf("événement: %+v", events.events)
	}

	if got := s.Inbox(tools.Caller{Task: "t1", Sovereign: true}); got != "" {
		t.Fatalf("piste renvoyée à sa propre tâche: %q", got)
	}
	if got := s.Inbox(tools.Caller{Task: "t2", Sovereign: true}); got != "- t1 #1 : [cause établie] AllocationFailed : capacité insuffisante [E001]" {
		t.Fatalf("boîte de réception: %q", got)
	}
	if got := s.Inbox(tools.Caller{Task: "t2", Sovereign: true}); got != "" {
		t.Fatalf("piste transmise deux fois: %q", got)
	}
	if got := s.Inbox(tools.Caller{Task: "t3", Sovereign: false}); got != "" {
		t.Fatalf("piste souveraine transmise à un modèle non souverain: %q", got)
	}
	if mem.Stats().ExposedToForeign != 0 {
		t.Fatal("croisement de souveraineté")
	}
}

func TestReplaces(t *testing.T) {
	mem := memory.NewStore()
	ev := evidence.Open(t.TempDir(), 1)
	old := ev.Add("t1", "az_activity_log", "{}", "VMExtensionProvisioningError", nil)
	recent := ev.Add("t1", "az_activity_log", "{}", "AllocationFailed", nil)
	s := New(mem, ev, audit.Nop())
	events := &sink{}
	s.Events = events
	tool := s.Tool()
	t1 := tools.WithCaller(context.Background(), tools.Caller{Task: "t1", Sovereign: true})
	if _, err := tool.Call(t1, json.RawMessage(`{"summary":"extension en échec, pas de capacité en cause","evidence":["`+old+`"],"status":"established"}`)); err != nil {
		t.Fatal(err)
	}
	if got := s.Inbox(tools.Caller{Task: "t2", Sovereign: true}); !strings.HasPrefix(got, "- t1 #1 : ") {
		t.Fatalf("boîte de réception: %q", got)
	}
	if _, err := tool.Call(t1, json.RawMessage(`{"summary":"x","evidence":["`+recent+`"],"status":"established","replaces":7}`)); err == nil || !strings.Contains(err.Error(), "#7 inconnue") {
		t.Fatalf("remplacement d'une cause inconnue accepté: %v", err)
	}
	out, err := tool.Call(t1, json.RawMessage(`{"summary":"AllocationFailed le plus récent","evidence":["`+recent+`"],"status":"established","replaces":1}`))
	if err != nil || !strings.Contains(out, "#2") {
		t.Fatalf("remplacement: %q %v", out, err)
	}
	leads := s.Leads()
	if len(leads) != 2 || leads[0].Content != "[remplacée par #2] [cause établie] extension en échec, pas de capacité en cause [E001]" || !slices.Contains(leads[0].Tags, Superseded) || slices.Contains(leads[0].Tags, Established) {
		t.Fatalf("cause remplacée: %+v", leads)
	}
	if leads[1].Content != "[cause établie] AllocationFailed le plus récent [E002] (corrige #1)" {
		t.Fatalf("cause de remplacement: %+v", leads[1])
	}
	if got := s.Inbox(tools.Caller{Task: "t2", Sovereign: true}); got != "- t1 #2 : [cause établie] AllocationFailed le plus récent [E002] (corrige #1)" {
		t.Fatalf("correction transmise: %q", got)
	}
	if len(events.events) != 2 || !strings.Contains(events.events[1].Detail, "#2") || !strings.Contains(events.events[1].Detail, "#1") {
		t.Fatalf("événements: %+v", events.events)
	}
	if _, err := tool.Call(t1, json.RawMessage(`{"summary":"y","evidence":["`+recent+`"],"status":"probable","replaces":1}`)); err == nil || !strings.Contains(err.Error(), "déjà remplacée") {
		t.Fatalf("double remplacement accepté: %v", err)
	}
}

func TestLeadsOfEarlierTurnsIgnored(t *testing.T) {
	mem := memory.NewStore()
	mem.Load([]memory.Entry{{ID: 1, Key: "cause/t1/1", Content: "ancienne", Kind: Kind, Task: "t1"}})
	s := New(mem, evidence.Open(t.TempDir(), 2), audit.Nop())
	if len(s.Leads()) != 0 || s.Inbox(tools.Caller{Task: "t2"}) != "" {
		t.Fatal("piste d'un tour précédent reprise")
	}
}

func TestClueThenEstablished(t *testing.T) {
	mem := memory.NewStore()
	ev := evidence.Open(t.TempDir(), 1)
	install := ev.Add("t0", "ssh_grep", "{}", "--forwarder 192.0.2.11", nil)
	config := ev.Add("t0", "ssh_read", "{}", "forwarders { 192.0.2.11; };", nil)
	s := New(mem, ev, audit.Nop())
	events := &sink{}
	s.Events = events
	tool := s.Tool()
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0", Sovereign: true})
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"192.0.2.11 posé comme forwarder à l'installation","evidence":["`+install+`"],"status":"clue"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"forwarders du serveur encore sur 192.0.2.11","evidence":["`+config+`"],"status":"established","replaces":1}`)); err != nil {
		t.Fatal(err)
	}
	leads := s.Leads()
	if len(leads) != 2 || leads[0].Content != "[remplacée par #2] [piste] 192.0.2.11 posé comme forwarder à l'installation [E001]" || !slices.Contains(leads[1].Tags, Established) {
		t.Fatalf("piste puis cause: %+v", leads)
	}
	if len(events.events) != 2 || !strings.Contains(events.events[0].Detail, "#1") || strings.Contains(events.events[0].Detail, "cause") {
		t.Fatalf("affichage de la piste: %+v", events.events)
	}
	if _, err := tool.Call(ctx, json.RawMessage(`{"summary":"z","evidence":["`+config+`"],"status":"hint"}`)); err == nil {
		t.Fatal("status inconnu accepté")
	}
}
