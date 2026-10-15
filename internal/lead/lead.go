package lead

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	ToolName    = "cause_report"
	Kind        = "lead"
	Established = "established"
	Probable    = "probable"
	Superseded  = "superseded"
)

type Store struct {
	Events   progress.Sink
	mem      *memory.Store
	ev       *evidence.Store
	audit    *audit.Logger
	since    time.Time
	mu       sync.Mutex
	n        int
	seen     map[string]int
	reported map[string]string
}

func New(mem *memory.Store, ev *evidence.Store, log *audit.Logger) *Store {
	return &Store{Events: progress.Nop{}, mem: mem, ev: ev, audit: log, since: time.Now(), seen: map[string]int{}, reported: map[string]string{}}
}

func (s *Store) Tool() tools.Tool { return reportTool{s} }

func (s *Store) Leads() []memory.Entry {
	var out []memory.Entry
	for _, e := range s.mem.All() {
		if e.Kind == Kind && !e.Time.Before(s.since) {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) Inbox(reader tools.Caller) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.seen[reader.Task]
	var b strings.Builder
	for _, e := range s.Leads() {
		if e.ID <= last {
			continue
		}
		s.seen[reader.Task] = e.ID
		if e.Task == reader.Task || (e.Sovereign && !reader.Sovereign) {
			continue
		}
		fmt.Fprintf(&b, "- %s #%d : %s\n", e.Task, e.ID, e.Content)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

type reportTool struct{ s *Store }

func (reportTool) Name() string { return ToolName }

func (reportTool) Description() string {
	return "Signale tout de suite une cause du dysfonctionnement décrit dans la demande (message d'erreur exact, configuration fautive), appuyée par au moins une preuve [Exxx], sans attendre ta conclusion : l'utilisateur la voit aussitôt et les autres tâches la reçoivent. status established si une preuve la démontre (message d'erreur, configuration), probable sinon. Une anomalie sans lien avec ce dysfonctionnement n'est pas une cause : elle va dans tes constats, pas ici. Un signal par cause, puis poursuis ta tâche (vérification, correctif). Une cause qui en contredit ou en corrige une déjà signalée (la tienne ou celle d'une autre tâche, numéro #N) la remplace : replaces=N. Une cause négative (« ce n'est pas X ») n'est established que si la preuve couvre toute la période en cause, événements les plus récents compris."
}

func (reportTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string","description":"la cause en une phrase, avec le code ou le message d'erreur exact"},"evidence":{"type":"array","items":{"type":"string"},"description":"identifiants des preuves qui l'établissent, ex: [\"E012\"]"},"status":{"type":"string","enum":["established","probable"],"description":"established : démontrée par une preuve ; probable : indices sans preuve directe"},"replaces":{"type":"integer","description":"numéro #N d'une cause signalée plus tôt dans ce run que celle-ci corrige ou infirme : elle est retirée et la correction est affichée"}},"required":["summary","evidence","status"]}`)
}

func (t reportTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Summary  string           `json:"summary"`
		Evidence tools.StringList `json:"evidence"`
		Status   string           `json:"status"`
		Replaces int              `json:"replaces"`
	}](raw)
	if err != nil {
		return "", err
	}
	summary := strings.Join(strings.Fields(a.Summary), " ")
	if summary == "" {
		return "", errors.New("summary requis")
	}
	if a.Status != Established && a.Status != Probable {
		return "", fmt.Errorf("status %q invalide (established|probable)", a.Status)
	}
	var ids []string
	for _, id := range a.Evidence {
		id = strings.Trim(strings.TrimSpace(id), "[]")
		if !t.s.ev.Has(id) {
			return "", fmt.Errorf("preuve %s inconnue dans ce run : cite l'identifiant [Exxx] d'une sortie d'outil", id)
		}
		ids = append(ids, "["+id+"]")
	}
	if len(ids) == 0 {
		return "", errors.New("au moins une preuve requise")
	}
	var old memory.Entry
	if a.Replaces != 0 {
		found := false
		for _, e := range t.s.Leads() {
			if e.ID == a.Replaces {
				old, found = e, true
			}
		}
		if !found {
			return "", fmt.Errorf("cause #%d inconnue dans ce run : replaces prend le numéro renvoyé par cause_report", a.Replaces)
		}
		if slices.Contains(old.Tags, Superseded) {
			return "", fmt.Errorf("cause #%d déjà remplacée : remplace la cause qui la corrige", a.Replaces)
		}
	}
	c := tools.CallerFrom(ctx)
	norm := strings.ToLower(summary)
	t.s.mu.Lock()
	if prev, dup := t.s.reported[norm]; dup {
		t.s.mu.Unlock()
		return fmt.Sprintf("cause déjà signalée par %s : ne la signale pas à nouveau ; poursuis ta tâche", prev), nil
	}
	t.s.reported[norm] = c.Task
	t.s.n++
	key := fmt.Sprintf("cause/%s/%d", c.Task, t.s.n)
	t.s.mu.Unlock()
	content := fmt.Sprintf("%s %s %s", label(a.Status), summary, strings.Join(ids, ""))
	if a.Replaces != 0 {
		content += fmt.Sprintf(" (corrige #%d)", a.Replaces)
	}
	id, err := t.s.mem.Put(memory.Entry{Key: key, Content: content, Tags: []string{"cause", a.Status}, Kind: Kind, Task: c.Task, Model: c.Model, Sovereign: c.Sovereign})
	if err != nil {
		return "", err
	}
	if a.Replaces != 0 {
		old.Content = fmt.Sprintf("[remplacée par #%d] %s", id, old.Content)
		old.Tags = []string{"cause", Superseded}
		if _, err := t.s.mem.Put(old); err != nil {
			return "", err
		}
	}
	t.s.audit.Log("lead", map[string]any{"task": c.Task, "model": c.Model, "status": a.Status, "summary": summary, "evidence": ids, "memory_id": id, "replaces": a.Replaces})
	detail := i18n.T("lead."+a.Status, id, summary+" "+strings.Join(ids, ""))
	if a.Replaces != 0 {
		detail += i18n.T("lead.replaces", a.Replaces)
	}
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "lead", Model: c.Model, Detail: detail})
	return fmt.Sprintf("cause signalée (#%d) : affichée à l'utilisateur et transmise aux autres tâches ; poursuis ta tâche", id), nil
}

func label(status string) string {
	if status == Established {
		return "[cause établie]"
	}
	return "[cause probable]"
}
