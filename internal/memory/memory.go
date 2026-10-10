package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/tools"
)

const maxContent = 4000

type Entry struct {
	ID        int       `json:"id"`
	Key       string    `json:"key"`
	Content   string    `json:"content"`
	Tags      []string  `json:"tags,omitempty"`
	Kind      string    `json:"kind"`
	Task      string    `json:"task"`
	Model     string    `json:"model,omitempty"`
	Sovereign bool      `json:"sovereign"`
	Time      time.Time `json:"time"`
}

type Store struct {
	mu        sync.Mutex
	entries   []Entry
	nextID    int
	crossings map[int]bool
}

func NewStore() *Store {
	return &Store{nextID: 1, crossings: map[int]bool{}}
}

func (s *Store) Load(entries []Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		s.entries = append(s.entries, e)
		if e.ID >= s.nextID {
			s.nextID = e.ID + 1
		}
	}
}

func (s *Store) Put(e Entry) (int, error) {
	if s == nil {
		return 0, errors.New("mémoire désactivée")
	}
	e.Key = strings.TrimSpace(e.Key)
	e.Content = strings.TrimSpace(e.Content)
	if e.Key == "" || e.Content == "" {
		return 0, errors.New("key et content requis")
	}
	if len(e.Content) > maxContent {
		e.Content = e.Content[:maxContent] + "…"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Time = time.Now()
	for i := range s.entries {
		if s.entries[i].Key == e.Key {
			e.ID = s.entries[i].ID
			s.entries[i] = e
			return e.ID, nil
		}
	}
	e.ID = s.nextID
	s.nextID++
	s.entries = append(s.entries, e)
	return e.ID, nil
}

func (s *Store) Search(query string, tags []string, limit int, reader tools.Caller) []Entry {
	if s == nil {
		return nil
	}
	terms := strings.Fields(strings.ToLower(query))
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
		if !matchTags(e.Tags, tags) {
			continue
		}
		hay := strings.ToLower(e.Key + " " + e.Content + " " + strings.Join(e.Tags, " ") + " " + e.Task)
		ok := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if e.Sovereign && !reader.Sovereign {
			s.crossings[e.ID] = true
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func matchTags(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if strings.EqualFold(h, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *Store) All() []Entry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Entry(nil), s.entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type Stats struct {
	Entries          int `json:"entries"`
	Sovereign        int `json:"sovereign"`
	ExposedToForeign int `json:"sovereign_exposed_to_non_sovereign"`
}

func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Entries: len(s.entries), ExposedToForeign: len(s.crossings)}
	for _, e := range s.entries {
		if e.Sovereign {
			st.Sovereign++
		}
	}
	return st
}

func (s *Store) Save(path string) error {
	data, err := json.MarshalIndent(map[string]any{"stats": s.Stats(), "entries": s.All()}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

var citesEvidence = regexp.MustCompile(`\bE(?:\d+\.)?\d{3,}\b`)

func Format(entries []Entry) string {
	if len(entries) == 0 {
		return "aucune entrée"
	}
	var b strings.Builder
	for _, e := range entries {
		origin := "souverain"
		if !e.Sovereign {
			origin = "non souverain"
		}
		proof := ""
		if !citesEvidence.MatchString(e.Content) {
			proof = ", sans preuve citée"
		}
		fmt.Fprintf(&b, "#%d [%s, %s, %s, %s%s] %s: %s", e.ID, e.Kind, e.Task, e.Time.UTC().Format("02/01 15:04Z"), origin, proof, e.Key, e.Content)
		if len(e.Tags) > 0 {
			fmt.Fprintf(&b, " (tags: %s)", strings.Join(e.Tags, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (s *Store) Tools() []tools.Tool {
	return []tools.Tool{writeTool{s}, searchTool{s}}
}

func (s *Store) TaskNotes(task string) string {
	var notes []Entry
	for _, e := range s.All() {
		if e.Kind == "note" && e.Task == task {
			notes = append(notes, e)
		}
	}
	if len(notes) == 0 {
		return ""
	}
	return Format(notes)
}

func ToolNames() []string {
	return []string{"memory_write", "memory_search"}
}

type writeTool struct{ s *Store }

func (writeTool) Name() string { return "memory_write" }
func (writeTool) Description() string {
	return "Enregistre un fait dans la mémoire partagée de la session (interne à clotr, aucune écriture sur l'infrastructure). Cite dans content la preuve [Exxx] dont le fait provient et l'heure de la mesure. Même key = mise à jour : corrige ainsi une note devenue fausse ou périmée."
}
func (writeTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","description":"identifiant court et stable, ex: prod/nodes/count"},"content":{"type":"string","description":"fait vérifié, concis"},"tags":{"type":"array","items":{"type":"string"},"description":"ex: prod, nodes, anomalie"}},"required":["key","content"]}`)
}

func (t writeTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Key     string           `json:"key"`
		Content string           `json:"content"`
		Tags    tools.StringList `json:"tags"`
	}](raw)
	if err != nil {
		return "", err
	}
	c := tools.CallerFrom(ctx)
	id, err := t.s.Put(Entry{Key: args.Key, Content: args.Content, Tags: args.Tags, Kind: "note", Task: c.Task, Model: c.Model, Sovereign: c.Sovereign})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("enregistré #%d", id), nil
}

type searchTool struct{ s *Store }

func (searchTool) Name() string { return "memory_search" }
func (searchTool) Description() string {
	return "Cherche dans la mémoire partagée du run (faits et constats des autres agents). query vide = entrées les plus récentes."
}
func (searchTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"mots-clés, tous requis"},"tags":{"type":"array","items":{"type":"string"}},"limit":{"type":"integer","description":"défaut 20"}}}`)
}

func (t searchTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Query string           `json:"query"`
		Tags  tools.StringList `json:"tags"`
		Limit int              `json:"limit"`
	}](raw)
	if err != nil {
		return "", err
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 20
	}
	return Format(t.s.Search(args.Query, args.Tags, limit, tools.CallerFrom(ctx))), nil
}
