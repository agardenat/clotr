package ticket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	GetTool     = "ticket_get"
	SearchTool  = "ticket_search"
	RelatedTool = "ticket_related"
	TaskID      = "tickets"
	Current     = "current"
	Similar     = "similar"

	BlockTicket  = "ticket"
	BlockRelated = "tickets.related"
)

type Source interface {
	TicketGet(ctx context.Context, id string) (*template.Ticket, error)
	TicketSearch(ctx context.Context, q template.TicketQuery) ([]template.Ticket, error)
}

type Related struct {
	ID         string   `json:"id"`
	Relation   string   `json:"relation"`
	Kind       string   `json:"kind"`
	Title      string   `json:"title"`
	Status     string   `json:"status,omitempty"`
	Opened     string   `json:"opened,omitempty"`
	Closed     string   `json:"closed,omitempty"`
	URL        string   `json:"url,omitempty"`
	Summary    string   `json:"summary"`
	Resolution string   `json:"resolution,omitempty"`
	Evidence   []string `json:"evidence"`
	Task       string   `json:"task,omitempty"`
}

type Store struct {
	Events progress.Sink
	Mode   string
	src    Source
	ev     *evidence.Store
	audit  *audit.Logger

	mu      sync.Mutex
	main    *template.Ticket
	mainEv  string
	seen    map[string]template.Ticket
	related []Related
}

func New(src Source, ev *evidence.Store, log *audit.Logger) *Store {
	if log == nil {
		log = audit.Nop()
	}
	return &Store{Events: progress.Nop{}, src: src, ev: ev, audit: log, seen: map[string]template.Ticket{}}
}

func (s *Store) SetMain(t *template.Ticket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.main = t
	if t != nil {
		s.seen[strings.ToUpper(t.ID)] = *t
	}
}

func (s *Store) Restore(main *template.Ticket, related []Related) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if main != nil {
		s.main = main
		s.seen[strings.ToUpper(main.ID)] = *main
	}
	s.related = append(s.related, related...)
}

func (s *Store) Main() *template.Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.main
}

func (s *Store) MainEvidence() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mainEv
}

func (s *Store) Related() []Related {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.related)
}

func (s *Store) Record() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.main == nil || s.ev == nil {
		return ""
	}
	args, _ := json.Marshal(map[string]string{"id": s.main.ID})
	s.mainEv = s.ev.Add(TaskID, GetTool, string(args), Format(*s.main, -1), nil)
	s.audit.Log("ticket_main", map[string]any{"ticket": s.main, "evidence": s.mainEv})
	return s.mainEv
}

func (s *Store) Tools() []tools.Tool {
	return []tools.Tool{getTool{s}, searchTool{s}, relatedTool{s}}
}

func ToolNames() []string {
	return []string{GetTool, SearchTool, RelatedTool}
}

func KindLabel(kind string) string {
	switch kind {
	case template.TicketIncident:
		return "incident"
	case template.TicketChange:
		return "demande de changement"
	}
	return "autre"
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if n < 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n])) + " […]"
}

func header(t template.Ticket) string {
	parts := []string{KindLabel(t.Kind)}
	if t.Category != "" {
		parts = append(parts, t.Category)
	}
	if t.Status != "" {
		parts = append(parts, "statut "+t.Status)
	}
	if t.Opened != "" {
		parts = append(parts, "ouvert le "+t.Opened)
	}
	if t.Closed != "" {
		parts = append(parts, "résolu le "+t.Closed)
	}
	if t.Customer != "" {
		parts = append(parts, "client "+t.Customer)
	}
	return fmt.Sprintf("%s (%s) : %s", t.ID, strings.Join(parts, ", "), t.Title)
}

func Format(t template.Ticket, limit int) string {
	var b strings.Builder
	b.WriteString(header(t))
	if t.URL != "" {
		b.WriteString("\nLien : " + t.URL)
	}
	if t.Description != "" {
		b.WriteString("\nDescription :\n" + clip(t.Description, limit))
	}
	if t.Resolution != "" {
		b.WriteString("\nRésolution :\n" + clip(t.Resolution, limit))
	}
	comments := t.Comments
	if limit >= 0 && len(comments) > 5 {
		comments = comments[len(comments)-5:]
		fmt.Fprintf(&b, "\nCommentaires (5 derniers sur %d) :", len(t.Comments))
	} else if len(comments) > 0 {
		b.WriteString("\nCommentaires :")
	}
	for _, c := range comments {
		head := strings.TrimSpace(c.Time + " " + c.Author)
		if head != "" {
			head += " : "
		}
		b.WriteString("\n- " + head + clip(strings.Join(strings.Fields(c.Body), " "), max(limit/2, -1)))
	}
	return b.String()
}

func (s *Store) Brief() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	if s.main != nil {
		ref := ""
		if s.mainEv != "" {
			ref = " [" + s.mainEv + "]"
		}
		b.WriteString("Ticket de la demande" + ref + " :\n" + Format(*s.main, 3000))
	}
	if len(s.related) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("Tickets liés relevés dans l'outil de tickets (résolutions passées : pistes à vérifier par les preuves de ce run, jamais des causes établies) :")
		for _, r := range s.related {
			b.WriteString("\n- " + r.line())
		}
	}
	return b.String()
}

func (r Related) line() string {
	rel := "similaire"
	if r.Relation == Current {
		rel = "ticket probable de cet incident, non confirmé"
	}
	parts := []string{rel, KindLabel(r.Kind)}
	if r.Status != "" {
		parts = append(parts, r.Status)
	}
	if r.Closed != "" {
		parts = append(parts, "résolu le "+r.Closed)
	} else if r.Opened != "" {
		parts = append(parts, "ouvert le "+r.Opened)
	}
	out := fmt.Sprintf("%s (%s) %s : %s", r.ID, strings.Join(parts, ", "), r.Title, r.Summary)
	if r.Resolution != "" {
		out += " ; résolution : " + r.Resolution
	}
	return out + " " + strings.Join(r.Evidence, "")
}

func (s *Store) Blocks() (map[string]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	blocks := map[string]string{}
	var order []string
	if t := s.main; t != nil {
		blocks[BlockTicket] = ticketBlock(*t, false, s.mainEv)
		order = append(order, BlockTicket)
	} else if i := slices.IndexFunc(s.related, func(r Related) bool { return r.Relation == Current }); i >= 0 {
		r := s.related[i]
		blocks[BlockTicket] = ticketBlock(template.Ticket{ID: r.ID, Kind: r.Kind, Title: r.Title, Status: r.Status, Opened: r.Opened, URL: r.URL}, true, strings.Join(r.Evidence, ""))
		order = append(order, BlockTicket)
	}
	if len(s.related) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n|---|---|---|---|---|", i18n.R("ticket.col.ticket"), i18n.R("ticket.col.relation"), i18n.R("ticket.col.status"), i18n.R("ticket.col.summary"), i18n.R("ticket.col.resolution"))
		for _, r := range s.related {
			id := r.ID
			if r.URL != "" {
				id = "[" + r.ID + "](" + r.URL + ")"
			}
			status := r.Status
			if r.Closed != "" {
				status = strings.TrimSpace(status + " " + r.Closed)
			}
			fmt.Fprintf(&b, "\n| %s — %s | %s | %s | %s %s | %s |", id, cell(r.Title), i18n.R("ticket.rel."+r.Relation), cell(status), cell(r.Summary), strings.Join(r.Evidence, ""), cell(r.Resolution))
		}
		blocks[BlockRelated] = b.String()
		order = append(order, BlockRelated)
	}
	return blocks, order
}

func cell(s string) string {
	return strings.ReplaceAll(strings.Join(strings.Fields(s), " "), "|", "\\|")
}

func ticketBlock(t template.Ticket, probable bool, ev string) string {
	label := i18n.R("ticket.label")
	if probable {
		label = i18n.R("ticket.probable")
	}
	id := t.ID
	if t.URL != "" {
		id = "[" + t.ID + "](" + t.URL + ")"
	}
	parts := []string{i18n.R("ticket.kind." + t.Kind)}
	if t.Category != "" {
		parts = append(parts, t.Category)
	}
	if t.Status != "" {
		parts = append(parts, i18n.R("ticket.status", t.Status))
	}
	if t.Opened != "" {
		parts = append(parts, i18n.R("ticket.opened", t.Opened))
	}
	if t.Customer != "" {
		parts = append(parts, i18n.R("ticket.customer", t.Customer))
	}
	out := fmt.Sprintf("> **%s %s** — %s  \n> %s", label, id, cell(t.Title), strings.Join(parts, " · "))
	if ev != "" {
		out += " " + ev
	}
	return out
}

func (s *Store) remember(ts ...template.Ticket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range ts {
		s.seen[strings.ToUpper(t.ID)] = t
	}
}

type getTool struct{ s *Store }

func (getTool) Name() string { return GetTool }
func (getTool) Description() string {
	return "Lit un ticket de l'outil de tickets par son identifiant : description, statut, résolution et commentaires."
}
func (getTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"identifiant du ticket"}},"required":["id"]}`)
}
func (t getTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		ID string `json:"id"`
	}](raw)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(a.ID)
	if id == "" {
		return "", errors.New("id requis")
	}
	tk, err := t.s.src.TicketGet(ctx, id)
	if err != nil {
		return "", err
	}
	if tk == nil {
		return fmt.Sprintf("ticket %s introuvable", id), nil
	}
	t.s.remember(*tk)
	return Format(*tk, 4000), nil
}

type searchTool struct{ s *Store }

func (searchTool) Name() string { return SearchTool }
func (searchTool) Description() string {
	return "Recherche des tickets dans l'outil de tickets (texte intégral sur le titre et la description), par défaut chez le même client que le ticket de la demande. Requêtes courtes : un ou deux termes distinctifs (composant, message d'erreur sans identifiant variable, nom de ressource), pas une phrase ; plusieurs requêtes courtes plutôt qu'une longue. Renvoie une ligne par ticket ; lis le détail d'un ticket pertinent avec " + GetTool + "."
}
func (searchTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"termes recherchés"},"kind":{"type":"string","enum":["incident","change","any"],"description":"type de ticket (any par défaut)"},"state":{"type":"string","enum":["open","closed","any"],"description":"open : en cours ; closed : résolus ou fermés ; any par défaut"},"since_days":{"type":"integer","description":"tickets créés depuis N jours (0 : sans limite)"},"limit":{"type":"integer","description":"nombre maximal de tickets (20 par défaut, 50 au plus)"},"all_customers":{"type":"boolean","description":"true : tous clients confondus (même produit ou même message chez d'autres clients)"}},"required":["query"]}`)
}
func (t searchTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Query        string `json:"query"`
		Kind         string `json:"kind"`
		State        string `json:"state"`
		SinceDays    int    `json:"since_days"`
		Limit        int    `json:"limit"`
		AllCustomers bool   `json:"all_customers"`
	}](raw)
	if err != nil {
		return "", err
	}
	q := template.TicketQuery{Query: strings.TrimSpace(a.Query), Kind: a.Kind, State: a.State, SinceDays: max(a.SinceDays, 0), Limit: a.Limit, AllCustomers: a.AllCustomers}
	if q.Query == "" {
		return "", errors.New("query requis")
	}
	if q.Kind == "any" {
		q.Kind = ""
	}
	if q.State == "any" {
		q.State = ""
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	q.Limit = min(q.Limit, 50)
	if m := t.s.Main(); m != nil {
		q.Exclude = m.ID
		if !q.AllCustomers {
			q.Customer = m.Customer
		}
	}
	found, err := t.s.src.TicketSearch(ctx, q)
	if err != nil {
		return "", err
	}
	t.s.remember(found...)
	if len(found) == 0 {
		return "aucun ticket trouvé", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d ticket(s) :", len(found))
	for _, tk := range found {
		b.WriteString("\n- " + header(tk))
		if tk.Resolution != "" {
			b.WriteString(" — résolution : " + clip(strings.Join(strings.Fields(tk.Resolution), " "), 300))
		}
	}
	return b.String(), nil
}

type relatedTool struct{ s *Store }

func (relatedTool) Name() string { return RelatedTool }
func (relatedTool) Description() string {
	return "Enregistre un ticket lié à la demande, lu avec " + SearchTool + " ou " + GetTool + " dans ce run : relation similar pour un ticket passé qui traite d'un problème ou d'une demande semblable (même composant, même symptôme ou message, même modification), current pour un ticket ouvert récent qui semble porter sur ce même incident. summary : ce qu'il a en commun avec la demande ; resolution : ce qui a été fait pour le résoudre ou le réaliser, d'après le ticket (vide si rien n'est indiqué). Il est affiché à l'utilisateur, transmis aux tâches suivantes et repris dans le rapport. Un ticket sans rapport réel avec la demande ne s'enregistre pas."
}
func (relatedTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"identifiant du ticket"},"relation":{"type":"string","enum":["similar","current"]},"summary":{"type":"string","description":"ce qu'il a en commun avec la demande, en une phrase"},"resolution":{"type":"string","description":"résolution appliquée d'après le ticket"},"evidence":{"type":"array","items":{"type":"string"},"description":"identifiants des preuves [Exxx] où le ticket a été lu"}},"required":["id","relation","summary","evidence"]}`)
}
func (t relatedTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		ID         string           `json:"id"`
		Relation   string           `json:"relation"`
		Summary    string           `json:"summary"`
		Resolution string           `json:"resolution"`
		Evidence   tools.StringList `json:"evidence"`
	}](raw)
	if err != nil {
		return "", err
	}
	if a.Relation != Similar && a.Relation != Current {
		return "", fmt.Errorf("relation %q invalide (similar|current)", a.Relation)
	}
	summary := strings.Join(strings.Fields(a.Summary), " ")
	if summary == "" {
		return "", errors.New("summary requis")
	}
	id := strings.ToUpper(strings.TrimSpace(a.ID))
	t.s.mu.Lock()
	tk, ok := t.s.seen[id]
	isMain := t.s.main != nil && strings.EqualFold(t.s.main.ID, id)
	dup := slices.ContainsFunc(t.s.related, func(r Related) bool { return strings.EqualFold(r.ID, id) })
	hasCurrent := slices.ContainsFunc(t.s.related, func(r Related) bool { return r.Relation == Current })
	t.s.mu.Unlock()
	switch {
	case !ok:
		return "", fmt.Errorf("ticket %s non lu dans ce run : trouve-le avec %s ou lis-le avec %s", id, SearchTool, GetTool)
	case isMain:
		return "", fmt.Errorf("%s est le ticket de la demande : n'enregistre que des tickets liés", id)
	case dup:
		return fmt.Sprintf("ticket %s déjà enregistré", id), nil
	case a.Relation == Current && t.s.Main() != nil:
		return "", errors.New("la demande a déjà son ticket : relation current impossible, utilise similar")
	case a.Relation == Current && hasCurrent:
		return "", errors.New("un ticket probable (current) est déjà enregistré : les autres sont similar")
	}
	var ids []string
	for _, e := range a.Evidence {
		e = strings.Trim(strings.TrimSpace(e), "[]")
		if t.s.ev != nil && !t.s.ev.Has(e) {
			return "", fmt.Errorf("preuve %s inconnue dans ce run : cite l'identifiant [Exxx] de la sortie où le ticket a été lu", e)
		}
		ids = append(ids, "["+e+"]")
	}
	if len(ids) == 0 {
		return "", errors.New("au moins une preuve requise")
	}
	c := tools.CallerFrom(ctx)
	r := Related{ID: tk.ID, Relation: a.Relation, Kind: tk.Kind, Title: tk.Title, Status: tk.Status, Opened: tk.Opened, Closed: tk.Closed, URL: tk.URL, Summary: summary, Resolution: strings.Join(strings.Fields(a.Resolution), " "), Evidence: ids, Task: c.Task}
	t.s.mu.Lock()
	t.s.related = append(t.s.related, r)
	t.s.mu.Unlock()
	t.s.audit.Log("ticket_related", map[string]any{"task": c.Task, "model": c.Model, "related": r})
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "ticket", Model: c.Model, Effort: c.Effort, Detail: i18n.T("ticket.related."+r.Relation, r.ID, r.Title, r.Summary)})
	return fmt.Sprintf("ticket %s enregistré (%s) : affiché à l'utilisateur et transmis aux tâches suivantes", r.ID, r.Relation), nil
}
