package template

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/i18n"
)

const (
	TicketIncident = "incident"
	TicketChange   = "change"
	TicketOther    = "other"
)

type TicketComment struct {
	Time   string `json:"time,omitempty"`
	Author string `json:"author,omitempty"`
	Body   string `json:"body"`
}

type Ticket struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Category    string          `json:"category,omitempty"`
	Title       string          `json:"title"`
	Status      string          `json:"status,omitempty"`
	Customer    string          `json:"customer,omitempty"`
	Scope       []string        `json:"scope,omitempty"`
	Opened      string          `json:"opened,omitempty"`
	Closed      string          `json:"closed,omitempty"`
	URL         string          `json:"url,omitempty"`
	Description string          `json:"description,omitempty"`
	Resolution  string          `json:"resolution,omitempty"`
	Comments    []TicketComment `json:"comments,omitempty"`
}

type TicketQuery struct {
	Query        string `json:"query"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	SinceDays    int    `json:"since_days"`
	Limit        int    `json:"limit"`
	Customer     string `json:"customer"`
	AllCustomers bool   `json:"all_customers"`
	Exclude      string `json:"exclude"`
}

func (in *Instance) TicketPattern() *regexp.Regexp {
	if !in.T.Tickets() || in.T.IDPattern == "" {
		return nil
	}
	return regexp.MustCompile(`(?i)\b(?:` + in.T.IDPattern + `)\b`)
}

func (in *Instance) TicketIDs(text string) []string {
	re := in.TicketPattern()
	if re == nil {
		return nil
	}
	var out []string
	for _, m := range re.FindAllString(text, -1) {
		m = strings.ToUpper(m)
		if !containsFold(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func (in *Instance) ticketFn(name string) (starlark.Callable, error) {
	if !in.T.Tickets() || in.script == nil {
		return nil, i18n.E("tpl.tickets.not", in.T.Name)
	}
	fn, ok := in.script.globals[name].(starlark.Callable)
	if !ok {
		return nil, i18n.E("tpl.star.tickets", in.T.Script)
	}
	return fn, nil
}

func (in *Instance) TicketGet(ctx context.Context, id string) (*Ticket, error) {
	fn, err := in.ticketFn("get")
	if err != nil {
		return nil, err
	}
	v, err := in.call(ctx, "get", fn, starlark.String(id))
	if err != nil {
		return nil, scriptErr(err)
	}
	if v == starlark.None {
		return nil, nil
	}
	var t Ticket
	if err := decodeTicketValue(v, &t); err != nil {
		return nil, i18n.E("tpl.tickets.result", "get", err)
	}
	if t.ID == "" {
		t.ID = id
	}
	t.normalize()
	return &t, nil
}

func (in *Instance) TicketSearch(ctx context.Context, q TicketQuery) ([]Ticket, error) {
	fn, err := in.ticketFn("search")
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	arg, err := jsonToStarlark(raw)
	if err != nil {
		return nil, err
	}
	v, err := in.call(ctx, "search", fn, arg)
	if err != nil {
		return nil, scriptErr(err)
	}
	if v == starlark.None {
		return nil, nil
	}
	var out []Ticket
	if err := decodeTicketValue(v, &out); err != nil {
		return nil, i18n.E("tpl.tickets.result", "search", err)
	}
	kept := out[:0]
	for _, t := range out {
		if t.ID == "" || strings.EqualFold(t.ID, q.Exclude) {
			continue
		}
		t.normalize()
		kept = append(kept, t)
	}
	return kept, nil
}

func decodeTicketValue(v starlark.Value, dst any) error {
	g, err := fromStarlark(v)
	if err != nil {
		return err
	}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func (t *Ticket) normalize() {
	t.ID = strings.TrimSpace(t.ID)
	t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
	switch t.Kind {
	case TicketIncident, TicketChange:
	default:
		t.Kind = TicketOther
	}
	t.Title = strings.Join(strings.Fields(t.Title), " ")
	t.Description = strings.TrimSpace(t.Description)
	t.Resolution = strings.TrimSpace(t.Resolution)
}
