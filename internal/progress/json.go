package progress

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type jsonEvent struct {
	Elapsed  float64        `json:"elapsed"`
	Task     string         `json:"task,omitempty"`
	Kind     string         `json:"kind"`
	Model    string         `json:"model,omitempty"`
	Effort   string         `json:"effort,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	Status   string         `json:"status,omitempty"`
	Step     int            `json:"step,omitempty"`
	Cost     float64        `json:"cost,omitempty"`
	Duration float64        `json:"duration,omitempty"`
	Plan     []jsonPlanItem `json:"plan,omitempty"`
}

type jsonPlanItem struct {
	ID        string   `json:"id"`
	Role      string   `json:"role,omitempty"`
	Goal      string   `json:"goal,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

type JSONPrinter struct {
	ch    chan Event
	wg    sync.WaitGroup
	start time.Time
	once  sync.Once
}

func NewJSON(w io.Writer) *JSONPrinter {
	p := &JSONPrinter{ch: make(chan Event, 256), start: time.Now()}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for e := range p.ch {
			if e.Kind == "stream" || e.Kind == "wait_end" {
				continue
			}
			_ = enc.Encode(jsonEvent{
				Elapsed:  time.Since(p.start).Truncate(100 * time.Millisecond).Seconds(),
				Task:     e.Task,
				Kind:     e.Kind,
				Model:    e.Model,
				Effort:   e.Effort,
				Detail:   e.Detail,
				Status:   e.Status,
				Step:     e.Step,
				Cost:     e.Cost,
				Duration: e.Duration.Truncate(time.Millisecond).Seconds(),
				Plan:     jsonPlan(e.Plan),
			})
		}
	}()
	return p
}

func jsonPlan(items []PlanItem) []jsonPlanItem {
	if len(items) == 0 {
		return nil
	}
	out := make([]jsonPlanItem, len(items))
	for i, it := range items {
		out[i] = jsonPlanItem{ID: it.ID, Role: it.Role, Goal: it.Goal, DependsOn: it.DependsOn}
	}
	return out
}

func (p *JSONPrinter) Emit(e Event) {
	p.ch <- e
}

func (p *JSONPrinter) Close() {
	p.once.Do(func() {
		close(p.ch)
		p.wg.Wait()
	})
}
