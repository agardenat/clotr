package progress

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type Event struct {
	Task     string
	Kind     string
	Model    string
	Detail   string
	Step     int
	Cost     float64
	Duration time.Duration
	Plan     []PlanItem
}

type PlanItem struct {
	ID        string
	Role      string
	Goal      string
	DependsOn []string
}

type Closer interface {
	Sink
	Close()
}

type Sink interface {
	Emit(Event)
}

type Nop struct{}

func (Nop) Emit(Event) {}

func (Nop) Close() {}

type Printer struct {
	ch    chan Event
	wg    sync.WaitGroup
	start time.Time
	once  sync.Once
}

func NewPrinter(w io.Writer) *Printer {
	p := &Printer{ch: make(chan Event, 256), start: time.Now()}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for e := range p.ch {
			if e.Kind == "stream" {
				continue
			}
			elapsed := time.Since(p.start).Truncate(100 * time.Millisecond)
			line := fmt.Sprintf("[%7s] %-14s %-10s", elapsed, e.Task, e.Kind)
			if e.Model != "" {
				line += " " + e.Model
			}
			if e.Duration > 0 {
				e.Detail += fmt.Sprintf(", %s", e.Duration.Truncate(time.Millisecond))
			}
			if e.Cost > 0 {
				e.Detail += fmt.Sprintf(", %.4f $", e.Cost)
			}
			if e.Detail != "" {
				line += " " + e.Detail
			}
			fmt.Fprintln(w, line)
		}
	}()
	return p
}

func (p *Printer) Emit(e Event) {
	p.ch <- e
}

func (p *Printer) Close() {
	p.once.Do(func() {
		close(p.ch)
		p.wg.Wait()
	})
}
