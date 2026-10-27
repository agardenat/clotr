package progress

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var (
	stHeader  = lipgloss.NewStyle().Bold(true)
	stFaint   = lipgloss.NewStyle().Faint(true)
	stRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	stDone    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	stFailed  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	stWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	stLead    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	stAlert   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	stAdvice  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	stActive  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	stSession = lipgloss.NewStyle().Bold(true).Reverse(true)
)

func Session(name string) string { return stSession.Render(name) }

const (
	statusPending = "pending"
	statusRunning = "running"
	statusDone    = "done"
	statusFailed  = "failed"
	statusSkipped = "skipped"
	barWidth      = 10
)

type row struct {
	id, role, model, status, detail string
	deps                            []string
	step, tools                     int
	cost                            float64
	warn, limited                   bool
	stop                            string
	start, end                      time.Time
}

type eventMsg Event
type finishMsg struct{}
type tickMsg time.Time
type logMsg string

type board struct {
	rows      []*row
	idx       map[string]*row
	maxSteps  int
	title     string
	start     time.Time
	width     int
	frame     int
	toolCalls int
	finished  bool
	ready     bool
	pending   []string
	now       func() time.Time
}

func newBoard(maxSteps int) *board {
	return &board{idx: map[string]*row{}, maxSteps: max(maxSteps, 1), start: time.Now(), width: 120, now: time.Now}
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (b *board) Init() tea.Cmd { return tick() }

func (b *board) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tickMsg:
		b.frame++
		if b.finished {
			return b, nil
		}
		if !b.ready {
			b.ready = true
			return b, tea.Batch(b.flushPending(), tick())
		}
		return b, tick()
	case tea.WindowSizeMsg:
		if m.Width > 0 {
			b.width = m.Width
		}
	case eventMsg:
		if m.Task == "budget" {
			return b, b.println(stWarn.Render(ansi.Truncate(i18n.T("budget.prefix", m.Model, m.Detail), max(b.width-1, 20), "…")))
		}
		switch m.Kind {
		case "lead":
			return b, b.println(stLead.Render(ansi.Wrap(m.Task+" · "+m.Detail, max(b.width-1, 20), "")))
		case "cve":
			line := ansi.Wrap(m.Task+" · "+m.Detail, max(b.width-1, 20), "")
			switch m.Status {
			case "vulnerable", "compromised":
				line = stAlert.Render(line)
			case "advisory":
				line = stAdvice.Render(line)
			}
			return b, b.println(line)
		case "activation":
			return b, b.println(stActive.Render(ansi.Wrap(m.Detail, max(b.width-1, 20), "")))
		case "evidence":
			return b, b.println(stFaint.Render(ansi.Wrap(m.Task+" · "+m.Detail, max(b.width-1, 20), "")))
		case "finding", "gap":
			return b, b.println(ansi.Wrap(m.Task+" · "+i18n.T("journal."+m.Kind, m.Detail), max(b.width-1, 20), ""))
		case "concluding":
			return b, b.println(stWarn.Render(ansi.Wrap(m.Detail, max(b.width-1, 20), "")))
		}
		b.apply(Event(m))
	case logMsg:
		return b, b.println(ansi.Truncate(string(m), max(b.width-1, 20), "…"))
	case finishMsg:
		b.finished = true
		if p := b.flushPending(); p != nil {
			return b, tea.Sequence(p, tea.Quit)
		}
		return b, tea.Quit
	}
	return b, nil
}

func (b *board) println(line string) tea.Cmd {
	if !b.ready {
		b.pending = append(b.pending, line)
		return nil
	}
	return tea.Println(line)
}

func (b *board) flushPending() tea.Cmd {
	if len(b.pending) == 0 {
		return nil
	}
	lines := strings.Join(b.pending, "\n")
	b.pending = nil
	return tea.Println(lines)
}

func (b *board) get(id string) *row {
	if r, ok := b.idx[id]; ok {
		return r
	}
	role := ""
	if id == "planner" || id == "synthesizer" {
		role = id
	}
	r := &row{id: id, role: role, status: statusPending}
	b.idx[id] = r
	if id == "synthesizer" || len(b.rows) == 0 || b.rows[len(b.rows)-1].id != "synthesizer" {
		b.rows = append(b.rows, r)
	} else {
		b.rows = append(b.rows[:len(b.rows)-1], r, b.rows[len(b.rows)-1])
	}
	return r
}

func (b *board) apply(e Event) {
	now := b.now()
	if e.Kind == "plan" {
		for _, p := range e.Plan {
			r := b.get(p.ID)
			r.role, r.deps = p.Role, p.DependsOn
			r.detail = p.Goal
		}
		return
	}
	r := b.get(e.Task)
	if e.Model != "" && e.Kind != "budget" {
		r.model = e.Model
	}
	switch e.Kind {
	case "start":
		r.status, r.start = statusRunning, now
		if e.Detail != "" {
			r.detail = e.Detail
		}
	case "step":
		r.status = statusRunning
		if r.start.IsZero() {
			r.start = now
		}
		r.step = e.Step
		r.detail = i18n.T("thinking")
	case "stream":
		r.status = statusRunning
		if e.Step > 0 {
			r.step = e.Step
		}
		r.detail = e.Detail
	case "tool":
		r.tools++
		b.toolCalls++
		r.detail = i18n.T("tool", e.Detail)
	case "limit", "time_limit", "stall_limit", "interrupted":
		r.limited, r.warn = true, true
		r.detail = e.Detail
		if e.Step > 0 {
			r.step = e.Step
		}
		switch e.Kind {
		case "time_limit":
			r.stop = i18n.T("stopped.time")
		case "interrupted":
			r.stop = i18n.T("stopped.user")
		case "stall_limit":
			r.stop = i18n.T("stopped.stall")
		default:
			r.stop = i18n.T("stopped.steps")
		}
	case "fallback":
		r.warn = true
		r.detail = i18n.T("fallback", e.Model, e.Detail)
	case "retry":
		r.warn = true
		r.detail = e.Detail
	case "dropped", "budget":
		r.warn = true
		r.detail = e.Detail
	case "done":
		r.status, r.end, r.detail = statusDone, now, e.Detail
		if e.Step > 0 {
			r.step = e.Step
		}
		r.cost = e.Cost
	case "failed":
		r.status, r.end, r.detail = statusFailed, now, e.Detail
	case "skipped":
		r.status, r.detail = statusSkipped, e.Detail
	}
}

func (b *board) counts() (done, failed, total int) {
	for _, r := range b.rows {
		if r.id == "planner" || r.id == "synthesizer" {
			continue
		}
		total++
		switch r.status {
		case statusDone:
			done++
		case statusFailed:
			failed++
		}
	}
	return
}

func (b *board) bar(r *row) string {
	filled := 0
	switch r.status {
	case statusDone:
		filled = barWidth
	case statusRunning, statusFailed:
		filled = min(barWidth, r.step*barWidth/b.maxSteps)
		if r.step > 0 && filled == 0 {
			filled = 1
		}
	}
	s := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	switch {
	case r.limited:
		return stWarn.Render(s)
	case r.status == statusDone:
		return stDone.Render(s)
	case r.status == statusFailed:
		return stFailed.Render(s)
	case r.status == statusRunning:
		return stRunning.Render(s)
	}
	return stFaint.Render(s)
}

func (b *board) line(r *row) string {
	now := b.now()
	var icon string
	switch r.status {
	case statusRunning:
		icon = stRunning.Render(spinner[b.frame%len(spinner)])
	case statusDone:
		icon = stDone.Render("✓")
	case statusFailed:
		icon = stFailed.Render("✗")
	case statusSkipped:
		icon = stFaint.Render("–")
	default:
		icon = stFaint.Render("·")
	}
	elapsed := ""
	switch {
	case !r.end.IsZero():
		elapsed = fmtDur(r.end.Sub(r.start))
	case !r.start.IsZero():
		elapsed = now.Sub(r.start).Truncate(time.Second).String()
	}
	steps := ""
	switch {
	case r.step > 0 && (r.status == statusDone || r.status == statusFailed):
		steps = i18n.N(r.step, "step")
	case r.step > 0:
		steps = i18n.T("step.n", r.step)
	}
	steps = fmt.Sprintf("%9s", steps)
	if r.limited {
		steps = stWarn.Render(steps)
	}
	detail := r.detail
	if r.status == statusPending && len(r.deps) > 0 {
		detail = i18n.T("waiting", strings.Join(r.deps, ", "))
	}
	if r.status == statusDone && r.stop != "" {
		detail += " · " + r.stop
	}
	if r.status == statusDone && r.cost > 0 {
		detail += fmt.Sprintf(" · %.4f $", r.cost)
	}
	detail = strings.Join(strings.Fields(detail), " ")
	prefix := fmt.Sprintf(" %s %-12s %-11s %-30s %s %s %7s ", icon, ansi.Truncate(r.id, 12, "…"), ansi.Truncate(r.role, 11, "…"), ansi.Truncate(r.model, 30, "…"), b.bar(r), steps, elapsed)
	room := max(b.width-ansi.StringWidth(prefix)-1, 10)
	detail = ansi.Truncate(detail, room, "…")
	switch {
	case r.status == statusFailed:
		detail = stFailed.Render(detail)
	case r.warn && (r.status == statusRunning || r.limited):
		detail = stWarn.Render(detail)
	case r.status != statusRunning:
		detail = stFaint.Render(detail)
	}
	return ansi.Truncate(prefix+detail, max(b.width-1, 20), "…")
}

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Truncate(100 * time.Millisecond).String()
}

func (b *board) render() string {
	lines := []string{b.header()}
	for _, r := range b.rows {
		lines = append(lines, b.line(r))
	}
	out := strings.Join(lines, "\n")
	if b.finished {
		out += "\n"
	}
	return out
}

func (b *board) header() string {
	done, failed, total := b.counts()
	state := i18n.T("state.running")
	if b.finished {
		state = i18n.T("state.done")
	}
	head := stHeader.Render("clotr · ")
	if b.title != "" {
		head += stSession.Render(b.title) + stHeader.Render(" · ")
	}
	rest := fmt.Sprintf("%s · %s · ", state, b.now().Sub(b.start).Truncate(time.Second)) + i18n.T("header.tasks", done, total)
	if failed > 0 {
		rest += i18n.T("header.failed", failed)
	}
	rest += " · " + i18n.N(b.toolCalls, "tool call")
	return ansi.Truncate(head+stHeader.Render(rest), max(b.width-1, 20), "…")
}

func (b *board) View() tea.View {
	return tea.NewView(b.render())
}

type TUI struct {
	p       *tea.Program
	out     *os.File
	done    chan struct{}
	stop    chan struct{}
	once    sync.Once
	restore func()
	drained chan struct{}
}

func NewTUI(stderr *os.File, maxSteps int, title string) *TUI {
	t := &TUI{done: make(chan struct{}), stop: make(chan struct{}), drained: make(chan struct{})}
	out, pipe, restore := captureStderr(stderr)
	t.out, t.restore = out, restore
	width, height, err := term.GetSize(out.Fd())
	if err != nil || width <= 0 || height <= 0 {
		width, height = 120, 40
	}
	b := newBoard(maxSteps)
	b.width, b.title = width, title
	t.p = tea.NewProgram(b, tea.WithOutput(out), tea.WithInput(nil), tea.WithoutSignalHandler(), tea.WithWindowSize(width, height))
	if pipe != nil {
		go func() {
			defer close(t.drained)
			sc := bufio.NewScanner(pipe)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				if line := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(line) != "" {
					t.p.Send(logMsg(line))
				}
			}
			_ = pipe.Close()
		}()
	} else {
		close(t.drained)
	}
	go watchResize(t.p, t.stop, out)
	go func() {
		defer close(t.done)
		if _, err := t.p.Run(); err != nil {
			fmt.Fprintln(out, i18n.T("progress.unavailable", err))
		}
	}()
	return t
}

func (t *TUI) Suspend() (resume func()) {
	select {
	case <-t.stop:
		return func() {}
	default:
	}
	if t.p.ReleaseTerminal() != nil {
		return func() {}
	}
	_, _ = io.WriteString(t.out, ansi.SetModeAltScreenSaveCursor+ansi.CursorHomePosition+ansi.EraseEntireScreen)
	return func() {
		_, _ = io.WriteString(t.out, ansi.ResetModeAltScreenSaveCursor)
		_ = t.p.RestoreTerminal()
	}
}

func (t *TUI) Emit(e Event) {
	t.p.Send(eventMsg(e))
}

func (t *TUI) Close() {
	t.once.Do(func() {
		close(t.stop)
		if t.restore != nil {
			t.restore()
		}
		select {
		case <-t.drained:
		case <-time.After(2 * time.Second):
		}
		t.p.Send(finishMsg{})
		<-t.done
	})
}
