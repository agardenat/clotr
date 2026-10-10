package progress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"

	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/markdown"
)

type TurnResult struct {
	Markdown string
	Info     []string
	Err      error
	Path     string
}

type ChatOptions struct {
	Title    string
	MaxSteps int
	Initial  string
	Turn     func(ctx context.Context, request string, events Sink, answer func(text string)) TurnResult
	OnStart  func(suspend func() (resume func()))
}

type chatMode int

const (
	modeInput chatMode = iota
	modeRunning
	modeIdle
)

const (
	inputLines = 3
	logLines   = 4
)

var (
	stRequest = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	stRule    = lipgloss.NewStyle().Faint(true)
)

type answerMsg string
type turnDoneMsg TurnResult
type interruptMsg struct{}
type copiedMsg struct {
	chars int
	via   string
	path  string
}

type entry struct {
	request  string
	board    *board
	live     string
	result   *TurnResult
	logs     []string
	cache    string
	cacheKey string
}

type chat struct {
	ctx      context.Context
	opts     ChatOptions
	send     func(tea.Msg)
	running  *sync.WaitGroup
	cancel   context.CancelFunc
	mode     chatMode
	entries  []*entry
	pending  []string
	vp       viewport.Model
	input    textarea.Model
	width    int
	height   int
	dark     bool
	dirty    bool
	follow   bool
	frame    int
	status   string
	stopping bool
}

func newChat(ctx context.Context, opts ChatOptions, width, height int) *chat {
	ta := textarea.New()
	ta.Placeholder = i18n.T("chat.placeholder")
	ta.ShowLineNumbers = false
	ta.CharLimit = 0
	ta.Prompt = "❯ "
	ta.SetHeight(inputLines)
	ta.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("alt+enter", "ctrl+j"))
	c := &chat{ctx: ctx, opts: opts, running: &sync.WaitGroup{}, vp: viewport.New(), input: ta, dark: true, follow: true, width: width, height: height, send: func(tea.Msg) {}}
	c.input.SetStyles(textarea.DefaultStyles(true))
	c.layout()
	return c
}

func (c *chat) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(), tea.RequestBackgroundColor}
	if req := strings.TrimSpace(c.opts.Initial); req != "" {
		cmds = append(cmds, c.start(req))
	} else {
		cmds = append(cmds, c.input.Focus())
	}
	return tea.Batch(cmds...)
}

func (c *chat) footerHeight() int {
	if c.mode == modeInput {
		return inputLines + 2
	}
	return 2
}

func (c *chat) layout() {
	c.vp.SetWidth(c.width)
	c.vp.SetHeight(max(c.height-1-c.footerHeight(), 1))
	c.input.SetWidth(max(c.width-1, 10))
	for _, e := range c.entries {
		e.board.width = c.width
	}
	c.dirty = true
}

func (c *chat) last() *entry {
	if len(c.entries) == 0 {
		return nil
	}
	return c.entries[len(c.entries)-1]
}

func (c *chat) start(req string) tea.Cmd {
	ctx, cancel := context.WithCancel(c.ctx)
	c.cancel = cancel
	b := newBoard(c.opts.MaxSteps)
	b.width, b.title = c.width, c.opts.Title
	e := &entry{request: req, board: b, logs: c.pending}
	c.pending = nil
	c.entries = append(c.entries, e)
	c.mode, c.status, c.follow, c.dirty = modeRunning, "", true, true
	c.layout()
	c.running.Add(1)
	send := c.send
	sink := chatSink{send: send}
	turn := c.opts.Turn
	return func() tea.Msg {
		defer c.running.Done()
		defer cancel()
		return turnDoneMsg(turn(ctx, req, sink, func(text string) { send(answerMsg(text)) }))
	}
}

type chatSink struct{ send func(tea.Msg) }

func (s chatSink) Emit(e Event) { s.send(eventMsg(e)) }

func (c *chat) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tickMsg:
		c.frame++
		if e := c.last(); e != nil && c.mode == modeRunning {
			e.board.frame = c.frame
			c.dirty = true
		}
		if c.dirty {
			c.refresh()
		}
		return c, tick()
	case tea.WindowSizeMsg:
		if m.Width > 0 && m.Height > 0 {
			c.width, c.height = m.Width, m.Height
			c.layout()
			c.refresh()
		}
		return c, nil
	case tea.BackgroundColorMsg:
		c.dark = m.IsDark()
		c.input.SetStyles(textarea.DefaultStyles(c.dark))
		c.dirty = true
		return c, nil
	case eventMsg:
		if e := c.last(); e != nil {
			if m.Task == "budget" {
				e.logs = append(e.logs, i18n.T("budget.prefix", m.Model, m.Detail))
			} else {
				e.board.apply(Event(m))
			}
			c.dirty = true
		}
		return c, nil
	case answerMsg:
		if e := c.last(); e != nil && e.result == nil {
			e.live = string(m)
			c.dirty = true
		}
		return c, nil
	case logMsg:
		if e := c.last(); e != nil {
			e.logs = append(e.logs, string(m))
		} else {
			c.pending = append(c.pending, string(m))
		}
		c.dirty = true
		return c, nil
	case turnDoneMsg:
		res := TurnResult(m)
		if e := c.last(); e != nil {
			e.result = &res
			e.board.finished = true
			if res.Err != nil {
				e.board.interrupt(i18n.T("chat.interrupted"))
			}
		}
		c.cancel, c.status = nil, ""
		c.mode = modeIdle
		c.layout()
		c.refresh()
		if c.stopping {
			return c, tea.Quit
		}
		return c, nil
	case copiedMsg:
		if m.chars == 0 {
			c.status = i18n.T("chat.copy.none")
		} else {
			c.status = i18n.T("chat.copied", m.chars, m.via)
			if m.path != "" {
				c.status += " · " + m.path
			}
		}
		return c, nil
	case interruptMsg:
		return c, c.quit()
	case tea.PasteMsg:
		if c.mode == modeInput {
			var cmd tea.Cmd
			c.input, cmd = c.input.Update(msg)
			return c, cmd
		}
		return c, nil
	case tea.KeyPressMsg:
		return c, c.key(m)
	}
	if c.mode == modeInput {
		var cmd tea.Cmd
		c.input, cmd = c.input.Update(msg)
		return c, cmd
	}
	return c, nil
}

func (c *chat) quit() tea.Cmd {
	if c.cancel != nil {
		c.stopping = true
		c.cancel()
		c.status = i18n.T("chat.interrupting")
		return nil
	}
	return tea.Quit
}

func (c *chat) key(m tea.KeyPressMsg) tea.Cmd {
	k := m.String()
	switch c.mode {
	case modeInput:
		switch k {
		case "ctrl+c":
			return tea.Quit
		case "esc":
			if len(c.entries) == 0 {
				return tea.Quit
			}
			c.input.Blur()
			c.mode = modeIdle
			c.layout()
			return nil
		case "enter":
			req := strings.TrimSpace(c.input.Value())
			if req == "" {
				return nil
			}
			c.input.Reset()
			c.input.Blur()
			return c.start(req)
		case "pgup", "pgdown":
			c.scroll(k)
			return nil
		}
		var cmd tea.Cmd
		c.input, cmd = c.input.Update(m)
		return cmd
	case modeRunning:
		if k == "ctrl+c" {
			if c.status == i18n.T("chat.interrupting") {
				return c.quit()
			}
			c.cancel()
			c.status = i18n.T("chat.interrupting")
			return nil
		}
		c.scroll(k)
		return nil
	}
	switch k {
	case "q", "esc", "ctrl+c":
		return tea.Quit
	case "r":
		c.mode, c.status = modeInput, ""
		c.layout()
		return c.input.Focus()
	case "c":
		e := c.last()
		if e == nil || e.result == nil || e.result.Markdown == "" {
			return func() tea.Msg { return copiedMsg{} }
		}
		md, path := e.result.Markdown, e.result.Path
		return tea.Batch(tea.SetClipboard(md), func() tea.Msg {
			return copiedMsg{chars: len([]rune(md)), via: copyExternal(md), path: path}
		})
	}
	c.scroll(k)
	return nil
}

func (c *chat) scroll(k string) {
	switch k {
	case "home", "g":
		c.vp.GotoTop()
	case "end", "G":
		c.vp.GotoBottom()
	case "up", "k":
		c.vp.ScrollUp(1)
	case "down", "j":
		c.vp.ScrollDown(1)
	case "pgup", "b":
		c.vp.PageUp()
	case "pgdown", "space", "f":
		c.vp.PageDown()
	case "u", "ctrl+u":
		c.vp.HalfPageUp()
	case "d", "ctrl+d":
		c.vp.HalfPageDown()
	default:
		return
	}
	c.follow = c.vp.AtBottom()
}

func (c *chat) refresh() {
	c.dirty = false
	var parts []string
	for _, e := range c.entries {
		parts = append(parts, c.renderEntry(e))
	}
	if len(c.pending) > 0 {
		parts = append(parts, c.renderLogs(c.pending))
	}
	c.vp.SetContent(strings.Join(parts, "\n\n"))
	if c.follow {
		c.vp.GotoBottom()
	}
}

func (c *chat) renderLogs(logs []string) string {
	shown := logs
	var out []string
	if len(shown) > logLines {
		out = append(out, stFaint.Render(i18n.T("chat.logs.more", len(shown)-logLines)))
		shown = shown[len(shown)-logLines:]
	}
	for _, l := range shown {
		out = append(out, stFaint.Render(ansi.Truncate(l, max(c.width-1, 20), "…")))
	}
	return strings.Join(out, "\n")
}

func (c *chat) renderMarkdown(e *entry, md string) string {
	k := fmt.Sprintf("%d|%t|%s", c.width, c.dark, md)
	if k != e.cacheKey {
		e.cache, e.cacheKey = markdown.Render(md, c.width, c.dark), k
	}
	return e.cache
}

func (c *chat) renderEntry(e *entry) string {
	var b strings.Builder
	b.WriteString(stRequest.Render(ansi.Wordwrap("❯ "+e.request, max(c.width-1, 20), "")))
	for _, r := range e.board.rows {
		b.WriteString("\n" + e.board.line(r))
	}
	if len(e.logs) > 0 {
		b.WriteString("\n" + c.renderLogs(e.logs))
	}
	md := e.live
	if e.result != nil && e.result.Markdown != "" {
		md = e.result.Markdown
	}
	if strings.TrimSpace(md) != "" {
		b.WriteString("\n\n" + c.renderMarkdown(e, md))
	}
	if e.result != nil {
		if err := e.result.Err; errors.Is(err, context.Canceled) {
			b.WriteString("\n" + stWarn.Render(i18n.T("chat.interrupted")))
		} else if err != nil {
			b.WriteString("\n" + stFailed.Render(ansi.Wordwrap(err.Error(), max(c.width-1, 20), "")))
		}
		for _, l := range e.result.Info {
			b.WriteString("\n" + stFaint.Render(ansi.Truncate(l, max(c.width-1, 20), "…")))
		}
	}
	return b.String()
}

func (c *chat) header() string {
	if e := c.last(); e != nil {
		return e.board.header()
	}
	head := "clotr"
	if c.opts.Title != "" {
		head += " · " + c.opts.Title
	}
	return stHeader.Render(ansi.Truncate(head, max(c.width-1, 20), "…"))
}

func (c *chat) footer() string {
	rule := stRule.Render(strings.Repeat("─", max(c.width, 1)))
	var help string
	switch c.mode {
	case modeInput:
		return rule + "\n" + c.input.View() + "\n" + stFaint.Render(ansi.Truncate(i18n.T("chat.help.input"), max(c.width-1, 20), "…"))
	case modeRunning:
		help = i18n.T("chat.help.running")
	default:
		help = i18n.T("chat.help.idle")
	}
	line := stFaint.Render(help)
	if c.status != "" {
		line = stWarn.Render(c.status) + stFaint.Render(" · "+help)
	}
	return rule + "\n" + ansi.Truncate(line, max(c.width-1, 20), "…")
}

func (c *chat) View() tea.View {
	v := tea.NewView(c.header() + "\n" + c.vp.View() + "\n" + c.footer())
	v.AltScreen = true
	return v
}

func (b *board) interrupt(detail string) {
	now := b.now()
	for _, r := range b.rows {
		if r.status == statusRunning || r.status == statusPending {
			r.status, r.detail = statusFailed, detail
			if !r.start.IsZero() {
				r.end = now
			}
		}
	}
}

func RunChat(ctx context.Context, stderr *os.File, opts ChatOptions) error {
	out, pipe, restore := captureStderr(stderr)
	width, height := 120, 40
	if w, h, err := term.GetSize(out.Fd()); err == nil && w > 0 && h > 0 {
		width, height = w, h
	}
	c := newChat(ctx, opts, width, height)
	p := tea.NewProgram(c, tea.WithOutput(out), tea.WithoutSignalHandler(), tea.WithWindowSize(width, height))
	c.send = p.Send
	drained := make(chan struct{})
	if pipe != nil {
		go func() {
			defer close(drained)
			sc := bufio.NewScanner(pipe)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				if line := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(line) != "" {
					p.Send(logMsg(line))
				}
			}
			_ = pipe.Close()
		}()
	} else {
		close(drained)
	}
	stop := make(chan struct{})
	go watchResize(p, stop, out)
	go func() {
		select {
		case <-ctx.Done():
			p.Send(interruptMsg{})
		case <-stop:
		}
	}()
	if opts.OnStart != nil {
		opts.OnStart(func() func() {
			if p.ReleaseTerminal() != nil {
				return func() {}
			}
			return func() { _ = p.RestoreTerminal() }
		})
	}
	_, err := p.Run()
	close(stop)
	c.running.Wait()
	if restore != nil {
		restore()
	}
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
	}
	return err
}
