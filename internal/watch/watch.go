package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/sysprobe"
)

const (
	ToolName  = "watch_source"
	TaskID    = "capture"
	KindFile  = "file"
	KindJour  = "journal"
	KindProbe = "sample"
	KindTool  = "tool"

	readChunk    = 256 << 10
	journalBytes = 4 << 20
	shownPerTick = 10
	defaultEvery = 15 * time.Second
)

type Host interface {
	Name() string
	Run(ctx context.Context, tool string, cmd func(ssh.Builder) string, maxBytes int) (ssh.Result, error)
}

type Instance interface {
	Host(target, host string) (Host, error)
	Path(p string) (string, error)
	Follow(ctx context.Context, tool string, args, cursor json.RawMessage) ([]string, json.RawMessage, error)
}

type Source struct {
	ID       string
	Instance string
	Host     string
	Kind     string
	Path     string
	Unit     string
	Kernel   bool
	Probe    string
	Tool     string
	Args     json.RawMessage
	Every    time.Duration
	Filter   string
	Why      string
	Task     string

	host     Host
	inst     Instance
	state    json.RawMessage
	re       *regexp.Regexp
	offset   int64
	inode    string
	cursor   string
	since    int64
	carry    string
	next     time.Time
	lines    int
	matched  int
	samples  int
	alerts   int
	prev     *sysprobe.Snapshot
	initial  string
	summary  string
	shown    int
	lastErr  string
	errors   []string
	content  strings.Builder
	live     *os.File
	evidence string
}

func (s *Source) Label() string {
	switch s.Kind {
	case KindFile:
		return s.Host + ":" + s.Path
	case KindJour:
		switch {
		case s.Kernel:
			return s.Host + ":journal -k"
		case s.Unit != "":
			return s.Host + ":journal -u " + s.Unit
		}
		return s.Host + ":journal"
	case KindTool:
		if a := strings.TrimSpace(string(s.Args)); a != "" && a != "{}" {
			return s.Tool + " " + a
		}
		return s.Tool
	}
	return s.Host + ":" + s.Probe
}

func (s *Source) short() string {
	switch s.Kind {
	case KindFile:
		return s.Host + ":" + filepath.Base(s.Path)
	case KindTool:
		return s.Tool
	}
	return s.Label()
}

func (s *Source) where() string {
	if s.Kind == KindTool {
		return s.Instance
	}
	return s.Host
}

func (s *Source) key() string {
	return strings.Join([]string{s.Instance, s.Host, s.Kind, s.Path, s.Unit, strconv.FormatBool(s.Kernel), s.Probe, s.Tool, string(s.Args)}, "\x00")
}

type Captured struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Why      string   `json:"why,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Lines    int      `json:"lines"`
	Matched  int      `json:"matched"`
	Samples  int      `json:"samples,omitempty"`
	Alerts   int      `json:"alerts,omitempty"`
	Filter   string   `json:"filter,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

type Summary struct {
	Start   time.Time  `json:"start"`
	End     time.Time  `json:"end"`
	Reason  string     `json:"reason"`
	Sources []Captured `json:"sources"`
}

type Store struct {
	Events   progress.Sink
	Interval time.Duration
	Dir      string

	lookup     func(name string) (Instance, bool)
	followable []string
	inScope    func(name string) bool
	ev         *evidence.Store
	audit      *audit.Logger
	now        func() time.Time
	mu         sync.Mutex
	sources    []*Source
	waiting    atomic.Bool
	stop       chan struct{}
	once       sync.Once
}

func New(lookup func(name string) (Instance, bool), ev *evidence.Store, log *audit.Logger) *Store {
	return &Store{Events: progress.Nop{}, Interval: 5 * time.Second, lookup: lookup, ev: ev, audit: log, now: time.Now, stop: make(chan struct{})}
}

func (s *Store) Scope(followable []string, inScope func(name string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.followable, s.inScope = followable, inScope
}

func (s *Store) scope() ([]string, func(string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.followable, s.inScope
}

func (s *Store) Sources() []*Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Source(nil), s.sources...)
}

func (s *Store) Waiting() bool { return s.waiting.Load() }

func (s *Store) Stop() {
	s.once.Do(func() { close(s.stop) })
}

func (s *Store) add(src *Source) (*Source, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.sources {
		if o.key() == src.key() {
			return o, false
		}
	}
	src.ID = fmt.Sprintf("w%d", len(s.sources)+1)
	s.sources = append(s.sources, src)
	return src, true
}

func (s *Store) Capture(ctx context.Context, limit time.Duration) Summary {
	srcs := s.Sources()
	sum := Summary{Start: s.now()}
	if len(srcs) == 0 {
		sum.End, sum.Reason = sum.Start, "no_source"
		return sum
	}
	items := make([]progress.PlanItem, 0, len(srcs))
	for _, src := range srcs {
		items = append(items, progress.PlanItem{ID: src.ID, Role: src.Kind, Goal: src.Label()})
	}
	s.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: items})
	if s.Dir != "" {
		if err := os.MkdirAll(s.Dir, 0o700); err == nil {
			for _, src := range srcs {
				src.live, _ = os.OpenFile(filepath.Join(s.Dir, src.ID+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			}
		}
	}
	var wg sync.WaitGroup
	for _, src := range srcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.baseline(ctx, src)
		}()
	}
	wg.Wait()
	sum.Start = s.now()
	for _, src := range srcs {
		s.Events.Emit(progress.Event{Task: src.ID, Kind: "start", Model: src.where(), Detail: src.Label()})
		fmt.Fprintf(&src.content, "# source %s : %s\n", src.ID, src.Label())
		if src.Why != "" {
			fmt.Fprintf(&src.content, "# rôle : %s\n", src.Why)
		}
		if src.Filter != "" {
			fmt.Fprintf(&src.content, "# filtre d'affichage : %s\n", src.Filter)
		}
		if src.Kind == KindProbe {
			fmt.Fprintf(&src.content, "# sonde %s, relevé toutes les %s : compteurs du noyau lus par clotr (/proc, df, ps ; rien d'installé sur l'hôte), débits calculés entre deux relevés sur l'horloge de l'hôte\n# %s\n", src.Probe, src.Every, sysprobe.Legend())
		}
		fmt.Fprintf(&src.content, "# début de la capture : %s (heure du poste clotr, avant chaque ligne)\n", sum.Start.Format(time.RFC3339))
		if src.initial != "" {
			src.content.WriteString(src.initial)
			s.writeLive(src, src.initial)
		}
	}
	s.audit.Log("watch_start", map[string]any{"sources": len(srcs), "interval": s.Interval.String(), "limit": limit.String()})
	msg := i18n.T("watch.waiting")
	if s.Dir != "" {
		msg += "\n" + i18n.T("watch.live_dir", s.Dir)
	}
	s.Events.Emit(progress.Event{Kind: "waiting", Detail: msg})
	s.waiting.Store(true)
	defer s.waiting.Store(false)
	var deadline <-chan time.Time
	if limit > 0 {
		t := time.NewTimer(limit)
		defer t.Stop()
		deadline = t.C
	}
	cctx, cancel := context.WithCancel(ctx)
	hosts := map[string][]*Source{}
	var order []string
	for _, src := range srcs {
		k := src.Instance + "\x00" + src.Host
		if src.Kind == KindTool {
			k = src.ID
		}
		if _, ok := hosts[k]; !ok {
			order = append(order, k)
		}
		hosts[k] = append(hosts[k], src)
	}
	for _, k := range order {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.loop(cctx, hosts[k])
		}()
	}
	select {
	case <-s.stop:
		sum.Reason = "stopped"
	case <-deadline:
		sum.Reason = "duration"
	case <-ctx.Done():
		sum.Reason = "cancelled"
	}
	cancel()
	wg.Wait()
	s.waiting.Store(false)
	if ctx.Err() == nil {
		fctx, fcancel := context.WithTimeout(context.Background(), 30*time.Second)
		for _, k := range order {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, src := range hosts[k] {
					s.poll(fctx, src, true)
				}
			}()
		}
		wg.Wait()
		fcancel()
	}
	sum.End = s.now()
	for _, src := range srcs {
		s.flushCarry(src)
		fmt.Fprintf(&src.content, "# fin de la capture : %s (%s)\n", sum.End.Format(time.RFC3339), sum.End.Sub(sum.Start).Truncate(time.Second))
		if src.live != nil {
			_ = src.live.Close()
		}
		args := fmt.Sprintf(`{"source":%q,"instance":%q,"kind":%q,"start":%q,"end":%q}`, src.Label(), src.Instance, src.Kind, sum.Start.Format(time.RFC3339), sum.End.Format(time.RFC3339))
		src.evidence = s.ev.Add(TaskID, ToolName, args, src.content.String(), nil)
		c := Captured{ID: src.ID, Label: src.Label(), Why: src.Why, Evidence: src.evidence, Lines: src.lines, Matched: src.matched, Samples: src.samples, Alerts: src.alerts, Filter: src.Filter, Errors: src.errors}
		sum.Sources = append(sum.Sources, c)
		s.Events.Emit(progress.Event{Task: src.ID, Kind: "done", Model: src.where(), Detail: src.detail() + " [" + src.evidence + "]"})
	}
	s.audit.Log("watch_end", map[string]any{"reason": sum.Reason, "start": sum.Start, "end": sum.End, "sources": sum.Sources})
	return sum
}

func (src *Source) detail() string {
	if src.Kind == KindProbe {
		d := i18n.N(src.samples, "sample") + ", " + i18n.N(src.alerts, "alert")
		if src.Filter != "" {
			d += ", " + i18n.N(src.matched, "retained")
		}
		if src.summary != "" {
			d += " · " + src.summary
		}
		return d
	}
	return i18n.N(src.lines, "line") + ", " + i18n.N(src.matched, "retained")
}

func (s *Store) loop(ctx context.Context, srcs []*Source) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		for _, src := range srcs {
			if ctx.Err() != nil {
				return
			}
			s.poll(ctx, src, false)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Store) baseline(ctx context.Context, src *Source) {
	switch src.Kind {
	case KindFile:
		res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Stat(src.Path) }, 1024)
		if err = runErr(res, err); err != nil {
			s.fail(src, err)
			return
		}
		src.offset, src.inode, _ = parseStat(res.Stdout)
	case KindJour:
		res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Journal(src.Unit, src.Kernel, "", 0) }, 64<<10)
		if err = runErr(res, err); err != nil {
			s.fail(src, err)
			return
		}
		first, rest, _ := strings.Cut(res.Stdout, "\n")
		src.since, _ = strconv.ParseInt(strings.TrimSpace(first), 10, 64)
		_, src.cursor = splitCursor(rest)
	case KindProbe:
		snap, err := sample(ctx, src)
		if err != nil {
			src.next = time.Time{}
			s.fail(src, err)
			return
		}
		src.prev, src.next = snap, s.now().Add(src.Every)
		rep := sysprobe.Diff(nil, snap, src.Probe)
		src.initial = fmt.Sprintf("=== état initial, %s (réponse en %s) ===\n%s\n", s.now().Format("15:04:05"), snap.Took.Round(10*time.Millisecond), ssh.Redact(rep.Text()+openFiles(ctx, src, snap, rep)))
		src.summary = rep.Summary(i18n.UI())
	case KindTool:
		_, next, err := src.inst.Follow(ctx, src.Tool, src.Args, nil)
		if err != nil {
			s.fail(src, err)
			return
		}
		src.state = next
	}
}

func (s *Store) poll(ctx context.Context, src *Source, final bool) {
	if src.host == nil && src.inst == nil {
		return
	}
	switch src.Kind {
	case KindTool:
		s.pollTool(ctx, src)
	case KindFile:
		s.pollFile(ctx, src)
	case KindJour:
		s.pollJournal(ctx, src)
	case KindProbe:
		if final || s.now().Before(src.next) {
			return
		}
		src.next = s.now().Add(src.Every)
		s.pollProbe(ctx, src)
	}
}

func (s *Store) pollFile(ctx context.Context, src *Source) {
	if src.inode == "" {
		s.baseline(ctx, src)
		if src.inode == "" {
			return
		}
	}
	for range 64 {
		off := src.offset
		res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Follow(src.Path, off, readChunk) }, readChunk+4096)
		if err = runErr(res, err); err != nil {
			s.fail(src, err)
			return
		}
		s.recover(src)
		head, data, _ := strings.Cut(res.Stdout, "\n")
		size, inode, ok := parseStat(head)
		if !ok {
			s.fail(src, fmt.Errorf("stat illisible : %q", head))
			return
		}
		if (src.inode != "" && inode != src.inode) || size < off {
			s.flushCarry(src)
			s.note(src, "fichier remplacé ou tronqué (rotation) : relu depuis le début ; les lignes écrites dans l'ancien fichier depuis la lecture précédente n'ont pas été lues")
			src.offset, src.inode, src.carry = 0, inode, ""
			continue
		}
		src.inode = inode
		n := min(size-off, readChunk)
		if n <= 0 {
			return
		}
		src.offset = off + n
		text := src.carry + data
		cut := strings.LastIndexByte(text, '\n')
		if cut < 0 {
			src.carry = text
		} else {
			src.carry = text[cut+1:]
			s.lines(src, strings.Split(text[:cut], "\n"))
		}
		if n < readChunk {
			return
		}
	}
}

func (s *Store) pollJournal(ctx context.Context, src *Source) {
	if src.cursor == "" && src.since == 0 {
		s.baseline(ctx, src)
		if src.cursor == "" && src.since == 0 {
			return
		}
	}
	cursor, since := src.cursor, src.since
	res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Journal(src.Unit, src.Kernel, cursor, since) }, journalBytes)
	if err = runErr(res, err); err != nil {
		s.fail(src, err)
		return
	}
	s.recover(src)
	body, next := splitCursor(res.Stdout)
	if next != "" {
		src.cursor, src.since = next, 0
	} else if res.Truncated {
		s.note(src, "sortie du journal tronquée sans curseur : des lignes peuvent manquer")
	}
	if body = strings.TrimRight(body, "\n"); body != "" {
		s.lines(src, strings.Split(body, "\n"))
	}
}

func (s *Store) pollTool(ctx context.Context, src *Source) {
	if src.state == nil && src.lastErr != "" {
		s.baseline(ctx, src)
		if src.state == nil {
			return
		}
	}
	lines, next, err := src.inst.Follow(ctx, src.Tool, src.Args, src.state)
	if err != nil {
		s.fail(src, err)
		return
	}
	s.recover(src)
	src.state = next
	var out []string
	for _, l := range lines {
		out = append(out, strings.Split(strings.TrimRight(l, "\n"), "\n")...)
	}
	if len(out) > 0 {
		s.lines(src, out)
	}
}

func sample(ctx context.Context, src *Source) (*sysprobe.Snapshot, error) {
	start := time.Now()
	res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string {
		cmd, _ := sysprobe.Command(src.Probe, b)
		return cmd
	}, sysprobe.MaxBytes)
	if err = runErr(res, err); err != nil {
		return nil, err
	}
	snap := sysprobe.Parse(res.Stdout)
	snap.Took = time.Since(start)
	if err := snap.Check(); err != nil {
		return nil, err
	}
	return snap, nil
}

func openFiles(ctx context.Context, src *Source, snap *sysprobe.Snapshot, rep sysprobe.Report) string {
	if len(rep.Hot) == 0 {
		return ""
	}
	res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return sysprobe.FilesCommand(rep.Hot, b) }, 1<<20)
	if err = runErr(res, err); err != nil {
		return "\nfichiers ouverts des processus en tête des E/S : lecture en échec : " + err.Error()
	}
	return "\n" + sysprobe.FilesText(snap, sysprobe.ParseFiles(res.Stdout), rep.Hot)
}

func (s *Store) pollProbe(ctx context.Context, src *Source) {
	snap, err := sample(ctx, src)
	if err != nil {
		s.fail(src, err)
		return
	}
	s.recover(src)
	rep := sysprobe.Diff(src.prev, snap, src.Probe)
	interval := ""
	if src.prev != nil {
		interval = fmt.Sprintf("intervalle %s, ", snap.Since(src.prev))
	}
	src.prev = snap
	src.samples++
	now := s.now()
	out := ssh.Redact(rep.Text() + openFiles(ctx, src, snap, rep))
	block := fmt.Sprintf("=== relevé %d, %s (%sréponse en %s) ===\n%s\n", src.samples, now.Format("15:04:05"), interval, snap.Took.Round(10*time.Millisecond), out)
	src.content.WriteString(block)
	s.writeLive(src, block)
	src.summary = rep.Summary(i18n.UI())
	if len(rep.Alerts) > 0 {
		src.alerts++
		s.Events.Emit(progress.Event{Task: src.ID, Kind: "captured", Detail: src.short() + " · ⚠ " + oneLine(rep.AlertLine(i18n.UI()), 600)})
	}
	var hits []string
	if src.re != nil {
		for _, l := range strings.Split(out, "\n") {
			if src.re.MatchString(l) {
				hits = append(hits, l)
			}
		}
	}
	src.matched += len(hits)
	s.show(src, hits)
	s.progress(src)
}

func (s *Store) lines(src *Source, raw []string) {
	now := s.now().Format("15:04:05.000")
	var b strings.Builder
	var hits []string
	for _, l := range raw {
		l = ssh.Redact(strings.TrimRight(l, "\r"))
		src.lines++
		fmt.Fprintf(&b, "%s %s\n", now, l)
		if src.re == nil || src.re.MatchString(l) {
			src.matched++
			hits = append(hits, l)
		}
	}
	src.content.WriteString(b.String())
	s.writeLive(src, b.String())
	s.show(src, hits)
	s.progress(src)
}

func (s *Store) show(src *Source, hits []string) {
	for i, h := range hits {
		if i == shownPerTick {
			s.Events.Emit(progress.Event{Task: src.ID, Kind: "captured", Detail: i18n.T("watch.more", len(hits)-shownPerTick)})
			break
		}
		s.Events.Emit(progress.Event{Task: src.ID, Kind: "captured", Detail: src.short() + " · " + oneLine(h, 600)})
	}
}

func (s *Store) progress(src *Source) {
	s.Events.Emit(progress.Event{Task: src.ID, Kind: "stream", Detail: src.detail()})
}

func (s *Store) flushCarry(src *Source) {
	if src.carry == "" {
		return
	}
	c := src.carry
	src.carry = ""
	s.lines(src, []string{c})
}

func (s *Store) note(src *Source, msg string) {
	line := fmt.Sprintf("%s [clotr] %s\n", s.now().Format("15:04:05.000"), msg)
	src.content.WriteString(line)
	s.writeLive(src, line)
}

func (s *Store) fail(src *Source, err error) {
	msg := err.Error()
	if msg == src.lastErr {
		return
	}
	src.lastErr = msg
	src.errors = append(src.errors, s.now().Format("15:04:05")+" "+msg)
	s.note(src, "lecture en échec : "+msg)
	s.Events.Emit(progress.Event{Task: src.ID, Kind: "retry", Detail: i18n.T("watch.error", oneLine(msg, 200))})
	s.audit.Log("watch_error", map[string]any{"source": src.ID, "label": src.Label(), "error": msg})
}

func (s *Store) recover(src *Source) {
	if src.lastErr == "" {
		return
	}
	src.lastErr = ""
	s.note(src, "lecture rétablie")
}

func (s *Store) writeLive(src *Source, text string) {
	if src.live != nil {
		_, _ = src.live.WriteString(text)
	}
}

func runErr(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.Exit != 0 {
		msg := strings.TrimSpace(ssh.Redact(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(ssh.Redact(res.Stdout))
		}
		return fmt.Errorf("exit %d: %s", res.Exit, oneLine(msg, 300))
	}
	return nil
}

func parseStat(s string) (int64, string, bool) {
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0, "", false
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	return n, f[1], err == nil
}

const cursorMark = "-- cursor: "

func splitCursor(out string) (string, string) {
	trimmed := strings.TrimRight(out, "\n")
	i := strings.LastIndex(trimmed, cursorMark)
	if i < 0 || (i > 0 && trimmed[i-1] != '\n') || strings.Contains(trimmed[i:], "\n") {
		return out, ""
	}
	return trimmed[:i], strings.TrimSpace(trimmed[i+len(cursorMark):])
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > n {
		return string([]rune(s)[:n]) + "…"
	}
	return s
}
