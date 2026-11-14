package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/gitsync"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/template"
)

const startupTimeout = 3 * time.Minute

type startupReport struct {
	failed     int
	rolledBack bool
}

func startupDisabled(o *options) bool {
	return o.noStartup || os.Getenv("CLOTR_NO_STARTUP") != ""
}

func startupStamp(name string) string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "clotr", "startup", name)
}

func startupDue(st config.Startup, now time.Time) bool {
	p := startupStamp(st.Name)
	if p == "" {
		return true
	}
	fi, err := os.Stat(p)
	return err != nil || now.Sub(fi.ModTime()) >= st.Every.Duration
}

const (
	stampOK      = "ok"
	stampChanged = "changed"
	stampSkipped = "skipped"
	stampFailed  = "failed"
)

type stampState struct {
	Status  string   `json:"status"`
	Repos   []string `json:"repos,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func (s *stampState) worse(status string) {
	rank := map[string]int{"": 0, stampOK: 1, stampChanged: 2, stampSkipped: 3, stampFailed: 4}
	if rank[status] > rank[s.Status] {
		s.Status = status
	}
}

func touchStamp(name string, now time.Time, state *stampState) {
	p := startupStamp(name)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	var data []byte
	if state != nil {
		data, _ = json.Marshal(state)
	}
	if err := os.WriteFile(p, data, 0o600); err == nil {
		_ = os.Chtimes(p, now, now)
	}
}

func readStamp(name string) (stampState, time.Time, bool) {
	var st stampState
	p := startupStamp(name)
	if p == "" {
		return st, time.Time{}, false
	}
	fi, err := os.Stat(p)
	if err != nil {
		return st, time.Time{}, false
	}
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &st)
	}
	return st, fi.ModTime(), true
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return i18n.T("cli.startup.ago_now")
	case d < time.Hour:
		return i18n.T("cli.startup.ago_min", int(d.Minutes()))
	}
	return i18n.T("cli.startup.ago_h", int(d.Hours()))
}

func recentLine(name string, now time.Time) (string, bool) {
	st, at, ok := readStamp(name)
	if !ok {
		return "", false
	}
	when := ago(now.Sub(at))
	switch st.Status {
	case stampFailed:
		return i18n.T("cli.startup.recent_failed", name, when, strings.Join(st.Reasons, " ; ")), true
	case stampSkipped:
		return i18n.T("cli.startup.recent_skipped", name, when, strings.Join(st.Reasons, " ; ")), true
	case stampOK, stampChanged:
		return i18n.T("cli.startup.recent_ok", name, when), false
	}
	return i18n.T("cli.startup.recent", name, when), false
}

func runStartup(ctx context.Context, path string, cfg *config.Config, force, quiet bool, w io.Writer) (*config.Config, startupReport) {
	var rep startupReport
	now := time.Now()
	warn := func(msg string) {
		fmt.Fprintln(w, i18n.T("cli.warning"), msg)
	}
	var due []config.Startup
	for _, st := range cfg.Startup {
		if !st.IsEnabled() {
			continue
		}
		if force || startupDue(st, now) {
			due = append(due, st)
			continue
		}
		if line, alert := recentLine(st.Name, now); alert {
			warn(line)
		} else if line != "" && !quiet {
			fmt.Fprintln(w, line)
		}
	}
	if len(due) == 0 {
		return cfg, rep
	}
	states := map[string]*stampState{}
	defer func() {
		for name, state := range states {
			if rep.rolledBack && state.Status == stampChanged {
				state.Status, state.Reasons = stampFailed, append(state.Reasons, i18n.T("cli.startup.undone"))
			}
			touchStamp(name, now, state)
		}
	}()
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		warn(i18n.T("cli.warn.templates_off", err))
		rep.failed++
		return cfg, rep
	}
	before := set.Warnings
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	var changed []gitsync.Result
	for _, st := range due {
		touchStamp(st.Name, now, nil)
		state := &stampState{}
		states[st.Name] = state
		var current []string
		t, ok := set.Get(st.Template)
		if !ok {
			warn(i18n.T("cli.startup.missing", st.Name, st.Template, cfg.Templates.Dir))
			rep.failed++
			state.worse(stampFailed)
			state.Reasons = append(state.Reasons, i18n.T("cli.startup.missing_short", st.Template))
			continue
		}
		if !t.Startup() {
			warn(i18n.T("cli.startup.not_startup", st.Name, st.Template))
			rep.failed++
			state.worse(stampFailed)
			state.Reasons = append(state.Reasons, i18n.T("cli.startup.not_startup", st.Name, st.Template))
			continue
		}
		in, err := template.NewInstance(st.Name, t, st.Params)
		if err != nil {
			warn(i18n.T("cli.startup.error", st.Name, err))
			rep.failed++
			state.worse(stampFailed)
			state.Reasons = append(state.Reasons, err.Error())
			continue
		}
		in.SetGitRoots(filepath.Dir(path), cfg.Templates.Dir)
		in.Print = func(msg string) { fmt.Fprintf(w, "%s: %s\n", st.Name, msg) }
		results, err := in.RunStartup(ctx)
		for _, r := range results {
			state.Repos = append(state.Repos, displayPath(r.Path)+" "+short(r.To))
			switch r.Status {
			case gitsync.Updated:
				fmt.Fprintln(w, i18n.T("cli.startup.updated", st.Name, displayPath(r.Path), r.Commits, short(r.From), short(r.To)))
				changed = append(changed, r)
				state.worse(stampChanged)
			case gitsync.Cloned:
				fmt.Fprintln(w, i18n.T("cli.startup.cloned", st.Name, displayPath(r.Path), r.URL))
				changed = append(changed, r)
				state.worse(stampChanged)
			case gitsync.Current:
				item := displayPath(r.Path) + " (" + short(r.To)
				if r.Reason != "" {
					item += ", " + r.Reason
				}
				current = append(current, item+")")
				state.worse(stampOK)
			case gitsync.Skipped:
				warn(i18n.T("cli.startup.skipped", st.Name, displayPath(r.Path), r.Reason))
				state.worse(stampSkipped)
				state.Reasons = append(state.Reasons, displayPath(r.Path)+" : "+r.Reason)
			default:
				warn(i18n.T("cli.startup.failed", st.Name, displayPath(r.Path), r.Reason))
				rep.failed++
				state.worse(stampFailed)
				state.Reasons = append(state.Reasons, displayPath(r.Path)+" : "+r.Reason)
			}
		}
		if len(current) > 0 && (force || !quiet) {
			fmt.Fprintln(w, i18n.T("cli.startup.current", st.Name, strings.Join(current, ", ")))
		}
		if err != nil {
			warn(i18n.T("cli.startup.error", st.Name, err))
			rep.failed++
			state.worse(stampFailed)
			state.Reasons = append(state.Reasons, err.Error())
		}
	}
	if len(changed) == 0 {
		return cfg, rep
	}
	next, cause := reloadAfterSync(path, before)
	if cause == "" {
		return next, rep
	}
	rep.rolledBack = true
	var undone []string
	for _, r := range slices.Backward(changed) {
		if r.Status != gitsync.Updated {
			continue
		}
		if err := gitsync.Rollback(context.WithoutCancel(ctx), r); err != nil {
			warn(i18n.T("cli.startup.rollback_failed", displayPath(r.Path), err))
			continue
		}
		undone = append(undone, displayPath(r.Path))
	}
	warn(i18n.T("cli.startup.rollback", strings.Join(undone, ", "), cause))
	if again, err := config.Load(path); err == nil {
		return again, rep
	}
	return cfg, rep
}

func reloadAfterSync(path string, before []string) (*config.Config, string) {
	next, err := config.Load(path)
	if err != nil {
		return nil, err.Error()
	}
	set, err := template.Load(next.Templates.Dir)
	if err != nil {
		return nil, err.Error()
	}
	for _, wn := range set.Warnings {
		if !slices.Contains(before, wn) {
			return nil, wn
		}
	}
	return next, ""
}

func short(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
}

func displayPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if rel, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
			return "~" + string(filepath.Separator) + rel
		}
	}
	return p
}

func cmdSync(ctx context.Context, o *options, w io.Writer) error {
	o.noStartup = true
	path, err := config.Resolve(o.config)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	if len(cfg.Startup) == 0 {
		fmt.Fprintln(w, i18n.T("cli.sync.none", path))
		return nil
	}
	_, rep := runStartup(ctx, path, cfg, true, false, w)
	if rep.rolledBack {
		return i18n.E("cli.err.sync_rollback")
	}
	if rep.failed > 0 {
		return i18n.E("cli.err.sync_failed", rep.failed)
	}
	return nil
}
