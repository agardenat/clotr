package main

import (
	"context"
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

func touchStamp(name string, now time.Time) {
	p := startupStamp(name)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if err := os.WriteFile(p, nil, 0o600); err == nil {
		_ = os.Chtimes(p, now, now)
	}
}

func runStartup(ctx context.Context, path string, cfg *config.Config, force bool, w io.Writer) (*config.Config, startupReport) {
	var rep startupReport
	now := time.Now()
	var due []config.Startup
	for _, st := range cfg.Startup {
		if st.IsEnabled() && (force || startupDue(st, now)) {
			due = append(due, st)
		}
	}
	if len(due) == 0 {
		return cfg, rep
	}
	warn := func(msg string) {
		fmt.Fprintln(w, i18n.T("cli.warning"), msg)
	}
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
		touchStamp(st.Name, now)
		t, ok := set.Get(st.Template)
		if !ok {
			warn(i18n.T("cli.startup.missing", st.Name, st.Template, cfg.Templates.Dir))
			rep.failed++
			continue
		}
		if !t.Startup() {
			warn(i18n.T("cli.startup.not_startup", st.Name, st.Template))
			rep.failed++
			continue
		}
		in, err := template.NewInstance(st.Name, t, st.Params)
		if err != nil {
			warn(i18n.T("cli.startup.error", st.Name, err))
			rep.failed++
			continue
		}
		in.SetGitRoots(filepath.Dir(path), cfg.Templates.Dir)
		in.Print = func(msg string) { fmt.Fprintf(w, "%s: %s\n", st.Name, msg) }
		results, err := in.RunStartup(ctx)
		for _, r := range results {
			switch r.Status {
			case gitsync.Updated:
				fmt.Fprintln(w, i18n.T("cli.startup.updated", st.Name, displayPath(r.Path), r.Commits, short(r.From), short(r.To)))
				changed = append(changed, r)
			case gitsync.Cloned:
				fmt.Fprintln(w, i18n.T("cli.startup.cloned", st.Name, displayPath(r.Path), r.URL))
				changed = append(changed, r)
			case gitsync.Current:
				if force {
					line := i18n.T("cli.startup.current", st.Name, displayPath(r.Path), short(r.To))
					if r.Reason != "" {
						line += " (" + r.Reason + ")"
					}
					fmt.Fprintln(w, line)
				}
			case gitsync.Skipped:
				warn(i18n.T("cli.startup.skipped", st.Name, displayPath(r.Path), r.Reason))
			default:
				warn(i18n.T("cli.startup.failed", st.Name, displayPath(r.Path), r.Reason))
				rep.failed++
			}
		}
		if err != nil {
			warn(i18n.T("cli.startup.error", st.Name, err))
			rep.failed++
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
	_, rep := runStartup(ctx, path, cfg, true, w)
	if rep.rolledBack {
		return i18n.E("cli.err.sync_rollback")
	}
	if rep.failed > 0 {
		return i18n.E("cli.err.sync_failed", rep.failed)
	}
	return nil
}
