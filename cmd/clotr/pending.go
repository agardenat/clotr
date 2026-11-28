package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/orchestrator"
	"github.com/agardenat/clotr/internal/pending"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

type pendingSource struct {
	dir     string
	turn    int
	items   []pending.Item
	open    []pending.Item
	request string
	goals   map[string]string
	roles   map[string]string
}

func preparePending(o *options, args []string) (*pendingSource, error) {
	if len(args) > 0 {
		return nil, i18n.E("pending.args")
	}
	if o.session == "" {
		return nil, i18n.E("pending.session_required")
	}
	if err := creds.CanPrompt(); err != nil {
		return nil, i18n.E("pending.terminal", err)
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return nil, err
	}
	sess, err := session.Open(cfg.Sessions.Dir, o.session)
	if err != nil {
		return nil, err
	}
	for n := len(sess.Turns); n >= 1; n-- {
		dir := sess.TurnDir(n)
		items, err := pending.Load(filepath.Join(dir, pending.FileName))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(dir, pending.FileName), err)
		}
		open := pending.Open(items)
		if len(open) == 0 {
			continue
		}
		src := &pendingSource{dir: dir, turn: n, items: items, open: open, goals: map[string]string{}, roles: map[string]string{}}
		if t := sess.Turns[n-1]; len(t.CVE) > 0 && o.cveFlag == "" {
			o.cveIDs = slices.Clone(t.CVE)
			o.cveFlag = strings.Join(t.CVE, ",")
		}
		if o.ceilings == nil {
			o.ceilings = map[string]access.Level{}
		}
		for _, it := range open {
			if !slices.Contains(o.tools, it.Instance) {
				o.tools = append(o.tools, it.Instance)
			}
			o.ceilings[it.Instance] = max(o.ceilings[it.Instance], itemLevel(it))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "results.json")); err == nil {
			var results []orchestrator.Result
			if json.Unmarshal(b, &results) == nil {
				for _, r := range results {
					src.goals[r.TaskID], src.roles[r.TaskID] = r.Goal, r.Role
				}
			}
		}
		if sess.Language != "" && o.langFlag == "" {
			i18n.SetReport(sess.Language)
		}
		src.request = i18n.R("pending.request", n)
		return src, nil
	}
	return nil, i18n.E("pending.none", o.session)
}

func (rt *app) askPending(ctx context.Context, src *pendingSource) error {
	fmt.Fprintln(os.Stderr, i18n.T("pending.intro", len(src.open), src.turn))
	confirm := confirmWithin(0)
	items := slices.Clone(src.open)
	for i := range items {
		it := &items[i]
		where := it.Where
		if where == "" {
			where = "-"
		}
		q := i18n.T("pending.ask", i+1, len(items), it.Instance, where, orDefault(it.Task, "?"), progress.Command(orchestrator.PendingCommand(*it)), orDefault(it.Reason, it.Level))
		ans, err := confirm(ctx, q)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case err != nil:
			return err
		case ans == access.Once || ans == access.Always:
			it.Status = pending.StatusApproved
		default:
			it.Status = pending.StatusRefused
		}
	}
	rt.resume = &orchestrator.Resume{From: src.turn, Items: items, Goals: src.goals, Roles: src.roles}
	if rt.cves != nil {
		rt.cves.Restore(cveFromAudit(filepath.Join(src.dir, "audit.jsonl")))
	}
	return nil
}

func (rt *app) callPending(ctx context.Context, reg *tools.Registry, it pending.Item) (string, error) {
	i := slices.IndexFunc(rt.instances, func(in *template.Instance) bool { return in.Name == it.Instance })
	if i < 0 {
		return "", i18n.E("pending.instance_missing", it.Instance)
	}
	if it.Kind == pending.KindExec {
		rt.instances[i].Approve(it.Argv)
	}
	level := itemLevel(it)
	ctx = template.WithGrant(tools.WithCaller(ctx, tools.Caller{Task: orchestrator.ResumeID}), level)
	return reg.Call(ctx, []string{it.Tool}, it.Tool, string(it.Args))
}

func (src *pendingSource) save(resolved []pending.Item, turn int) error {
	byID := map[int]pending.Item{}
	for _, it := range resolved {
		byID[it.ID] = it
	}
	items := slices.Clone(src.items)
	for i, it := range items {
		r, ok := byID[it.ID]
		if !ok || r.Status == pending.StatusPending || r.Status == pending.StatusApproved {
			continue
		}
		items[i].Status, items[i].Evidence, items[i].Error, items[i].Resolved = r.Status, r.Evidence, r.Error, turn
	}
	return pending.Write(filepath.Join(src.dir, pending.FileName), items)
}

func withPendingSection(md string, items []pending.Item, sessName string) string {
	cell := func(s string) string {
		s = strings.Join(strings.Fields(s), " ")
		return strings.NewReplacer("|", "\\|", "`", "'").Replace(s)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n## %s\n\n%s\n\n%s\n", i18n.R("pending.title"), i18n.R("pending.report_intro", sessName), i18n.R("pending.head"))
	b.WriteString("|---|---|---|---|---|\n")
	for _, it := range items {
		where := it.Where
		if where == "" {
			where = "-"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s |\n", cell(orDefault(it.Task, "?")), cell(it.Instance), cell(where), cell(orchestrator.PendingCommand(it)), cell(orDefault(it.Reason, it.Level)))
	}
	annex := "\n\n---\n\n## " + i18n.R("evidence.title")
	if i := strings.Index(md, annex); i >= 0 {
		return md[:i] + b.String() + md[i:]
	}
	return strings.TrimRight(md, "\n") + b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func itemLevel(it pending.Item) access.Level {
	level, err := access.Parse(it.Level)
	if err != nil || it.Level == "" {
		return access.Exec
	}
	return level
}
