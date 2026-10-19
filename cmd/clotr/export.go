package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/export"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/mcp"
)

func outputFormat(path string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if slices.Contains(config.ExportFormats, ext) {
		return ext
	}
	return ""
}

func (o *options) resolveExport() error {
	if o.exportFmt != "" && !slices.Contains(config.ExportFormats, o.exportFmt) {
		return i18n.E("cli.err.export_format", o.exportFmt, strings.Join(config.ExportFormats, "|"))
	}
	f := outputFormat(o.output)
	if f == "" {
		return nil
	}
	if o.exportFmt != "" && o.exportFmt != f {
		return i18n.E("cli.err.export_output", o.output, o.exportFmt)
	}
	if o.json {
		return i18n.E("cli.err.export_json", o.output)
	}
	o.exportFmt, o.exportPath, o.output = f, o.output, ""
	return nil
}

func (o *options) checkExport(cfg *config.Config, confidential bool) error {
	if o.exportFmt == "" {
		return nil
	}
	name := cfg.Export.MCP
	switch {
	case name == "":
		return i18n.E("cli.err.export_mcp")
	case confidential:
		return i18n.E("cli.err.export_confidential", name)
	case matchGroup(o.exclude, "mcp_"+name):
		return i18n.E("cli.err.export_excluded", name)
	case cfg.ExportRole() == "":
		return i18n.E("cli.err.export_role")
	}
	return nil
}

func exportTitle(md, request string) string {
	for _, l := range strings.Split(md, "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(l), "# "); ok && strings.TrimSpace(t) != "" {
			return strings.TrimSpace(t)
		}
	}
	r := []rune(strings.Join(strings.Fields(request), " "))
	if len(r) > 80 {
		return string(r[:80]) + "…"
	}
	return string(r)
}

func (rt *app) newRunner(events progress.Sink, reg *tools.Registry) *agent.Runner {
	r := &agent.Runner{
		Chat:            rt.pool,
		Tools:           reg,
		Audit:           rt.audit,
		Events:          events,
		MaxSteps:        rt.cfg.Limits.MaxSteps,
		ConcludeReserve: min(5*time.Minute, rt.cfg.Limits.RequestTimeout.Duration),
		Attempts:        2,
		Backoff:         2 * time.Second,
		RoundPause:      30 * time.Second,
		Persistent: func(provider string) bool {
			p, ok := rt.cfg.Provider(provider)
			return ok && p.PersistentRetry
		},
		StallSteps: *rt.cfg.Limits.StallSteps,
		KeepSteps:  *rt.cfg.Limits.HistoryKeepSteps,
		ToolChars:  *rt.cfg.Limits.HistoryToolChars,
		Budget:     rt.budget,
	}
	if rt.memory != nil {
		r.ConcludeNotes = rt.memory.TaskNotes
	}
	return r
}

func exportApp(ctx context.Context, o *options, turnDir string) (*app, error) {
	rt, err := loadBase(ctx, o)
	if err != nil {
		return nil, err
	}
	rt.pool = llm.NewPool(rt.cfg, &http.Client{})
	rt.budget = budget.NewTracker(rt.cfg)
	if a, err := audit.Open(turnDir, "audit"); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.audit"), err)
	} else {
		rt.audit = a
		rt.closers = append(rt.closers, func() { _ = a.Close() })
	}
	return rt, nil
}

func (rt *app) exportReport(ctx context.Context, o *options, turnDir, title, md string) error {
	cfg := rt.cfg
	var srvCfg config.MCPServer
	for _, m := range cfg.MCP {
		if m.Name == cfg.Export.MCP {
			srvCfg = m
		}
	}
	role := cfg.ExportRole()
	cands, err := rt.router.Candidates(role)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, i18n.T("export.start", o.exportFmt, srvCfg.Name, role))
	srv, err := mcp.ConnectWriter(ctx, srvCfg, version)
	if err != nil {
		return err
	}
	defer srv.Close()
	if len(srv.Tools()) == 0 {
		return i18n.E("export.no_tools", srvCfg.Name)
	}
	job := &export.Job{Server: srv, Format: o.exportFmt, Markdown: md, Title: title}
	reg := job.Registry(cfg.Limits.ToolOutputMaxChars)
	rt.budget.NewRun()
	rt.audit.Log("export_start", map[string]any{"format": o.exportFmt, "mcp": srvCfg.Name, "role": role, "tools": reg.Names(), "chars": len(md)})
	events := newProgress(o, cfg.Limits.MaxSteps, i18n.T("export.title", o.exportFmt))
	out, runErr := rt.newRunner(events, reg).Run(ctx, job.Spec(ctx, role, cands, reg))
	events.Close()
	res, err := job.Result(ctx)
	model := ""
	if out != nil {
		model = out.Model
	}
	rec := map[string]any{"model": model, "error": errString(runErr)}
	if res != nil {
		rec["bytes"], rec["checked"], rec["missing"], rec["moved"], rec["flat"], rec["artifacts"] = len(res.Data), res.Checked, len(res.Missing), len(res.Moved), len(res.Flat), res.Artifacts
	}
	rt.audit.Log("export_end", rec)
	for _, c := range rt.budget.Summary() {
		fmt.Fprintln(os.Stderr, i18n.T("cost.line", c.String()))
	}
	if res == nil {
		if runErr != nil {
			return i18n.E("export.failed", runErr)
		}
		return i18n.E("export.failed", err)
	}
	path := filepath.Join(turnDir, "report."+o.exportFmt)
	if err := os.WriteFile(path, res.Data, 0o600); err != nil {
		return err
	}
	if o.exportPath != "" {
		if err := os.WriteFile(o.exportPath, res.Data, 0o644); err != nil {
			return err
		}
		path = o.exportPath
	}
	if model != "" {
		fmt.Fprintln(os.Stderr, i18n.T("models.used", model))
	}
	switch {
	case !res.Checked:
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("export.unchecked", o.exportFmt))
	case res.Issues() > 0:
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("export.issues"))
		for _, g := range []struct {
			label string
			items []string
		}{
			{i18n.T("export.missing", len(res.Missing)), res.Missing},
			{i18n.T("export.moved", len(res.Moved)), res.Moved},
			{i18n.T("export.flat", len(res.Flat)), res.Flat},
			{i18n.T("export.artifacts", len(res.Artifacts)), res.Artifacts},
		} {
			if len(g.items) == 0 {
				continue
			}
			fmt.Fprintln(os.Stderr, "  "+g.label)
			for _, m := range g.items[:min(3, len(g.items))] {
				fmt.Fprintln(os.Stderr, "    - "+m)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, i18n.T("export.checked"))
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), runErr)
	}
	fmt.Fprintln(os.Stderr, i18n.T("export.saved"), path)
	return nil
}
