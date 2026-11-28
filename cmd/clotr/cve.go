package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/cve"
	"github.com/agardenat/clotr/internal/cve/sources"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/mcp"
)

func cveCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     i18n.T("cli.cve.use"),
		Short:   i18n.T("cli.cve.short"),
		Long:    i18n.T("cli.cve.long"),
		Example: i18n.T("cli.cve.example"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return cmdCVE(c.Context(), o, args, c.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&o.cveForce, "force", false, i18n.T("cli.flag.cve_force"))
	cmd.Flags().StringToStringVarP(&o.models, "model", "m", nil, i18n.T("cli.flag.model"))
	cmd.Flags().StringVar(&o.web, "web", "", i18n.T("cli.flag.web"))
	cmd.Flags().IntVar(&o.maxSteps, "max-steps", 0, i18n.T("cli.flag.max_steps"))
	cmd.Flags().BoolVar(&o.json, "json", false, i18n.T("cli.flag.cve_json"))
	cmd.Flags().StringVarP(&o.output, "output", "o", "", i18n.T("cli.flag.output"))
	cmd.Flags().BoolVar(&o.raw, "raw", false, i18n.T("cli.flag.raw"))
	cmd.Flags().BoolVarP(&o.quiet, "quiet", "q", false, i18n.T("cli.flag.quiet"))
	cmd.Flags().BoolVar(&o.plain, "plain", false, i18n.T("cli.flag.plain"))
	cmd.Flags().BoolVar(&o.progressJSON, "progress-json", false, i18n.T("cli.flag.progress_json"))
	return cmd
}

func cmdCVE(ctx context.Context, o *options, args []string, w io.Writer) error {
	ids := cve.Extract(strings.Join(args, " "))
	if len(ids) == 0 {
		return i18n.E("cli.cve.no_id")
	}
	rt, err := loadBase(ctx, o)
	if err != nil {
		return err
	}
	defer rt.close()
	cfg := rt.cfg
	warn := func(msg string) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), msg)
	}
	rt.pool = llm.NewPool(cfg, &http.Client{})
	rt.lang = o.lang
	rt.budget = budget.NewTracker(cfg)
	statuses := budget.FetchAll(ctx, &http.Client{Timeout: 15 * time.Second}, cfg)
	for _, st := range statuses {
		if st.Error != "" {
			fmt.Fprint(os.Stderr, i18n.T("cli.warn.budget_unchecked", st.Provider, st.Error))
		}
	}
	for _, msg := range rt.budget.Seed(statuses) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.budget"), msg)
	}
	if a, err := audit.Open(cfg.Audit.Dir, time.Now().Format("20060102-150405")); err != nil {
		warn(i18n.T("cli.warn.audit_off", err))
	} else {
		rt.audit = a
		rt.closers = append(rt.closers, func() { _ = a.Close() })
	}
	rt.registry = tools.NewRegistry(cfg.Limits.ToolOutputMaxChars)
	rt.evidence = evidence.Open("", 1)
	rt.memory = memory.NewStore()
	rt.registry.Add(rt.memory.Tools()...)
	rt.registry.Add(rt.evidence.Tool(), rt.evidence.SearchTool())
	rt.cves = cve.New(ids, rt.memory, rt.evidence, rt.audit)
	rt.cves.CacheDir = filepath.Join(config.StateDir(), "clotr", "cve")
	rt.cves.Sources = sources.New(cveDistros(cfg, cfg.Clients), rt.cves.CacheDir)
	rt.cves.Force = o.cveForce
	rt.registry.Add(rt.cves.Tools()...)

	if rt.lang != "fr" && rt.lang != "en" {
		i18n.SetReport(i18n.UI())
	}
	request := i18n.R("cve.fiche_request", strings.Join(ids, ", "))
	events := newProgress(o, cfg.Limits.MaxSteps, strings.Join(ids, ", "))
	defer events.Close()
	rt.cves.Events = events
	rt.cves.Prepare(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if rt.cves.NeedsWeb() {
		if err := o.decideWeb(cfg, rt.confidential, nil, request); err != nil {
			return err
		}
		if rt.setupWeb(ctx, o, warn); len(rt.webTools) == 0 {
			warn(i18n.T("cli.cve.no_web"))
		}
	}
	result := rt.orchestrator(events, rt.registry, "").Advisories(ctx, request)
	events.Close()

	fiches := map[string]string{}
	var parts []string
	for _, a := range rt.cves.Advisories() {
		md := "# " + a.CVE + "\n\n" + rt.cves.Fiche(a.CVE)
		fiches[a.CVE] = md
		parts = append(parts, md)
	}
	missing := rt.cves.Missing()
	md := strings.Join(parts, "\n\n")
	if o.json {
		doc := map[string]any{"advisories": rt.cves.Advisories(), "fiches": fiches, "missing": missing}
		out, _ := json.MarshalIndent(doc, "", "  ")
		if err := writeReport(w, o.output, append(out, '\n'), nil); err != nil {
			return err
		}
	} else if md != "" {
		if o.output != "" {
			if err := writeReport(w, o.output, []byte(md+"\n"), nil); err != nil {
				return err
			}
		} else {
			writeMarkdown(w, md, o.raw)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(missing) > 0 {
		if result.Error != "" {
			return i18n.E("cli.cve.failed", strings.Join(missing, ", "), result.Error)
		}
		return i18n.E("cli.cve.missing", strings.Join(missing, ", "))
	}
	return nil
}

func (rt *app) setupWeb(ctx context.Context, o *options, warn func(string)) {
	if !o.webAllowed {
		return
	}
	kind, ref := webTarget(rt.cfg, o.exclude)
	switch kind {
	case "model":
		rt.addModelWeb(ref, warn)
	case "mcp":
		for _, m := range rt.cfg.MCP {
			if m.Name != ref {
				continue
			}
			servers, warnings := mcp.ConnectAll(ctx, []config.MCPServer{m}, version)
			for _, msg := range warnings {
				warn(msg)
			}
			for _, s := range servers {
				rt.closers = append(rt.closers, func() { _ = s.Close() })
				rt.registry.Add(s.Tools()...)
			}
		}
		mcp.CloseLogins()
		for _, n := range rt.registry.Names() {
			if strings.HasPrefix(n, "mcp_"+ref+"_") {
				rt.webTools = append(rt.webTools, n)
			}
		}
	}
}
