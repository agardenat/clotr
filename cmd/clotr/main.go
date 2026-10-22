package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/cve"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/lead"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/markdown"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/orchestrator"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/router"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/dns"
	"github.com/agardenat/clotr/internal/tools/files"
	"github.com/agardenat/clotr/internal/tools/mcp"
	"github.com/agardenat/clotr/internal/websearch"
)

var version = "dev"

type options struct {
	config       string
	refresh      bool
	models       map[string]string
	tools        []string
	exclude      []string
	output       string
	json         bool
	quiet        bool
	all          bool
	sovereign    string
	confidential bool
	plain        bool
	session      string
	turn         int
	showPath     bool
	auditDir     string
	langFlag     string
	lang         string
	uiLangFlag   string
	evidenceID   string
	synthesize   bool
	web          string
	webAllowed   bool
	evidence     *evidence.Store
	maxAgents    int
	maxTasks     int
	maxSteps     int
	direct       string
	chat         bool
	withEvidence bool
	raw          bool
	incident     bool
	panic        bool
	exportFmt    string
	exportPath   string
	accessFlag   string
	accessSet    bool
	access       access.Level
	cveMode      bool
	cveIDs       []string
}

type app struct {
	cfg         *config.Config
	cat         *catalog.Catalog
	router      *router.Router
	registry    *tools.Registry
	pool        *llm.Pool
	audit       *audit.Logger
	budget      *budget.Tracker
	mcpServers  []*mcp.Server
	instances   []*template.Instance
	memory      *memory.Store
	lang        string
	environment string
	baseEnv     []string
	instanceEnv map[string][]string
	webTools    []string
	evidence    *evidence.Store
	leads       *lead.Store
	cves        *cve.Store
	journal     bool
	filtered    []*template.Instance
	closers     []func()
}

func (r *app) close() {
	for i := len(r.closers) - 1; i >= 0; i-- {
		r.closers[i]()
	}
}

func main() {
	httpx.UserAgent = "clotr/" + version
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go watchInterrupts(ctx, cancel, sigs, &interruptHook)
	initUILanguage(os.Args[1:])
	if err := newRoot().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.error"), err)
		os.Exit(1)
	}
}

var interruptHook atomic.Pointer[func()]

func watchInterrupts(ctx context.Context, cancel context.CancelFunc, sigs <-chan os.Signal, hook *atomic.Pointer[func()]) {
	hooked := false
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			if f := hook.Load(); f != nil && !hooked && sig == os.Interrupt {
				hooked = true
				(*f)()
				continue
			}
			cancel()
			return
		}
	}
}

func newRoot() *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:           "clotr",
		Short:         i18n.T("cli.root.short"),
		Long:          i18n.T("cli.root.long"),
		Example:       i18n.T("cli.root.example"),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&o.config, "config", "c", "", i18n.T("cli.flag.config"))
	root.PersistentFlags().BoolVar(&o.refresh, "refresh", false, i18n.T("cli.flag.refresh"))
	root.PersistentFlags().StringVar(&o.sovereign, "sovereign", "", i18n.T("cli.flag.sovereign"))
	root.PersistentFlags().BoolVar(&o.confidential, "confidential", false, i18n.T("cli.flag.confidential"))
	root.PersistentFlags().StringVar(&o.langFlag, "lang", "", i18n.T("cli.flag.lang"))
	root.PersistentFlags().StringVar(&o.uiLangFlag, "ui-lang", "", i18n.T("cli.flag.ui_lang"))

	models := &cobra.Command{
		Use:   "models",
		Short: i18n.T("cli.models.short"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdModels(cmd.Context(), o, cmd.OutOrStdout())
		},
	}
	models.Flags().BoolVar(&o.json, "json", false, i18n.T("cli.flag.json"))
	models.Flags().BoolVar(&o.all, "all", false, i18n.T("cli.flag.all"))

	addTaskFlags := func(c *cobra.Command) {
		c.Flags().StringToStringVarP(&o.models, "model", "m", nil, i18n.T("cli.flag.model"))
		c.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, i18n.T("cli.flag.tools"))
		c.Flags().StringSliceVarP(&o.exclude, "exclude", "x", nil, i18n.T("cli.flag.exclude"))
		c.Flags().StringVar(&o.web, "web", "", i18n.T("cli.flag.web"))
		c.Flags().IntVar(&o.maxAgents, "max-agents", 0, i18n.T("cli.flag.max_agents"))
		c.Flags().IntVar(&o.maxTasks, "max-tasks", 0, i18n.T("cli.flag.max_tasks"))
		c.Flags().IntVar(&o.maxSteps, "max-steps", 0, i18n.T("cli.flag.max_steps"))
	}

	plan := &cobra.Command{
		Use:   i18n.T("cli.plan.use"),
		Short: i18n.T("cli.plan.short"),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdPlan(cmd.Context(), o, args, cmd.OutOrStdout())
		},
	}
	addTaskFlags(plan)
	plan.Flags().BoolVarP(&o.quiet, "quiet", "q", false, i18n.T("cli.flag.quiet"))
	plan.Flags().BoolVar(&o.plain, "plain", false, i18n.T("cli.flag.plain"))

	run := &cobra.Command{
		Use:     i18n.T("cli.run.use"),
		Short:   i18n.T("cli.run.short"),
		Long:    i18n.T("cli.run.long"),
		Example: i18n.T("cli.run.example"),
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.accessSet = cmd.Flags().Changed("access")
			return cmdRun(cmd.Context(), o, args, cmd.OutOrStdout())
		},
	}
	addTaskFlags(run)
	run.Flags().StringVarP(&o.output, "output", "o", "", i18n.T("cli.flag.output"))
	run.Flags().BoolVar(&o.json, "json", false, i18n.T("cli.flag.run_json"))
	run.Flags().BoolVarP(&o.quiet, "quiet", "q", false, i18n.T("cli.flag.quiet"))
	run.Flags().BoolVar(&o.plain, "plain", false, i18n.T("cli.flag.plain"))
	run.Flags().StringVarP(&o.session, "session", "s", "", i18n.T("cli.flag.session"))
	run.Flags().StringVar(&o.direct, "direct", "", i18n.T("cli.flag.direct"))
	run.Flags().Lookup("direct").NoOptDefVal = directAuto
	run.Flags().BoolVar(&o.chat, "chat", false, i18n.T("cli.flag.chat"))
	run.Flags().BoolVar(&o.raw, "raw", false, i18n.T("cli.flag.raw"))
	run.Flags().BoolVar(&o.withEvidence, "with-evidence", false, i18n.T("cli.flag.with_evidence"))
	run.Flags().BoolVar(&o.incident, "incident", false, i18n.T("cli.flag.incident"))
	run.Flags().BoolVar(&o.cveMode, "cve", false, i18n.T("cli.flag.cve"))
	run.Flags().BoolVar(&o.panic, "panic", false, i18n.T("cli.flag.panic"))
	run.Flags().StringVar(&o.exportFmt, "export", "", i18n.T("cli.flag.export"))
	run.Flags().StringVar(&o.accessFlag, "access", "", i18n.T("cli.flag.access"))

	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: i18n.T("cli.sessions.short"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdSessions(o, cmd.OutOrStdout())
		},
	}
	sessionCmd := &cobra.Command{
		Use:   i18n.T("cli.session.use"),
		Short: i18n.T("cli.session.short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.synthesize {
				return cmdResynthesize(cmd.Context(), o, args[0], cmd.OutOrStdout())
			}
			return cmdSession(cmd.Context(), o, args[0], cmd.OutOrStdout())
		},
	}
	sessionCmd.Flags().IntVar(&o.turn, "turn", 0, i18n.T("cli.flag.turn"))
	sessionCmd.Flags().BoolVar(&o.showPath, "path", false, i18n.T("cli.flag.path"))
	sessionCmd.Flags().BoolVar(&o.synthesize, "synthesize", false, i18n.T("cli.flag.synthesize"))
	sessionCmd.Flags().StringVarP(&o.output, "output", "o", "", i18n.T("cli.flag.output"))
	sessionCmd.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, i18n.T("cli.flag.resynth_tools"))
	sessionCmd.Flags().StringSliceVarP(&o.exclude, "exclude", "x", nil, i18n.T("cli.flag.resynth_exclude"))
	sessionCmd.Flags().StringVar(&o.evidenceID, "evidence", "", i18n.T("cli.flag.evidence"))
	sessionCmd.Flags().BoolVar(&o.raw, "raw", false, i18n.T("cli.flag.raw"))
	sessionCmd.Flags().BoolVar(&o.withEvidence, "with-evidence", false, i18n.T("cli.flag.with_evidence"))
	sessionCmd.Flags().StringVar(&o.exportFmt, "export", "", i18n.T("cli.flag.export"))
	sessionCmd.Flags().BoolVarP(&o.quiet, "quiet", "q", false, i18n.T("cli.flag.quiet"))
	sessionCmd.Flags().BoolVar(&o.plain, "plain", false, i18n.T("cli.flag.plain"))

	toolsCmd := &cobra.Command{
		Use:   "tools",
		Short: i18n.T("cli.tools.short"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdTools(cmd.Context(), o, cmd.OutOrStdout())
		},
	}
	toolsCmd.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, i18n.T("cli.flag.tools"))
	toolsCmd.Flags().StringSliceVarP(&o.exclude, "exclude", "x", nil, i18n.T("cli.flag.exclude"))

	templatesCmd := &cobra.Command{
		Use:   i18n.T("cli.templates.use"),
		Short: i18n.T("cli.templates.short"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdTemplates(o, args, cmd.OutOrStdout())
		},
	}
	var testDir string
	templatesTest := &cobra.Command{
		Use:   i18n.T("cli.templates_test.use"),
		Short: i18n.T("cli.templates_test.short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdTemplatesTest(cmd.Context(), o, testDir, args[0], cmd.OutOrStdout())
		},
	}
	templatesTest.Flags().StringVar(&testDir, "dir", "", i18n.T("cli.flag.templates_dir"))
	templatesCmd.AddCommand(templatesTest)

	ver := &cobra.Command{
		Use:   "version",
		Short: i18n.T("cli.version.short"),
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}

	root.AddCommand(models, plan, run, sessionsCmd, sessionCmd, toolsCmd, templatesCmd, ver)
	localizeCobra(root)
	return root
}

func readRequest(args []string) (string, error) {
	if len(args) == 1 && args[0] == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		args = []string{string(data)}
	}
	req := strings.TrimSpace(strings.Join(args, " "))
	if req == "" {
		return "", i18n.E("cli.err.empty_request")
	}
	return req, nil
}

func loadConfig(o *options) (*config.Config, error) {
	if o.uiLangFlag != "" {
		if !config.ValidUILanguage(o.uiLangFlag) {
			return nil, i18n.E("cli.err.ui_lang", o.uiLangFlag)
		}
		i18n.SetUI(o.uiLangFlag)
	}
	path, err := config.Resolve(o.config)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	applyVaultEnv(cfg.Vault)
	for _, l := range []struct {
		flag string
		v    int
		dst  *int
	}{{"--max-agents", o.maxAgents, &cfg.Limits.MaxAgents}, {"--max-tasks", o.maxTasks, &cfg.Limits.MaxTasks}, {"--max-steps", o.maxSteps, &cfg.Limits.MaxSteps}} {
		if l.v < 0 {
			return nil, i18n.E("cli.err.positive", l.flag, l.v)
		}
		if l.v > 0 {
			*l.dst = l.v
		}
	}
	o.lang = cfg.Language
	if o.langFlag != "" {
		if !config.ValidLanguage(o.langFlag) {
			return nil, i18n.E("cli.err.lang", o.langFlag)
		}
		o.lang = o.langFlag
	}
	i18n.SetReport(o.lang)
	return cfg, nil
}

func loadBase(ctx context.Context, o *options) (*app, error) {
	cfg, err := loadConfig(o)
	if err != nil {
		return nil, err
	}
	cat, err := catalog.Load(ctx, cfg, &http.Client{Timeout: 15 * time.Second}, catalog.DefaultCachePath(), o.refresh)
	if err != nil {
		return nil, err
	}
	for _, w := range cat.Warnings {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), w)
	}
	if o.confidential {
		if o.sovereign != "" && o.sovereign != "require" {
			return nil, i18n.E("cli.err.confidential_sovereign", o.sovereign)
		}
		o.sovereign = "require"
	}
	rt, err := router.New(cfg, cat, o.models, o.sovereign)
	if err != nil {
		return nil, err
	}
	return &app{cfg: cfg, cat: cat, router: rt, audit: audit.Nop()}, nil
}

func webTarget(cfg *config.Config, exclude []string) (kind, name string) {
	if name := cfg.WebSearch.MCP; name != "" && !matchGroup(exclude, "mcp_"+name) {
		for _, m := range cfg.MCP {
			if m.Name == name && m.IsEnabled() {
				return "mcp", name
			}
		}
	}
	if cfg.WebSearch.Model != "" {
		return "model", cfg.WebSearch.Model
	}
	return "", ""
}

func resolveWeb(cfg *config.Config, o *options, confidential bool) (bool, string, error) {
	if cfg.WebSearch.MCP == "" && cfg.WebSearch.Model == "" {
		return false, "", nil
	}
	switch o.web {
	case "", "yes", "no":
	default:
		return false, "", i18n.E("cli.err.web", o.web)
	}
	if confidential {
		if o.web == "yes" {
			return false, "", i18n.E("cli.err.web_confidential")
		}
		return false, i18n.T("web.confidential"), nil
	}
	_, target := webTarget(cfg, o.exclude)
	if target == "" {
		if !matchGroup(o.exclude, "mcp_"+cfg.WebSearch.MCP) {
			return false, "", nil
		}
		if o.web == "yes" {
			return false, "", i18n.E("cli.err.web_excluded", cfg.WebSearch.MCP)
		}
		return false, i18n.T("web.exclude"), nil
	}
	switch {
	case o.web == "yes":
		return true, target, nil
	case o.web == "no":
		return false, i18n.T("web.flag"), nil
	case cfg.WebSearch.Policy == "allow":
		return true, target, nil
	case cfg.WebSearch.Policy == "deny":
		return false, i18n.T("web.policy"), nil
	}
	ok, err := creds.Confirm(i18n.T("web.ask", target))
	if err != nil {
		return false, i18n.T("web.notty"), nil
	}
	if !ok {
		return false, i18n.T("web.denied"), nil
	}
	return true, target, nil
}

func (o *options) decideWeb(cfg *config.Config, confidential bool) error {
	allowed, why, err := resolveWeb(cfg, o, confidential)
	if err != nil {
		return err
	}
	o.webAllowed = allowed
	if why == "" {
		return nil
	}
	if allowed {
		fmt.Fprintln(os.Stderr, i18n.T("web.on", why))
	} else {
		fmt.Fprintln(os.Stderr, i18n.T("web.off", why))
	}
	return nil
}

type toolFilter struct {
	only, exclude []string
}

func toolGroup(t string) string {
	return strings.TrimSuffix(strings.TrimSuffix(t, "*"), "_")
}

func matchGroup(list []string, prefix string) bool {
	for _, t := range list {
		t = toolGroup(t)
		if t == prefix || strings.HasPrefix(prefix, t+"_") {
			return true
		}
	}
	return false
}

func (f toolFilter) enabled(prefix string) bool {
	if matchGroup(f.exclude, prefix) {
		return false
	}
	return len(f.only) == 0 || matchGroup(f.only, prefix)
}

func (f toolFilter) active(prefix string, on bool) bool {
	if !f.enabled(prefix) {
		return false
	}
	return on || slices.ContainsFunc(f.only, func(t string) bool { return toolGroup(t) == prefix })
}

func expandClients(cfg *config.Config, list []string) []string {
	var out []string
	for _, t := range list {
		var names []string
		for _, in := range cfg.Instances {
			if in.Client != "" && in.Client == toolGroup(t) && in.IsEnabled() {
				names = append(names, in.Name)
			}
		}
		if len(names) == 0 {
			names = []string{t}
		}
		out = append(out, names...)
	}
	return out
}

func applyVaultEnv(v config.VaultConf) {
	for env, val := range map[string]string{"VAULT_ADDR": v.Addr, "VAULT_NAMESPACE": v.Namespace} {
		if val != "" && os.Getenv(env) == "" {
			os.Setenv(env, val)
		}
	}
}

func renderVars(v any, vars map[string]any) (any, error) {
	switch x := v.(type) {
	case string:
		return template.Render(x, vars)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := renderVars(e, vars)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			r, err := renderVars(e, vars)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = r
		}
		return out, nil
	}
	return v, nil
}

func newInstance(cfg *config.Config, ic config.Instance, t *template.Template, level access.Level) (*template.Instance, error) {
	cl, _ := cfg.Client(ic.Client)
	params := map[string]any{}
	for k, v := range cl.Params {
		if _, declared := t.Params[k]; declared {
			params[k] = v
		}
	}
	maps.Copy(params, ic.Params)
	vars := map[string]any{}
	for k, v := range cl.Vars {
		vars[k] = v
	}
	rendered, err := renderVars(params, vars)
	if err != nil {
		return nil, fmt.Errorf("instance %s: params.%w", ic.Name, err)
	}
	in, err := template.NewInstance(ic.Name, t, rendered.(map[string]any))
	if err != nil {
		return nil, err
	}
	if err := in.ExtendPaths(ic.SSHPaths); err != nil {
		return nil, err
	}
	if err := in.ExtendCommands(ic.Commands); err != nil {
		return nil, err
	}
	in.SetAccess(level)
	if ic.Client != "" {
		in.Client, in.ClientTerms = ic.Client, append([]string{cl.Name}, cl.Aliases...)
	}
	return in, nil
}

func checkToolGroups(cfg *config.Config, lists ...[]string) error {
	groups := []string{"fs", "memory", "evidence", dns.Group}
	for _, m := range cfg.MCP {
		groups = append(groups, "mcp_"+m.Name)
	}
	for _, in := range cfg.Instances {
		groups = append(groups, in.Name)
	}
	for _, list := range lists {
		for _, t := range list {
			if slices.ContainsFunc(groups, func(g string) bool { return matchGroup([]string{t}, g) }) {
				continue
			}
			if slices.Contains(groups, "mcp_"+toolGroup(t)) {
				return i18n.E("cli.err.group_mcp", t, toolGroup(t))
			}
			return i18n.E("cli.err.group", t)
		}
	}
	return nil
}

func setup(ctx context.Context, o *options, withAudit bool) (*app, error) {
	rt, err := loadBase(ctx, o)
	if err != nil {
		return nil, err
	}
	cfg := rt.cfg
	rt.pool = llm.NewPool(cfg, &http.Client{})
	rt.lang = o.lang
	rt.budget = budget.NewTracker(cfg)
	statuses := budget.FetchAll(ctx, &http.Client{Timeout: 15 * time.Second}, cfg)
	for _, st := range statuses {
		if st.Error != "" {
			fmt.Fprint(os.Stderr, i18n.T("cli.warn.budget_unchecked", st.Provider, st.Error))
		}
	}
	for _, w := range rt.budget.Seed(statuses) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.budget"), w)
	}
	rt.registry = tools.NewRegistry(cfg.Limits.ToolOutputMaxChars)
	filter := toolFilter{only: expandClients(cfg, o.tools), exclude: expandClients(cfg, o.exclude)}
	if err := checkToolGroups(cfg, filter.only, filter.exclude); err != nil {
		return nil, err
	}
	warn := func(msg string) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), msg)
	}
	if withAudit {
		dir, runID := cfg.Audit.Dir, time.Now().Format("20060102-150405")
		if o.auditDir != "" {
			dir, runID = o.auditDir, "audit"
		}
		a, err := audit.Open(dir, runID)
		if err != nil {
			warn(i18n.T("cli.warn.audit_off", err))
		} else {
			rt.audit = a
			rt.closers = append(rt.closers, func() { _ = a.Close() })
		}
	}
	var envLines []string

	if cfg.Files != nil && filter.enabled("fs") {
		f, warnings, err := files.New(cfg.Files)
		for _, w := range warnings {
			warn(w)
		}
		if err != nil {
			warn(i18n.T("cli.warn.fs_off", err))
		} else {
			rt.registry.Add(f.Tools()...)
			envLines = append(envLines, "- Fichiers locaux: "+strings.Join(cfg.Files.Roots, ", "))
		}
	}
	var mcpCfgs []config.MCPServer
	for _, m := range cfg.MCP {
		if m.Name == cfg.Export.MCP {
			continue
		}
		if m.Name == cfg.WebSearch.MCP {
			if o.webAllowed && m.IsEnabled() && !matchGroup(o.exclude, "mcp_"+m.Name) {
				mcpCfgs = append(mcpCfgs, m)
			}
			continue
		}
		if filter.active("mcp_"+m.Name, m.IsEnabled()) {
			mcpCfgs = append(mcpCfgs, m)
		}
	}
	if len(mcpCfgs) > 0 {
		servers, warnings := mcp.ConnectAll(ctx, mcpCfgs, version)
		for _, w := range warnings {
			warn(w)
		}
		rt.mcpServers = servers
		for _, s := range servers {
			rt.closers = append(rt.closers, func() { _ = s.Close() })
			rt.registry.Add(s.Tools()...)
			envLines = append(envLines, fmt.Sprintf("- MCP %s: %d outils (préfixe mcp_%s)", s.Name(), len(s.Tools()), s.Name()))
		}
	}
	if kind, ref := webTarget(cfg, o.exclude); o.webAllowed && kind == "model" {
		prov, model, _ := strings.Cut(ref, "/")
		p, _ := cfg.Provider(prov)
		if t, err := websearch.New(p, model, cfg.WebSearch.API, cfg.Limits.RequestTimeout.Duration); err != nil {
			warn(i18n.T("cli.warn.web_off", err))
		} else {
			rt.registry.Add(t)
			rt.webTools = append(rt.webTools, t.Name())
			envLines = append(envLines, fmt.Sprintf("- Recherche web: %s (recherche native du modèle %s)", t.Name(), t.Ref()))
		}
	}
	rt.setupInstances(ctx, o, filter, warn)
	rt.baseEnv = envLines
	for _, in := range rt.instances {
		envLines = append(envLines, rt.instanceEnv[in.Name]...)
	}
	if rt.registry.Len() == 0 {
		rt.close()
		return nil, i18n.E("cli.err.no_tools")
	}
	rt.evidence = o.evidence
	rt.memory = memory.NewStore()
	rt.registry.Add(rt.memory.Tools()...)
	if !matchGroup(o.exclude, dns.Group) {
		rt.registry.Add(dns.New())
	}
	if rt.evidence != nil {
		rt.registry.Add(rt.evidence.Tool(), rt.evidence.SearchTool())
		if o.incident {
			rt.leads = lead.New(rt.memory, rt.evidence, rt.audit)
			rt.journal = o.panic
			rt.registry.Add(rt.leads.Tool())
		}
		if len(o.cveIDs) > 0 {
			rt.cves = cve.New(o.cveIDs, rt.memory, rt.evidence, rt.audit)
			rt.registry.Add(rt.cves.Tools()...)
		}
	}
	rt.environment = strings.Join(envLines, "\n")
	if cfg.WebSearch.MCP != "" {
		for _, n := range rt.registry.Names() {
			if strings.HasPrefix(n, "mcp_"+cfg.WebSearch.MCP+"_") {
				rt.webTools = append(rt.webTools, n)
			}
		}
	}

	return rt, nil
}

func (rt *app) setupInstances(ctx context.Context, o *options, filter toolFilter, warn func(string)) {
	cfg := rt.cfg
	var active, filtered []config.Instance
	for _, in := range cfg.Instances {
		switch {
		case filter.active(in.Name, in.IsEnabled()):
			active = append(active, in)
		case in.IsEnabled() && !matchGroup(filter.exclude, in.Name):
			filtered = append(filtered, in)
		}
	}
	if len(active)+len(filtered) == 0 {
		return
	}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		warn(i18n.T("cli.warn.templates_off", err))
		return
	}
	for _, w := range set.Warnings {
		warn(w)
	}
	rt.instanceEnv = map[string][]string{}
	for _, ic := range filtered {
		t, ok := set.Get(ic.Template)
		if !ok {
			continue
		}
		in, err := newInstance(cfg, ic, t, o.levelFor(cfg, ic))
		if err == nil {
			err = in.Defer(ctx, cfg.Templates.CacheDir, cfg.Templates.CacheTTL.Duration, false)
		}
		if err != nil {
			continue
		}
		rt.filtered = append(rt.filtered, in)
		rt.closers = append(rt.closers, in.Close)
	}
	for _, ic := range active {
		t, ok := set.Get(ic.Template)
		if !ok {
			warn(i18n.T("cli.warn.template_missing", ic.Name, ic.Template))
			continue
		}
		in, err := newInstance(cfg, ic, t, o.levelFor(cfg, ic))
		if err == nil {
			in.Audit = rt.audit.Log
			in.Warn = warn
			in.Confirm = confirmCommand
			if len(o.cveIDs) > 0 {
				in.SetCeiling(access.Create)
			}
			if !o.quiet {
				name, tname := ic.Name, t.Name
				in.Activating = func() { fmt.Fprintln(os.Stderr, i18n.T("instance.discovering", name, tname)) }
			}
			err = in.Defer(ctx, cfg.Templates.CacheDir, cfg.Templates.CacheTTL.Duration, o.refresh)
		}
		if err != nil {
			warn(i18n.T("cli.warn.instance_off", err, ic.Name))
			continue
		}
		rt.instances = append(rt.instances, in)
		rt.closers = append(rt.closers, in.Close)
		rt.registry.Add(in.Tools()...)
		rt.registry.AddGroup(in.ToolPrefix())
		rt.registry.AddCompanions(in.ToolPrefix(), in.Companions()...)
		rt.instanceEnv[ic.Name] = in.EnvironmentLines()
	}
}

func (rt *app) warnFiltered(text string) {
	for _, in := range rt.filtered {
		if why := in.Mention(text); why != "" {
			fmt.Fprintln(os.Stderr, i18n.T("instance.filtered", in.Name, why, in.Name))
			rt.audit.Log("instance_filtered", map[string]any{"instance": in.Name, "match": why})
		}
	}
}

func (rt *app) scope(forced []string, text string) (*tools.Registry, string) {
	forced = expandClients(rt.cfg, forced)
	env := append([]string(nil), rt.baseEnv...)
	named := map[string]bool{}
	var clients []string
	for _, cl := range rt.cfg.Clients {
		if template.MentionTerm(text, append([]string{cl.Name}, cl.Aliases...)) != "" {
			named[cl.Name] = true
			clients = append(clients, cl.Name)
		}
	}
	var offered, hidden []string
	offeredBy := map[string][]string{}
	for _, in := range rt.instances {
		explicit := slices.ContainsFunc(forced, func(t string) bool {
			return toolGroup(t) == in.Name
		})
		generic := in.MentionGeneric(text) != ""
		if explicit || in.Activated() || in.MentionOwn(text) != "" || named[in.Client] || generic && len(named) == 0 {
			offered = append(offered, in.Name)
			offeredBy[in.Client] = append(offeredBy[in.Client], in.Name)
			env = append(env, rt.instanceEnv[in.Name]...)
			continue
		}
		hidden = append(hidden, in.Name)
		if generic {
			env = append(env, fmt.Sprintf("- Instance %s (template %s) : non proposée, la demande cite le client %s et pas cette instance (la nommer, ou -t %s, pour l'utiliser).", in.Name, in.T.Name, strings.Join(clients, ", "), in.Name))
			continue
		}
		env = append(env, fmt.Sprintf("- Instance %s (template %s) : non proposée pour cette demande, qui ne la mentionne pas (la nommer, ou -t %s, pour l'utiliser).", in.Name, in.T.Name, in.Name))
	}
	for _, cl := range rt.cfg.Clients {
		names := offeredBy[cl.Name]
		if len(names) == 0 {
			continue
		}
		line := "- Client " + cl.Name
		if len(cl.Aliases) > 0 {
			line += " (" + strings.Join(cl.Aliases, ", ") + ")"
		}
		if ctx := strings.TrimRight(strings.TrimSpace(cl.Context), "."); ctx != "" {
			line += " : " + ctx
		}
		if len(cl.Vars) > 0 {
			var refs []string
			for _, k := range slices.Sorted(maps.Keys(cl.Vars)) {
				refs = append(refs, k+"="+cl.Vars[k])
			}
			line += ". Références : " + strings.Join(refs, ", ")
		}
		env = append(env, line+". Instances de ce client : "+strings.Join(names, ", ")+".")
	}
	if len(rt.instances) > 0 {
		rt.audit.Log("instances_scope", map[string]any{"offered": offered, "hidden": hidden, "clients": clients})
	}
	if len(hidden) == 0 {
		return rt.registry, strings.Join(env, "\n")
	}
	return rt.registry.Without(hidden...), strings.Join(env, "\n")
}

func (rt *app) orchestrator(events progress.Sink, reg *tools.Registry, env string) *orchestrator.Orchestrator {
	runner := rt.newRunner(events, reg)
	runner.Evidence = rt.evidence
	runner.Journal = rt.journal
	if rt.leads != nil {
		rt.leads.Events = events
		runner.Inbox = rt.leads.Inbox
	}
	if rt.cves != nil {
		rt.cves.Events = events
		runner.Inbox = rt.cves.Inbox
	}
	return &orchestrator.Orchestrator{
		Cfg:         rt.cfg,
		Router:      rt.router,
		Runner:      runner,
		Tools:       reg,
		Audit:       rt.audit,
		Events:      events,
		Environment: env,
		Memory:      rt.memory,
		Language:    rt.lang,
		WebTools:    rt.webTools,
		Incident:    rt.leads != nil,
		CVE:         rt.cves,
		Journal:     rt.journal,
	}
}

func cmdModels(ctx context.Context, o *options, w io.Writer) error {
	rt, err := loadBase(ctx, o)
	if err != nil {
		return err
	}
	roles := map[string][]string{}
	for name := range rt.cfg.Roles {
		cands, err := rt.router.Candidates(name)
		if err != nil {
			roles[name] = []string{i18n.T("cli.models.error") + err.Error()}
			continue
		}
		for _, c := range cands {
			roles[name] = append(roles[name], c.Ref())
		}
	}
	statuses := budget.FetchAll(ctx, &http.Client{Timeout: 15 * time.Second}, rt.cfg)
	if o.json {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"fetched_at": rt.cat.FetchedAt, "from_cache": rt.cat.FromCache, "models": rt.cat.Models, "roles": roles, "budgets": statuses})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("models.head"))
	for _, m := range rt.cat.Models {
		ctxs := "?"
		if m.Context > 0 {
			ctxs = fmt.Sprint(m.Context)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\t%d\t%s\n", m.Provider, m.ID, m.Tier, ctxs, m.Tools, yesNo(m.Sovereign), m.Score(), m.Source)
	}
	tw.Flush()
	src := i18n.T("models.discovery")
	if rt.cat.FromCache {
		src = "cache"
	}
	fmt.Fprintf(w, "\n%s\n\n%s\n", i18n.T("models.fetched", src, rt.cat.FetchedAt.Local().Format(time.DateTime)), i18n.T("models.routing"))
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	names := append([]string{config.RolePlanner}, rt.cfg.WorkerRoles()...)
	names = append(names, config.RoleSynthesizer)
	for _, n := range names {
		r := rt.cfg.Roles[n]
		chain := roles[n]
		if !o.all && len(chain) > 3 {
			chain = append(chain[:3:3], fmt.Sprintf("(+%d)", len(roles[n])-3))
		}
		fmt.Fprintf(tw, "%s\t(tier>=%s tools=%t min_context=%d sovereign=%s)\t%s\n", n, r.Tier, r.Tools, r.MinContext, rt.router.Policy(n), strings.Join(chain, " → "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w, "\n"+i18n.T("models.budget"))
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("models.budget.head"))
	for _, p := range rt.cfg.Providers {
		if !p.Budget.Limited() {
			status := i18n.T("budget.undeclared")
			if p.Budget != nil && p.Budget.Unlimited {
				status = i18n.T("budget.unlimited")
			}
			fmt.Fprintf(tw, "%s\t%s\t\t\t\t\t\n", p.Name, status)
		}
	}
	for _, st := range statuses {
		p, _ := rt.cfg.Provider(st.Provider)
		seuils := fmt.Sprintf("min_remaining=%.2f max_run_cost=%.2f", p.Budget.MinRemaining, p.Budget.MaxRunCost)
		switch {
		case st.Error != "":
			fmt.Fprintf(tw, "%s\t%s\t\t\t\t\t%s\n", st.Provider, i18n.T("budget.error", st.Error), seuils)
		case !st.HasMax:
			fmt.Fprintf(tw, "%s\t%.4f $\t%s\t-\t%s\t%s\t%s\n", st.Provider, st.Spend, i18n.T("budget.unlimited"), st.Duration, st.ResetAt, seuils)
		default:
			fmt.Fprintf(tw, "%s\t%.4f $\t%.2f $\t%.4f $\t%s\t%s\t%s\n", st.Provider, st.Spend, st.Max, st.Remaining(), st.Duration, st.ResetAt, seuils)
		}
	}
	return tw.Flush()
}

func cmdTools(ctx context.Context, o *options, w io.Writer) error {
	o.webAllowed = true
	rt, err := setup(ctx, o, false)
	if err != nil {
		return err
	}
	defer rt.close()
	fmt.Fprintln(w, i18n.T("tools.env"))
	fmt.Fprintln(w, rt.environment)
	fmt.Fprintln(w, "\n"+i18n.T("tools.exposed"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, n := range rt.registry.Names() {
		desc := rt.registry.Description(n)
		if len(desc) > 100 {
			desc = desc[:100] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\n", n, desc)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, s := range rt.mcpServers {
		if sk := s.Skipped(); len(sk) > 0 {
			fmt.Fprintf(w, "\n%s\n  %s\n", i18n.T("tools.skipped", s.Name()), strings.Join(sk, "\n  "))
		}
	}
	return nil
}

func cmdTemplatesTest(ctx context.Context, o *options, dir, name string, w io.Writer) error {
	if dir == "" {
		cfg, err := loadConfig(o)
		if err != nil {
			return err
		}
		dir = cfg.Templates.Dir
	}
	set, err := template.Load(dir)
	if err != nil {
		return err
	}
	for _, wn := range set.Warnings {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), wn)
	}
	t, ok := set.Get(name)
	if !ok {
		return i18n.E("cli.err.template_not_in", name, dir)
	}
	passed, failed, err := template.RunTests(ctx, t, w)
	if err != nil {
		return err
	}
	fmt.Fprint(w, i18n.T("cli.templates_test.summary", passed, failed))
	if failed > 0 {
		return i18n.E("cli.err.tests_failed", failed)
	}
	return nil
}

func cmdTemplates(o *options, args []string, w io.Writer) error {
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		return err
	}
	for _, wn := range set.Warnings {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), wn)
	}
	if len(args) == 1 {
		t, ok := set.Get(args[0])
		if !ok {
			return i18n.E("cli.err.template_missing", args[0])
		}
		if _, err := w.Write(t.Raw); err != nil {
			return err
		}
		if t.ScriptSrc != nil {
			fmt.Fprintf(w, "\n# --- %s ---\n", t.ScriptPath)
			_, err := w.Write(t.ScriptSrc)
			return err
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("templates.head"))
	for _, t := range set.All() {
		var users []string
		for _, in := range cfg.Instances {
			if in.Template == t.Name {
				users = append(users, in.Name)
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", t.Name, t.Version, t.Source, strings.Join(users, ","), t.Description)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w, "\n"+i18n.T("templates.dir", cfg.Templates.Dir))
	if len(cfg.Instances) == 0 {
		return nil
	}
	fmt.Fprintln(w, "\n"+i18n.T("instances.title"))
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("instances.head"))
	for _, in := range cfg.Instances {
		state := i18n.T("instances.enabled")
		if !in.IsEnabled() {
			state = i18n.T("instances.disabled")
		}
		if _, ok := set.Get(in.Template); !ok {
			state = i18n.T("instances.missing")
		} else if t, _ := set.Get(in.Template); t != nil {
			if ti, err := template.NewInstance(in.Name, t, in.Params); err != nil {
				state = err.Error()
			} else if err := ti.ExtendPaths(in.SSHPaths); err != nil {
				state = err.Error()
			} else if err := ti.ExtendCommands(in.Commands); err != nil {
				state = err.Error()
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", in.Name, in.Template, state)
	}
	return tw.Flush()
}

func cmdPlan(ctx context.Context, o *options, args []string, w io.Writer) error {
	request, err := readRequest(args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	if err := o.decideWeb(cfg, o.confidential || o.sovereign == "require"); err != nil {
		return err
	}
	rt, err := setup(ctx, o, true)
	if err != nil {
		return err
	}
	defer rt.close()
	events := newProgress(o, rt.cfg.Limits.MaxSteps, "")
	defer events.Close()
	rt.audit.Log("plan_start", map[string]any{"request": request, "version": version})
	rt.warnFiltered(request)
	reg, env := rt.scope(o.tools, request)
	orch := rt.orchestrator(events, reg, env)
	p, err := orch.Plan(ctx, request)
	events.Close()
	if rt.audit.Path != "" {
		fmt.Fprintln(os.Stderr, "audit:", rt.audit.Path)
	}
	if err != nil {
		return err
	}
	for _, t := range p.Tasks {
		model := "?"
		if cands, err := rt.router.Candidates(t.Role); err == nil {
			model = cands[0].Ref()
			if len(cands) > 1 {
				model += i18n.T("plan.fallbacks", len(cands)-1)
			}
		}
		fmt.Fprint(w, i18n.T("plan.task", t.ID, t.Role, model, t.Goal))
		if len(t.Tools) > 0 {
			fmt.Fprint(w, i18n.T("plan.tools", strings.Join(t.Tools, ", ")))
		}
		if len(t.DependsOn) > 0 {
			fmt.Fprint(w, i18n.T("plan.deps", strings.Join(t.DependsOn, ", ")))
		}
	}
	return nil
}

const directAuto = "auto"

func (o *options) directRole() string {
	if o.direct == directAuto {
		return ""
	}
	return o.direct
}

func openRun(ctx context.Context, o *options) (*session.Session, *app, error) {
	cfg, err := loadConfig(o)
	if err != nil {
		return nil, nil, err
	}
	sess, err := openSession(cfg, o)
	if err != nil {
		return nil, nil, err
	}
	if err := o.decideWeb(cfg, sess.Confidential); err != nil {
		return nil, nil, err
	}
	next := len(sess.Turns) + 1
	o.evidence = evidence.Open("", next)
	importPriorEvidence(sess, o.evidence, next)
	rt, err := setup(ctx, o, false)
	if err != nil {
		return nil, nil, err
	}
	rt.closers = append(rt.closers, func() { _ = rt.audit.Close() })
	prior, err := sess.LoadMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.memory"), err)
	}
	rt.memory.Load(prior)
	return sess, rt, nil
}

type turnOutcome struct {
	report *orchestrator.Report
	err    error
	n      int
	dir    string
	used   []usedModel
	costs  []budget.Line
	info   []string
}

func (rt *app) runTurn(ctx context.Context, o *options, sess *session.Session, request string, events progress.Sink, answer func(string)) turnOutcome {
	history := sess.History(20000)
	turn, turnDir, err := sess.NewTurn(request)
	if err != nil {
		return turnOutcome{err: err}
	}
	n := turn.N
	sess.Turns[n-1].Tools = o.tools
	sess.Turns[n-1].Exclude = o.exclude
	sess.Turns[n-1].CVE = o.cveIDs
	rt.evidence.Begin(filepath.Join(turnDir, "evidence"), n)
	if err := rt.audit.Reopen(turnDir, "audit"); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.audit"), err)
	}
	rt.budget.NewRun()
	fmt.Fprintln(os.Stderr, i18n.T("session.start", sess.Name, n, filepath.Join(turnDir, "audit.jsonl")))
	if rt.journal {
		fmt.Fprintln(os.Stderr, i18n.T("journal.dir", filepath.Join(turnDir, "evidence")))
	}
	rt.audit.Log("run_start", map[string]any{"request": request, "version": version, "tools": rt.registry.Names(), "session": sess.Name, "turn": n, "memory_loaded": len(rt.memory.All()), "web": o.webAllowed, "direct": o.direct, "access": o.access.String(), "access_set": o.accessSet})
	mention := request
	forced := slices.Clone(o.tools)
	for _, t := range sess.Turns[:n-1] {
		mention += "\n" + t.Request
		forced = append(forced, t.Tools...)
	}
	rt.warnFiltered(mention)
	reg, env := rt.scope(forced, mention)
	if levels := accessSummary(rt.instances, reg); levels != "" {
		sess.Turns[n-1].Access = levels
		fmt.Fprintln(os.Stderr, i18n.T("access.line", levels))
		rt.audit.Log("access", map[string]any{"levels": levels})
	}
	orch := rt.orchestrator(events, reg, env)
	orch.History, orch.Turn = history, n
	orch.AfterTask = rt.budgetRefresher(events)
	orch.OnAnswer = answer
	orch.EvidenceDisplay = func(p string) string {
		if rel, err := filepath.Rel(sess.Dir(), p); err == nil {
			return rel
		}
		return p
	}
	var report *orchestrator.Report
	var runErr error
	if o.direct != "" {
		report, runErr = orch.Direct(ctx, request, o.directRole())
	} else {
		if orch.Incident || orch.CVE != nil {
			conclude := orch.ConcludeNow
			interruptHook.Store(&conclude)
		}
		report, runErr = orch.Run(ctx, request)
		interruptHook.Store(nil)
	}
	cleaned := rt.cleanup(ctx)
	used := rt.usedModels(report)
	costs := rt.budget.Summary()
	rt.audit.Log("run_end", map[string]any{"error": errString(runErr), "models": used, "costs": costs, "memory": rt.memory.Stats()})
	rt.saveTurn(sess, n, turnDir, report, runErr, used, costs)
	res := turnOutcome{report: report, err: runErr, n: n, dir: turnDir, used: used, costs: costs, info: cleaned}
	if len(used) > 0 {
		var parts, foreign []string
		for _, u := range used {
			parts = append(parts, u.Ref)
			if !u.Sovereign {
				foreign = append(foreign, u.Ref)
			}
		}
		res.info = append(res.info, i18n.T("models.used", strings.Join(parts, ", ")))
		if len(foreign) > 0 {
			res.info = append(res.info, i18n.T("models.foreign", strings.Join(foreign, ", ")))
		} else {
			res.info = append(res.info, i18n.T("models.allsov"))
		}
	}
	for _, c := range costs {
		res.info = append(res.info, i18n.T("cost.line", c.String()))
	}
	mst := rt.memory.Stats()
	res.info = append(res.info, i18n.T("memory.line", i18n.N(mst.Entries, "entry"), mst.Sovereign, mst.ExposedToForeign))
	if err := rt.evidence.Save(); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.evidence"), err)
	}
	if k := rt.evidence.Len(); k > 0 {
		res.info = append(res.info, i18n.T("evidence.line", k, filepath.Join(turnDir, "evidence"), sess.Name))
	}
	res.info = append(res.info, i18n.T("session.line", sess.Name, n, sess.Dir()))
	return res
}

func (o *options) levelFor(cfg *config.Config, ic config.Instance) access.Level {
	if o.accessSet {
		return o.access
	}
	cl, _ := cfg.Client(ic.Client)
	l, _ := access.Parse(cl.Access)
	return l
}

func offeredInstances(instances []*template.Instance, reg *tools.Registry) []*template.Instance {
	names := reg.Names()
	var out []*template.Instance
	for _, in := range instances {
		if slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, in.ToolPrefix()) }) {
			out = append(out, in)
		}
	}
	return out
}

func accessSummary(instances []*template.Instance, reg *tools.Registry) string {
	by := map[access.Level][]string{}
	for _, in := range offeredInstances(instances, reg) {
		if in.Access() != access.Read {
			by[in.Access()] = append(by[in.Access()], in.Name)
		}
	}
	var parts []string
	for _, l := range []access.Level{access.Exec, access.Create} {
		if len(by[l]) > 0 {
			parts = append(parts, i18n.T("access.instances", l, strings.Join(by[l], ", ")))
		}
	}
	return strings.Join(parts, ", ")
}

func confirmCommand(ctx context.Context, question string) (access.Answer, error) {
	s, err := creds.Ask(ctx, question)
	if err != nil {
		return access.No, err
	}
	return access.ParseAnswer(s), nil
}

func (rt *app) cleanup(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	var out []string
	for _, in := range rt.instances {
		for _, r := range in.Cleanup(ctx) {
			if r.Err != nil {
				out = append(out, i18n.T("cli.warning")+" "+i18n.T("access.cleanup_failed", r.Resource, r.Err))
			} else {
				out = append(out, i18n.T("access.cleanup_ok", r.Resource))
			}
		}
	}
	return out
}

func cmdRun(ctx context.Context, o *options, args []string, w io.Writer) error {
	var err error
	if o.access, err = access.Parse(o.accessFlag); err != nil {
		return err
	}
	if o.panic {
		o.incident = true
	}
	if o.incident && (o.chat || o.direct != "") {
		return i18n.E("cli.err.incident_modes")
	}
	if o.cveMode && (o.incident || o.chat || o.direct != "") {
		return i18n.E("cve.modes")
	}
	if o.chat {
		return cmdChat(ctx, o, args)
	}
	if err := o.resolveExport(); err != nil {
		return err
	}
	request, err := readRequest(args)
	if err != nil {
		return err
	}
	if o.cveMode {
		if o.cveIDs = cve.Extract(request); len(o.cveIDs) == 0 {
			return i18n.E("cve.no_id")
		}
	}
	sess, rt, err := openRun(ctx, o)
	if err != nil {
		return err
	}
	defer rt.close()
	if err := o.checkExport(rt.cfg, sess.Confidential); err != nil {
		return err
	}
	if o.cveMode {
		fmt.Fprintln(os.Stderr, i18n.T("cve.mode", strings.Join(o.cveIDs, ", ")))
		if !o.webAllowed {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("cve.no_web"))
		}
	}
	events := newProgress(o, rt.cfg.Limits.MaxSteps, sess.Name)
	defer events.Close()
	res := rt.runTurn(ctx, o, sess, request, events, nil)
	events.Close()
	for _, l := range res.info {
		fmt.Fprintln(os.Stderr, l)
	}
	fmt.Fprintln(os.Stderr, i18n.T("session.refine", sess.Name))
	report, runErr := res.report, res.err
	if report == nil {
		return runErr
	}
	md := o.fullReport(report.Markdown, sess.Dir())
	if o.json {
		doc := map[string]any{"plan": report.Plan, "results": report.Results, "report": md, "model": report.Model, "models_used": res.used, "costs": res.costs, "memory": rt.memory.All()}
		if rt.leads != nil {
			doc["leads"] = rt.leads.Leads()
		}
		if rt.cves != nil {
			doc["cve"] = map[string]any{"advisories": rt.cves.Advisories(), "findings": rt.cves.Findings()}
		}
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
			writeMarkdown(w, md, o.raw || o.withEvidence)
		}
	}
	if o.exportFmt != "" && md != "" {
		if err := rt.exportReport(ctx, o, res.dir, exportTitle(md, request), md); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.error"), err)
			if runErr == nil {
				runErr = err
			}
		}
	}
	return runErr
}

func (o *options) fullReport(md, sessDir string) string {
	if !o.withEvidence || md == "" {
		return md
	}
	titles, full, missing := i18n.All("evidence.title"), i18n.All("evidence.full"), i18n.All("evidence.missing")
	for i, t := range titles {
		if body, ok := evidence.StripAnnex(md, t); ok {
			return evidence.WithContent(body, sessDir, full[i], missing[i])
		}
	}
	return evidence.WithContent(md, sessDir, i18n.R("evidence.full"), i18n.R("evidence.missing"))
}

func writeReport(w io.Writer, path string, out []byte, runErr error) error {
	if path == "" {
		_, _ = w.Write(out)
		return runErr
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, i18n.T("cli.report"), path)
	return runErr
}

func writeMarkdown(w io.Writer, md string, raw bool) {
	f, ok := w.(*os.File)
	if raw || !ok || !term.IsTerminal(f.Fd()) {
		_, _ = io.WriteString(w, md+"\n")
		return
	}
	width, _, err := term.GetSize(f.Fd())
	if err != nil || width <= 0 {
		width = 100
	}
	dark := true
	if term.IsTerminal(os.Stdin.Fd()) {
		dark = lipgloss.HasDarkBackground(os.Stdin, f)
	}
	_, _ = io.WriteString(w, markdown.Render(md, min(width, 120), dark)+"\n")
}

func cmdChat(ctx context.Context, o *options, args []string) error {
	if o.json || o.output != "" || o.withEvidence || o.exportFmt != "" {
		return i18n.E("cli.err.chat_flags")
	}
	if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stderr.Fd()) {
		return i18n.E("cli.err.chat_tty")
	}
	initial := strings.TrimSpace(strings.Join(args, " "))
	sess, rt, err := openRun(ctx, o)
	if err != nil {
		return err
	}
	defer rt.close()
	err = progress.RunChat(ctx, os.Stderr, progress.ChatOptions{
		Title:    sess.Name,
		MaxSteps: rt.cfg.Limits.MaxSteps,
		Initial:  initial,
		OnStart:  func(suspend func() func()) { creds.Suspend = suspend },
		Turn: func(ctx context.Context, request string, events progress.Sink, answer func(string)) progress.TurnResult {
			res := rt.runTurn(ctx, o, sess, request, events, answer)
			out := progress.TurnResult{Info: res.info, Err: res.err}
			if res.report != nil && res.report.Markdown != "" {
				out.Markdown = res.report.Markdown
				out.Path = filepath.Join(res.dir, "report.md")
				out.Info = append(out.Info, i18n.T("chat.report", out.Path))
			}
			return out
		},
	})
	creds.Suspend = nil
	if len(sess.Turns) > 0 {
		fmt.Fprintln(os.Stderr, i18n.T("session.line", sess.Name, len(sess.Turns), sess.Dir()))
		fmt.Fprintln(os.Stderr, i18n.T("session.refine", sess.Name))
	}
	return err
}

func (rt *app) budgetRefresher(events progress.Sink) func(context.Context) {
	var busy atomic.Bool
	hc := &http.Client{Timeout: 15 * time.Second}
	return func(ctx context.Context) {
		used := rt.budget.Used()
		if len(used) == 0 || !busy.CompareAndSwap(false, true) {
			return
		}
		defer busy.Store(false)
		for _, ex := range rt.budget.Refresh(budget.FetchAll(ctx, hc, rt.cfg, used...)) {
			events.Emit(progress.Event{Task: "budget", Kind: "budget", Model: ex.Provider, Detail: i18n.T("budget.dropped", ex.Reason)})
			rt.audit.Log("budget_exhausted", map[string]any{"provider": ex.Provider, "reason": ex.Reason})
		}
	}
}

func openSession(cfg *config.Config, o *options) (*session.Session, error) {
	confidential := o.confidential || o.sovereign == "require"
	if o.session == "" {
		s, err := session.Create(cfg.Sessions.Dir, confidential, o.sovereign)
		if err == nil {
			s.Language = o.lang
		}
		return s, err
	}
	sess, err := session.Open(cfg.Sessions.Dir, o.session)
	if err != nil {
		return nil, err
	}
	if o.langFlag == "" && sess.Language != "" {
		o.lang = sess.Language
		i18n.SetReport(o.lang)
	}
	sess.Language = o.lang
	if sess.Confidential {
		if o.sovereign != "" && o.sovereign != "require" {
			return nil, i18n.E("cli.err.session_confidential", sess.Name, o.sovereign)
		}
		o.sovereign = "require"
	} else if confidential {
		sess.Confidential = true
	}
	if o.sovereign == "" && sess.Sovereign != "" {
		o.sovereign = sess.Sovereign
	}
	return sess, nil
}

func (rt *app) saveTurn(sess *session.Session, n int, dir string, report *orchestrator.Report, runErr error, used []usedModel, costs []budget.Line) {
	t := &sess.Turns[n-1]
	t.Status = "ok"
	if runErr != nil {
		t.Status, t.Error = "failed", runErr.Error()
	}
	for _, u := range used {
		t.Models = append(t.Models, u.Ref)
	}
	for _, c := range costs {
		t.Cost += c.RunCost
	}
	warn := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warn.session"), err)
		}
	}
	if report != nil {
		if report.Plan != nil {
			warn(sess.WriteJSON(dir, "plan.json", report.Plan))
		}
		warn(sess.WriteJSON(dir, "results.json", report.Results))
		if report.Markdown != "" {
			warn(sess.WriteReport(dir, report.Markdown))
		} else if t.Status == "ok" {
			t.Status = "partial"
		}
	}
	warn(sess.WriteJSON(dir, "summary.json", map[string]any{"models_used": used, "costs": costs, "memory": rt.memory.Stats()}))
	warn(sess.SaveMemory(rt.memory))
	warn(sess.Save())
}

func cmdSessions(o *options, w io.Writer) error {
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	all, err := session.List(cfg.Sessions.Dir)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Fprintln(w, i18n.T("sessions.none", cfg.Sessions.Dir))
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("sessions.head"))
	for _, s := range all {
		last := ""
		if n := len(s.Turns); n > 0 {
			last = strings.Join(strings.Fields(s.Turns[n-1].Request), " ")
			if len(last) > 70 {
				last = last[:70] + "…"
			}
		}
		conf := ""
		if s.Confidential {
			conf = i18n.T("yes")
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", s.Name, s.Updated.Local().Format("2006-01-02 15:04"), len(s.Turns), conf, last)
	}
	return tw.Flush()
}

func cmdResynthesize(ctx context.Context, o *options, name string, w io.Writer) error {
	if err := o.resolveExport(); err != nil {
		return err
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	sess, err := session.Open(cfg.Sessions.Dir, name)
	if err != nil {
		return err
	}
	if err := o.checkExport(cfg, sess.Confidential); err != nil {
		return err
	}
	n := o.turn
	if n == 0 {
		n = len(sess.Turns)
	}
	if n < 1 || n > len(sess.Turns) {
		return i18n.E("cli.err.no_turn", n)
	}
	dir := sess.TurnDir(n)
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		return i18n.E("cli.err.turn_results", n, err)
	}
	var results []orchestrator.Result
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("results.json: %w", err)
	}
	if o.evidence, err = evidence.Reopen(filepath.Join(dir, "evidence"), n); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.evidence"), err)
		o.evidence = evidence.Open(filepath.Join(dir, "evidence"), n)
	}
	importPriorEvidence(sess, o.evidence, n)
	if len(o.tools) == 0 {
		o.tools = sess.Turns[n-1].Tools
	}
	if len(o.exclude) == 0 {
		o.exclude = sess.Turns[n-1].Exclude
	}
	if len(o.tools) == 0 {
		o.tools = toolFilterFromAudit(filepath.Join(dir, "audit.jsonl"))
	}
	connectors := strings.Join(o.tools, ",")
	if len(o.exclude) > 0 {
		connectors += " -x " + strings.Join(o.exclude, ",")
	}
	fmt.Fprintln(os.Stderr, i18n.T("session.resynth", sess.Name, n, connectors))
	rt, err := setup(ctx, o, true)
	if err != nil {
		return err
	}
	defer rt.close()
	prior, err := sess.LoadMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn.memory"), err)
	}
	rt.memory.Load(prior)
	events := newProgress(o, rt.cfg.Limits.MaxSteps, sess.Name)
	defer events.Close()
	orch := rt.orchestrator(events, rt.registry, rt.environment)
	orch.Turn = n
	if n > 1 {
		orch.History = sess.History(20000)
	}
	orch.EvidenceDisplay = func(p string) string {
		if rel, err := filepath.Rel(sess.Dir(), p); err == nil {
			return rel
		}
		return p
	}
	rt.audit.Log("resynthesize", map[string]any{"session": sess.Name, "turn": n, "results": len(results)})
	md, model, err := orch.Synthesize(ctx, sess.Turns[n-1].Request, results)
	events.Close()
	if err != nil {
		return err
	}
	if err := sess.WriteReport(dir, md); err != nil {
		return err
	}
	if t := &sess.Turns[n-1]; t.Status == "partial" {
		t.Status = "ok"
	}
	if err := sess.Save(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, i18n.T("models.used", model))
	for _, c := range rt.budget.Summary() {
		fmt.Fprintln(os.Stderr, i18n.T("cost.line", c.String()))
	}
	md = o.fullReport(md, sess.Dir())
	if o.output != "" {
		if err := os.WriteFile(o.output, []byte(md+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, i18n.T("cli.report"), o.output)
	} else if _, err := fmt.Fprintln(w, md); err != nil {
		return err
	}
	if o.exportFmt == "" {
		return nil
	}
	return rt.exportReport(ctx, o, dir, exportTitle(md, sess.Turns[n-1].Request), md)
}

func importPriorEvidence(sess *session.Session, store *evidence.Store, turn int) {
	for n := 1; n < turn; n++ {
		dir := filepath.Join(sess.TurnDir(n), "evidence")
		if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
			continue
		}
		if err := store.Import(dir); err != nil {
			fmt.Fprint(os.Stderr, i18n.T("cli.warn.turn_evidence", n, err))
		}
	}
}

func toolFilterFromAudit(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Kind  string   `json:"kind"`
			Tools []string `json:"tools"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Kind != "run_start" {
			continue
		}
		var out []string
		for _, t := range ev.Tools {
			parts := strings.SplitN(t, "_", 3)
			prefix := parts[0]
			if prefix == "mcp" && len(parts) > 1 {
				prefix += "_" + parts[1]
			}
			if prefix != "memory" && !slices.Contains(out, prefix) {
				out = append(out, prefix)
			}
		}
		return out
	}
	return nil
}

func cmdSession(ctx context.Context, o *options, name string, w io.Writer) error {
	if err := o.resolveExport(); err != nil {
		return err
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	s, err := session.Open(cfg.Sessions.Dir, name)
	if err != nil {
		return err
	}
	if o.showPath {
		fmt.Fprintln(w, s.Dir())
		return nil
	}
	if o.evidenceID != "" {
		return showEvidence(s.Dir(), o.evidenceID, w)
	}
	if err := o.checkExport(cfg, s.Confidential); err != nil {
		return err
	}
	conf := ""
	if s.Confidential {
		conf = i18n.T("session.conf")
	}
	fmt.Fprintf(os.Stderr, "%s\n%s\n", i18n.T("session.header", s.Name, s.Created.Local().Format("2006-01-02 15:04"), len(s.Turns), conf), s.Dir())
	for _, t := range s.Turns {
		models := ""
		if len(t.Models) > 0 {
			models = " · " + strings.Join(t.Models, ", ")
		}
		fmt.Fprintf(os.Stderr, "%s\n    %s\n", i18n.T("session.turn", t.N, t.Time.Local().Format("2006-01-02 15:04"), t.Status, models), strings.Join(strings.Fields(t.Request), " "))
	}
	if o.turn > len(s.Turns) || o.turn < 0 {
		return i18n.E("cli.err.no_turn", o.turn)
	}
	report, err := s.Report(o.turn)
	if err != nil {
		return err
	}
	if report == "" {
		fmt.Fprintln(os.Stderr, i18n.T("session.noreport"))
		return nil
	}
	report = o.fullReport(report, s.Dir())
	if o.output != "" {
		if err := writeReport(w, o.output, []byte(report+"\n"), nil); err != nil {
			return err
		}
	} else if o.exportFmt == "" {
		fmt.Fprintln(os.Stderr)
		writeMarkdown(w, report, o.raw || o.withEvidence)
	}
	if o.exportFmt == "" {
		return nil
	}
	n := o.turn
	if n == 0 {
		n = len(s.Turns)
	}
	if o.sovereign == "" {
		o.sovereign = s.Sovereign
	}
	rt, err := exportApp(ctx, o, s.TurnDir(n))
	if err != nil {
		return err
	}
	defer rt.close()
	return rt.exportReport(ctx, o, s.TurnDir(n), exportTitle(report, s.Turns[n-1].Request), report)
}

type usedModel struct {
	Ref       string `json:"ref"`
	Sovereign bool   `json:"sovereign"`
	Tasks     int    `json:"tasks"`
}

func (rt *app) usedModels(rep *orchestrator.Report) []usedModel {
	if rep == nil {
		return nil
	}
	var refs []string
	if rep.Plan != nil {
		refs = append(refs, rep.Plan.Model)
	}
	for _, r := range rep.Results {
		refs = append(refs, r.Model)
	}
	refs = append(refs, rep.Model)
	idx := map[string]int{}
	var out []usedModel
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if i, ok := idx[ref]; ok {
			out[i].Tasks++
			continue
		}
		sov := false
		if m, ok := rt.cat.Find(ref); ok {
			sov = m.Sovereign
		} else if prov, _, ok := catalog.SplitRef(ref); ok {
			if p, ok := rt.cfg.Provider(prov); ok {
				sov = p.Sovereign
			}
		}
		idx[ref] = len(out)
		out = append(out, usedModel{Ref: ref, Sovereign: sov, Tasks: 1})
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return i18n.T("yesno.yes")
	}
	return i18n.T("yesno.no")
}

func newProgress(o *options, maxSteps int, title string) progress.Closer {
	if o.quiet {
		return progress.Nop{}
	}
	if !o.plain && term.IsTerminal(os.Stderr.Fd()) {
		t := progress.NewTUI(os.Stderr, maxSteps, title)
		creds.Suspend = t.Suspend
		return t
	}
	return progress.NewPrinter(os.Stderr)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func showEvidence(sessDir, id string, w io.Writer) error {
	path := evidence.Path(sessDir, id)
	data, err := os.ReadFile(path)
	if err != nil {
		return i18n.E("cli.err.evidence_missing", id, path)
	}
	_, err = w.Write(data)
	return err
}
