package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/orchestrator"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/router"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/files"
	"github.com/agardenat/clotr/internal/tools/k8s"
	"github.com/agardenat/clotr/internal/tools/mcp"
)

var version = "dev"

type options struct {
	config       string
	refresh      bool
	models       map[string]string
	tools        []string
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
	evidenceID   string
	synthesize   bool
	web          string
	webAllowed   bool
	evidence     *evidence.Store
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
	webTools    []string
	evidence    *evidence.Store
	closers     []func()
}

func (r *app) close() {
	for i := len(r.closers) - 1; i >= 0; i-- {
		r.closers[i]()
	}
}

func main() {
	httpx.UserAgent = "clotr/" + version
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "erreur:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:           "clotr",
		Short:         "Agent d'analyse d'infrastructure en lecture seule, multi-modèles",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&o.config, "config", "c", "", "fichier de configuration (défaut: $CLOTR_CONFIG ou ~/.config/clotr/config.yaml)")
	root.PersistentFlags().BoolVar(&o.refresh, "refresh", false, "rafraîchir le catalogue de modèles")
	root.PersistentFlags().StringVar(&o.sovereign, "sovereign", "", "politique souveraine pour ce run: any|prefer|require (prioritaire sur la config)")
	root.PersistentFlags().BoolVar(&o.confidential, "confidential", false, "run confidentiel: équivaut à --sovereign require")
	root.PersistentFlags().StringVar(&o.langFlag, "lang", "", "langue de sortie: auto|fr|en (auto: rapport dans la langue de la demande, interface en anglais)")

	models := &cobra.Command{
		Use:   "models",
		Short: "Affiche le catalogue des modèles découverts et le routage par rôle",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdModels(cmd.Context(), o, cmd.OutOrStdout())
		},
	}
	models.Flags().BoolVar(&o.json, "json", false, "sortie JSON")
	models.Flags().BoolVar(&o.all, "all", false, "afficher les chaînes de fallback complètes")

	addTaskFlags := func(c *cobra.Command) {
		c.Flags().StringToStringVarP(&o.models, "model", "m", nil, "forcer un modèle par rôle: role=provider/model")
		c.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, "restreindre les outils par préfixe: k8s,fs,mcp,mcp_<serveur>,<instance>")
		c.Flags().StringVar(&o.web, "web", "", "recherche web pour ce run: yes|no (défaut: web_search.policy)")
	}

	plan := &cobra.Command{
		Use:   "plan <demande>",
		Short: "Planifie la demande sans l'exécuter",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdPlan(cmd.Context(), o, args, cmd.OutOrStdout())
		},
	}
	addTaskFlags(plan)
	plan.Flags().BoolVarP(&o.quiet, "quiet", "q", false, "pas de progression sur stderr")
	plan.Flags().BoolVar(&o.plain, "plain", false, "progression ligne par ligne au lieu du tableau dynamique")

	run := &cobra.Command{
		Use:   "run <demande>",
		Short: "Planifie et exécute la demande, produit un rapport Markdown",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdRun(cmd.Context(), o, args, cmd.OutOrStdout())
		},
	}
	addTaskFlags(run)
	run.Flags().StringVarP(&o.output, "output", "o", "", "écrire le rapport dans ce fichier")
	run.Flags().BoolVar(&o.json, "json", false, "sortie JSON (plan, résultats, rapport)")
	run.Flags().BoolVarP(&o.quiet, "quiet", "q", false, "pas de progression sur stderr")
	run.Flags().BoolVar(&o.plain, "plain", false, "progression ligne par ligne au lieu du tableau dynamique")
	run.Flags().StringVarP(&o.session, "session", "s", "", "affiner une session existante (nom ou last)")

	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: "Liste les sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdSessions(o, cmd.OutOrStdout())
		},
	}
	sessionCmd := &cobra.Command{
		Use:   "session <nom|last>",
		Short: "Affiche une session et son dernier rapport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.synthesize {
				return cmdResynthesize(cmd.Context(), o, args[0], cmd.OutOrStdout())
			}
			return cmdSession(o, args[0], cmd.OutOrStdout())
		},
	}
	sessionCmd.Flags().IntVar(&o.turn, "turn", 0, "rapport d'un tour précis")
	sessionCmd.Flags().BoolVar(&o.showPath, "path", false, "afficher seulement le répertoire de la session")
	sessionCmd.Flags().BoolVar(&o.synthesize, "synthesize", false, "régénérer le rapport d'un tour à partir de ses résultats enregistrés, sans relancer les tâches")
	sessionCmd.Flags().StringVarP(&o.output, "output", "o", "", "écrire le rapport régénéré dans ce fichier")
	sessionCmd.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, "avec --synthesize : connecteurs à préparer (défaut : ceux du tour)")
	sessionCmd.Flags().StringVar(&o.evidenceID, "evidence", "", "afficher la sortie d'outil archivée d'une preuve (ex: E012, E2.005)")

	toolsCmd := &cobra.Command{
		Use:   "tools",
		Short: "Liste les outils exposés aux agents, et les outils MCP écartés",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmdTools(cmd.Context(), o, cmd.OutOrStdout())
		},
	}
	toolsCmd.Flags().StringSliceVarP(&o.tools, "tools", "t", nil, "restreindre les outils par préfixe: k8s,fs,mcp,mcp_<serveur>,<instance>")

	templatesCmd := &cobra.Command{
		Use:   "templates [nom]",
		Short: "Liste les templates disponibles et les instances configurées, ou affiche un template",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdTemplates(o, args, cmd.OutOrStdout())
		},
	}
	var testDir string
	templatesTest := &cobra.Command{
		Use:   "test <nom>",
		Short: "Exécute les tests d'un template (fonctions test_* de <script>_test.star)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdTemplatesTest(cmd.Context(), o, testDir, args[0], cmd.OutOrStdout())
		},
	}
	templatesTest.Flags().StringVar(&testDir, "dir", "", "répertoire des templates (défaut : templates.dir de la configuration)")
	templatesCmd.AddCommand(templatesTest)

	ver := &cobra.Command{
		Use:   "version",
		Short: "Affiche la version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}

	root.AddCommand(models, plan, run, sessionsCmd, sessionCmd, toolsCmd, templatesCmd, ver)
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
		return "", errors.New("demande vide")
	}
	return req, nil
}

func loadConfig(o *options) (*config.Config, error) {
	path, err := config.Resolve(o.config)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	o.lang = cfg.Language
	if o.langFlag != "" {
		if !config.ValidLanguage(o.langFlag) {
			return nil, fmt.Errorf("--lang %q invalide (auto|fr|en)", o.langFlag)
		}
		o.lang = o.langFlag
	}
	i18n.Set(o.lang)
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
		fmt.Fprintln(os.Stderr, "avertissement:", w)
	}
	if o.confidential {
		if o.sovereign != "" && o.sovereign != "require" {
			return nil, fmt.Errorf("--confidential incompatible avec --sovereign %s", o.sovereign)
		}
		o.sovereign = "require"
	}
	rt, err := router.New(cfg, cat, o.models, o.sovereign)
	if err != nil {
		return nil, err
	}
	return &app{cfg: cfg, cat: cat, router: rt, audit: audit.Nop()}, nil
}

func resolveWeb(cfg *config.Config, o *options, confidential bool) (bool, string, error) {
	if cfg.WebSearch.MCP == "" {
		return false, "", nil
	}
	switch o.web {
	case "", "yes", "no":
	default:
		return false, "", fmt.Errorf("--web: %q invalide (yes|no)", o.web)
	}
	if confidential {
		if o.web == "yes" {
			return false, "", errors.New("--web yes refusé: session confidentielle")
		}
		return false, i18n.T("web.confidential"), nil
	}
	switch {
	case o.web == "yes":
		return true, cfg.WebSearch.MCP, nil
	case o.web == "no":
		return false, i18n.T("web.flag"), nil
	case cfg.WebSearch.Policy == "allow":
		return true, cfg.WebSearch.MCP, nil
	case cfg.WebSearch.Policy == "deny":
		return false, i18n.T("web.policy"), nil
	}
	ok, err := creds.Confirm(i18n.T("web.ask", cfg.WebSearch.MCP))
	if err != nil {
		return false, i18n.T("web.notty"), nil
	}
	if !ok {
		return false, i18n.T("web.denied"), nil
	}
	return true, cfg.WebSearch.MCP, nil
}

func (o *options) decideWeb(cfg *config.Config, confidential bool) error {
	allowed, why, err := resolveWeb(cfg, o, confidential)
	if err != nil {
		return err
	}
	o.webAllowed = allowed
	if cfg.WebSearch.MCP == "" {
		return nil
	}
	if allowed {
		fmt.Fprintln(os.Stderr, i18n.T("web.on", why))
	} else {
		fmt.Fprintln(os.Stderr, i18n.T("web.off", why))
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
			fmt.Fprintf(os.Stderr, "avertissement: budget %s non vérifié: %s\n", st.Provider, st.Error)
		}
	}
	for _, w := range rt.budget.Seed(statuses) {
		fmt.Fprintln(os.Stderr, "avertissement: budget:", w)
	}
	rt.registry = tools.NewRegistry(cfg.Limits.ToolOutputMaxChars)
	enabled := func(prefix string) bool {
		if len(o.tools) == 0 {
			return true
		}
		for _, t := range o.tools {
			t = strings.TrimSuffix(strings.TrimSuffix(t, "*"), "_")
			if t == prefix || strings.HasPrefix(prefix, t+"_") {
				return true
			}
		}
		return false
	}
	warn := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "avertissement: "+format+"\n", args...)
	}
	if withAudit {
		dir, runID := cfg.Audit.Dir, time.Now().Format("20060102-150405")
		if o.auditDir != "" {
			dir, runID = o.auditDir, "audit"
		}
		a, err := audit.Open(dir, runID)
		if err != nil {
			warn("audit désactivé: %v", err)
		} else {
			rt.audit = a
			rt.closers = append(rt.closers, func() { _ = a.Close() })
		}
	}
	var envLines []string

	if cfg.K8s != nil && enabled("k8s") {
		k, err := k8s.New(cfg.K8s)
		if err == nil {
			for _, f := range k.Probe(ctx, 5*time.Second) {
				warn("k8s: %s", f)
			}
			if ctxs, _ := k.Contexts(); len(ctxs) == 0 {
				err = errors.New("k8s: aucun contexte joignable")
			}
		}
		if err != nil {
			warn("%v (outils k8s désactivés)", err)
		} else {
			rt.registry.Add(k.Tools()...)
			ctxs, def := k.Contexts()
			envLines = append(envLines, fmt.Sprintf("- Kubernetes: contextes autorisés %s (défaut: %s)", strings.Join(ctxs, ", "), def))
		}
	}
	if cfg.Files != nil && enabled("fs") {
		f, warnings, err := files.New(cfg.Files)
		for _, w := range warnings {
			warn("%s", w)
		}
		if err != nil {
			warn("%v (outils fs désactivés)", err)
		} else {
			rt.registry.Add(f.Tools()...)
			envLines = append(envLines, "- Fichiers locaux: "+strings.Join(cfg.Files.Roots, ", "))
		}
	}
	var mcpCfgs []config.MCPServer
	for _, m := range cfg.MCP {
		if m.Name == cfg.WebSearch.MCP {
			if o.webAllowed && m.IsEnabled() {
				mcpCfgs = append(mcpCfgs, m)
			}
			continue
		}
		if m.IsEnabled() && enabled("mcp_"+m.Name) {
			mcpCfgs = append(mcpCfgs, m)
		}
	}
	if len(mcpCfgs) > 0 {
		servers, warnings := mcp.ConnectAll(ctx, mcpCfgs, version)
		for _, w := range warnings {
			warn("%s", w)
		}
		rt.mcpServers = servers
		for _, s := range servers {
			rt.closers = append(rt.closers, func() { _ = s.Close() })
			rt.registry.Add(s.Tools()...)
			envLines = append(envLines, fmt.Sprintf("- MCP %s: %d outils (préfixe mcp_%s)", s.Name(), len(s.Tools()), s.Name()))
		}
	}
	envLines = append(envLines, rt.setupInstances(ctx, o, enabled, warn)...)
	if rt.registry.Len() == 0 {
		rt.close()
		return nil, errors.New("aucun outil disponible: configurer k8s, files, mcp ou une instance de template")
	}
	rt.evidence = o.evidence
	rt.memory = memory.NewStore()
	rt.registry.Add(rt.memory.Tools()...)
	if rt.evidence != nil {
		rt.registry.Add(rt.evidence.Tool(), rt.evidence.SearchTool())
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

func (rt *app) setupInstances(ctx context.Context, o *options, enabled func(string) bool, warn func(string, ...any)) []string {
	cfg := rt.cfg
	var active []config.Instance
	for _, in := range cfg.Instances {
		if in.IsEnabled() && enabled(in.Name) {
			active = append(active, in)
		}
	}
	if len(active) == 0 {
		return nil
	}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		warn("templates: %v (instances désactivées)", err)
		return nil
	}
	for _, w := range set.Warnings {
		warn("%s", w)
	}
	var lines []string
	for _, ic := range active {
		t, ok := set.Get(ic.Template)
		if !ok {
			warn("instance %s: template %q introuvable (instance désactivée)", ic.Name, ic.Template)
			continue
		}
		in, err := template.NewInstance(ic.Name, t, ic.Params)
		if err == nil {
			in.Audit = rt.audit.Log
			in.Warn = func(msg string) { warn("%s", msg) }
			if !o.quiet {
				name, tname := ic.Name, t.Name
				in.Activating = func() { fmt.Fprintln(os.Stderr, i18n.T("instance.discovering", name, tname)) }
			}
			err = in.Defer(ctx, cfg.Templates.CacheDir, cfg.Templates.CacheTTL.Duration, o.refresh)
		}
		if err != nil {
			warn("%v (instance %s désactivée)", err, ic.Name)
			continue
		}
		rt.instances = append(rt.instances, in)
		rt.closers = append(rt.closers, in.Close)
		rt.registry.Add(in.Tools()...)
		rt.registry.AddGroup(in.ToolPrefix())
		rt.registry.AddCompanions(in.ToolPrefix(), in.Companions()...)
		lines = append(lines, in.EnvironmentLines()...)
	}
	return lines
}

func (rt *app) orchestrator(events progress.Sink) *orchestrator.Orchestrator {
	runner := &agent.Runner{
		Chat:            rt.pool,
		Tools:           rt.registry,
		Audit:           rt.audit,
		Events:          events,
		MaxSteps:        rt.cfg.Limits.MaxSteps,
		ConcludeReserve: min(5*time.Minute, rt.cfg.Limits.RequestTimeout.Duration),
		Evidence:        rt.evidence,
		Attempts:        2,
		Backoff:         2 * time.Second,
		RoundPause:      30 * time.Second,
		StallSteps:      *rt.cfg.Limits.StallSteps,
		KeepSteps:       *rt.cfg.Limits.HistoryKeepSteps,
		ToolChars:       *rt.cfg.Limits.HistoryToolChars,
		ConcludeNotes:   rt.memory.TaskNotes,
		Budget:          rt.budget,
	}
	return &orchestrator.Orchestrator{
		Cfg:         rt.cfg,
		Router:      rt.router,
		Runner:      runner,
		Tools:       rt.registry,
		Audit:       rt.audit,
		Events:      events,
		Environment: rt.environment,
		Memory:      rt.memory,
		Language:    rt.lang,
		WebTools:    rt.webTools,
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
			roles[name] = []string{"ERREUR: " + err.Error()}
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
		fmt.Fprintln(os.Stderr, "avertissement:", wn)
	}
	t, ok := set.Get(name)
	if !ok {
		return fmt.Errorf("template %q introuvable dans %s", name, dir)
	}
	passed, failed, err := template.RunTests(ctx, t, w)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%d réussis, %d en échec\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d test(s) en échec", failed)
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
		fmt.Fprintln(os.Stderr, "avertissement:", wn)
	}
	if len(args) == 1 {
		t, ok := set.Get(args[0])
		if !ok {
			return fmt.Errorf("template %q introuvable", args[0])
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
			if _, err := template.NewInstance(in.Name, t, in.Params); err != nil {
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
	orch := rt.orchestrator(events)
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

func cmdRun(ctx context.Context, o *options, args []string, w io.Writer) error {
	request, err := readRequest(args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	sess, err := openSession(cfg, o)
	if err != nil {
		return err
	}
	if err := o.decideWeb(cfg, sess.Confidential); err != nil {
		return err
	}
	history := sess.History(20000)
	turn, turnDir, err := sess.NewTurn(request)
	if err != nil {
		return err
	}
	turnN := turn.N
	sess.Turns[turnN-1].Tools = o.tools
	o.auditDir = turnDir
	fmt.Fprintln(os.Stderr, i18n.T("session.start", sess.Name, turnN, filepath.Join(turnDir, "audit.jsonl")))
	o.evidence = evidence.Open(filepath.Join(turnDir, "evidence"), turnN)
	importPriorEvidence(sess, o.evidence, turnN)
	rt, err := setup(ctx, o, true)
	if err != nil {
		sess.Turns[turnN-1].Status, sess.Turns[turnN-1].Error = "failed", err.Error()
		_ = sess.Save()
		return err
	}
	defer rt.close()
	prior, err := sess.LoadMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "avertissement: mémoire de session illisible:", err)
	}
	rt.memory.Load(prior)
	events := newProgress(o, rt.cfg.Limits.MaxSteps, sess.Name)
	defer events.Close()
	rt.audit.Log("run_start", map[string]any{"request": request, "version": version, "tools": rt.registry.Names(), "session": sess.Name, "turn": turnN, "memory_loaded": len(prior), "web": o.webAllowed})
	orch := rt.orchestrator(events)
	orch.History, orch.Turn = history, turnN
	orch.AfterTask = rt.budgetRefresher(events)
	orch.EvidenceDisplay = func(p string) string {
		if rel, err := filepath.Rel(sess.Dir(), p); err == nil {
			return rel
		}
		return p
	}
	report, runErr := orch.Run(ctx, request)
	used := rt.usedModels(report)
	costs := rt.budget.Summary()
	rt.audit.Log("run_end", map[string]any{"error": errString(runErr), "models": used, "costs": costs, "memory": rt.memory.Stats()})
	events.Close()
	rt.saveTurn(sess, turnN, turnDir, report, runErr, used, costs)
	if len(used) > 0 {
		var parts, foreign []string
		for _, u := range used {
			parts = append(parts, u.Ref)
			if !u.Sovereign {
				foreign = append(foreign, u.Ref)
			}
		}
		fmt.Fprintln(os.Stderr, i18n.T("models.used", strings.Join(parts, ", ")))
		if len(foreign) > 0 {
			fmt.Fprintln(os.Stderr, i18n.T("models.foreign", strings.Join(foreign, ", ")))
		} else {
			fmt.Fprintln(os.Stderr, i18n.T("models.allsov"))
		}
	}
	for _, c := range costs {
		fmt.Fprintln(os.Stderr, i18n.T("cost.line", c.String()))
	}
	mst := rt.memory.Stats()
	fmt.Fprintln(os.Stderr, i18n.T("memory.line", i18n.N(mst.Entries, "entry"), mst.Sovereign, mst.ExposedToForeign))
	if err := rt.evidence.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "avertissement: preuves:", err)
	}
	if n := rt.evidence.Len(); n > 0 {
		fmt.Fprintln(os.Stderr, i18n.T("evidence.line", n, filepath.Join(turnDir, "evidence"), sess.Name))
	}
	fmt.Fprintln(os.Stderr, i18n.T("session.line", sess.Name, turnN, sess.Dir()))
	fmt.Fprintln(os.Stderr, i18n.T("session.refine", sess.Name))
	if report == nil {
		return runErr
	}
	var out []byte
	if o.json {
		out, _ = json.MarshalIndent(map[string]any{"plan": report.Plan, "results": report.Results, "report": report.Markdown, "model": report.Model, "models_used": used, "costs": costs, "memory": rt.memory.All()}, "", "  ")
		out = append(out, '\n')
	} else {
		out = []byte(report.Markdown + "\n")
	}
	if report.Markdown == "" && !o.json {
		return runErr
	}
	if o.output != "" {
		if err := os.WriteFile(o.output, out, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "rapport:", o.output)
	} else {
		_, _ = w.Write(out)
	}
	return runErr
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
			events.Emit(progress.Event{Task: "budget", Kind: "budget", Model: ex.Provider, Detail: "provider dropped for the rest of the run: " + ex.Reason})
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
		i18n.Set(o.lang)
	}
	sess.Language = o.lang
	if sess.Confidential {
		if o.sovereign != "" && o.sovereign != "require" {
			return nil, fmt.Errorf("session %s confidentielle: --sovereign %s refusé", sess.Name, o.sovereign)
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
			fmt.Fprintln(os.Stderr, "avertissement: session:", err)
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
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	sess, err := session.Open(cfg.Sessions.Dir, name)
	if err != nil {
		return err
	}
	n := o.turn
	if n == 0 {
		n = len(sess.Turns)
	}
	if n < 1 || n > len(sess.Turns) {
		return fmt.Errorf("tour %d inexistant", n)
	}
	dir := sess.TurnDir(n)
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		return fmt.Errorf("tour %d sans résultats enregistrés: %w", n, err)
	}
	var results []orchestrator.Result
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("results.json: %w", err)
	}
	if o.evidence, err = evidence.Reopen(filepath.Join(dir, "evidence"), n); err != nil {
		fmt.Fprintln(os.Stderr, "avertissement: preuves:", err)
		o.evidence = evidence.Open(filepath.Join(dir, "evidence"), n)
	}
	importPriorEvidence(sess, o.evidence, n)
	if len(o.tools) == 0 {
		o.tools = sess.Turns[n-1].Tools
	}
	if len(o.tools) == 0 {
		o.tools = toolFilterFromAudit(filepath.Join(dir, "audit.jsonl"))
	}
	fmt.Fprintln(os.Stderr, i18n.T("session.resynth", sess.Name, n, strings.Join(o.tools, ",")))
	rt, err := setup(ctx, o, true)
	if err != nil {
		return err
	}
	defer rt.close()
	prior, err := sess.LoadMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "avertissement: mémoire de session illisible:", err)
	}
	rt.memory.Load(prior)
	events := newProgress(o, rt.cfg.Limits.MaxSteps, sess.Name)
	defer events.Close()
	orch := rt.orchestrator(events)
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
	if o.output != "" {
		if err := os.WriteFile(o.output, []byte(md+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "rapport:", o.output)
		return nil
	}
	_, err = fmt.Fprintln(w, md)
	return err
}

func importPriorEvidence(sess *session.Session, store *evidence.Store, turn int) {
	for n := 1; n < turn; n++ {
		dir := filepath.Join(sess.TurnDir(n), "evidence")
		if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
			continue
		}
		if err := store.Import(dir); err != nil {
			fmt.Fprintf(os.Stderr, "avertissement: preuves du tour %d: %v\n", n, err)
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

func cmdSession(o *options, name string, w io.Writer) error {
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
		return fmt.Errorf("tour %d inexistant", o.turn)
	}
	report, err := s.Report(o.turn)
	if err != nil {
		return err
	}
	if report == "" {
		fmt.Fprintln(os.Stderr, i18n.T("session.noreport"))
		return nil
	}
	fmt.Fprintln(os.Stderr)
	_, err = io.WriteString(w, report+"\n")
	return err
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
	turn := 1
	if rest, ok := strings.CutPrefix(id, "E"); ok {
		if n, _, found := strings.Cut(rest, "."); found {
			if v, err := strconv.Atoi(n); err == nil {
				turn = v
			}
		}
	}
	path := filepath.Join(sessDir, "turns", fmt.Sprintf("%03d", turn), "evidence", id+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("preuve %s introuvable (%s)", id, path)
	}
	_, err = w.Write(data)
	return err
}
