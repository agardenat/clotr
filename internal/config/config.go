package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RolePlanner     = "planner"
	RoleSynthesizer = "synthesizer"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var mcpName = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

var tiers = map[string]int{"fast": 1, "balanced": 2, "deep": 3}

func TierRank(t string) int {
	return tiers[t]
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, s)
	}
	d.Duration = v
	return nil
}

type Config struct {
	Providers []Provider      `yaml:"providers"`
	Profiles  []Profile       `yaml:"profiles"`
	Roles     map[string]Role `yaml:"roles"`
	Limits    Limits          `yaml:"limits"`
	Catalog   CatalogConf     `yaml:"catalog"`
	Audit     AuditConf       `yaml:"audit"`
	K8s       *K8s            `yaml:"k8s"`
	Files     *Files          `yaml:"files"`
	MCP       []MCPServer     `yaml:"mcp"`
	Templates TemplatesConf   `yaml:"templates"`
	Instances []Instance      `yaml:"instances"`
	Routing   Routing         `yaml:"routing"`
	Sessions  SessionsConf    `yaml:"sessions"`
	Language  string          `yaml:"language"`
	WebSearch WebSearch       `yaml:"web_search"`
}

type WebSearch struct {
	Policy string `yaml:"policy"`
	MCP    string `yaml:"mcp"`
}

func ValidWebPolicy(p string) bool {
	return p == "ask" || p == "allow" || p == "deny"
}

func ValidLanguage(l string) bool {
	return l == "auto" || l == "fr" || l == "en"
}

type TemplatesConf struct {
	Dir      string   `yaml:"dir"`
	CacheDir string   `yaml:"cache_dir"`
	CacheTTL Duration `yaml:"cache_ttl"`
}

type Instance struct {
	Name     string         `yaml:"name"`
	Template string         `yaml:"template"`
	Enabled  *bool          `yaml:"enabled"`
	Params   map[string]any `yaml:"params"`
}

func (i Instance) IsEnabled() bool {
	return i.Enabled == nil || *i.Enabled
}

var instanceName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var reservedPrefixes = []string{"k8s", "fs", "mcp", "memory", "evidence"}

type SessionsConf struct {
	Dir string `yaml:"dir"`
}

type Routing struct {
	Sovereign string `yaml:"sovereign"`
}

var SovereignPolicies = []string{"any", "prefer", "require"}

func ValidSovereignPolicy(p string) bool {
	return slices.Contains(SovereignPolicies, p)
}

type Provider struct {
	Name           string            `yaml:"name"`
	BaseURL        string            `yaml:"base_url"`
	Key            string            `yaml:"api_key"`
	Weight         int               `yaml:"weight"`
	Sovereign      bool              `yaml:"sovereign"`
	Budget         *Budget           `yaml:"budget"`
	SessionHeader  string            `yaml:"session_header"`
	Stream         *bool             `yaml:"stream"`
	APIKeyEnv      string            `yaml:"api_key_env"`
	MaxConcurrency int               `yaml:"max_concurrency"`
	ModelInfo      bool              `yaml:"model_info"`
	Headers        map[string]string `yaml:"headers"`
}

type Budget struct {
	InfoPath     string  `yaml:"info_path"`
	MinRemaining float64 `yaml:"min_remaining"`
	MaxRunCost   float64 `yaml:"max_run_cost"`
	Unlimited    bool    `yaml:"-"`
}

func (b *Budget) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "unlimited" {
			return fmt.Errorf("line %d: budget: %q invalide (unlimited ou {info_path, min_remaining, max_run_cost})", n.Line, n.Value)
		}
		*b = Budget{Unlimited: true}
		return nil
	}
	type plain Budget
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*b = Budget(p)
	return nil
}

func (b *Budget) Limited() bool {
	return b != nil && !b.Unlimited
}

func (p Provider) BudgetStatus() string {
	switch {
	case p.Budget == nil:
		return "non déclaré"
	case p.Budget.Unlimited:
		return "illimité"
	}
	return "limité"
}

func (p Provider) APIKey() string {
	if p.Key != "" {
		return os.ExpandEnv(p.Key)
	}
	if p.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(p.APIKeyEnv)
}

type Profile struct {
	Match     string `yaml:"match"`
	Tier      string `yaml:"tier"`
	Context   int    `yaml:"context"`
	Tools     *bool  `yaml:"tools"`
	Exclude   bool   `yaml:"exclude"`
	Priority  int    `yaml:"priority"`
	Sovereign *bool  `yaml:"sovereign"`
}

type Role struct {
	Description string `yaml:"description"`
	Tier        string `yaml:"tier"`
	Tools       bool   `yaml:"tools"`
	MinContext  int    `yaml:"min_context"`
	Sovereign   string `yaml:"sovereign"`
}

type Limits struct {
	MaxAgents          int      `yaml:"max_agents"`
	MaxTasks           int      `yaml:"max_tasks"`
	MaxSteps           int      `yaml:"max_steps"`
	Continuations      *int     `yaml:"continuations"`
	AgentTimeout       Duration `yaml:"agent_timeout"`
	RequestTimeout     Duration `yaml:"request_timeout"`
	IdleTimeout        Duration `yaml:"idle_timeout"`
	ToolOutputMaxChars int      `yaml:"tool_output_max_chars"`
	StallSteps         *int     `yaml:"stall_steps"`
	VerifyFindings     *bool    `yaml:"verify_findings"`
	HistoryKeepSteps   *int     `yaml:"history_keep_steps"`
	HistoryToolChars   *int     `yaml:"history_tool_chars"`
}

type CatalogConf struct {
	CacheTTL Duration `yaml:"cache_ttl"`
}

type AuditConf struct {
	Dir string `yaml:"dir"`
}

type K8s struct {
	Kubeconfig string   `yaml:"kubeconfig"`
	Contexts   []string `yaml:"contexts"`
	Timeout    Duration `yaml:"timeout"`
}

type Files struct {
	Roots        []string `yaml:"roots"`
	MaxFileBytes int      `yaml:"max_file_bytes"`
}

type MCPServer struct {
	Name      string            `yaml:"name"`
	Command   string            `yaml:"command"`
	Args      []string          `yaml:"args"`
	Env       map[string]string `yaml:"env"`
	URL       string            `yaml:"url"`
	Transport string            `yaml:"transport"`
	Headers   map[string]string `yaml:"headers"`
	Allow     []string          `yaml:"allow"`
	Deny      []string          `yaml:"deny"`
	Timeout   Duration          `yaml:"timeout"`
	Enabled   *bool             `yaml:"enabled"`
}

func (m MCPServer) IsEnabled() bool {
	return m.Enabled == nil || *m.Enabled
}

func DefaultRoles() map[string]Role {
	return map[string]Role{
		RolePlanner:     {Description: "décompose la demande en tâches", Tier: "deep"},
		"collector":     {Description: "collecte factuelle via les outils, sans interprétation poussée", Tier: "fast", Tools: true},
		"analyst":       {Description: "analyse approfondie d'un périmètre via les outils, détection d'anomalies et de mauvaises pratiques", Tier: "balanced", Tools: true, MinContext: 32000},
		RoleSynthesizer: {Description: "rédige le rapport final", Tier: "deep"},
	}
}

func Resolve(flag string) (string, error) {
	if flag != "" {
		return ExpandHome(flag), nil
	}
	if env := os.Getenv("CLOTR_CONFIG"); env != "" {
		return ExpandHome(env), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "clotr", "config.yaml"), nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if len(c.Roles) == 0 {
		c.Roles = DefaultRoles()
	}
	for i := range c.Providers {
		if c.Providers[i].MaxConcurrency <= 0 {
			c.Providers[i].MaxConcurrency = 4
		}
		c.Providers[i].BaseURL = strings.TrimRight(c.Providers[i].BaseURL, "/")
		if b := c.Providers[i].Budget; b.Limited() && b.InfoPath == "" {
			b.InfoPath = "/key/info"
		}
	}
	l := &c.Limits
	if l.MaxAgents <= 0 {
		l.MaxAgents = 6
	}
	if l.MaxTasks <= 0 {
		l.MaxTasks = 12
	}
	if l.Continuations == nil {
		one := 1
		l.Continuations = &one
	}
	if l.MaxSteps <= 0 {
		l.MaxSteps = 100
	}
	if l.VerifyFindings == nil {
		v := true
		l.VerifyFindings = &v
	}
	if l.StallSteps == nil {
		v := 3
		l.StallSteps = &v
	}
	if l.RequestTimeout.Duration <= 0 {
		l.RequestTimeout.Duration = 10 * time.Minute
	}
	if l.IdleTimeout.Duration <= 0 {
		l.IdleTimeout.Duration = 2 * time.Minute
	}
	if l.ToolOutputMaxChars <= 0 {
		l.ToolOutputMaxChars = 20000
	}
	if l.HistoryKeepSteps == nil {
		v := 2
		l.HistoryKeepSteps = &v
	}
	if l.HistoryToolChars == nil {
		v := 1500
		l.HistoryToolChars = &v
	}
	if c.Language == "" {
		c.Language = "auto"
	}
	if c.Routing.Sovereign == "" {
		c.Routing.Sovereign = "any"
	}
	if c.WebSearch.Policy == "" {
		c.WebSearch.Policy = "ask"
	}
	if c.Catalog.CacheTTL.Duration <= 0 {
		c.Catalog.CacheTTL.Duration = time.Hour
	}
	if c.Audit.Dir == "" {
		c.Audit.Dir = filepath.Join(StateDir(), "clotr", "audit")
	}
	c.Audit.Dir = ExpandHome(c.Audit.Dir)
	if c.Sessions.Dir == "" {
		c.Sessions.Dir = filepath.Join(StateDir(), "clotr", "sessions")
	}
	c.Sessions.Dir = ExpandHome(c.Sessions.Dir)
	if c.K8s != nil {
		c.K8s.Kubeconfig = ExpandHome(c.K8s.Kubeconfig)
		if c.K8s.Timeout.Duration <= 0 {
			c.K8s.Timeout.Duration = 30 * time.Second
		}
	}
	for i := range c.MCP {
		m := &c.MCP[i]
		if m.Transport == "" {
			if m.Command != "" {
				m.Transport = "stdio"
			} else {
				m.Transport = "http"
			}
		}
		if m.Timeout.Duration <= 0 {
			m.Timeout.Duration = time.Minute
		}
		m.Command = ExpandHome(m.Command)
	}
	if c.Templates.Dir == "" {
		if dir, err := os.UserConfigDir(); err == nil {
			c.Templates.Dir = filepath.Join(dir, "clotr", "templates")
		}
	}
	c.Templates.Dir = ExpandHome(c.Templates.Dir)
	if c.Templates.CacheDir == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			c.Templates.CacheDir = filepath.Join(dir, "clotr", "inventory")
		}
	}
	c.Templates.CacheDir = ExpandHome(c.Templates.CacheDir)
	if c.Templates.CacheTTL.Duration == 0 {
		c.Templates.CacheTTL.Duration = 15 * time.Minute
	}
	if c.Files != nil {
		if c.Files.MaxFileBytes <= 0 {
			c.Files.MaxFileBytes = 1 << 20
		}
		for i, r := range c.Files.Roots {
			c.Files.Roots[i] = ExpandHome(r)
		}
	}
}

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if len(c.Providers) == 0 {
		fail("providers: au moins un provider requis")
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		if p.Name == "" {
			fail("providers[%d].name: requis", i)
		}
		if strings.Contains(p.Name, "/") {
			fail("providers[%d].name: %q ne doit pas contenir '/'", i, p.Name)
		}
		if seen[p.Name] {
			fail("providers[%d].name: %q dupliqué", i, p.Name)
		}
		seen[p.Name] = true
		if p.APIKeyEnv != "" && !envName.MatchString(p.APIKeyEnv) {
			fail("providers[%d].api_key_env: attend un nom de variable d'environnement, pas une clé (utiliser api_key pour une clé en clair ou ${VAR})", i)
		}
		if b := p.Budget; b.Limited() && (b.MinRemaining < 0 || b.MaxRunCost < 0 || !strings.HasPrefix(b.InfoPath, "/")) {
			fail("providers[%d].budget: min_remaining/max_run_cost >= 0 et info_path commençant par /", i)
		}
		if p.APIKeyEnv != "" && p.Key != "" {
			fail("providers[%d]: api_key et api_key_env sont exclusifs", i)
		}
		if u, err := url.Parse(p.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			fail("providers[%d].base_url: URL invalide %q", i, p.BaseURL)
		}
	}
	for i, p := range c.Profiles {
		if p.Match == "" {
			fail("profiles[%d].match: requis", i)
		}
		if p.Tier != "" && TierRank(p.Tier) == 0 {
			fail("profiles[%d].tier: %q invalide (fast|balanced|deep)", i, p.Tier)
		}
	}
	if !ValidLanguage(c.Language) {
		fail("language: %q invalide (auto|fr|en)", c.Language)
	}
	if !ValidSovereignPolicy(c.Routing.Sovereign) {
		fail("routing.sovereign: %q invalide (any|prefer|require)", c.Routing.Sovereign)
	}
	for name, r := range c.Roles {
		if TierRank(r.Tier) == 0 {
			fail("roles.%s.tier: %q invalide (fast|balanced|deep)", name, r.Tier)
		}
		if r.Sovereign != "" && !ValidSovereignPolicy(r.Sovereign) {
			fail("roles.%s.sovereign: %q invalide (any|prefer|require)", name, r.Sovereign)
		}
	}
	for _, req := range []string{RolePlanner, RoleSynthesizer} {
		if _, ok := c.Roles[req]; !ok {
			fail("roles.%s: requis", req)
		}
	}
	if len(c.WorkerRoles()) == 0 {
		fail("roles: au moins un rôle de travail (hors planner/synthesizer) requis")
	}
	if c.Files != nil && len(c.Files.Roots) == 0 {
		fail("files.roots: au moins une racine requise")
	}
	mcpNames := map[string]bool{}
	for i, m := range c.MCP {
		if !mcpName.MatchString(m.Name) {
			fail("mcp[%d].name: %q invalide ([a-zA-Z0-9-]+)", i, m.Name)
		}
		if mcpNames[m.Name] {
			fail("mcp[%d].name: %q dupliqué", i, m.Name)
		}
		mcpNames[m.Name] = true
		if (m.Command == "") == (m.URL == "") {
			fail("mcp[%d]: command ou url requis (exclusifs)", i)
		}
		switch m.Transport {
		case "", "stdio", "http", "sse":
		default:
			fail("mcp[%d].transport: %q invalide (stdio|http|sse)", i, m.Transport)
		}
		if m.Command != "" && m.Transport != "" && m.Transport != "stdio" {
			fail("mcp[%d].transport: %q incompatible avec command", i, m.Transport)
		}
		if m.URL != "" && m.Transport == "stdio" {
			fail("mcp[%d].transport: stdio incompatible avec url", i)
		}
	}
	if *c.Limits.StallSteps < 0 {
		fail("limits.stall_steps: valeur positive ou 0 (0 désactive la détection de non-progression)")
	}
	if *c.Limits.HistoryKeepSteps < 0 || *c.Limits.HistoryToolChars < 0 {
		fail("limits.history_keep_steps / history_tool_chars: valeurs positives ou 0 (0 désactive le raccourcissement)")
	}
	if !ValidWebPolicy(c.WebSearch.Policy) {
		fail("web_search.policy: %q invalide (ask|allow|deny)", c.WebSearch.Policy)
	}
	if c.WebSearch.MCP != "" && !mcpNames[c.WebSearch.MCP] {
		fail("web_search.mcp: serveur MCP %q absent de mcp", c.WebSearch.MCP)
	}
	instNames := map[string]bool{}
	for i, in := range c.Instances {
		if !instanceName.MatchString(in.Name) {
			fail("instances[%d].name: %q invalide ([a-z][a-z0-9-]*)", i, in.Name)
		}
		if slices.Contains(reservedPrefixes, in.Name) {
			fail("instances[%d].name: %q réservé (%s)", i, in.Name, strings.Join(reservedPrefixes, ", "))
		}
		if instNames[in.Name] {
			fail("instances[%d].name: %q dupliqué", i, in.Name)
		}
		instNames[in.Name] = true
		if in.Template == "" {
			fail("instances[%d].template: requis", i)
		}
	}
	if *c.Limits.Continuations < 0 || *c.Limits.Continuations > 3 {
		fail("limits.continuations: entre 0 et 3")
	}
	if c.Templates.CacheTTL.Duration < 0 {
		fail("templates.cache_ttl: négatif")
	}
	return errors.Join(errs...)
}

func (c *Config) WorkerRoles() []string {
	var out []string
	for name := range c.Roles {
		if name != RolePlanner && name != RoleSynthesizer {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func (c *Config) Provider(name string) (Provider, bool) {
	for _, p := range c.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}

func StateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserCacheDir(); err == nil {
			return d
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state")
}

func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(filepath.Separator)) {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
