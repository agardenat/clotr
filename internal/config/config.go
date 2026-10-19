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

	"github.com/agardenat/clotr/internal/i18n"
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
		return i18n.E("config.duration", n.Line, s)
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
	Files     *Files          `yaml:"files"`
	MCP       []MCPServer     `yaml:"mcp"`
	Templates TemplatesConf   `yaml:"templates"`
	Instances []Instance      `yaml:"instances"`
	Clients   []Client        `yaml:"-"`
	Routing   Routing         `yaml:"routing"`
	Sessions  SessionsConf    `yaml:"sessions"`
	Language  string          `yaml:"language"`
	UILang    string          `yaml:"ui_language"`
	WebSearch WebSearch       `yaml:"web_search"`
	Export    ReportExport    `yaml:"report_export"`
	Vault     VaultConf       `yaml:"vault"`
}

type ReportExport struct {
	MCP  string `yaml:"mcp"`
	Role string `yaml:"role"`
}

var ExportFormats = []string{"docx", "pdf"}

func (c *Config) ExportRole() string {
	if c.Export.Role != "" {
		return c.Export.Role
	}
	best := ""
	for _, name := range c.WorkerRoles() {
		r := c.Roles[name]
		if !r.Tools {
			continue
		}
		if b := c.Roles[best]; best == "" || TierRank(r.Tier) > TierRank(b.Tier) || (TierRank(r.Tier) == TierRank(b.Tier) && r.MinContext > b.MinContext) {
			best = name
		}
	}
	return best
}

type VaultConf struct {
	Addr      string `yaml:"addr"`
	Namespace string `yaml:"namespace"`
}

type WebSearch struct {
	Policy string `yaml:"policy"`
	MCP    string `yaml:"mcp"`
	Model  string `yaml:"model"`
	API    string `yaml:"api"`
}

func ValidWebPolicy(p string) bool {
	return p == "ask" || p == "allow" || p == "deny"
}

func ValidLanguage(l string) bool {
	return l == "auto" || l == "fr" || l == "en"
}

func ValidUILanguage(l string) bool {
	return l == "en" || l == "fr"
}

func PeekUILanguage(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var c struct {
		UILang string `yaml:"ui_language"`
	}
	if yaml.Unmarshal(data, &c) != nil {
		return ""
	}
	return c.UILang
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
	Client   string         `yaml:"-"`
}

type Client struct {
	Name      string            `yaml:"name"`
	Aliases   []string          `yaml:"aliases"`
	Context   string            `yaml:"context"`
	Vars      map[string]string `yaml:"vars"`
	Params    map[string]any    `yaml:"params"`
	Instances []Instance        `yaml:"instances"`
}

func (c *Config) Client(name string) (Client, bool) {
	for _, cl := range c.Clients {
		if cl.Name == name {
			return cl, true
		}
	}
	return Client{}, false
}

func (i Instance) IsEnabled() bool {
	return i.Enabled == nil || *i.Enabled
}

var instanceName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var varName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var reservedPrefixes = []string{"fs", "mcp", "memory", "evidence", "web", "cause", "dns"}

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
	Name            string            `yaml:"name"`
	BaseURL         string            `yaml:"base_url"`
	Key             string            `yaml:"api_key"`
	Weight          int               `yaml:"weight"`
	Sovereign       bool              `yaml:"sovereign"`
	Budget          *Budget           `yaml:"budget"`
	SessionHeader   string            `yaml:"session_header"`
	Stream          *bool             `yaml:"stream"`
	APIKeyEnv       string            `yaml:"api_key_env"`
	MaxConcurrency  int               `yaml:"max_concurrency"`
	PersistentRetry bool              `yaml:"persistent_retry"`
	ModelInfo       bool              `yaml:"model_info"`
	Headers         map[string]string `yaml:"headers"`
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
			return i18n.E("config.budget", n.Line, n.Value)
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
		return i18n.T("config.budget.undeclared")
	case p.Budget.Unlimited:
		return i18n.T("config.budget.unlimited")
	}
	return i18n.T("config.budget.limited")
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
	return parse(data, ClientsDir(path))
}

func ClientsDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "clients")
}

func Parse(data []byte) (*Config, error) {
	return parse(data, "")
}

func parse(data []byte, clientsDir string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if ValidUILanguage(c.UILang) {
		i18n.DefaultUI(c.UILang)
	}
	if clientsDir != "" {
		if err := c.loadClients(clientsDir); err != nil {
			return nil, err
		}
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) loadClients(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var cl Client
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cl); err != nil {
			return fmt.Errorf("client %s: %w", f, err)
		}
		if base := strings.TrimSuffix(filepath.Base(f), ".yaml"); cl.Name != base {
			return i18n.E("config.client_file", f, cl.Name, base)
		}
		for _, in := range cl.Instances {
			in.Client = cl.Name
			c.Instances = append(c.Instances, in)
		}
		cl.Instances = nil
		c.Clients = append(c.Clients, cl)
	}
	return nil
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
	if c.UILang == "" {
		c.UILang = "en"
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
	fail := func(msg string) {
		errs = append(errs, errors.New(msg))
	}
	if len(c.Providers) == 0 {
		fail(i18n.T("config.providers"))
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		if p.Name == "" {
			fail(i18n.T("config.provider_name", i))
		}
		if strings.Contains(p.Name, "/") {
			fail(i18n.T("config.provider_slash", i, p.Name))
		}
		if seen[p.Name] {
			fail(i18n.T("config.provider_dup", i, p.Name))
		}
		seen[p.Name] = true
		if p.APIKeyEnv != "" && !envName.MatchString(p.APIKeyEnv) {
			fail(i18n.T("config.api_key_env", i))
		}
		if b := p.Budget; b.Limited() && (b.MinRemaining < 0 || b.MaxRunCost < 0 || !strings.HasPrefix(b.InfoPath, "/")) {
			fail(i18n.T("config.provider_budget", i))
		}
		if p.APIKeyEnv != "" && p.Key != "" {
			fail(i18n.T("config.api_key_both", i))
		}
		if u, err := url.Parse(p.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			fail(i18n.T("config.base_url", i, p.BaseURL))
		}
	}
	for i, p := range c.Profiles {
		if p.Match == "" {
			fail(i18n.T("config.profile_match", i))
		}
		if p.Tier != "" && TierRank(p.Tier) == 0 {
			fail(i18n.T("config.profile_tier", i, p.Tier))
		}
	}
	if !ValidLanguage(c.Language) {
		fail(i18n.T("config.language", c.Language))
	}
	if !ValidUILanguage(c.UILang) {
		fail(i18n.T("config.ui_language", c.UILang))
	}
	if !ValidSovereignPolicy(c.Routing.Sovereign) {
		fail(i18n.T("config.sovereign", c.Routing.Sovereign))
	}
	for name, r := range c.Roles {
		if TierRank(r.Tier) == 0 {
			fail(i18n.T("config.role_tier", name, r.Tier))
		}
		if r.Sovereign != "" && !ValidSovereignPolicy(r.Sovereign) {
			fail(i18n.T("config.role_sovereign", name, r.Sovereign))
		}
	}
	for _, req := range []string{RolePlanner, RoleSynthesizer} {
		if _, ok := c.Roles[req]; !ok {
			fail(i18n.T("config.role_required", req))
		}
	}
	if len(c.WorkerRoles()) == 0 {
		fail(i18n.T("config.worker_role"))
	}
	if c.Files != nil && len(c.Files.Roots) == 0 {
		fail(i18n.T("config.roots"))
	}
	mcpNames := map[string]bool{}
	for i, m := range c.MCP {
		if !mcpName.MatchString(m.Name) {
			fail(i18n.T("config.mcp_name", i, m.Name))
		}
		if mcpNames[m.Name] {
			fail(i18n.T("config.mcp_dup", i, m.Name))
		}
		mcpNames[m.Name] = true
		if (m.Command == "") == (m.URL == "") {
			fail(i18n.T("config.mcp_cmd_url", i))
		}
		switch m.Transport {
		case "", "stdio", "http", "sse":
		default:
			fail(i18n.T("config.mcp_transport", i, m.Transport))
		}
		if m.Command != "" && m.Transport != "" && m.Transport != "stdio" {
			fail(i18n.T("config.mcp_transport_cmd", i, m.Transport))
		}
		if m.URL != "" && m.Transport == "stdio" {
			fail(i18n.T("config.mcp_stdio_url", i))
		}
	}
	if *c.Limits.StallSteps < 0 {
		fail(i18n.T("config.stall_steps"))
	}
	if *c.Limits.HistoryKeepSteps < 0 || *c.Limits.HistoryToolChars < 0 {
		fail(i18n.T("config.history"))
	}
	if !ValidWebPolicy(c.WebSearch.Policy) {
		fail(i18n.T("config.web_policy", c.WebSearch.Policy))
	}
	if c.WebSearch.MCP != "" && !mcpNames[c.WebSearch.MCP] {
		fail(i18n.T("config.web_mcp", c.WebSearch.MCP))
	}
	if c.WebSearch.Model != "" {
		prov, id, ok := strings.Cut(c.WebSearch.Model, "/")
		if _, known := c.Provider(prov); !ok || id == "" || !known {
			fail(i18n.T("config.web_model", c.WebSearch.Model))
		}
		if c.WebSearch.API != "messages" && c.WebSearch.API != "responses" {
			fail(i18n.T("config.web_api", c.WebSearch.API))
		}
	} else if c.WebSearch.API != "" {
		fail(i18n.T("config.web_api_model"))
	}
	if c.Export.MCP != "" && !mcpNames[c.Export.MCP] {
		fail(i18n.T("config.export_mcp", c.Export.MCP))
	}
	if c.Export.MCP != "" && c.Export.MCP == c.WebSearch.MCP {
		fail(i18n.T("config.export_web", c.Export.MCP))
	}
	if r := c.Export.Role; r != "" && (!slices.Contains(c.WorkerRoles(), r) || !c.Roles[r].Tools) {
		fail(i18n.T("config.export_role", r))
	}
	instNames := map[string]bool{}
	for i, in := range c.Instances {
		if !instanceName.MatchString(in.Name) {
			fail(i18n.T("config.instance_name", i, in.Name))
		}
		if slices.Contains(reservedPrefixes, in.Name) {
			fail(i18n.T("config.instance_reserved", i, in.Name, strings.Join(reservedPrefixes, ", ")))
		}
		if instNames[in.Name] {
			fail(i18n.T("config.instance_dup", i, in.Name))
		}
		instNames[in.Name] = true
		if in.Template == "" {
			fail(i18n.T("config.instance_template", i))
		}
	}
	terms := map[string]string{}
	for _, cl := range c.Clients {
		if !instanceName.MatchString(cl.Name) {
			fail(i18n.T("config.client_name", cl.Name))
		}
		if slices.Contains(reservedPrefixes, cl.Name) || instNames[cl.Name] {
			fail(i18n.T("config.client_taken", cl.Name))
		}
		for _, t := range append([]string{cl.Name}, cl.Aliases...) {
			key := strings.ToLower(strings.TrimSpace(t))
			if key == "" {
				fail(i18n.T("config.client_alias", cl.Name))
				continue
			}
			if other, dup := terms[key]; dup {
				fail(i18n.T("config.client_alias_dup", cl.Name, t, other))
			}
			terms[key] = cl.Name
		}
		for k, v := range cl.Vars {
			if !varName.MatchString(k) {
				fail(i18n.T("config.client_var", cl.Name, k))
			}
			if strings.TrimSpace(v) == "" {
				fail(i18n.T("config.client_var_empty", cl.Name, k))
			}
		}
	}
	if c.Vault.Addr != "" {
		if u, err := url.Parse(c.Vault.Addr); err != nil || u.Scheme == "" || u.Host == "" {
			fail(i18n.T("config.vault_addr", c.Vault.Addr))
		}
	}
	if *c.Limits.Continuations < 0 || *c.Limits.Continuations > 3 {
		fail(i18n.T("config.continuations"))
	}
	if c.Templates.CacheTTL.Duration < 0 {
		fail(i18n.T("config.cache_ttl"))
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
