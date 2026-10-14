package template

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/netx"
)

type Inventory struct {
	Instance     string    `json:"instance"`
	Template     string    `json:"template"`
	Fingerprint  string    `json:"fingerprint"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Targets      []*Target `json:"targets"`
	Lines        []string  `json:"lines,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
	Data         any       `json:"data,omitempty"`
}

type Target struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Status   string            `json:"status,omitempty"`
	Error    string            `json:"error,omitempty"`
	Summary  string            `json:"summary,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	Hosts    []*Host           `json:"hosts,omitempty"`
	Networks []string          `json:"networks,omitempty"`
	Data     any               `json:"data,omitempty"`
}

func (t *Target) inNetworks(ip net.IP) bool {
	return t.network(ip) != ""
}

func (t *Target) network(ip net.IP) string {
	for _, n := range t.Networks {
		if _, ipn, err := net.ParseCIDR(n); err == nil && ipn.Contains(ip) {
			return n
		}
	}
	return ""
}

type Host struct {
	Name  string            `json:"name"`
	IP    string            `json:"ip,omitempty"`
	Group string            `json:"group,omitempty"`
	State string            `json:"state,omitempty"`
	Roles []string          `json:"roles,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

type sshExecutor interface {
	ExecInput(ctx context.Context, e ssh.Endpoint, cmd, stdin string, maxBytes int) (ssh.Result, error)
	Close()
}

type Instance struct {
	Name   string
	T      *Template
	params map[string]any
	tools  []ToolSpec
	conns  map[string]options
	fp     string

	Audit func(kind string, fields map[string]any)
	Print func(msg string)
	Warn  func(msg string)

	Activating func()

	Client      string
	ClientTerms []string

	mu        sync.Mutex
	inv       *Inventory
	invValue  starlark.Value
	https     map[string]*httpConn
	sshName   string
	pool      sshExecutor
	rules     *ssh.Rules
	sudo      bool
	sudoPass  map[string]bool
	script    *script
	memo      map[string]*memoEntry
	loaded    map[string]*loadEntry
	loadedSrc []byte

	getenv    func(string) string
	readFile  func(string) ([]byte, error)
	now       func() time.Time
	transport http.RoundTripper
	clients   map[string]*http.Client
	files     []string
	creds     map[string]creds.Pair
	pending   *activation
}

type activation struct {
	ctx      context.Context
	cacheDir string
	ttl      time.Duration
	refresh  bool
	once     sync.Once
	err      error
	ok       atomic.Bool
}

func NewInstance(name string, t *Template, given map[string]any) (*Instance, error) {
	params, err := t.ResolveParams(given)
	if err != nil {
		return nil, fmt.Errorf("instance %s: %w", name, err)
	}
	in := &Instance{Name: name, T: t, params: params, conns: map[string]options{}, https: map[string]*httpConn{}, memo: map[string]*memoEntry{}, creds: map[string]creds.Pair{}, getenv: os.Getenv, readFile: os.ReadFile, now: time.Now}
	for i, f := range t.Files {
		r, err := Render(f, params)
		if err != nil {
			return nil, fmt.Errorf("instance %s: files[%d]: %w", name, i, err)
		}
		if r = strings.TrimSpace(r); r != "" {
			in.files = append(in.files, r)
		}
	}
	for _, cn := range sortedKeys(t.Connectors) {
		c := t.Connectors[cn]
		r, err := renderAny(map[string]any(c.Options), params)
		if err != nil {
			return nil, fmt.Errorf("instance %s: connectors.%s: %w", name, cn, err)
		}
		o := options(r.(map[string]any))
		in.conns[cn] = o
		switch c.Driver {
		case "http":
			hc, err := newHTTPConn(cn, o)
			if err != nil {
				return nil, fmt.Errorf("instance %s: connectors.%s: %w", name, cn, err)
			}
			in.https[cn] = hc
		case "ssh":
			in.sshName = cn
		}
	}
	for i, ts := range t.Tools {
		on, err := toolEnabled(ts, params)
		if err != nil {
			return nil, fmt.Errorf("instance %s: tools[%d].when: %w", name, i, err)
		}
		if on {
			in.tools = append(in.tools, ts)
		}
	}
	if in.sshName != "" {
		paths, err := renderPaths(t.SSHPaths, params)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", name, err)
		}
		in.rules, err = ssh.CompileRules(paths)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", name, err)
		}
		in.sudo, err = in.conns[in.sshName].bool("sudo", false)
		if err != nil {
			return nil, fmt.Errorf("instance %s: connecteur %s: %w", name, in.sshName, err)
		}
	}
	if t.ScriptSrc != nil {
		if err := in.loadScript(); err != nil {
			return nil, fmt.Errorf("instance %s: %w", name, err)
		}
	}
	h := sha256.New()
	h.Write(t.Raw)
	h.Write(t.ScriptSrc)
	h.Write(in.loadedSrc)
	pj, _ := json.Marshal(params)
	h.Write(pj)
	in.fp = hex.EncodeToString(h.Sum(nil))[:16]
	if err := in.checkToolNames(); err != nil {
		return nil, fmt.Errorf("instance %s: %w", name, err)
	}
	return in, nil
}

func (in *Instance) Params() map[string]any {
	return maps.Clone(in.params)
}

func (in *Instance) audit(kind string, f map[string]any) {
	if in.Audit != nil {
		f["instance"] = in.Name
		in.Audit(kind, f)
	}
}

func (in *Instance) buildTargets() ([]*Target, error) {
	var out []*Target
	for i, spec := range in.T.Targets {
		datas := []map[string]any{in.params}
		if fe := spec["foreach"]; fe != "" {
			datas = nil
			items, _ := in.params[fe].([]map[string]any)
			for _, it := range items {
				d := maps.Clone(in.params)
				for k, v := range it {
					if s, ok := v.(string); ok && s == "" {
						if _, inherited := in.params[k]; inherited {
							continue
						}
					}
					d[k] = v
				}
				datas = append(datas, d)
			}
		}
		for _, d := range datas {
			t := &Target{Kind: spec["kind"], Attrs: map[string]string{}}
			for k, v := range spec {
				if k == "kind" || k == "foreach" {
					continue
				}
				r, err := Render(v, d)
				if err != nil {
					return nil, fmt.Errorf("targets[%d].%s: %w", i, k, err)
				}
				if k == "name" {
					t.Name = r
					continue
				}
				if r != "" {
					t.Attrs[k] = r
				}
			}
			if t.Name == "" {
				t.Name = t.Kind
			}
			out = append(out, t)
		}
	}
	return out, nil
}

func (in *Instance) Prepare(ctx context.Context) error {
	for _, cn := range sortedKeys(in.https) {
		hc := in.https[cn]
		if hc.auth == nil {
			continue
		}
		if _, ok := in.creds[cn]; ok {
			continue
		}
		p, err := creds.Resolve(ctx, hc.auth.userEnv, hc.auth.passEnv, hc.auth.passVault, in.Name+" ("+hc.auth.label+")")
		if err != nil {
			return err
		}
		in.creds[cn] = p
	}
	return nil
}

func (in *Instance) Defer(ctx context.Context, cacheDir string, ttl time.Duration, refresh bool) error {
	var inv *Inventory
	if cacheDir != "" && !refresh {
		inv, _ = readCache(filepath.Join(cacheDir, in.Name+".json"), in.fp, -1)
	}
	if inv == nil {
		targets, err := in.buildTargets()
		if err != nil {
			return fmt.Errorf("instance %s: %w", in.Name, err)
		}
		inv = &Inventory{Instance: in.Name, Template: in.T.Name, Fingerprint: in.fp, Targets: targets}
		if in.script != nil && in.script.discover != nil {
			off := &Inventory{Instance: in.Name, Template: in.T.Name, Fingerprint: in.fp, Targets: targets}
			run := &offlineRun{}
			octx, cancel := context.WithTimeout(context.WithValue(ctx, offlineKey{}, run), 10*time.Second)
			if in.runDiscover(octx, off) == nil && !run.network.Load() {
				inv = off
			}
			cancel()
		}
	}
	in.pending = &activation{ctx: ctx, cacheDir: cacheDir, ttl: ttl, refresh: refresh}
	return in.setInventory(inv)
}

func (in *Instance) ensure() error {
	a := in.pending
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		if in.Activating != nil {
			in.Activating()
		}
		err := in.Prepare(a.ctx)
		if err == nil {
			ctx, cancel := context.WithTimeout(a.ctx, 3*time.Minute)
			err = in.Discover(ctx, a.cacheDir, a.ttl, a.refresh)
			cancel()
		}
		if err == nil {
			in.warnInventory()
			if len(in.Reachable()) == 0 {
				err = errors.New("aucune cible joignable")
			}
		}
		f := map[string]any{}
		if err != nil {
			a.err = fmt.Errorf("instance %s indisponible pour ce run: %w", in.Name, err)
			in.warn(a.err.Error())
			f["error"] = err.Error()
		} else {
			a.ok.Store(true)
		}
		in.audit("instance_activation", f)
	})
	return a.err
}

func (in *Instance) warnInventory() {
	for _, w := range in.inv.Warnings {
		in.warn(fmt.Sprintf("instance %s: %s", in.Name, w))
	}
	for _, t := range in.inv.Targets {
		if t.Error != "" {
			in.warn(fmt.Sprintf("instance %s: cible %s injoignable, retirée pour ce run: %s", in.Name, t.Name, t.Error))
		}
	}
}

func (in *Instance) warn(msg string) {
	if in.Warn != nil {
		in.Warn(msg)
	}
}

func (in *Instance) Discover(ctx context.Context, cacheDir string, ttl time.Duration, refresh bool) error {
	cachePath := ""
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, in.Name+".json")
	}
	if !refresh && cachePath != "" && ttl > 0 {
		if inv, ok := readCache(cachePath, in.fp, ttl); ok {
			return in.setInventory(inv)
		}
	}
	targets, err := in.buildTargets()
	if err != nil {
		return fmt.Errorf("instance %s: %w", in.Name, err)
	}
	inv := &Inventory{Instance: in.Name, Template: in.T.Name, Fingerprint: in.fp, DiscoveredAt: in.now(), Targets: targets}
	if in.script != nil && in.script.discover != nil {
		if err := in.runDiscover(ctx, inv); err != nil {
			return fmt.Errorf("instance %s: discover: %w", in.Name, err)
		}
	}
	if err := in.setInventory(inv); err != nil {
		return err
	}
	complete := len(inv.Warnings) == 0
	for _, t := range inv.Targets {
		if t.Error != "" {
			complete = false
		}
	}
	if cachePath != "" && complete {
		_ = writeCache(cachePath, inv)
	}
	return nil
}

func (in *Instance) Activated() bool {
	return in.pending == nil || in.pending.ok.Load()
}

func (in *Instance) Mentioned(text string) bool {
	return in.Mention(text) != ""
}

func (in *Instance) Mention(text string) string {
	if why := in.MentionOwn(text); why != "" {
		return why
	}
	if why := in.MentionClient(text); why != "" {
		return why
	}
	return in.MentionGeneric(text)
}

func (in *Instance) MentionOwn(text string) string {
	terms := []string{in.Name}
	var networks []*Target
	in.mu.Lock()
	if in.inv != nil {
		for _, t := range in.inv.Targets {
			terms = append(terms, t.Name)
			if len(t.Networks) > 0 {
				networks = append(networks, t)
			}
		}
	}
	in.mu.Unlock()
	for _, lit := range ipv4Re.FindAllString(text, -1) {
		ip := net.ParseIP(lit)
		for _, t := range networks {
			if n := t.network(ip); ip != nil && n != "" {
				return lit + " ∈ " + n
			}
		}
	}
	return MentionTerm(text, terms)
}

func (in *Instance) MentionClient(text string) string {
	if MentionTerm(text, in.ClientTerms) == "" {
		return ""
	}
	return "client " + in.Client
}

func (in *Instance) MentionGeneric(text string) string {
	return MentionTerm(text, append([]string{in.T.Name}, in.T.Keywords...))
}

func MentionTerm(text string, terms []string) string {
	for _, term := range terms {
		if term = strings.TrimSpace(term); term == "" {
			continue
		}
		if regexp.MustCompile(`(?i)(^|[^\pL\pN_])` + regexp.QuoteMeta(term) + `($|[^\pL\pN_])`).MatchString(text) {
			return term
		}
	}
	return ""
}

func (in *Instance) hasCachedInventory() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.inv != nil && !in.inv.DiscoveredAt.IsZero()
}

func (in *Instance) inventoryToolName() string {
	for _, ts := range in.tools {
		if ts.Kind == "inventory" {
			return in.Name + "_" + ts.ToolName()
		}
	}
	return ""
}

func (in *Instance) setInventory(inv *Inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	v, err := jsonToStarlark(b)
	if err != nil {
		return err
	}
	v.Freeze()
	in.mu.Lock()
	in.inv, in.invValue = inv, v
	in.mu.Unlock()
	return nil
}

func readCache(path, fp string, ttl time.Duration) (*Inventory, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var inv Inventory
	if json.Unmarshal(data, &inv) != nil || inv.Fingerprint != fp || (ttl >= 0 && time.Since(inv.DiscoveredAt) > ttl) {
		return nil, false
	}
	return &inv, true
}

func writeCache(path string, inv *Inventory) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (in *Instance) Inventory() *Inventory {
	return in.inv
}

func (in *Instance) Reachable() []*Target {
	var out []*Target
	if in.inv == nil {
		return nil
	}
	for _, t := range in.inv.Targets {
		if t.Error == "" {
			out = append(out, t)
		}
	}
	return out
}

func (in *Instance) target(name string) (*Target, error) {
	if in.inv == nil {
		return nil, fmt.Errorf("inventaire de %s non découvert", in.Name)
	}
	var names []string
	for _, t := range in.inv.Targets {
		if strings.EqualFold(t.Name, name) || (strings.EqualFold(t.Kind, name) && countKind(in.inv, t.Kind) == 1) {
			return t, nil
		}
		names = append(names, t.Name)
	}
	return nil, fmt.Errorf("cible %q inconnue (cibles: %s)", name, strings.Join(names, ", "))
}

func countKind(inv *Inventory, kind string) int {
	n := 0
	for _, t := range inv.Targets {
		if t.Kind == kind {
			n++
		}
	}
	return n
}

func (in *Instance) sshPool() (sshExecutor, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pool != nil {
		return in.pool, nil
	}
	if in.sshName == "" {
		return nil, fmt.Errorf("aucun connecteur ssh dans le template %s", in.T.Name)
	}
	o := in.conns[in.sshName]
	port, err := o.int("proxy_port", 0)
	if err != nil {
		return nil, err
	}
	px, err := netx.ProxyURL(o.str("proxy"), port)
	if err != nil {
		return nil, err
	}
	maxConns, err := o.int("max_conns", 4)
	if err != nil {
		return nil, err
	}
	kh := o.str("known_hosts")
	if kh == "" {
		kh = filepath.Join(config.StateDir(), "clotr", "known_hosts")
	}
	p, err := ssh.NewPool(ssh.Options{Proxy: px, KnownHosts: config.ExpandHome(kh), HostKey: ssh.HostKeyPolicy(o.str("host_key")), MaxConns: maxConns})
	if err != nil {
		return nil, err
	}
	in.pool = p
	return p, nil
}

type sshLogin struct {
	in        *Instance
	label     string
	user      string
	passEnv   string
	passVault string
}

func (l *sshLogin) password(ctx context.Context) (string, error) {
	if p, ok := l.in.creds[l.in.sshName]; ok {
		return p.Pass, nil
	}
	p, err := creds.ResolveUser(ctx, l.user, l.passEnv, l.passVault, l.label)
	return p.Pass, err
}

func (l *sshLogin) forget() {
	creds.Forget(l.label, l.user)
}

func (in *Instance) sshEndpoint(ctx context.Context, t *Target, h *Host) (ssh.Endpoint, *sshLogin, error) {
	o := in.conns[in.sshName]
	pick := func(attr, opt string) string {
		if v := t.Attrs[attr]; v != "" {
			return v
		}
		return o.str(opt)
	}
	port, err := strconv.Atoi(defaultStr(pick("ssh_port", "port"), "22"))
	if err != nil {
		return ssh.Endpoint{}, nil, fmt.Errorf("port SSH invalide")
	}
	host := h.IP
	if host == "" {
		host = h.Name
	}
	ep := ssh.Endpoint{Host: host, Port: port, User: pick("ssh_user", "user"), KeyPath: config.ExpandHome(pick("ssh_key_path", "key"))}
	a := o.sub("auth")
	if len(a) == 0 {
		return ep, nil, nil
	}
	l := &sshLogin{in: in, label: in.Name + " (" + defaultStr(a.str("label"), "SSH") + ")", user: ep.User, passEnv: a.str("password_env"), passVault: a.str("password_vault")}
	if l.user == "" {
		p, ok := in.creds[in.sshName]
		if !ok {
			if p, err = creds.Resolve(ctx, a.str("user_env"), l.passEnv, l.passVault, l.label); err != nil {
				return ssh.Endpoint{}, nil, err
			}
		}
		ep.User, l.user = p.User, p.User
	}
	ep.Password = l.password
	return ep, l, nil
}

func (in *Instance) sudoNeedsPassword(ep ssh.Endpoint) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.sudoPass[ep.User+"@"+net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))]
}

func (in *Instance) setSudoNeedsPassword(ep ssh.Endpoint) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.sudoPass == nil {
		in.sudoPass = map[string]bool{}
	}
	in.sudoPass[ep.User+"@"+net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))] = true
}

func (in *Instance) findHost(target, host string) (*Target, *Host, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, nil, fmt.Errorf("host requis")
	}
	if in.inv == nil {
		return nil, nil, fmt.Errorf("inventaire de %s non découvert", in.Name)
	}
	var cands []*Target
	if target != "" {
		t, err := in.target(target)
		if err != nil {
			return nil, nil, err
		}
		cands = []*Target{t}
	} else {
		cands = in.inv.Targets
	}
	type hit struct {
		t *Target
		h *Host
	}
	var exact, suffix []hit
	for _, t := range cands {
		for _, h := range t.Hosts {
			name := strings.ToLower(h.Name)
			short := strings.SplitN(name, ".", 2)[0]
			switch {
			case name == host || h.IP == host || short == host:
				exact = append(exact, hit{t, h})
			case strings.HasSuffix(short, "-"+host):
				suffix = append(suffix, hit{t, h})
			}
		}
	}
	if len(exact) == 1 || (len(exact) == 0 && len(suffix) == 1) {
		r := append(exact, suffix...)[0]
		return r.t, r.h, nil
	}
	if amb := append(exact, suffix...); len(amb) > 1 {
		var names []string
		for _, a := range amb {
			names = append(names, a.h.Name)
		}
		return nil, nil, fmt.Errorf("hôte %q ambigu : %s (préciser target ou le nom complet)", host, strings.Join(names, ", "))
	}
	var networks, inRange []string
	var rangeTarget *Target
	ip := net.ParseIP(host)
	for _, t := range cands {
		networks = append(networks, t.Networks...)
		if ip != nil && t.inNetworks(ip) {
			rangeTarget = t
			inRange = append(inRange, t.Name)
		}
	}
	switch {
	case len(inRange) == 1:
		return rangeTarget, &Host{Name: ip.String(), IP: ip.String()}, nil
	case len(inRange) > 1:
		return nil, nil, fmt.Errorf("IP %s dans les plages de plusieurs cibles : %s (préciser target)", host, strings.Join(inRange, ", "))
	case len(networks) > 0:
		return nil, nil, fmt.Errorf("hôte %q absent de l'inventaire de %s et hors des plages %s (voir %s_inventory ; hors inventaire, donner l'IP)", host, in.Name, strings.Join(networks, ", "), in.Name)
	}
	return nil, nil, fmt.Errorf("hôte %q absent de l'inventaire de %s (voir %s_inventory)", host, in.Name, in.Name)
}

func (in *Instance) Close() {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pool != nil {
		in.pool.Close()
	}
}

func (in *Instance) ToolPrefix() string {
	return in.Name + "_"
}

func (in *Instance) Companions() []string {
	var out []string
	for _, c := range in.T.Companions {
		out = append(out, in.Name+"_"+c)
	}
	return out
}

func (in *Instance) EnvironmentLines() []string {
	inv := in.inv
	if inv == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("- Instance %s (template %s : %s). Outils : %s", in.Name, in.T.Name, in.T.Description, strings.Join(in.ToolNames(), ", "))}
	if in.pending != nil {
		if inv.DiscoveredAt.IsZero() {
			lines = append(lines, "  Instance activée seulement si une tâche appelle l'un de ses outils (identifiants demandés à l'utilisateur s'ils ne sont pas dans l'environnement, puis découverte) ; inventaire pas encore découvert, cibles issues de la configuration.")
		} else {
			line := "  Instance activée seulement si une tâche appelle l'un de ses outils (identifiants demandés à l'utilisateur s'ils ne sont pas dans l'environnement, puis découverte) ; inventaire ci-dessous issu du cache du " + inv.DiscoveredAt.Format(time.RFC3339) + ", actualisé à l'activation."
			if name := in.inventoryToolName(); name != "" {
				line += " " + name + " lit ce cache sans activer l'instance."
			}
			lines = append(lines, line)
		}
	}
	for _, l := range inv.Lines {
		lines = append(lines, "  "+l)
	}
	for _, t := range inv.Targets {
		head := fmt.Sprintf("  - %s %s", t.Kind, t.Name)
		if t.Status != "" {
			head += " [" + t.Status + "]"
		}
		switch {
		case t.Error != "":
			lines = append(lines, head+" : INJOIGNABLE pour ce run ("+oneLine(t.Error, 160)+")")
		case t.Summary != "":
			lines = append(lines, head+" : "+t.Summary)
		default:
			lines = append(lines, head)
		}
		if len(t.Networks) > 0 {
			lines = append(lines, "    plages "+strings.Join(t.Networks, ", ")+" : toute IP de ces plages est accessible par les outils SSH, même hors inventaire (passer l'IP en host)")
		}
	}
	if h := strings.TrimSpace(in.T.Hints); h != "" {
		for _, l := range strings.Split(h, "\n") {
			lines = append(lines, "  "+strings.TrimSpace(l))
		}
	}
	return append(lines, "  "+CommonHint)
}

const CommonHint = "Règle commune à tous les templates : rester factuel et ne jamais supposer le comportement, les valeurs par défaut ou la signification des messages des produits de cette plateforme ; en cas de doute, chercher dans la documentation officielle de l'éditeur (recherche web si elle est disponible), sinon le noter comme non vérifié."

var ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func toolEnabled(ts ToolSpec, params map[string]any) (bool, error) {
	if ts.When == "" {
		return true, nil
	}
	r, err := Render(ts.When, params)
	if err != nil {
		return false, err
	}
	r = strings.TrimSpace(r)
	if r == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(r)
	if err != nil {
		return false, fmt.Errorf("booléen attendu, %q", r)
	}
	return b, nil
}
