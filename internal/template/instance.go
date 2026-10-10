package template

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Status  string            `json:"status,omitempty"`
	Error   string            `json:"error,omitempty"`
	Summary string            `json:"summary,omitempty"`
	Attrs   map[string]string `json:"attrs,omitempty"`
	Hosts   []*Host           `json:"hosts,omitempty"`
	Data    any               `json:"data,omitempty"`
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
	Exec(ctx context.Context, e ssh.Endpoint, cmd string, maxBytes int) (ssh.Result, error)
	Close()
}

type Instance struct {
	Name   string
	T      *Template
	params map[string]any
	conns  map[string]options
	fp     string

	Audit func(kind string, fields map[string]any)
	Print func(msg string)

	mu        sync.Mutex
	inv       *Inventory
	invValue  starlark.Value
	https     map[string]*httpConn
	sshName   string
	pool      sshExecutor
	rules     *ssh.Rules
	sudo      bool
	script    *script
	memo      map[string]*memoEntry
	loaded    map[string]*loadEntry
	loadedSrc []byte

	getenv    func(string) string
	readFile  func(string) ([]byte, error)
	now       func() time.Time
	transport http.RoundTripper
	creds     map[string]creds.Pair
}

func NewInstance(name string, t *Template, given map[string]any) (*Instance, error) {
	params, err := t.ResolveParams(given)
	if err != nil {
		return nil, fmt.Errorf("instance %s: %w", name, err)
	}
	in := &Instance{Name: name, T: t, params: params, conns: map[string]options{}, https: map[string]*httpConn{}, memo: map[string]*memoEntry{}, creds: map[string]creds.Pair{}, getenv: os.Getenv, readFile: os.ReadFile, now: time.Now}
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
	if in.sshName != "" {
		in.rules, err = ssh.CompileRules(t.SSHPaths)
		if err != nil {
			return nil, err
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

func (in *Instance) Prepare() error {
	for _, cn := range sortedKeys(in.https) {
		hc := in.https[cn]
		if hc.auth == nil {
			continue
		}
		if _, ok := in.creds[cn]; ok {
			continue
		}
		p, err := creds.Resolve(hc.auth.userEnv, hc.auth.passEnv, in.Name+" ("+hc.auth.label+")")
		if err != nil {
			return err
		}
		in.creds[cn] = p
	}
	return nil
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
	if json.Unmarshal(data, &inv) != nil || inv.Fingerprint != fp || time.Since(inv.DiscoveredAt) > ttl {
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
		kh = filepath.Join(stateDir(), "clotr", "known_hosts")
	}
	p, err := ssh.NewPool(ssh.Options{Proxy: px, KnownHosts: config.ExpandHome(kh), HostKey: ssh.HostKeyPolicy(o.str("host_key")), MaxConns: maxConns})
	if err != nil {
		return nil, err
	}
	in.pool = p
	return p, nil
}

func stateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state")
}

func (in *Instance) sshEndpoint(t *Target, h *Host) (ssh.Endpoint, error) {
	o := in.conns[in.sshName]
	pick := func(attr, opt string) string {
		if v := t.Attrs[attr]; v != "" {
			return v
		}
		return o.str(opt)
	}
	port, err := strconv.Atoi(defaultStr(pick("ssh_port", "port"), "22"))
	if err != nil {
		return ssh.Endpoint{}, fmt.Errorf("port SSH invalide")
	}
	host := h.Name
	if host == "" {
		host = h.IP
	}
	return ssh.Endpoint{Host: host, Port: port, User: pick("ssh_user", "user"), KeyPath: config.ExpandHome(pick("ssh_key_path", "key"))}, nil
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
	}
	if h := strings.TrimSpace(in.T.Hints); h != "" {
		for _, l := range strings.Split(h, "\n") {
			lines = append(lines, "  "+strings.TrimSpace(l))
		}
	}
	return append(lines, "  "+CommonHint)
}

const CommonHint = "Règle commune à tous les templates : rester factuel et ne jamais supposer le comportement, les valeurs par défaut ou la signification des messages des produits de cette plateforme ; en cas de doute, chercher dans la documentation officielle de l'éditeur (recherche web si elle est disponible), sinon le noter comme non vérifié."

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
