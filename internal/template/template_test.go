package template

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/testutil"
)

func TestDemoScriptTests(t *testing.T) {
	s, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Warnings) > 0 {
		t.Fatalf("testdata: %v", s.Warnings)
	}
	tpl, ok := s.Get("demo")
	if !ok {
		t.Fatal("template demo absent de testdata/")
	}
	var out bytes.Buffer
	passed, failed, err := RunTests(context.Background(), tpl, &out)
	if err != nil || failed != 0 || passed == 0 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
}

func writeTemplate(t *testing.T, yaml, star string) *Template {
	t.Helper()
	dir := t.TempDir()
	if star != "" {
		if err := os.WriteFile(filepath.Join(dir, "x.star"), []byte(star), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "x.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl, err := Parse([]byte(yaml), p)
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestValidation(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ok.star"), []byte("def f(a):\n    return 'x'\ntool(name='t', description='d', schema={'type':'object'}, fn=f)\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "bad.star"), []byte("def f(:\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "undef.star"), []byte("x = unknown_builtin()\n"), 0o600)
	base := "name: x\ntargets: [{kind: a}]\n"
	cases := map[string]string{
		base + "connectors: {c: {driver: ftp}}\n":                                             "inconnu",
		base + "connectors: {c: {driver: http, methods: [POST]}}\n":                           "exige une liste allow",
		base + "connectors: {c: {driver: http, verbs: [GET]}}\n":                              "option \"verbs\" inconnue",
		base + "connectors: {c: {driver: http, allow: [\"(\"]}}\n":                            "allow",
		base + "connectors: {c: {driver: http, auth: {token: x}}}\n":                          "auth.token",
		base + "script: bad.star\n":                                                           "bad.star",
		base + "script: undef.star\n":                                                         "unknown_builtin",
		base + "env: [\"A-B\"]\n":                                                             "env[0]",
		base + "tools: [{kind: ssh_list}]\n":                                                  "exige un connecteur de driver ssh",
		base + "tools: [{kind: nope}]\n":                                                      "inconnu",
		"name: x\n":                                                                           "targets ou script",
		base + "connectors: {a: {driver: ssh}, b: {driver: ssh}}\nssh_paths: {allow: [/x]}\n": "un seul connecteur ssh",
	}
	for y, want := range cases {
		if _, err := Parse([]byte(y), filepath.Join(dir, "x.yaml")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v (attendu %q)", y, err, want)
		}
	}
	tpl, err := Parse([]byte(base+"script: ok.star\ntools: [{kind: inventory, name: t}]\n"), filepath.Join(dir, "x.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), "deux fois") {
		t.Fatalf("doublon: %v", err)
	}
	tpl, _ = Parse([]byte(base+"companions: [zz]\ntools: [{kind: inventory}]\n"), filepath.Join(dir, "x.yaml"))
	if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), "companions") {
		t.Fatalf("companions: %v", err)
	}
	tpl, _ = Parse([]byte(base), filepath.Join(dir, "x.yaml"))
	if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), "aucun outil") {
		t.Fatalf("sans outil: %v", err)
	}
}

func TestScriptRuntimeGuards(t *testing.T) {
	tpl := writeTemplate(t, "name: x\nscript: x.star\nenv: [OK_VAR]\nfiles: [/nonexistent/ok]\n", `
def get_env(a):
    return env(a["name"])

def get_file(a):
    return file.read(a["path"])

def spin(a):
    n = 0
    while True:
        n += 1

def top_level_call():
    return http.request("c", "GET", "/")

tool(name = "get_env", description = "d", schema = {"type": "object"}, fn = get_env)
tool(name = "get_file", description = "d", schema = {"type": "object"}, fn = get_file)
tool(name = "spin", description = "d", schema = {"type": "object"}, fn = spin)
tool(name = "list_type", description = "d", schema = {"type": "object"}, fn = lambda a: [1, {"b": 2.5}])

def discover(ctx):
    return {"targets": [{"name": "a", "kind": "a"}]}
`)
	t.Setenv("OK_VAR", "v")
	t.Setenv("OTHER_VAR", "secret")
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	tools := map[string]func(string) (string, error){}
	for _, tl := range in.Tools() {
		tools[tl.Name()] = func(a string) (string, error) { return tl.Call(context.Background(), []byte(a)) }
	}
	if out, err := tools["i_get_env"](`{"name":"OK_VAR"}`); err != nil || out != "v" {
		t.Fatalf("env: %q %v", out, err)
	}
	if _, err := tools["i_get_env"](`{"name":"OTHER_VAR"}`); err == nil || !strings.Contains(err.Error(), "non déclarée") {
		t.Fatalf("env non déclarée: %v", err)
	}
	if _, err := tools["i_get_file"](`{"path":"/etc/passwd"}`); err == nil || !strings.Contains(err.Error(), "non déclaré") {
		t.Fatalf("fichier non déclaré: %v", err)
	}
	if out, err := tools["i_list_type"](`{}`); err != nil || out != `[1,{"b":2.5}]` {
		t.Fatalf("sortie JSON: %q %v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	for _, tl := range in.Tools() {
		if tl.Name() == "i_spin" {
			if _, err := tl.Call(ctx, []byte(`{}`)); err == nil {
				t.Fatal("spin: annulation attendue")
			}
		}
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("annulation trop lente: %s", time.Since(start))
	}
	old := maxScriptSteps
	maxScriptSteps = 10_000
	defer func() { maxScriptSteps = old }()
	if _, err := tools["i_spin"](`{}`); err == nil || !strings.Contains(err.Error(), "too many steps") {
		t.Fatalf("plafond de pas: %v", err)
	}
}

func TestSignVector(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	want := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	method, sig, err := sign(base64.StdEncoding.EncodeToString(seed), nil)
	if err != nil || method != "ed25519" || hex.EncodeToString(sig) != want {
		t.Fatalf("%s %x %v", method, sig, err)
	}
	if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil, sig) {
		t.Fatal("signature invalide")
	}
	if _, _, err := sign("pas une clé", nil); err == nil {
		t.Fatal("clé invalide acceptée")
	}
}

func TestRealHTTPSSHAndCache(t *testing.T) {
	dir := t.TempDir()
	client, clientPEM := testutil.NewSSHKey(t)
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, clientPEM, 0o600)
	hostKey, _ := testutil.NewSSHKey(t)
	sshSrv := testutil.StartSSHServer(t, client.PublicKey(), hostKey, func(cmd string) (string, int) {
		if strings.Contains(cmd, "tail -n 5") {
			return "ligne 1\nsecret: abc\n", 0
		}
		return "", 2
	})
	sshHost, sshPort, _ := net.SplitHostPort(sshSrv.Addr)
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "u" || p != "p" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		hits++
		mu.Unlock()
		switch r.URL.Path {
		case "/base/api/hosts":
			w.Write([]byte(`{"hosts":[{"name":"` + sshHost + `","n":12345678901}]}`))
		case "/base/api/big":
			w.Write(bytes.Repeat([]byte("x"), 2048))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tpl := writeTemplate(t, `name: x
script: x.star
params:
  url: {type: url, required: true}
  key: {type: path}
  port: {type: int}
connectors:
  api:
    driver: http
    base_url: "{{.url}}/base"
    auth: {user_env: T_U, password_env: T_P, label: api}
    max_bytes: 1024
  ssh:
    driver: ssh
    user: demo
    key: "{{.key}}"
    port: "{{.port}}"
tools:
  - kind: ssh_tail
  - kind: inventory
ssh_paths: {allow: [/var/log/**]}
`, `
def discover(ctx):
    r = http.request("api", "GET", "/api/hosts", jq = ".hosts")
    hosts = r.data[0]
    return {"targets": [{"name": "t1", "kind": "k", "summary": "n=%d" % hosts[0]["n"], "hosts": [{"name": h["name"]} for h in hosts]}]}

def big(a):
    return http.request("api", "GET", "/api/big").body

tool(name = "big", description = "d", schema = {"type": "object"}, fn = big)
`)
	t.Setenv("T_U", "u")
	t.Setenv("T_P", "p")
	t.Setenv("XDG_STATE_HOME", dir)
	port, _ := strconv.Atoi(sshPort)
	newInst := func() *Instance {
		in, err := NewInstance("i", tpl, map[string]any{"url": srv.URL, "key": keyPath, "port": port})
		if err != nil {
			t.Fatal(err)
		}
		if err := in.Prepare(); err != nil {
			t.Fatal(err)
		}
		return in
	}
	in := newInst()
	audit := map[string]int{}
	in.Audit = func(kind string, f map[string]any) { audit[kind]++ }
	cache := filepath.Join(dir, "cache")
	if err := in.Discover(context.Background(), cache, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if got := in.Inventory().Targets[0].Summary; got != "n=12345678901" {
		t.Fatalf("summary: %q", got)
	}
	var out string
	var err error
	for _, tl := range in.Tools() {
		switch tl.Name() {
		case "i_ssh_tail":
			out, err = tl.Call(context.Background(), []byte(`{"host":"`+sshHost+`","path":"/var/log/a.log","lines":5}`))
		case "i_big":
			if _, berr := tl.Call(context.Background(), []byte(`{}`)); berr == nil || !strings.Contains(berr.Error(), "réponse de plus de") {
				t.Errorf("max_bytes: %v", berr)
			}
		}
	}
	if err != nil || !strings.Contains(out, "ligne 1") || strings.Contains(out, "abc") {
		t.Fatalf("ssh_tail: %q %v", out, err)
	}
	if audit["http_call"] < 2 || audit["remote_exec"] != 1 {
		t.Fatalf("audit: %v", audit)
	}
	in.Close()
	before := hits
	in2 := newInst()
	if err := in2.Discover(context.Background(), cache, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if hits != before || in2.Inventory().Targets[0].Summary != "n=12345678901" {
		t.Fatalf("cache non utilisé: %d→%d", before, hits)
	}
	t.Setenv("T_P", "bad")
	in3, _ := NewInstance("i", tpl, map[string]any{"url": srv.URL, "key": keyPath, "port": port})
	in3.Prepare()
	if err := in3.Discover(context.Background(), "", 0, true); err == nil {
		t.Fatal("401 attendu en erreur de discover")
	}
}

func TestParamsAndForeach(t *testing.T) {
	tpl := writeTemplate(t, `name: x
params:
  url: {type: url, required: true}
  user_env: {type: env, default: X_USER}
  key: {type: path}
  port: {type: int, default: 443}
  login: {type: string, default: admin}
  groups:
    type: list
    item: {name: string, url: url, login: string}
targets:
  - kind: main
    url: "{{.url}}"
  - kind: group
    foreach: groups
    name: "{{.name}}"
    url: "{{.url}}"
    port: "{{.port}}"
    login: "{{.login}}"
    key: "{{.key}}"
tools: [{kind: inventory}]
`, "")
	if _, err := tpl.ResolveParams(map[string]any{}); err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("paramètre requis manquant accepté: %v", err)
	}
	if _, err := tpl.ResolveParams(map[string]any{"url": "https://x", "typo": 1}); err == nil {
		t.Fatal("paramètre inconnu accepté")
	}
	if _, err := tpl.ResolveParams(map[string]any{"url": "https://x", "user_env": "not a var"}); err == nil {
		t.Fatal("env invalide accepté")
	}
	in, err := NewInstance("prod", tpl, map[string]any{
		"url": "https://gw/main",
		"key": "~/.ssh/k",
		"groups": []any{
			map[string]any{"name": "g1", "url": "https://gw/g1"},
			map[string]any{"name": "g2", "url": "https://gw/g2", "login": "other"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := in.buildTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 || ts[0].Name != "main" || ts[1].Name != "g1" || ts[2].Name != "g2" {
		t.Fatalf("cibles: %+v", ts)
	}
	home, _ := os.UserHomeDir()
	if ts[1].Attrs["login"] != "admin" || ts[2].Attrs["login"] != "other" || ts[1].Attrs["key"] != home+"/.ssh/k" || ts[1].Attrs["port"] != "443" {
		t.Fatalf("héritage des attributs: %+v %+v", ts[1].Attrs, ts[2].Attrs)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil || len(in.Inventory().Targets) != 3 {
		t.Fatalf("découverte statique: %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("name: dup\ntargets: [{kind: a}]\ntools: [{kind: inventory}]\n")
	os.WriteFile(filepath.Join(dir, "a.yaml"), raw, 0o600)
	os.WriteFile(filepath.Join(dir, "b.yaml"), raw, 0o600)
	os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("name: [x"), 0o600)
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, ok := s.Get("dup")
	if !ok || tpl.Source != filepath.Join(dir, "a.yaml") || len(s.All()) != 1 {
		t.Fatalf("chargement: %+v", s.All())
	}
	if len(s.Warnings) != 2 {
		t.Fatalf("avertissements (doublon + invalide): %v", s.Warnings)
	}
	missing, err := Load(filepath.Join(dir, "absent"))
	if err != nil || len(missing.All()) != 0 || len(missing.Warnings) != 1 {
		t.Fatalf("répertoire absent: %+v %v", missing, err)
	}
}

func TestFindHostShortNames(t *testing.T) {
	in := &Instance{Name: "prod", inv: &Inventory{Targets: []*Target{
		{Name: "g1", Kind: "group", Hosts: []*Host{{Name: "g1-node0.example.test", IP: "10.0.0.1"}, {Name: "g1-node1.example.test"}}},
		{Name: "g2", Kind: "group", Hosts: []*Host{{Name: "g2-node0.example.test"}}},
	}}}
	if _, h, err := in.findHost("g1", "node0"); err != nil || h.Name != "g1-node0.example.test" {
		t.Fatalf("suffixe: %v %v", h, err)
	}
	if _, _, err := in.findHost("", "node0"); err == nil || !strings.Contains(err.Error(), "ambigu") {
		t.Fatalf("ambiguïté non signalée: %v", err)
	}
	if tg, _, err := in.findHost("", "g2-node0"); err != nil || tg.Name != "g2" {
		t.Fatalf("nom court: %v %v", tg, err)
	}
	if _, _, err := in.findHost("", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := in.findHost("", "ode0"); err == nil {
		t.Fatal("suffixe partiel accepté")
	}
}
