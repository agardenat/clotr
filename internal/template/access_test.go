package template

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/driver/ssh"
)

type execSSH struct {
	mu   sync.Mutex
	cmds []string
}

func (r *execSSH) ExecInput(_ context.Context, _ ssh.Endpoint, cmd, _ string, _ int) (ssh.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = append(r.cmds, cmd)
	return ssh.Result{Stdout: "PHP 8.3.1\n"}, nil
}

func (r *execSSH) Close() {}

func toolMap(in *Instance) map[string]func(string) (string, error) {
	out := map[string]func(string) (string, error){}
	for _, tl := range in.Tools() {
		out[tl.Name()] = func(a string) (string, error) { return tl.Call(context.Background(), json.RawMessage(a)) }
	}
	return out
}

func TestAccessLevelTools(t *testing.T) {
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  ssh: {driver: ssh, user: ops}
tools:
  - kind: ssh_read
  - kind: ssh_exec
ssh_paths: {allow: [/var/log/**]}
`, `
tool(name = "r", description = "d", schema = {"type": "object"}, fn = lambda a: "r")
tool(name = "e", description = "d", schema = {"type": "object"}, fn = lambda a: "e", access = "exec")
tool(name = "c", description = "d", schema = {"type": "object"}, fn = lambda a: "c", access = "create")
`)
	want := map[access.Level][]string{
		access.Read:   {"i_r", "i_ssh_read"},
		access.Exec:   {"i_e", "i_r", "i_ssh_exec", "i_ssh_read"},
		access.Create: {"i_c", "i_e", "i_r", "i_ssh_exec", "i_ssh_read"},
	}
	for lvl, names := range want {
		in, err := NewInstance("i", tpl, nil)
		if err != nil {
			t.Fatal(err)
		}
		in.SetAccess(lvl)
		var got []string
		for _, tl := range in.Tools() {
			got = append(got, tl.Name())
		}
		slices.Sort(got)
		if !slices.Equal(got, names) || !slices.Equal(sorted(in.ToolNames()), names) {
			t.Fatalf("%s: %v / %v, attendu %v", lvl, got, in.ToolNames(), names)
		}
	}
	bad := "name: x\ntargets: [{kind: a}]\ncommands: {allow: [\"**\"]}\n"
	if _, err := Parse([]byte(bad), "bad.yaml"); err == nil || !strings.Contains(err.Error(), "commands") {
		t.Fatalf("commands invalide accepté: %v", err)
	}
	if err := writeAndParseErr(t, "name: x\nscript: x.star\n", "tool(name = 'z', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1, access = 'root')\n"); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("niveau inconnu accepté: %v", err)
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

func writeAndParseErr(t *testing.T, yaml, star string) error {
	t.Helper()
	tpl := writeTemplate(t, yaml, star)
	_, err := NewInstance("i", tpl, nil)
	return err
}

func TestSSHExec(t *testing.T) {
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  ssh: {driver: ssh, user: ops, sudo: true}
tools:
  - kind: ssh_exec
ssh_paths: {allow: [/var/log/**]}
commands:
  allow: ["php -v"]
  deny: ["rm **"]
`, `
def discover(ctx):
    return {"targets": [{"name": "t", "kind": "hosts", "hosts": [{"name": "web1", "ip": "10.0.0.7"}]}]}

def run(a):
    return ssh.exec(host = "web1", argv = a["argv"]).stdout

tool(name = "run", description = "d", schema = {"type": "object"}, fn = run)
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.ExtendCommands(access.Rules{Allow: []string{"openssl version"}}); err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	rec := &execSSH{}
	in.pool = rec
	var audits []map[string]any
	in.Audit = func(kind string, f map[string]any) {
		if kind == "exec_decision" {
			audits = append(audits, f)
		}
	}
	if _, err := toolMap(in)["i_run"](`{"argv":["php","-v"]}`); err == nil || !strings.Contains(err.Error(), "--access exec") {
		t.Fatalf("read: exec accepté: %v", err)
	}
	in.SetAccess(access.Exec)
	tools := toolMap(in)
	out, err := tools["i_ssh_exec"](`{"host":"web1","argv":["php","-v"]}`)
	if err != nil || !strings.Contains(out, "PHP 8.3.1") || !strings.Contains(out, "[exit 0]") {
		t.Fatalf("php -v: %q %v", out, err)
	}
	if got := rec.cmds[0]; got != "exec 'php' '-v' </dev/null" {
		t.Fatalf("commande sans sudo attendue: %q", got)
	}
	if _, err := tools["i_run"](`{"argv":["openssl","version"]}`); err != nil {
		t.Fatalf("commande de l'instance: %v", err)
	}
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["rm","-rf","/"]}`); err == nil || !strings.Contains(err.Error(), "commands.deny") {
		t.Fatalf("deny: %v", err)
	}
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["sh","-c","rpm -qa | grep -i php"]}`); err != nil {
		t.Fatalf("lecture seule: %v", err)
	}
	in.Trusted = func() []string { return []string{"apachectl  -t -D DUMP_MODULES"} }
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["apachectl","-t","-D","DUMP_MODULES"]}`); err != nil {
		t.Fatalf("commande de confiance: %v", err)
	}
	in.Trusted = nil
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["touch","/tmp/x"]}`); err == nil || !strings.Contains(err.Error(), "no terminal") && !strings.Contains(err.Error(), "pas de terminal") {
		t.Fatalf("sans confirmation: %v", err)
	}
	var questions []string
	answer := access.No
	in.Confirm = func(_ context.Context, q string) (access.Answer, error) {
		questions = append(questions, q)
		return answer, nil
	}
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["touch","/tmp/x"]}`); err == nil {
		t.Fatal("refus de l'utilisateur ignoré")
	}
	answer = access.Always
	for range 2 {
		if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["touch","/tmp/x"]}`); err != nil {
			t.Fatal(err)
		}
	}
	if len(questions) != 2 || !strings.Contains(questions[1], "web1") || !strings.Contains(questions[1], "touch") {
		t.Fatalf("questions: %q", questions)
	}
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["touch","/tmp/y"]}`); err != nil || len(questions) != 3 {
		t.Fatalf("toujours limité à l'argv exact: %v %d", err, len(questions))
	}
	if _, err := tools["i_ssh_exec"](`{"host":"web1","argv":["sh","-c","id\nreboot"]}`); err == nil {
		t.Fatal("caractère de contrôle accepté")
	}
	var decisions []string
	for _, a := range audits {
		decisions = append(decisions, fmt.Sprint(a["decision"]))
	}
	if strings.Join(decisions, ",") != "allowed,allowed,denied,readonly,trusted,refused,refused,always,always,always" {
		t.Fatalf("audit: %v", decisions)
	}
	if n := len(rec.cmds); n != 7 {
		t.Fatalf("%d commandes exécutées: %q", n, rec.cmds)
	}
}

func TestHTTPCreateTracked(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	objects := map[string]bool{"/v1/things/theirs": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method {
		case http.MethodPost:
			var body struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			p := "/v1/things/" + body.Name
			if objects[p] {
				w.WriteHeader(http.StatusConflict)
				return
			}
			objects[p] = true
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			if !objects[r.URL.Path] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(objects, r.URL.Path)
		}
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  api:
    driver: http
    base_url: `+srv.URL+`
    allow: ["^/v1/things(/[^/]+)?$"]
    deny: ["/secret"]
    levels:
      create:
        methods: [POST, DELETE]
        allow: ["^/v1/things(/[^/]+)?$", "^/v1/secret$"]
`, `
def create(a):
    return http.request("api", "POST", "/v1/things", json = {"name": a["name"]}, track = a.get("track", "")).status

def remove(a):
    return http.request("api", "DELETE", "/v1/things/" + a["name"]).status

tool(name = "create", description = "d", schema = {"type": "object"}, fn = create, access = "create")
tool(name = "remove", description = "d", schema = {"type": "object"}, fn = remove, access = "create")
tool(name = "post_secret", description = "d", schema = {"type": "object"}, fn = lambda a: http.request("api", "POST", "/v1/secret", track = "/v1/secret").status, access = "create")
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.SetAccess(access.Create)
	var cleanups int
	in.Audit = func(kind string, _ map[string]any) {
		if kind == "cleanup" {
			cleanups++
		}
	}
	tools := toolMap(in)
	if _, err := tools["i_create"](`{"name":"a"}`); err == nil || !strings.Contains(err.Error(), "track") {
		t.Fatalf("POST sans track: %v", err)
	}
	if _, err := tools["i_create"](`{"name":"a","track":"/v1/other/a"}`); err == nil {
		t.Fatal("track hors allow accepté")
	}
	if _, err := tools["i_create"](`{"name":"a","track":"/v1/things"}`); err == nil || !strings.Contains(err.Error(), "under the POST path") {
		t.Fatalf("track hors du chemin du POST: %v", err)
	}
	if out, err := tools["i_create"](`{"name":"a","track":"/v1/things/a"}`); err != nil || out != "201" {
		t.Fatalf("création: %q %v", out, err)
	}
	if out, err := tools["i_create"](`{"name":"theirs","track":"/v1/things/theirs"}`); err != nil || out != "409" {
		t.Fatalf("conflit: %q %v", out, err)
	}
	if got := in.Tracked(); !slices.Equal(got, []string{"api /v1/things/a"}) {
		t.Fatalf("suivi: %v", got)
	}
	if _, err := tools["i_remove"](`{"name":"theirs"}`); err == nil || !strings.Contains(err.Error(), "clotr") {
		t.Fatalf("DELETE d'un objet non créé par clotr: %v", err)
	}
	if _, err := tools["i_post_secret"](`{}`); err == nil || !strings.Contains(err.Error(), "deny") {
		t.Fatalf("deny absolu: %v", err)
	}
	if _, err := tools["i_create"](`{"name":"b","track":"/v1/things/b"}`); err != nil {
		t.Fatal(err)
	}
	if out, err := tools["i_remove"](`{"name":"a"}`); err != nil || out != "200" {
		t.Fatalf("suppression: %q %v", out, err)
	}
	if got := in.Tracked(); !slices.Equal(got, []string{"api /v1/things/b"}) {
		t.Fatalf("suivi après suppression: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := in.Cleanup(context.WithoutCancel(ctx))
	if len(res) != 1 || res[0].Err != nil || len(in.Tracked()) != 0 || cleanups != 1 {
		t.Fatalf("nettoyage: %+v %v", res, in.Tracked())
	}
	mu.Lock()
	defer mu.Unlock()
	if !objects["/v1/things/theirs"] || objects["/v1/things/a"] || objects["/v1/things/b"] {
		t.Fatalf("objets: %v", objects)
	}
	in.SetAccess(access.Exec)
	if _, ok := toolMap(in)["i_create"]; ok {
		t.Fatal("outil create exposé en exec")
	}
	if _, err := in.checkHTTP(context.Background(), in.https["api"], http.MethodPost, "/v1/things", "/v1/things/c"); err == nil || !strings.Contains(err.Error(), "--access create") {
		t.Fatalf("POST en exec: %v", err)
	}
}

func TestHTTPStream(t *testing.T) {
	type seen struct {
		query    string
		protocol string
		closed   bool
	}
	got := make(chan seen, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade attendu", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: v5.channel.example\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = encodeFrame(rw, wsPing, []byte("p"), false)
		_ = encodeFrame(rw, wsBinary, []byte("\x01PHP 8.3.1\n"), false)
		head := []byte{wsBinary, 3, '\x02', 'w', 'a'}
		_, _ = rw.Write(head)
		_ = encodeFrame(rw, wsContinuation, []byte("rn"), false)
		_ = encodeFrame(rw, wsClose, []byte{0x03, 0xE8}, false)
		_ = rw.Flush()
		br := bufio.NewReader(rw)
		s := seen{query: r.URL.RawQuery, protocol: r.Header.Get("Sec-WebSocket-Protocol")}
		for {
			_, op, _, err := readFrame(br, 1<<20)
			if err != nil {
				break
			}
			if op == wsClose {
				s.closed = true
				break
			}
		}
		got <- s
	}))
	defer srv.Close()
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  api:
    driver: http
    base_url: `+srv.URL+`
    allow: ["^/v1/.*$"]
    deny: ["/attach$"]
    levels:
      exec:
        allow: ["^/v1/boxes/[^/]+/exec$", "^/v1/boxes/[^/]+/attach$"]
        argv_param: command
`, `
def run(a):
    r = http.stream("api", "/v1/boxes/" + a["box"] + "/exec", argv = a["argv"], query = {"stdout": "true"}, protocols = ["v5.channel.example"], label = "box " + a["box"])
    out = []
    for m in r.messages:
        out.append(str(list(m.elems())[0]) + ":" + str(m[1:]))
    return {"protocol": r.protocol, "out": out, "close": r.close_code}

tool(name = "run", description = "d", schema = {"type": "object"}, fn = run, access = "exec")
tool(name = "attach", description = "d", schema = {"type": "object"}, fn = lambda a: http.stream("api", "/v1/boxes/b/attach", argv = ["sh"]).status, access = "exec")
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.SetAccess(access.Exec)
	if err := in.ExtendCommands(access.Rules{Allow: []string{"php -v"}}); err != nil {
		t.Fatal(err)
	}
	tools := toolMap(in)
	out, err := tools["i_run"](`{"box":"b1","argv":["php","-v"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"close":1000,"out":["1:PHP 8.3.1\n","2:warn"],"protocol":"v5.channel.example"}` {
		t.Fatalf("sortie: %s", out)
	}
	s := <-got
	if s.query != "command=php&command=-v&stdout=true" || s.protocol != "v5.channel.example" || !s.closed {
		t.Fatalf("serveur: %+v", s)
	}
	if _, err := tools["i_run"](`{"box":"b1","argv":["sh","-c","touch /tmp/x"]}`); err == nil || !strings.Contains(err.Error(), "touch /tmp/x") {
		t.Fatalf("commande hors liste sans terminal: %v", err)
	}
	if _, err := tools["i_attach"](`{}`); err == nil || !strings.Contains(err.Error(), "deny") {
		t.Fatalf("deny absolu: %v", err)
	}
	in.SetAccess(access.Read)
	if _, err := in.call(context.Background(), "run", in.script.tools[0].fn, mustDict(t, `{"box":"b1","argv":["php","-v"]}`)); err == nil || !strings.Contains(scriptErr(err).Error(), "--access exec") {
		t.Fatalf("stream en read: %v", err)
	}
}

func mustDict(t *testing.T, s string) *starlark.Dict {
	t.Helper()
	v, err := jsonToStarlark([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*starlark.Dict)
}

func TestSleep(t *testing.T) {
	tpl := writeTemplate(t, "name: x\nscript: x.star\n", `
tool(name = "nap", description = "d", schema = {"type": "object"}, fn = lambda a: sleep(a["s"]))
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	nap := in.Tools()[0]
	if _, err := nap.Call(context.Background(), json.RawMessage(`{"s":0.01}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := nap.Call(context.Background(), json.RawMessage(`{"s":-1}`)); err == nil {
		t.Fatal("durée négative acceptée")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := nap.Call(ctx, json.RawMessage(`{"s":30}`)); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("sleep non annulé: %v %s", err, time.Since(start))
	}
	if err := writeAndParseErr(t, "name: x\nscript: x.star\n", "sleep(1)\ntool(name = 'z', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1)\n"); err == nil {
		t.Fatal("sleep au chargement accepté")
	}
}

func TestEscalation(t *testing.T) {
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  ssh: {driver: ssh, user: ops}
tools:
  - kind: ssh_exec
ssh_paths: {allow: [/var/log/**]}
commands:
  allow: ["php -v"]
`, `
def discover(ctx):
    return {"targets": [{"name": "t", "kind": "hosts", "hosts": [{"name": "web1", "ip": "10.0.0.7"}]}]}

tool(name = "sneaky", description = "d", schema = {"type": "object"}, fn = lambda a: ssh.exec(host = "web1", argv = ["php", "-v"]).stdout)
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	rec := &execSSH{}
	in.pool = rec
	if _, ok := toolMap(in)["i_ssh_exec"]; ok {
		t.Fatal("outil exec exposé en read sans plafond")
	}
	in.SetCeiling(access.Create)
	var gated string
	for _, tl := range in.Tools() {
		if tl.Name() == "i_ssh_exec" {
			gated = tl.Description()
		}
	}
	if !strings.Contains(gated, "Soumis à l'autorisation") || !strings.Contains(strings.Join(in.EnvironmentLines(), "\n"), "i_ssh_exec") {
		t.Fatalf("outil soumis à autorisation non signalé: %q", gated)
	}
	call := `{"host":"web1","argv":["php","-v"]}`
	if _, err := toolMap(in)["i_ssh_exec"](call); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("sans confirmation: %v", err)
	}
	answer := access.No
	var asked []string
	in.Confirm = func(_ context.Context, q string) (access.Answer, error) {
		asked = append(asked, q)
		return answer, nil
	}
	if _, err := toolMap(in)["i_ssh_exec"](call); err == nil || !strings.Contains(err.Error(), "refused by the user") {
		t.Fatalf("refus: %v", err)
	}
	answer = access.Once
	if _, err := toolMap(in)["i_ssh_exec"](call); err != nil {
		t.Fatal(err)
	}
	if in.Access() != access.Read || len(rec.cmds) != 1 || !strings.Contains(asked[1], "i_ssh_exec") || !strings.Contains(asked[1], "php") {
		t.Fatalf("une fois: %v %d %q", in.Access(), len(rec.cmds), asked)
	}
	if _, err := toolMap(in)["i_sneaky"](`{}`); err == nil || !strings.Contains(err.Error(), "--access exec") {
		t.Fatalf("primitive exec depuis un outil de lecture: %v", err)
	}
	answer = access.Always
	if _, err := toolMap(in)["i_ssh_exec"](call); err != nil {
		t.Fatal(err)
	}
	n := len(asked)
	if _, err := toolMap(in)["i_ssh_exec"](call); err != nil || len(asked) != n || in.Access() != access.Exec {
		t.Fatalf("toujours: %v %d/%d %v", err, len(asked), n, in.Access())
	}
	if len(rec.cmds) != 3 {
		t.Fatalf("%d commandes exécutées", len(rec.cmds))
	}
}

func TestLocalDriver(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh requis")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"), []byte("version=1.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.key"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  shell: {driver: local, max_conns: 2}
tools:
  - kind: ssh_read
  - kind: ssh_exec
ssh_paths:
  allow: ["`+dir+`/**"]
  deny: ["**/*.key"]
`, `
def discover(ctx):
    return {"targets": [{"name": "poste", "kind": "hosts", "hosts": [{"name": "localhost"}]}]}
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	var execs []map[string]any
	in.Audit = func(kind string, f map[string]any) {
		if kind == "remote_exec" {
			execs = append(execs, f)
		}
	}
	tools := toolMap(in)
	if _, ok := tools["i_ssh_exec"]; ok {
		t.Fatal("ssh_exec proposé en read")
	}
	out, err := tools["i_ssh_read"](`{"host":"localhost","path":"` + dir + `/app.conf"}`)
	if err != nil || !strings.Contains(out, "version=1.2") {
		t.Fatalf("lecture locale: %q %v", out, err)
	}
	if _, err := tools["i_ssh_read"](`{"host":"localhost","path":"` + dir + `/app.key"}`); err == nil {
		t.Fatal("deny ignoré")
	}
	in.SetAccess(access.Exec)
	out, err = toolMap(in)["i_ssh_exec"](`{"host":"localhost","argv":["cat","` + dir + `/app.conf"]}`)
	if err != nil || !strings.Contains(out, "version=1.2") || !strings.Contains(out, "[exit 0]") {
		t.Fatalf("exec local: %q %v", out, err)
	}
	if len(execs) != 2 || execs[1]["host"] != "localhost" {
		t.Fatalf("audit: %v", execs)
	}
	for _, bad := range []string{"connectors:\n  shell: {driver: local, sudo: true}\n", "connectors:\n  shell: {driver: local}\n  ssh: {driver: ssh}\n"} {
		if _, err := Parse([]byte("name: x\ntargets: [{name: a, kind: hosts}]\n"+bad+"ssh_paths: {allow: [/etc/**]}\n"), "x.yaml"); err == nil || !strings.Contains(err.Error(), "local") {
			t.Fatalf("%s : %v", bad, err)
		}
	}
}

func TestShellDriver(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pty requis")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"), []byte("version=1.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gw := filepath.Join(dir, "gw.sh")
	if err := os.WriteFile(gw, []byte("#!/bin/sh\necho \"Connexion à $1\"\nPS1='$ ' exec sh -i\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	tpl := writeTemplate(t, `name: x
script: x.star
connectors:
  shell: {driver: shell, command: ["`+gw+`", "%h"], max_conns: 2, open_timeout: 20}
tools:
  - kind: ssh_read
ssh_paths:
  allow: ["`+dir+`/**"]
`, `
def discover(ctx):
    return {"targets": [{"name": "vms", "kind": "hosts", "hosts": [{"name": "vm1"}]}]}
`)
	in, err := NewInstance("i", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	out, err := toolMap(in)["i_ssh_read"](`{"host":"vm1","path":"` + dir + `/app.conf"}`)
	if err != nil || !strings.Contains(out, "version=1.2") {
		t.Fatalf("lecture : %q %v", out, err)
	}
	for _, bad := range []string{"connectors:\n  s: {driver: shell}\n", "connectors:\n  s: {driver: shell, command: [x], user: u}\n", "connectors:\n  s: {driver: shell, command: [x]}\n  ssh: {driver: ssh}\n"} {
		if _, err := Parse([]byte("name: x\ntargets: [{name: a, kind: hosts}]\n"+bad+"ssh_paths: {allow: [/etc/**]}\n"), "x.yaml"); err == nil || !strings.Contains(err.Error(), "connectors") {
			t.Fatalf("%s : %v", bad, err)
		}
	}
}
