package watch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/progress"
)

type localHost struct{ l *ssh.Local }

func (localHost) Name() string { return "h1" }

func (h localHost) Run(ctx context.Context, _ string, cmd func(ssh.Builder) string, maxBytes int) (ssh.Result, error) {
	return h.l.ExecInput(ctx, ssh.Endpoint{}, cmd(ssh.Builder{}), "", maxBytes)
}

type fakeInstance struct {
	root string
	mu   sync.Mutex
	logs []string
	down bool
}

func (f *fakeInstance) Host(_, host string) (Host, error) {
	if host != "h1" {
		return nil, errors.New("hôte inconnu")
	}
	return localHost{ssh.NewLocal(4)}, nil
}

func (f *fakeInstance) Path(p string) (string, error) {
	if !strings.HasPrefix(p, f.root) {
		return "", errors.New("hors de ssh_paths.allow")
	}
	return p, nil
}

func (f *fakeInstance) Follow(_ context.Context, tool string, _, cursor json.RawMessage) ([]string, json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tool != "vm_logs" {
		return nil, nil, errors.New("outil sans suivi")
	}
	if f.down {
		return nil, nil, errors.New("api injoignable")
	}
	n := 0
	if len(cursor) > 0 && string(cursor) != "null" {
		_ = json.Unmarshal(cursor, &n)
	} else {
		n = len(f.logs)
	}
	next, _ := json.Marshal(len(f.logs))
	return append([]string(nil), f.logs[n:]...), next, nil
}

func (f *fakeInstance) log(l string) {
	f.mu.Lock()
	f.logs = append(f.logs, l)
	f.mu.Unlock()
}

type sink struct {
	mu sync.Mutex
	ev []progress.Event
}

func (s *sink) Emit(e progress.Event) {
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
}

func (s *sink) kind(k string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.ev {
		if e.Kind == k {
			out = append(out, e.Detail)
		}
	}
	return out
}

func newStore(t *testing.T) (*Store, *fakeInstance, *evidence.Store, *sink) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sh requis")
	}
	dir := t.TempDir()
	inst := &fakeInstance{root: dir}
	ev := evidence.Open(filepath.Join(dir, "evidence"), 1)
	s := New(func(name string) (Instance, bool) { return inst, name == "vm" }, ev, audit.Nop())
	s.Interval = 20 * time.Millisecond
	s.Dir = filepath.Join(dir, "watch")
	s.Scope([]string{"vm_logs", "k8s_logs"}, func(name string) bool { return name == "vm" })
	ek := &sink{}
	s.Events = ek
	return s, inst, ev, ek
}

func call(t *testing.T, s *Store, args string) (string, error) {
	t.Helper()
	return s.Tool().Call(context.Background(), json.RawMessage(args))
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 200 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition non atteinte")
}

func TestCaptureFileWithRotation(t *testing.T) {
	s, inst, ev, ek := newStore(t)
	log := filepath.Join(inst.root, "app.log")
	if err := os.WriteFile(log, []byte("ancienne ligne ERROR avant l'attente\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := call(t, s, `{"kind":"file","instance":"vm","host":"h1","path":"`+log+`","filter":"ERROR","why":"journal applicatif"}`)
	if err != nil || !strings.Contains(out, "w1") {
		t.Fatalf("%s %v", out, err)
	}
	if out, _ := call(t, s, `{"kind":"file","instance":"vm","host":"h1","path":"`+log+`","why":"doublon"}`); !strings.Contains(out, "déjà déclarée") {
		t.Fatalf("doublon : %s", out)
	}
	var sum Summary
	done := make(chan struct{})
	go func() {
		sum = s.Capture(context.Background(), 0)
		close(done)
	}()
	waitFor(t, s.Waiting)
	appendTo(t, log, "connexion 10.0.0.5 ERROR Kerberos\npartielle")
	waitFor(t, func() bool { return len(ek.kind("captured")) == 1 })
	appendTo(t, log, " fin\n")
	waitFor(t, func() bool { return strings.Contains(strings.Join(ek.kind("stream"), "\n"), "2 lines") })
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte("nouveau fichier ERROR 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(ek.kind("captured")) >= 2 })
	s.Stop()
	<-done
	if sum.Reason != "stopped" || len(sum.Sources) != 1 {
		t.Fatalf("%+v", sum)
	}
	c := sum.Sources[0]
	it, ok := ev.Item(c.Evidence)
	if !ok {
		t.Fatalf("preuve %s absente", c.Evidence)
	}
	data, _ := os.ReadFile(it.File)
	text := string(data)
	for _, want := range []string{"connexion 10.0.0.5 ERROR Kerberos", "partielle fin", "fichier remplacé ou tronqué", "nouveau fichier ERROR 2", "# rôle : journal applicatif"} {
		if !strings.Contains(text, want) {
			t.Errorf("preuve sans %q :\n%s", want, text)
		}
	}
	if strings.Contains(text, "avant l'attente") {
		t.Errorf("ligne antérieure à l'attente capturée :\n%s", text)
	}
	if c.Lines != 3 || c.Matched != 2 {
		t.Errorf("décomptes %+v", c)
	}
	live, _ := os.ReadFile(filepath.Join(s.Dir, "w1.log"))
	if !strings.Contains(string(live), "nouveau fichier ERROR 2") {
		t.Errorf("fichier en direct : %s", live)
	}
	if _, err := call(t, s, `{"kind":"file","instance":"vm","host":"h1","path":"`+log+`","why":"x"}`); err != nil {
		t.Errorf("déclaration après capture : %v", err)
	}
}

func TestCaptureToolAndProbe(t *testing.T) {
	s, inst, _, ek := newStore(t)
	inst.log("avant")
	if _, err := call(t, s, `{"kind":"tool","instance":"vm","tool":"k8s_logs","why":"pod"}`); err == nil {
		t.Fatal("outil d'une autre instance accepté")
	}
	if _, err := call(t, s, `{"kind":"tool","instance":"vm","tool":"vm_logs","args":{"pod":"a"},"filter":"Error","why":"pod"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, s, `{"kind":"sample","instance":"vm","host":"h1","probe":"gpu","why":"x"}`); err == nil {
		t.Fatal("sonde inconnue acceptée")
	}
	done := make(chan Summary)
	go func() { done <- s.Capture(context.Background(), 2*time.Second) }()
	waitFor(t, s.Waiting)
	inst.log("ligne 1\nError: refus")
	waitFor(t, func() bool { return len(ek.kind("captured")) == 1 })
	inst.mu.Lock()
	inst.down = true
	inst.mu.Unlock()
	waitFor(t, func() bool { return len(ek.kind("retry")) == 1 })
	inst.mu.Lock()
	inst.down = false
	inst.mu.Unlock()
	inst.log("Error après coupure")
	waitFor(t, func() bool { return len(ek.kind("captured")) == 2 })
	s.Stop()
	sum := <-done
	c := sum.Sources[0]
	if c.Lines != 3 || c.Matched != 2 || len(c.Errors) != 1 || !strings.Contains(c.Errors[0], "api injoignable") {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(strings.Join(ek.kind("captured"), "\n"), "avant") {
		t.Fatal("ligne antérieure affichée")
	}
}

func TestSourceValidation(t *testing.T) {
	s, inst, _, _ := newStore(t)
	cases := map[string]string{
		`{"kind":"file","instance":"autre","host":"h1","path":"/x","why":"x"}`:                            "inconnue",
		`{"kind":"file","instance":"vm","host":"h1","path":"/etc/shadow","why":"x"}`:                      "ssh_paths",
		`{"kind":"file","instance":"vm","host":"h1","path":"` + inst.root + `/absent.log","why":"x"}`:     "exit",
		`{"kind":"file","instance":"vm","host":"h1","path":"` + inst.root + `/a.gz","why":"x"}`:           "compressé",
		`{"kind":"journal","instance":"vm","host":"h1","unit":"a;reboot","why":"x"}`:                      "unit",
		`{"kind":"file","instance":"vm","host":"h1","path":"` + inst.root + `/a","filter":"(","why":"x"}`: "filter",
		`{"kind":"tool","instance":"vm","tool":"vm_exec","why":"x"}`:                                      "sans suivi",
		`{"kind":"autre","instance":"vm","why":"x"}`:                                                      "kind",
	}
	for args, want := range cases {
		if _, err := call(t, s, args); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s : %v (attendu %q)", args, err, want)
		}
	}
	if sum := s.Capture(context.Background(), 0); sum.Reason != "no_source" {
		t.Fatalf("%+v", sum)
	}
}

func TestSplitCursor(t *testing.T) {
	body, c := splitCursor("2026-11-18T10:00:00+0100 h sshd[1]: Failed password\n-- cursor: s=ab;i=1\n")
	if c != "s=ab;i=1" || body != "2026-11-18T10:00:00+0100 h sshd[1]: Failed password\n" {
		t.Fatalf("%q %q", body, c)
	}
	if body, c = splitCursor("ligne -- cursor: faux\n"); c != "" {
		t.Fatalf("curseur dans une ligne : %q %q", body, c)
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureSystemProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc requis")
	}
	s, _, ev, ek := newStore(t)
	out, err := call(t, s, `{"kind":"sample","instance":"vm","host":"h1","probe":"system","every":1,"filter":"^charge","why":"VM lente"}`)
	if err != nil || !strings.Contains(out, "hôte lisible (") || !strings.Contains(out, "vCPU") {
		t.Fatalf("%s %v", out, err)
	}
	var sum Summary
	done := make(chan struct{})
	go func() {
		sum = s.Capture(context.Background(), 0)
		close(done)
	}()
	waitFor(t, s.Waiting)
	waitFor(t, func() bool { return strings.Contains(strings.Join(ek.kind("stream"), "\n"), "1 sample") })
	s.Stop()
	<-done
	c := sum.Sources[0]
	if c.Samples < 1 || c.Matched < 1 {
		t.Fatalf("%+v", c)
	}
	it, _ := ev.Item(c.Evidence)
	data, _ := os.ReadFile(it.File)
	text := string(data)
	for _, want := range []string{"# sonde system, relevé toutes les 1s", "# seuils d'alerte", "=== état initial", "=== relevé 1, ", "(intervalle ", "cpu (", "occupé ", "disques :", "interfaces réseau", "processus par CPU"} {
		if !strings.Contains(text, want) {
			t.Errorf("preuve sans %q :\n%s", want, text)
		}
	}
	if !strings.Contains(strings.Join(ek.kind("captured"), "\n"), "h1:system · charge : ") {
		t.Errorf("ligne filtrée non affichée : %v", ek.kind("captured"))
	}
	if !strings.Contains(strings.Join(ek.kind("stream"), "\n"), "cpu ") {
		t.Errorf("résumé absent : %v", ek.kind("stream"))
	}
}
