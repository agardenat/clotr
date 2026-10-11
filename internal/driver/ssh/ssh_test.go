package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/agardenat/clotr/internal/testutil"
)

func testRules(t *testing.T) *Rules {
	r, err := CompileRules(PathRules{
		Allow: []string{"/var/log/**", "/etc/*/conf/**", "/var/run/agent/process/**"},
		Deny:  []string{"**/*.keytab", "**/creds.localjceks", "**/*password*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRules(t *testing.T) {
	r := testRules(t)
	ok := []string{"/var/log/app/server.log", "/var/log/app", "/etc/app/conf/app-site.xml", "/var/run/agent/process/123-app-SERVER/app-site.xml", "/var/log//app/./x.log"}
	for _, p := range ok {
		if _, err := r.Check(p); err != nil {
			t.Errorf("%s refusé: %v", p, err)
		}
	}
	ko := []string{"/etc/shadow", "/var/log/../../etc/shadow", "var/log/x", "/var/run/agent/process/1-app-SERVER/app.keytab", "/var/run/agent/process/1-x/creds.localjceks", "/etc/app/conf/password.txt", "/etc/app/conf2/x", "/var/log/x\n/etc/shadow", "/var/log"}
	for _, p := range ko {
		if _, err := r.Check(p); err == nil {
			t.Errorf("%q accepté", p)
		}
	}
	if got := strings.Join(r.ExcludeGlobs(), ","); got != "*.keytab,creds.localjceks,*password*" {
		t.Errorf("excludes: %s", got)
	}
}

func TestQuoteAndBuilders(t *testing.T) {
	if q := Quote(`a'b; rm -rf / $(id)`); q != `'a'"'"'b; rm -rf / $(id)'` {
		t.Fatalf("quote: %s", q)
	}
	b := Builder{Sudo: true}
	cases := map[string]string{
		b.Tail("/var/log/x.log", 50):                                                   `sudo -n tail -n 50 -- '/var/log/x.log'`,
		b.Read("/etc/app/conf/a", 0, 0, 100):                                           `sudo -n head -c 100 -- '/etc/app/conf/a'`,
		b.Read("/etc/app/conf/a", 10, 20, 100):                                         `sudo -n sed -n '10,20p' -- '/etc/app/conf/a' | head -c 100`,
		b.Grep("/var/log", "ERROR|$(reboot)", true, true, 5, []string{"*.keytab"}, 10): `sudo -n grep -n -E -I -m 5 -i -r --exclude='*.keytab' -e 'ERROR|$(reboot)' -- '/var/log' | head -c 10`,
		b.GrepCount("/var/log/a.log", "PREAUTH", false, false, nil, 10):                `sudo -n grep -c -E -I -e 'PREAUTH' -- '/var/log/a.log' | head -c 10`,
		b.GrepCount("/var/log", "x'y", true, true, []string{"*.keytab"}, 10):           `sudo -n grep -c -E -I -i -r --exclude='*.keytab' -e 'x'"'"'y' -- '/var/log' | grep -v ':0$' | head -c 10`,
		Builder{}.Tail("/var/log/x", 1):                                                `tail -n 1 -- '/var/log/x'`,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("commande:\n%s\nattendu:\n%s", got, want)
		}
	}
}

func TestRedact(t *testing.T) {
	in := "db.password=s3cr3t\nfoo=bar\n<property><name>javax.jdo.option.ConnectionPassword</name>\n<value>hunter2</value></property>\ntoken: abc123"
	out := Redact(in)
	for _, leak := range []string{"s3cr3t", "hunter2", "abc123"} {
		if strings.Contains(out, leak) {
			t.Errorf("fuite %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "foo=bar") {
		t.Errorf("valeur non sensible masquée:\n%s", out)
	}
}

func TestPoolExecAndKnownHosts(t *testing.T) {
	dir := t.TempDir()
	client, clientPEM := testutil.NewSSHKey(t)
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, clientPEM, 0o600)
	host1, _ := testutil.NewSSHKey(t)
	srv := testutil.StartSSHServer(t, client.PublicKey(), host1, func(cmd string) (string, int) {
		if strings.HasPrefix(cmd, "grep") {
			return "", 1
		}
		return "hello\n", 0
	})
	h, p, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(p)
	kh := filepath.Join(dir, "known_hosts")
	pool, err := NewPool(Options{KnownHosts: kh, HostKey: AcceptNew})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ep := Endpoint{Host: h, Port: port, User: "admin", KeyPath: keyPath}
	res, err := pool.Exec(context.Background(), ep, "tail -n 1 -- '/var/log/x'", 3)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hel" || !res.Truncated || res.Exit != 0 {
		t.Fatalf("résultat: %+v", res)
	}
	res, err = pool.Exec(context.Background(), ep, "grep x", 100)
	if err != nil || res.Exit != 1 {
		t.Fatalf("exit 1 attendu: %+v %v", res, err)
	}
	data, _ := os.ReadFile(kh)
	if !strings.Contains(string(data), "ssh-ed25519") {
		t.Fatalf("known_hosts non alimenté: %q", data)
	}

	host2, _ := testutil.NewSSHKey(t)
	srv2 := testutil.StartSSHServer(t, client.PublicKey(), host2, func(string) (string, int) { return "", 0 })
	_, p2, _ := net.SplitHostPort(srv2.Addr)
	port2, _ := strconv.Atoi(p2)
	os.WriteFile(kh, []byte(strings.Replace(string(data), "]:"+p, "]:"+p2, 1)), 0o600)
	pool2, _ := NewPool(Options{KnownHosts: kh, HostKey: AcceptNew})
	defer pool2.Close()
	if _, err := pool2.Exec(context.Background(), Endpoint{Host: h, Port: port2, User: "admin", KeyPath: keyPath}, "true", 10); err == nil || !strings.Contains(err.Error(), "différente") {
		t.Fatalf("clé d'hôte changée acceptée: %v", err)
	}
	strict, _ := NewPool(Options{KnownHosts: filepath.Join(dir, "empty"), HostKey: Strict})
	defer strict.Close()
	if _, err := strict.Exec(context.Background(), ep, "true", 10); err == nil {
		t.Fatal("hôte inconnu accepté en strict")
	}
}

func TestPoolRetriesMissingExitStatus(t *testing.T) {
	saved := missingExitRetries
	missingExitRetries = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { missingExitRetries = saved }()
	dir := t.TempDir()
	client, clientPEM := testutil.NewSSHKey(t)
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, clientPEM, 0o600)
	hostKey, _ := testutil.NewSSHKey(t)
	var mu sync.Mutex
	calls := map[string]int{}
	srv := testutil.StartSSHServer(t, client.PublicKey(), hostKey, func(cmd string) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		calls[cmd]++
		if cmd == "always" || calls[cmd] == 1 {
			return "", -1
		}
		return "ok\n", 0
	})
	h, p, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(p)
	pool, _ := NewPool(Options{KnownHosts: filepath.Join(dir, "kh"), HostKey: AcceptNew})
	defer pool.Close()
	ep := Endpoint{Host: h, Port: port, User: "admin", KeyPath: keyPath}
	res, err := pool.Exec(context.Background(), ep, "once", 100)
	if err != nil || res.Stdout != "ok\n" || calls["once"] != 2 {
		t.Fatalf("relance attendue: %+v %v (%d appels)", res, err, calls["once"])
	}
	var me *gossh.ExitMissingError
	if _, err := pool.Exec(context.Background(), ep, "always", 100); !errors.As(err, &me) || calls["always"] != 3 {
		t.Fatalf("erreur après relances attendue: %v (%d appels)", err, calls["always"])
	}
}

func TestPoolPasswordFallbackAndStdin(t *testing.T) {
	dir := t.TempDir()
	_, refusedPEM := testutil.NewSSHKey(t)
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, refusedPEM, 0o600)
	other, _ := testutil.NewSSHKey(t)
	hostKey, _ := testutil.NewSSHKey(t)
	srv := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{ClientKey: other.PublicKey(), Password: "s3cret", HostKey: hostKey, Reply: func(cmd, stdin string) (string, int) {
		return "stdin=" + stdin, 0
	}})
	h, p, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(p)
	pool, _ := NewPool(Options{KnownHosts: filepath.Join(dir, "kh"), HostKey: AcceptNew})
	defer pool.Close()
	asked := 0
	pw := "s3cret"
	ep := Endpoint{Host: h, Port: port, User: "ops", KeyPath: keyPath, Password: func(context.Context) (string, error) {
		asked++
		return pw, nil
	}}
	res, err := pool.ExecInput(context.Background(), ep, "cat", "abc\n", 100)
	if err != nil || res.Stdout != "stdin=abc\n" || asked != 1 {
		t.Fatalf("repli sur mot de passe: %+v %v (%d demandes)", res, err, asked)
	}
	if _, err := pool.Exec(context.Background(), ep, "true", 100); err != nil || asked != 1 {
		t.Fatalf("connexion non réutilisée: %v (%d demandes)", err, asked)
	}
	pool2, _ := NewPool(Options{KnownHosts: filepath.Join(dir, "kh"), HostKey: AcceptNew})
	defer pool2.Close()
	pw = "faux"
	if _, err := pool2.Exec(context.Background(), ep, "true", 100); !errors.Is(err, ErrAuth) {
		t.Fatalf("ErrAuth attendu: %v", err)
	}
	noKey := Endpoint{Host: h, Port: port, User: "ops"}
	if _, err := pool2.Exec(context.Background(), noKey, "true", 100); err == nil || !strings.Contains(err.Error(), "ni mot de passe") {
		t.Fatalf("absence de clé et de mot de passe: %v", err)
	}
}

func TestSudoWithPassword(t *testing.T) {
	got := SudoWithPassword(Builder{}.Tail("/var/log/x", 5))
	want := `sudo -S -p '' -- sh -c 'exec </dev/null; tail -n 5 -- '"'"'/var/log/x'"'"''`
	if got != want {
		t.Fatalf("commande:\n%s\nattendu:\n%s", got, want)
	}
	for res, want := range map[Result]bool{
		{Stderr: "sudo: a password is required\n"}:                                       true,
		{Stdout: "sudo: a password is required\n"}:                                       true,
		{Stderr: "grep: x: Permission denied"}:                                           false,
		{Stdout: "Oct 11 host sudo[1]: ops : a password is required ; COMMAND=/bin/x\n"}: false,
	} {
		if SudoNeedsPassword(res) != want {
			t.Errorf("SudoNeedsPassword(%+v) != %v", res, want)
		}
	}
	if !SudoPasswordRejected("Sorry, try again.\nsudo: 1 incorrect password attempt\n") {
		t.Fatal("détection du mot de passe sudo refusé")
	}
}
