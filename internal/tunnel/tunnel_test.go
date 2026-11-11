package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/netx"
	"github.com/agardenat/clotr/internal/testutil"
)

func echoServer(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func fakeVault(t *testing.T, secrets map[string]string) *[]string {
	var mu sync.Mutex
	var reads []string
	old := creds.ReadVault
	creds.ReadVault = func(_ context.Context, ref string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		reads = append(reads, ref)
		if v, ok := secrets[ref]; ok {
			return v, nil
		}
		return "", errors.New("absent")
	}
	t.Cleanup(func() { creds.ReadVault = old })
	return &reads
}

func TestTunnelThroughTwoHops(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	reads := fakeVault(t, map[string]string{"kv/p/adm": "s3cret", "kv/p/adm#username": "ops"})
	reply := func(string, string) (string, int) { return "", 0 }
	k1, _ := testutil.NewSSHKey(t)
	k2, _ := testutil.NewSSHKey(t)
	hop1 := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{Password: "s3cret", HostKey: k1, Reply: reply, Forward: true})
	hop2 := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{Password: "s3cret", HostKey: k2, Reply: reply, Forward: true})
	tn, err := Open("acme/PRJ-0000", config.Tunnel{Hops: []string{hop1.Addr, hop2.Addr}, PasswordVault: "kv/p/adm"})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if tn.Shared() || !strings.HasPrefix(tn.URL, "socks5h://127.0.0.1:") {
		t.Fatalf("URL: %s", tn.URL)
	}
	var warnings []string
	tn.Warn = func(m string) { warnings = append(warnings, m) }
	px, _ := netx.ProxyURL(tn.URL, 0)
	d, _ := netx.Dialer(px)
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)
	c, err := d.DialContext(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("connexion par le tunnel: %v (avertissements %v)", err, warnings)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("écho: %q %v", buf, err)
	}
	c.Close()
	if len(*reads) == 0 || len(warnings) > 0 {
		t.Fatalf("lectures Vault %v, avertissements %v", *reads, warnings)
	}
}

func TestTunnelDownWarnsOnce(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	fakeVault(t, map[string]string{"kv/x": "s3cret", "kv/x#username": "ops"})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	tn, err := Open("acme", config.Tunnel{Hops: []string{closed}, PasswordVault: "kv/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	var warnings []string
	tn.Warn = func(m string) { warnings = append(warnings, m) }
	for i := 0; i < 3; i++ {
		if _, err := tn.dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
			t.Fatal("rebond injoignable non signalé")
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "acme") {
		t.Fatalf("avertissements: %v", warnings)
	}
}

func TestTunnelSharedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	tn, err := Open("acme", config.Tunnel{Hops: []string{"jump.example"}, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if !tn.Shared() || tn.URL != "socks5h://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("port déjà ouvert : %v %s", tn.Shared(), tn.URL)
	}
}
