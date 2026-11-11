package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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

func endpoint(t *testing.T, addr string) Endpoint {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return Endpoint{Host: h, Port: port}
}

func TestChainTwoHops(t *testing.T) {
	dir := t.TempDir()
	client, clientPEM := testutil.NewSSHKey(t)
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, clientPEM, 0o600)
	k1, _ := testutil.NewSSHKey(t)
	k2, _ := testutil.NewSSHKey(t)
	reply := func(string, string) (string, int) { return "", 0 }
	hop1 := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{Password: "s3cret", HostKey: k1, Reply: reply, Forward: true})
	hop2 := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{ClientKey: client.PublicKey(), Password: "s3cret", HostKey: k2, Reply: reply, Forward: true})
	asked := 0
	pw := func(context.Context) (string, error) {
		asked++
		return "s3cret", nil
	}
	e1, e2 := endpoint(t, hop1.Addr), endpoint(t, hop2.Addr)
	e1.User, e1.Password = "ops", pw
	e2.User, e2.KeyPath, e2.Password = "ops", keyPath, pw
	ch, err := NewChain([]Endpoint{e1, e2}, Options{KnownHosts: filepath.Join(dir, "kh"), HostKey: AcceptNew})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	echo := echoServer(t)
	for i := 0; i < 2; i++ {
		c, err := ch.DialContext(context.Background(), "tcp", echo)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("écho: %q %v", buf, err)
		}
		c.Close()
	}
	if asked != 1 {
		t.Fatalf("mot de passe demandé %d fois, attendu 1 (saut 1 seulement, clé sur le saut 2)", asked)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	if _, err := ch.DialContext(context.Background(), "tcp", closed); !errors.Is(err, netx.ErrRefused) {
		t.Fatalf("cible fermée : ErrRefused attendu, obtenu %v", err)
	}
	ch.mu.Lock()
	first := ch.conns[0]
	ch.mu.Unlock()
	first.Close()
	c, err := ch.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("pas de reconnexion après coupure du premier saut: %v", err)
	}
	c.Close()
}

func TestChainHopRefused(t *testing.T) {
	dir := t.TempDir()
	k1, _ := testutil.NewSSHKey(t)
	hop1 := testutil.StartSSHServerConfig(t, testutil.SSHServerConfig{Password: "s3cret", HostKey: k1, Reply: func(string, string) (string, int) { return "", 0 }})
	e1 := endpoint(t, hop1.Addr)
	e1.User, e1.Password = "ops", func(context.Context) (string, error) { return "faux", nil }
	ch, _ := NewChain([]Endpoint{e1}, Options{KnownHosts: filepath.Join(dir, "kh"), HostKey: AcceptNew})
	defer ch.Close()
	if _, err := ch.DialContext(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(err, ErrAuth) {
		t.Fatalf("ErrAuth attendu: %v", err)
	}
}
