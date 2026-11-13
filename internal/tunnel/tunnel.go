package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/netx"
)

const dialTimeout = 30 * time.Second

type Tunnel struct {
	Name  string
	URL   string
	Warn  func(string)
	Audit func(kind string, fields map[string]any)

	cfg    config.Tunnel
	label  string
	hops   []ssh.Endpoint
	user   string
	opts   ssh.Options
	mu     sync.Mutex
	chain  *ssh.Chain
	warned map[string]bool
	cancel context.CancelFunc
	done   chan struct{}
}

var listen = func(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

func Open(name string, c config.Tunnel) (*Tunnel, error) {
	t := &Tunnel{Name: name, cfg: c, label: "tunnel " + name, warned: map[string]bool{}}
	for _, h := range c.Hops {
		host, port, err := config.SplitHop(h)
		if err != nil {
			return nil, err
		}
		t.hops = append(t.hops, ssh.Endpoint{Host: host, Port: port})
	}
	kh := filepath.Join(config.StateDir(), "clotr", "known_hosts")
	t.opts = ssh.Options{KnownHosts: kh, HostKey: ssh.HostKeyPolicy(c.HostKey), ReadVault: func(ctx context.Context, ref string) (string, error) { return creds.ReadVault(ctx, ref) }, OnReplace: t.hostKeyReplaced}
	l, err := listen(c.Port)
	if err != nil {
		if c.Port > 0 && listening(c.Port) {
			t.URL = fmt.Sprintf("socks5h://127.0.0.1:%d", c.Port)
			return t, nil
		}
		return nil, i18n.E("tunnel.listen", name, err)
	}
	t.URL = "socks5h://" + l.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel, t.done = cancel, make(chan struct{})
	go func() {
		defer close(t.done)
		netx.ServeSOCKS(ctx, l, t.dial, dialTimeout)
	}()
	return t, nil
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (t *Tunnel) Shared() bool {
	return t.done == nil
}

func (t *Tunnel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ch, err := t.connect(ctx)
	if err == nil {
		var conn net.Conn
		if conn, err = ch.DialContext(ctx, network, addr); err == nil || errors.Is(err, netx.ErrRefused) || ctx.Err() != nil {
			return conn, err
		}
	}
	t.mu.Lock()
	if errors.Is(err, ssh.ErrAuth) && t.cfg.PasswordVault != "" || errors.Is(err, ssh.ErrAuth) && t.cfg.KeyPath == "" && t.cfg.KeyVault == "" {
		creds.Forget(t.label, t.user)
	}
	if t.chain != nil {
		t.chain.Close()
		t.chain = nil
	}
	msg := i18n.T("tunnel.down", t.Name, err)
	first := !t.warned[msg]
	t.warned[msg] = true
	t.mu.Unlock()
	if first {
		if t.Warn != nil {
			t.Warn(msg)
		}
		if t.Audit != nil {
			t.Audit("tunnel_error", map[string]any{"tunnel": t.Name, "error": err.Error()})
		}
	}
	return nil, err
}

func (t *Tunnel) connect(ctx context.Context) (*ssh.Chain, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.chain != nil {
		return t.chain, nil
	}
	user := t.cfg.User
	if user == "" && t.cfg.KeyVault != "" {
		path, _, _ := strings.Cut(t.cfg.KeyVault, "#")
		u, err := creds.ReadVault(ctx, path+"#username")
		if err == nil {
			user = u
		}
	}
	withKey := t.cfg.KeyPath != "" || t.cfg.KeyVault != ""
	var password func(context.Context) (string, error)
	if !withKey || t.cfg.PasswordVault != "" {
		if user == "" {
			p, err := creds.ResolveUser(ctx, "", "", t.cfg.PasswordVault, t.label)
			if err != nil {
				return nil, err
			}
			user = p.User
		}
		password = func(ctx context.Context) (string, error) {
			p, err := creds.ResolveUser(ctx, user, "", t.cfg.PasswordVault, t.label)
			return p.Pass, err
		}
	}
	if user == "" {
		return nil, i18n.E("tunnel.user", t.Name)
	}
	t.user = user
	hops := make([]ssh.Endpoint, len(t.hops))
	for i, h := range t.hops {
		h.User, h.KeyPath, h.KeyVault, h.Password = user, config.ExpandHome(t.cfg.KeyPath), t.cfg.KeyVault, password
		hops[i] = h
	}
	ch, err := ssh.NewChain(hops, t.opts)
	if err != nil {
		return nil, err
	}
	if err := ch.Connect(ctx); err != nil {
		return nil, err
	}
	t.chain = ch
	if t.Audit != nil {
		t.Audit("tunnel_open", map[string]any{"tunnel": t.Name, "hops": t.cfg.Hops, "user": user, "url": t.URL})
	}
	return ch, nil
}

func (t *Tunnel) hostKeyReplaced(host, old, new string) {
	if t.Warn != nil {
		t.Warn(i18n.T("ssh.host_replaced", "tunnel "+t.Name, host, old, new))
	}
	if t.Audit != nil {
		t.Audit("host_key_replaced", map[string]any{"tunnel": t.Name, "host": host, "old": old, "new": new})
	}
}

func (t *Tunnel) Close() {
	if t.cancel != nil {
		t.cancel()
		<-t.done
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.chain != nil {
		t.chain.Close()
		t.chain = nil
	}
}
