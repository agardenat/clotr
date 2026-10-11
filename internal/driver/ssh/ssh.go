package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/agardenat/clotr/internal/netx"
)

type HostKeyPolicy string

const (
	AcceptNew HostKeyPolicy = "accept-new"
	Strict    HostKeyPolicy = "strict"
	Insecure  HostKeyPolicy = "insecure"
)

type Endpoint struct {
	Host     string
	Port     int
	User     string
	KeyPath  string
	Password func(ctx context.Context) (string, error)
}

var ErrAuth = errors.New("authentification SSH refusée")

func (e Endpoint) key() string {
	return e.User + "@" + net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) + "#" + e.KeyPath
}

type Options struct {
	Proxy      *url.URL
	KnownHosts string
	HostKey    HostKeyPolicy
	MaxConns   int
	Timeout    time.Duration
}

type Pool struct {
	opts    Options
	dialer  netx.ContextDialer
	sem     chan struct{}
	mu      sync.Mutex
	clients map[string]*gossh.Client
	signers map[string]gossh.Signer
	khMu    sync.Mutex
}

func NewPool(o Options) (*Pool, error) {
	d, err := netx.Dialer(o.Proxy)
	if err != nil {
		return nil, err
	}
	if o.MaxConns <= 0 {
		o.MaxConns = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	switch o.HostKey {
	case "":
		o.HostKey = AcceptNew
	case AcceptNew, Strict, Insecure:
	default:
		return nil, fmt.Errorf("host_key %q invalide (accept-new|strict|insecure)", o.HostKey)
	}
	return &Pool{opts: o, dialer: d, sem: make(chan struct{}, o.MaxConns), clients: map[string]*gossh.Client{}, signers: map[string]gossh.Signer{}}, nil
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.clients {
		_ = c.Close()
		delete(p.clients, k)
	}
}

func (p *Pool) signer(path string) (gossh.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.signers[path]; ok {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clé SSH: %w", err)
	}
	s, err := gossh.ParsePrivateKey(data)
	if err != nil {
		var pp *gossh.PassphraseMissingError
		if errors.As(err, &pp) {
			return nil, fmt.Errorf("clé SSH %s protégée par une passphrase: non supporté", path)
		}
		return nil, fmt.Errorf("clé SSH %s: %w", path, err)
	}
	p.signers[path] = s
	return s, nil
}

func (p *Pool) hostKeyCallback() (gossh.HostKeyCallback, error) {
	if p.opts.HostKey == Insecure {
		return gossh.InsecureIgnoreHostKey(), nil
	}
	path := p.opts.KnownHosts
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		p.khMu.Lock()
		defer p.khMu.Unlock()
		cb, err := knownhosts.New(path)
		if err != nil {
			return err
		}
		err = cb(hostname, remote, key)
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 && p.opts.HostKey == AcceptNew {
			line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
			af, ferr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
			if ferr != nil {
				return ferr
			}
			defer af.Close()
			_, ferr = fmt.Fprintln(af, line)
			return ferr
		}
		if errors.As(err, &ke) && len(ke.Want) > 0 {
			return fmt.Errorf("clé d'hôte SSH de %s différente de celle enregistrée dans %s (réinstallation de la VM ? supprimer la ligne pour accepter la nouvelle)", hostname, path)
		}
		return err
	}, nil
}

func (p *Pool) client(ctx context.Context, e Endpoint) (*gossh.Client, error) {
	k := e.key()
	p.mu.Lock()
	c, ok := p.clients[k]
	p.mu.Unlock()
	if ok {
		return c, nil
	}
	hk, err := p.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	if e.KeyPath == "" && e.Password == nil {
		return nil, errors.New("aucune clé SSH (ssh_key_path) ni mot de passe (auth) configuré")
	}
	if e.KeyPath != "" {
		signer, err := p.signer(e.KeyPath)
		if err != nil {
			return nil, err
		}
		c, err = p.connect(ctx, e, hk, gossh.PublicKeys(signer))
		if err != nil && (e.Password == nil || !errors.Is(err, ErrAuth)) {
			return nil, err
		}
	}
	if c == nil {
		pw, err := e.Password(ctx)
		if err != nil {
			return nil, err
		}
		answer := func(_, _ string, questions []string, echos []bool) ([]string, error) {
			out := make([]string, len(questions))
			for i := range questions {
				if !echos[i] {
					out[i] = pw
				}
			}
			return out, nil
		}
		c, err = p.connect(ctx, e, hk, gossh.Password(pw), gossh.KeyboardInteractive(answer))
		if err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	if old, ok := p.clients[k]; ok {
		p.mu.Unlock()
		c.Close()
		return old, nil
	}
	p.clients[k] = c
	p.mu.Unlock()
	return c, nil
}

func (p *Pool) connect(ctx context.Context, e Endpoint, hk gossh.HostKeyCallback, auth ...gossh.AuthMethod) (*gossh.Client, error) {
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	dctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	conn, err := p.dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connexion SSH %s: %w", addr, err)
	}
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cc, chans, reqs, err := gossh.NewClientConn(conn, addr, &gossh.ClientConfig{
		User:            e.User,
		Auth:            auth,
		HostKeyCallback: hk,
		Timeout:         p.opts.Timeout,
	})
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("handshake SSH %s@%s: %w (%v)", e.User, addr, ErrAuth, err)
		}
		return nil, fmt.Errorf("handshake SSH %s@%s: %w", e.User, addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return gossh.NewClient(cc, chans, reqs), nil
}

func (p *Pool) drop(e Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[e.key()]; ok {
		c.Close()
		delete(p.clients, e.key())
	}
}

type Result struct {
	Stdout    string
	Stderr    string
	Exit      int
	Truncated bool
}

func (p *Pool) Exec(ctx context.Context, e Endpoint, cmd string, maxBytes int) (Result, error) {
	return p.ExecInput(ctx, e, cmd, "", maxBytes)
}

func (p *Pool) ExecInput(ctx context.Context, e Endpoint, cmd, stdin string, maxBytes int) (Result, error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	defer func() { <-p.sem }()
	res, err := p.exec(ctx, e, cmd, stdin, maxBytes)
	var oe *gossh.OpenChannelError
	if err != nil && (errors.Is(err, io.EOF) || errors.As(err, &oe)) {
		p.drop(e)
		res, err = p.exec(ctx, e, cmd, stdin, maxBytes)
	}
	for _, wait := range missingExitRetries {
		var me *gossh.ExitMissingError
		if !errors.As(err, &me) {
			break
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
		res, err = p.exec(ctx, e, cmd, stdin, maxBytes)
	}
	return res, err
}

var missingExitRetries = []time.Duration{300 * time.Millisecond, time.Second, 3 * time.Second}

func (p *Pool) exec(ctx context.Context, e Endpoint, cmd, stdin string, maxBytes int) (Result, error) {
	c, err := p.client(ctx, e)
	if err != nil {
		return Result{}, err
	}
	s, err := c.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer s.Close()
	stdout := &limitBuffer{max: maxBytes}
	stderr := &limitBuffer{max: 8 << 10}
	s.Stdout, s.Stderr = stdout, stderr
	if stdin != "" {
		s.Stdin = strings.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = s.Signal(gossh.SIGKILL)
		_ = s.Close()
		return Result{}, ctx.Err()
	case err = <-done:
	}
	r := Result{Stdout: stdout.String(), Stderr: stderr.String(), Truncated: stdout.truncated}
	var ee *gossh.ExitError
	if errors.As(err, &ee) {
		r.Exit = ee.ExitStatus()
		return r, nil
	}
	return r, err
}

type limitBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.max > 0 && b.buf.Len()+len(p) > b.max {
		if room := b.max - b.buf.Len(); room > 0 {
			b.buf.Write(p[:room])
		}
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitBuffer) String() string {
	return b.buf.String()
}
