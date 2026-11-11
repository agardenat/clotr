package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/agardenat/clotr/internal/netx"
)

const (
	chainKeepalive        = 30 * time.Second
	chainKeepaliveTimeout = 15 * time.Second
)

type Chain struct {
	hops  []Endpoint
	opts  Options
	mu    sync.Mutex
	conns []*gossh.Client
	stop  chan struct{}
}

func NewChain(hops []Endpoint, o Options) (*Chain, error) {
	if len(hops) == 0 {
		return nil, errors.New("ssh: chain without hop")
	}
	if _, err := NewPool(o); err != nil {
		return nil, err
	}
	return &Chain{hops: hops, opts: o}, nil
}

func (c *Chain) client(ctx context.Context) (*gossh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.conns); n > 0 {
		return c.conns[n-1], nil
	}
	var d netx.ContextDialer
	var conns []*gossh.Client
	for _, h := range c.hops {
		p, err := NewPool(c.opts)
		if err != nil {
			closeAll(conns)
			return nil, err
		}
		if d != nil {
			p.dialer = d
		}
		cl, err := p.client(ctx, h)
		if err != nil {
			closeAll(conns)
			return nil, fmt.Errorf("%s: %w", net.JoinHostPort(h.Host, strconv.Itoa(h.Port)), err)
		}
		conns = append(conns, cl)
		d = cl
	}
	last := conns[len(conns)-1]
	c.conns, c.stop = conns, make(chan struct{})
	go c.watch(last, c.stop)
	return last, nil
}

func (c *Chain) watch(last *gossh.Client, stop chan struct{}) {
	dead := make(chan struct{})
	go func() {
		_ = last.Wait()
		close(dead)
	}()
	t := time.NewTicker(chainKeepalive)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-dead:
			c.reset(last)
			return
		case <-t.C:
			errc := make(chan error, 1)
			go func() {
				_, _, err := last.SendRequest("keepalive@openssh.com", true, nil)
				errc <- err
			}()
			select {
			case err := <-errc:
				if err == nil {
					continue
				}
			case <-time.After(chainKeepaliveTimeout):
			case <-stop:
				return
			}
			c.reset(last)
			return
		}
	}
}

func (c *Chain) reset(last *gossh.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.conns); n == 0 || c.conns[n-1] != last {
		return
	}
	c.closeLocked()
}

func (c *Chain) closeLocked() {
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
	closeAll(c.conns)
	c.conns = nil
}

func closeAll(conns []*gossh.Client) {
	for i := len(conns) - 1; i >= 0; i-- {
		_ = conns[i].Close()
	}
}

func (c *Chain) Connect(ctx context.Context) error {
	_, err := c.client(ctx)
	return err
}

func (c *Chain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := cl.DialContext(ctx, network, addr)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	if refused(err) {
		return nil, fmt.Errorf("%w: %v", netx.ErrRefused, err)
	}
	c.reset(cl)
	if cl, err = c.client(ctx); err != nil {
		return nil, err
	}
	conn, err = cl.DialContext(ctx, network, addr)
	if err != nil && refused(err) {
		return nil, fmt.Errorf("%w: %v", netx.ErrRefused, err)
	}
	return conn, err
}

func refused(err error) bool {
	var oe *gossh.OpenChannelError
	return errors.As(err, &oe)
}

func (c *Chain) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}
