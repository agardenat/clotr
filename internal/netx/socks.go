package netx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const socksHandshakeTimeout = 10 * time.Second

func ServeSOCKS(ctx context.Context, l net.Listener, dial func(ctx context.Context, network, addr string) (net.Conn, error), dialTimeout time.Duration) {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveSOCKSConn(ctx, c, dial, dialTimeout)
		}()
	}
}

func serveSOCKSConn(ctx context.Context, c net.Conn, dial func(ctx context.Context, network, addr string) (net.Conn, error), dialTimeout time.Duration) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	addr, err := socksRequest(c)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	up, err := dial(dctx, "tcp", addr)
	cancel()
	if err != nil {
		_, _ = c.Write(socksReply(socksFailure(err)))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksReply(0)); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() {
		c.Close()
		up.Close()
	})
	defer stop()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, c)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(c, up)
	closeWrite(c)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

var errSOCKS = errors.New("socks: invalid request")

func socksRequest(c net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return "", errSOCKS
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xff})
		return "", errSOCKS
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return "", errSOCKS
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, 4)
		if req[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_, _ = c.Write(socksReply(8))
		return "", errSOCKS
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	if req[1] != 1 {
		_, _ = c.Write(socksReply(7))
		return "", errSOCKS
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func socksReply(code byte) []byte {
	return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
}

var ErrRefused = errors.New("connection refused by the remote side")

func socksFailure(err error) byte {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return 6
	case errors.Is(err, ErrRefused):
		return 5
	}
	return 1
}
