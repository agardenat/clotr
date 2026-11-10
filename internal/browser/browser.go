package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var Open = start

var ErrTimeout = errors.New("browser: no answer")

func start(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		return
	}
	go func() { _ = cmd.Wait() }()
}

type Callback struct {
	ln   net.Listener
	path string
}

func Listen(addr, path string) (*Callback, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Callback{ln: ln, path: path}, nil
}

func (c *Callback) Wait(ctx context.Context, wait time.Duration, page func(url.Values) string) (url.Values, error) {
	got := make(chan url.Values, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != c.path {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, page(q))
		select {
		case got <- q:
		default:
		}
	})}
	go func() { _ = srv.Serve(c.ln) }()
	defer srv.Close()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case q := <-got:
		return q, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-timer.C:
		return nil, ErrTimeout
	}
}

func (c *Callback) Close() error {
	return c.ln.Close()
}
