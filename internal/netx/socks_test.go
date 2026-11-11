package netx

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeSOCKS(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	_, echoPort, _ := net.SplitHostPort(echo.Addr().String())
	var asked []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		if strings.HasPrefix(addr, "refused.example:") {
			return nil, fmt.Errorf("%w: test", ErrRefused)
		}
		host, port, _ := net.SplitHostPort(addr)
		if host == "remote.example" {
			host = "127.0.0.1"
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ServeSOCKS(ctx, l, dial, 5*time.Second)
		close(done)
	}()
	px, _ := ProxyURL("socks5h://"+l.Addr().String(), 0)
	d, err := Dialer(px)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), "tcp", "remote.example:"+echoPort)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("écho: %q %v", buf, err)
	}
	c.Close()
	if asked[0] != "remote.example:"+echoPort {
		t.Fatalf("nom non transmis tel quel: %v", asked)
	}
	_, err = d.DialContext(context.Background(), "tcp", "refused.example:22")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("refus attendu: %v", err)
	}
	raw, _ := net.Dial("tcp", l.Addr().String())
	raw.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(raw, reply); err != nil || reply[1] != 0xff {
		t.Fatalf("authentification par mot de passe acceptée: %v %v", reply, err)
	}
	raw.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSOCKS ne s'arrête pas")
	}
	if _, err := net.Dial("tcp", l.Addr().String()); err == nil {
		t.Fatal("écoute toujours ouverte")
	}
}
