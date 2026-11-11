package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

type SSHServer struct {
	Addr     string
	mu       sync.Mutex
	Commands []string
	HostKey  gossh.Signer
}

type SSHServerConfig struct {
	ClientKey gossh.PublicKey
	Password  string
	HostKey   gossh.Signer
	Reply     func(cmd, stdin string) (string, int)
	Forward   bool
}

func StartSSHServer(t testing.TB, clientKey gossh.PublicKey, hostKey gossh.Signer, reply func(cmd string) (string, int)) *SSHServer {
	return StartSSHServerConfig(t, SSHServerConfig{ClientKey: clientKey, HostKey: hostKey, Reply: func(cmd, _ string) (string, int) { return reply(cmd) }})
}

func StartSSHServerConfig(t testing.TB, c SSHServerConfig) *SSHServer {
	hostKey, reply, fwd := c.HostKey, c.Reply, c.Forward
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, k gossh.PublicKey) (*gossh.Permissions, error) {
			if c.ClientKey != nil && string(k.Marshal()) == string(c.ClientKey.Marshal()) {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	if c.Password != "" {
		cfg.PasswordCallback = func(_ gossh.ConnMetadata, pw []byte) (*gossh.Permissions, error) {
			if string(pw) == c.Password {
				return nil, nil
			}
			return nil, os.ErrPermission
		}
	}
	cfg.AddHostKey(hostKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &SSHServer{Addr: l.Addr().String(), HostKey: hostKey}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := gossh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go gossh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() == "direct-tcpip" {
						go forward(nc, fwd)
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							n := binary.BigEndian.Uint32(r.Payload)
							cmd := string(r.Payload[4 : 4+n])
							s.mu.Lock()
							s.Commands = append(s.Commands, cmd)
							s.mu.Unlock()
							r.Reply(true, nil)
							stdin, _ := io.ReadAll(ch)
							out, code := reply(cmd, string(stdin))
							ch.Write([]byte(out))
							if code < 0 {
								ch.Close()
								continue
							}
							status := make([]byte, 4)
							binary.BigEndian.PutUint32(status, uint32(code))
							ch.SendRequest("exit-status", false, status)
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return s
}

func forward(nc gossh.NewChannel, allowed bool) {
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if !allowed || gossh.Unmarshal(nc.ExtraData(), &req) != nil {
		nc.Reject(gossh.Prohibited, "forwarding disabled")
		return
	}
	up, err := net.Dial("tcp", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
	if err != nil {
		nc.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}
	go gossh.DiscardRequests(reqs)
	done := make(chan struct{})
	go func() {
		io.Copy(ch, up)
		ch.CloseWrite()
		close(done)
	}()
	io.Copy(up, ch)
	up.(*net.TCPConn).CloseWrite()
	<-done
	ch.Close()
	up.Close()
}

func NewSSHKey(t testing.TB) (gossh.Signer, []byte) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, pem.EncodeToMemory(block)
}

func (s *SSHServer) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Commands...)
}
