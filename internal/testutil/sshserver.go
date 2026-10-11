package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"net"
	"os"
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

func StartSSHServer(t testing.TB, clientKey gossh.PublicKey, hostKey gossh.Signer, reply func(cmd string) (string, int)) *SSHServer {
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, k gossh.PublicKey) (*gossh.Permissions, error) {
			if string(k.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
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
							out, code := reply(cmd)
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
