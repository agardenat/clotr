package dns

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

type fake struct {
	cname string
	addrs []net.IPAddr
	err   error
}

func (f fake) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }
func (f fake) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return f.addrs, f.err
}

func call(t *testing.T, r Resolver, args string) (string, error) {
	t.Helper()
	return Tool{R: r}.Call(context.Background(), json.RawMessage(args))
}

func TestResolve(t *testing.T) {
	r := fake{cname: "lb.example.net.", addrs: []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.20")}, {IP: net.ParseIP("192.0.2.10")}}}
	out, err := call(t, r, `{"name":"https://app.example.com:8443/login?x=1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "app.example.com (résolveur du poste, ") || !strings.Contains(out, "CNAME\tlb.example.net\nA\t192.0.2.10\nA\t192.0.2.20\nAAAA\t2001:db8::1\n") {
		t.Fatalf("sortie: %q", out)
	}
}

func TestNoCNAMEWhenCanonical(t *testing.T) {
	out, err := call(t, fake{cname: "app.example.com.", addrs: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}}, `{"name":"app.example.com"}`)
	if err != nil || strings.Contains(out, "CNAME") || !strings.Contains(out, "A\t192.0.2.10") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestNotFound(t *testing.T) {
	out, err := call(t, fake{err: &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}}, `{"name":"absent.example.com"}`)
	if err != nil || !strings.Contains(out, "NXDOMAIN") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestRejected(t *testing.T) {
	for _, a := range []string{`{"name":""}`, `{"name":"192.0.2.1"}`} {
		if _, err := call(t, fake{}, a); err == nil {
			t.Fatalf("%s accepté", a)
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{"app.example.com.": "app.example.com", "user@app.example.com:22": "app.example.com", "[2001:db8::1]:443": "2001:db8::1", " app.example.com/x ": "app.example.com"} {
		if got := hostOf(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
