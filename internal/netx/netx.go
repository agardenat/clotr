package netx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"

	"github.com/agardenat/clotr/internal/i18n"
)

func ProxyURL(raw string, port int) (*url.URL, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "socks5h://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, i18n.E("netx.proxy", raw, err)
	}
	if u.Port() == "" {
		if port == 0 {
			return nil, i18n.E("netx.proxy_port", raw)
		}
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	}
	switch u.Scheme {
	case "socks5", "socks5h", "http", "https":
	default:
		return nil, i18n.E("netx.proxy_scheme", raw, u.Scheme)
	}
	return u, nil
}

type TLS struct {
	Verify  bool
	CAFile  string
	CAPEM   []byte
	CertPEM []byte
	KeyPEM  []byte
}

func Transport(proxyURL *url.URL, verifyTLS bool, caFile string) (*http.Transport, error) {
	return TransportTLS(proxyURL, TLS{Verify: verifyTLS, CAFile: caFile})
}

func TransportTLS(proxyURL *url.URL, o TLS) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !o.Verify}
	ca := o.CAPEM
	if len(ca) == 0 && o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		ca = pem
	}
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, i18n.E("netx.ca")
		}
		tlsCfg.RootCAs = pool
	}
	if len(o.CertPEM) > 0 || len(o.KeyPEM) > 0 {
		cert, err := tls.X509KeyPair(o.CertPEM, o.KeyPEM)
		if err != nil {
			return nil, i18n.E("netx.client_cert", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	return tr, nil
}

type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

func Dialer(proxyURL *url.URL) (ContextDialer, error) {
	direct := &net.Dialer{}
	if proxyURL == nil {
		return direct, nil
	}
	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return nil, i18n.E("netx.ssh_socks", proxyURL.Redacted())
	}
	var auth *proxy.Auth
	if proxyURL.User != nil {
		pw, _ := proxyURL.User.Password()
		auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, direct)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(ContextDialer)
	if !ok {
		return nil, i18n.E("netx.dialer")
	}
	return cd, nil
}
