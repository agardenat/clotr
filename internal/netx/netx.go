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
		return nil, fmt.Errorf("proxy invalide %q: %w", raw, err)
	}
	if u.Port() == "" {
		if port == 0 {
			return nil, fmt.Errorf("proxy sans port: %q", raw)
		}
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	}
	switch u.Scheme {
	case "socks5", "socks5h", "http", "https":
	default:
		return nil, fmt.Errorf("proxy %q: schéma %q non supporté (socks5, socks5h, http, https)", raw, u.Scheme)
	}
	return u, nil
}

func Transport(proxyURL *url.URL, verifyTLS bool, caFile string) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifyTLS}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file: aucun certificat PEM valide")
		}
		tlsCfg.RootCAs = pool
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
		return nil, fmt.Errorf("proxy %s: seul SOCKS5 est supporté pour SSH", proxyURL.Redacted())
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
		return nil, fmt.Errorf("dialer SOCKS5 sans DialContext")
	}
	return cd, nil
}
