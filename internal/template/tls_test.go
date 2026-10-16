package template

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	signer := key
	if parent == nil {
		tpl.IsCA, tpl.BasicConstraintsValid, tpl.KeyUsage = true, true, x509.KeyUsageCertSign
		parent = tpl
	} else {
		signer = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func TestPerRequestTLSDenyAndYAML(t *testing.T) {
	ca, caKey, _, _ := testCert(t, "client-ca", nil, nil)
	_, _, certPEM, keyPEM := testCert(t, "ops", ca, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"path":%q,"cn":%q,"auth":%q}`, r.URL.Path, r.TLS.PeerCertificates[0].Subject.CommonName, r.Header.Get("Authorization"))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	b64 := base64.StdEncoding.EncodeToString
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cluster.yaml")
	doc := fmt.Sprintf("server: %s\nca: %s\ncert: %s\nkey: %s\nlabels: {a: 1}\n", srv.URL, b64(serverCA), b64(certPEM), b64(keyPEM))
	if err := os.WriteFile(cfg, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := writeTemplate(t, `name: x
script: x.star
params:
  cfg: {type: path, required: true}
files: ["{{.cfg}}"]
connectors:
  api:
    driver: http
    base_url: https://unused.invalid
    deny: ["/forbidden$"]
`, `
def conf():
    return yaml.decode(file.read(instance.params["cfg"]))

def get(a):
    c = conf()
    material = {"ca": base64.decode(c["ca"]), "cert": base64.decode(c["cert"]), "key": base64.decode(c["key"])}
    if a.get("no_cert"):
        material = {"ca": base64.decode(c["ca"])}
    r = http.request("api", "GET", a["path"], base = c["server"], tls = material, headers = {"Authorization": "Bearer t"})
    return yaml.encode({"status": r.status, "body": json.decode(r.body), "labels": c["labels"]})

def discover(ctx):
    return {"targets": [{"name": "c1", "kind": "cluster"}]}

tool(name = "get", description = "d", schema = {"type": "object"}, fn = get)
`)
	in, err := NewInstance("i", tpl, map[string]any{"cfg": cfg})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Discover(context.Background(), "", 0, true); err != nil {
		t.Fatal(err)
	}
	var get func(string) (string, error)
	for _, tl := range in.Tools() {
		if tl.Name() == "i_get" {
			get = func(args string) (string, error) { return tl.Call(context.Background(), []byte(args)) }
		}
	}
	out, err := get(`{"path":"/api/v1/secrets"}`)
	want := "body:\n  auth: Bearer t\n  cn: ops\n  path: /api/v1/secrets\nlabels:\n  a: 1\nstatus: 200\n"
	if err != nil || out != want {
		t.Fatalf("certificat client, deny propre au connecteur, yaml:\n%s%v", out, err)
	}
	if _, err := get(`{"path":"/forbidden"}`); err == nil || !strings.Contains(err.Error(), "deny list") {
		t.Fatalf("deny: %v", err)
	}
	if _, err := get(`{"path":"/ok","no_cert":true}`); err == nil {
		t.Fatal("requête acceptée sans certificat client")
	}
}

func TestDefaultSensitivePathsWithoutDeny(t *testing.T) {
	hc, err := newHTTPConn("api", options{"base_url": "https://x.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkRequestPath(hc, http.MethodGet, "/api/v1/secrets"); err == nil || !strings.Contains(err.Error(), "sensitive keyword") {
		t.Fatalf("mots-clés par défaut: %v", err)
	}
	hc, _ = newHTTPConn("api", options{"base_url": "https://x.invalid", "deny": []any{}})
	if _, err := checkRequestPath(hc, http.MethodGet, "/api/v1/secrets"); err != nil {
		t.Fatalf("deny vide déclaré: %v", err)
	}
}
