package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/tools"
)

const (
	Group    = "dns"
	ToolName = "dns_resolve"
	timeout  = 5 * time.Second
)

type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type Tool struct{ R Resolver }

func New() Tool { return Tool{R: net.DefaultResolver} }

func (Tool) Name() string { return ToolName }

func (Tool) Description() string {
	return "Résout un nom DNS depuis le poste qui exécute clotr (résolveur du système) : nom canonique (CNAME) et adresses IPv4/IPv6. Lecture seule. Pour un incident d'accès à une URL, comparer l'IP obtenue au point d'entrée attendu (adresse du load balancer d'un ingress, IP d'une VM). Le résultat reflète la vue DNS de ce poste, qui peut différer de celle d'un autre réseau (DNS interne et externe distincts)."
}

func (Tool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"nom à résoudre, ex: app.example.com (un schéma, un port ou un chemin d'URL sont ignorés)"}},"required":["name"]}`)
}

func (t Tool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Name string `json:"name"`
	}](raw)
	if err != nil {
		return "", err
	}
	name := HostOf(a.Name)
	if name == "" {
		return "", errors.New("name requis")
	}
	if ip := net.ParseIP(name); ip != nil {
		return "", fmt.Errorf("%s est déjà une adresse IP", name)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var b strings.Builder
	fmt.Fprintf(&b, "%s (résolveur du poste, %s)\n", name, time.Now().UTC().Format(time.RFC3339))
	cname, cerr := t.R.LookupCNAME(ctx, name)
	if cname = strings.TrimSuffix(cname, "."); cerr == nil && cname != "" && !strings.EqualFold(cname, name) {
		fmt.Fprintf(&b, "CNAME\t%s\n", cname)
	}
	addrs, err := t.R.LookupIPAddr(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			b.WriteString("aucune adresse : nom inexistant (NXDOMAIN) ou sans enregistrement A/AAAA\n")
			return b.String(), nil
		}
		return "", fmt.Errorf("résolution de %s : %w", name, err)
	}
	var v4, v6 []string
	for _, ad := range addrs {
		if ad.IP.To4() != nil {
			v4 = append(v4, ad.IP.String())
		} else {
			v6 = append(v6, ad.IP.String())
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	for _, ip := range v4 {
		fmt.Fprintf(&b, "A\t%s\n", ip)
	}
	for _, ip := range v6 {
		fmt.Fprintf(&b, "AAAA\t%s\n", ip)
	}
	return b.String(), nil
}

func HostOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.TrimSuffix(strings.Trim(s, "[]"), ".")
}
