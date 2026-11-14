package sources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var fixtureRe = []struct {
	re     *regexp.Regexp
	prefix string
}{
	{regexp.MustCompile(`cveawg\.mitre\.org/api/cve/(.+)$`), "cveorg"},
	{regexp.MustCompile(`services\.nvd\.nist\.gov/.*cveId=(.+)$`), "nvd"},
	{regexp.MustCompile(`api\.first\.org/.*cve=(.+)$`), "epss"},
	{regexp.MustCompile(`api\.github\.com/advisories\?cve_id=(.+)$`), "gh"},
	{regexp.MustCompile(`api\.github\.com/advisories/(GHSA-.+)$`), "gh"},
	{regexp.MustCompile(`securitydata/cve/(.+)\.json$`), "redhat"},
	{regexp.MustCompile(`ubuntu\.com/security/cves/(.+)\.json$`), "ubuntu"},
	{regexp.MustCompile(`api\.osv\.dev/v1/vulns/DEBIAN-(.+)$`), "osvdeb"},
}

func fixtures(t *testing.T, calls *[]string, fail map[string]int) Getter {
	return func(_ context.Context, url string) (int, []byte, error) {
		*calls = append(*calls, url)
		for k, code := range fail {
			if strings.Contains(url, k) {
				if code == 0 {
					return 0, nil, errors.New("connexion refusée")
				}
				return code, []byte("unavailable"), nil
			}
		}
		if strings.HasSuffix(url, "known_exploited_vulnerabilities.json") {
			b, err := os.ReadFile("testdata/kev.json")
			return 200, b, err
		}
		for _, f := range fixtureRe {
			if m := f.re.FindStringSubmatch(url); m != nil {
				b, err := os.ReadFile(filepath.Join("testdata", f.prefix+"-"+m[1]+".json"))
				if err != nil {
					if f.prefix == "epss" {
						b, _ = os.ReadFile("testdata/epss-none.json")
						return 200, b, nil
					}
					return http.StatusNotFound, []byte(`{"message":"Not Found"}`), nil
				}
				return 200, b, nil
			}
		}
		t.Fatalf("URL inattendue %s", url)
		return 0, nil, nil
	}
}

func client(t *testing.T, calls *[]string, fail map[string]int) *Client {
	c := New(nil, t.TempDir())
	c.Get = fixtures(t, calls, fail)
	c.Retries = []time.Duration{time.Millisecond}
	return c
}

func recorder(n *int) Record {
	return func(source, url, body string, err error) string {
		*n++
		return fmt.Sprintf("E%03d", *n)
	}
}

func TestCollectOpenSSH(t *testing.T) {
	var calls []string
	n := 0
	f := client(t, &calls, nil).Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	var names []string
	for _, s := range f.Sources {
		names = append(names, s.Name+":"+s.State)
	}
	want := []string{"cveorg:ok", "nvd:ok", "kev:ok", "epss:ok", "github:ok", "redhat:ok", "ubuntu:ok", "debian:ok"}
	if !slices.Equal(names, want) {
		t.Fatalf("sources %v, attendu %v", names, want)
	}
	if f.KEV != nil || !f.KEVChecked {
		t.Fatalf("KEV : %+v checked=%v", f.KEV, f.KEVChecked)
	}
	if f.EPSS == nil || f.EPSS.Score < 0.99 || f.EPSS.Date == "" {
		t.Fatalf("EPSS %+v", f.EPSS)
	}
	if f.SSVC != "poc" {
		t.Fatalf("SSVC %q", f.SSVC)
	}
	if !slices.Contains(f.CWE, "CWE-364") || !slices.Contains(f.CWE, "CWE-362") {
		t.Fatalf("CWE %v", f.CWE)
	}
	var nvd, cna bool
	for _, s := range f.Scores {
		nvd = nvd || s.Source == "NVD" && s.Score == 8.1 && s.Severity == "HIGH"
		cna = cna || strings.HasPrefix(s.Source, "CNA") && s.Version == "3.1"
	}
	if !nvd || !cna {
		t.Fatalf("scores %+v", f.Scores)
	}
	fix := Fix{Distro: RedHat, Release: "Red Hat Enterprise Linux 9", Package: "openssh", Version: "0:8.7p1-38.el9_4.1", State: FixFixed, Advisory: "RHSA-2024:4312"}
	if !slices.Contains(f.Fixes, fix) {
		t.Fatalf("correctif RHEL 9 absent : %+v", f.Fixes)
	}
	if !slices.ContainsFunc(f.Fixes, func(x Fix) bool {
		return x.Distro == Ubuntu && x.Release == "jammy" && x.State == FixFixed && x.Version == "1:8.9p1-3ubuntu0.10" && strings.Contains(x.Advisory, "USN-6859-1")
	}) {
		t.Fatalf("correctif jammy absent")
	}
	if !slices.ContainsFunc(f.Fixes, func(x Fix) bool { return x.Distro == Debian && x.Release == "Debian 12" && x.State == FixFixed }) {
		t.Fatalf("correctif Debian 12 absent")
	}
	if !slices.ContainsFunc(f.Mitigations, func(m Text) bool {
		return strings.Contains(m.Source, "Red Hat") && strings.Contains(m.Source, "CNA redhat") && strings.Contains(m.Text, "LoginGraceTime")
	}) {
		t.Fatalf("mitigation Red Hat absente : %+v", f.Mitigations)
	}
	if len(f.Upstream) == 0 || !strings.Contains(f.Upstream[0].Versions, "9.7p1") {
		t.Fatalf("plages amont %+v", f.Upstream)
	}
	cmds := f.Commands()
	if len(cmds) != 3 || cmds[0] != OSRelease || !strings.Contains(cmds[1], "grep -E ' openssh-[0-9]'") || !strings.Contains(cmds[2], "grep -E ' (openssh|openssh-ssh1)$'") {
		t.Fatalf("commandes %q", cmds)
	}
	if got := f.Evidence(); len(got) != 8 {
		t.Fatalf("preuves %v", got)
	}
}

func TestCollectApplicationPackage(t *testing.T) {
	var calls []string
	n := 0
	f := client(t, &calls, nil).Collect(context.Background(), "CVE-2023-32681", recorder(&n))
	if !slices.Contains(f.Packages, Package{Ecosystem: "pip", Name: "requests", Vulnerable: ">= 2.3.0, < 2.31.0", Fixed: "2.31.0"}) {
		t.Fatalf("paquet pip absent : %+v", f.Packages)
	}
	if f.SSVC != "none" {
		t.Fatalf("SSVC %q", f.SSVC)
	}
	if !slices.ContainsFunc(f.Fixes, func(x Fix) bool { return x.Distro == Debian && x.Release == "Debian 12" && x.State == FixAffected }) {
		t.Fatalf("Debian 12 non corrigée attendue")
	}
	for _, x := range f.Fixes {
		if strings.HasPrefix(x.Package, "python39:") && x.Version != "" {
			t.Fatalf("module RHEL pris pour un paquet : %+v", x)
		}
	}
	cmds := f.Commands()
	if !slices.ContainsFunc(cmds, func(c string) bool { return strings.Contains(c, "python-requests") && strings.HasPrefix(c, "rpm") }) {
		t.Fatalf("commande rpm sans python-requests : %q", cmds)
	}
	if !slices.ContainsFunc(cmds, func(c string) bool { return strings.Contains(c, "python-pip") && strings.HasPrefix(c, "dpkg-query") }) {
		t.Fatalf("commande dpkg sans python-pip : %q", cmds)
	}
}

func TestCollectGHSA(t *testing.T) {
	var calls []string
	n := 0
	f := client(t, &calls, nil).Collect(context.Background(), "GHSA-j8r2-6x86-q33q", recorder(&n))
	if f.CVE != "CVE-2023-32681" {
		t.Fatalf("alias CVE %q", f.CVE)
	}
	if strings.Count(strings.Join(calls, " "), "api.github.com") != 1 {
		t.Fatalf("GitHub appelé plusieurs fois : %v", calls)
	}
	if !f.Found() || f.EPSS == nil {
		t.Fatalf("sources CVE non interrogées : %+v", f.Sources)
	}
}

func TestCollectUnknownAndErrors(t *testing.T) {
	var calls []string
	n := 0
	f := client(t, &calls, nil).Collect(context.Background(), "CVE-2099-0001", recorder(&n))
	if f.Found() {
		t.Fatalf("identifiant inconnu trouvé : %+v", f.Sources)
	}
	calls = nil
	f = client(t, &calls, map[string]int{"nvd.nist.gov": 503, "ubuntu.com": 0}).Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	nvd, _ := f.SourceOf(NVD)
	ub, _ := f.SourceOf(Ubuntu)
	if nvd.State != StateError || ub.State != StateError || nvd.Error != "HTTP 503" {
		t.Fatalf("états %+v %+v", nvd, ub)
	}
	if c := strings.Count(strings.Join(calls, " "), "nvd.nist.gov"); c != 2 {
		t.Fatalf("NVD appelé %d fois, attendu 2 (une relance)", c)
	}
	if !f.Found() {
		t.Fatalf("CVE.org doit suffire")
	}
}

func TestDistroSelection(t *testing.T) {
	var calls []string
	n := 0
	c := client(t, &calls, nil)
	c.Distros = []string{RedHat}
	c.Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	joined := strings.Join(calls, " ")
	if strings.Contains(joined, "ubuntu.com") || strings.Contains(joined, "osv.dev") || !strings.Contains(joined, "access.redhat.com") {
		t.Fatalf("appels %v", calls)
	}
}

func TestChanged(t *testing.T) {
	var calls []string
	n := 0
	c := client(t, &calls, nil)
	old := c.Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	cur := c.Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	cur.EPSS.Score = 0.5
	if changed, _ := Changed(old, cur); changed {
		t.Fatalf("EPSS ou numéros de preuve ne doivent pas changer la fiche")
	}
	failing := client(t, &calls, map[string]int{"redhat.com": 503}).Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	if changed, _ := Changed(old, failing); changed {
		t.Fatalf("une source en échec ne change pas la fiche")
	}
	mod := client(t, &calls, nil).Collect(context.Background(), "CVE-2024-6387", recorder(&n))
	for i, s := range mod.Sources {
		if s.Name == RedHat {
			mod.Fixes = append(mod.Fixes, Fix{Distro: RedHat, Release: "Red Hat Enterprise Linux 10", Package: "openssh", Version: "0:9.9p1-1.el10", State: FixFixed, Advisory: "RHSA-2099:0001"})
			mod.Sources[i].Hash = "autre"
		}
	}
	changed, diff := Changed(old, mod)
	if !changed || len(diff) != 1 || !strings.HasPrefix(diff[0], "+ distribution : Red Hat Enterprise Linux 10 openssh fixed 0:9.9p1-1.el10") {
		t.Fatalf("changement %v %q", changed, diff)
	}
}

func TestKEVCache(t *testing.T) {
	var calls []string
	n := 0
	c := client(t, &calls, nil)
	c.Collect(context.Background(), "CVE-2026-114713", recorder(&n))
	calls = nil
	f := c.Collect(context.Background(), "CVE-2026-114713", recorder(&n))
	if strings.Contains(strings.Join(calls, " "), "cisa.gov") {
		t.Fatalf("flux KEV retéléchargé malgré le cache")
	}
	if f.KEV == nil || f.KEV.DateAdded != "2026-11-13" {
		t.Fatalf("entrée KEV %+v", f.KEV)
	}
	c.Now = func() time.Time { return time.Now().Add(7 * time.Hour) }
	calls = nil
	c.Get = fixtures(t, &calls, map[string]int{"cisa.gov": 503})
	f = c.Collect(context.Background(), "CVE-2026-114713", recorder(&n))
	if f.KEV == nil {
		t.Fatalf("cache périmé non utilisé quand la CISA ne répond pas")
	}
}

func TestSplitNEVR(t *testing.T) {
	for in, want := range map[string][2]string{
		"openssh-0:8.7p1-38.el9_4.1":       {"openssh", "0:8.7p1-38.el9_4.1"},
		"python-requests-0:2.20.0-3.el8_8": {"python-requests", "0:2.20.0-3.el8_8"},
	} {
		name, ver, ok := SplitNEVR(in)
		if !ok || name != want[0] || ver != want[1] {
			t.Fatalf("%s : %s %s %v", in, name, ver, ok)
		}
	}
	if _, _, ok := SplitNEVR("python39:3.9-8090020230922213827.7484f1d1"); ok {
		t.Fatalf("module accepté")
	}
}
