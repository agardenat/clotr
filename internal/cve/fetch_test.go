package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/cve/sources"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/tools"
)

var fixtureNames = []struct {
	re     *regexp.Regexp
	prefix string
}{
	{regexp.MustCompile(`cveawg\.mitre\.org/api/cve/(.+)$`), "cveorg"},
	{regexp.MustCompile(`cveId=(.+)$`), "nvd"},
	{regexp.MustCompile(`epss\?cve=(.+)$`), "epss"},
	{regexp.MustCompile(`advisories\?cve_id=(.+)$`), "gh"},
	{regexp.MustCompile(`securitydata/cve/(.+)\.json$`), "redhat"},
	{regexp.MustCompile(`security/cves/(.+)\.json$`), "ubuntu"},
	{regexp.MustCompile(`vulns/DEBIAN-(.+)$`), "osvdeb"},
}

func fixtureClient(t *testing.T, cacheDir string, patch func(prefix string, body []byte) []byte) *sources.Client {
	c := sources.New(nil, cacheDir)
	c.Retries = nil
	c.Get = func(_ context.Context, url string) (int, []byte, error) {
		if strings.HasSuffix(url, "known_exploited_vulnerabilities.json") {
			b, err := os.ReadFile("sources/testdata/kev.json")
			return http.StatusOK, b, err
		}
		for _, f := range fixtureNames {
			if m := f.re.FindStringSubmatch(url); m != nil {
				b, err := os.ReadFile(filepath.Join("sources/testdata", f.prefix+"-"+m[1]+".json"))
				if err != nil {
					return http.StatusNotFound, []byte(`{}`), nil
				}
				if patch != nil {
					b = patch(f.prefix, b)
				}
				return http.StatusOK, b, nil
			}
		}
		t.Fatalf("URL inattendue %s", url)
		return 0, nil, nil
	}
	return c
}

func preparedStore(t *testing.T, cacheDir string, patch func(string, []byte) []byte) (*Store, *evidence.Store) {
	ev := evidence.Open(t.TempDir(), 1)
	s := New([]string{"CVE-2024-6387"}, memory.NewStore(), ev, audit.Nop())
	s.CacheDir = cacheDir
	s.Sources = fixtureClient(t, cacheDir, patch)
	s.Prepare(context.Background())
	return s, ev
}

const narrative = `{"cve":"CVE-2024-6387","kind":"vulnerability","summary":"Condition de course dans le gestionnaire de signal de sshd","product":"OpenSSH sshd","affected":"8.5p1 à 9.7p1","fixed":"9.8p1 et versions corrigées des distributions","exposure":"sshd joignable par le réseau, sans authentification","host_component":false,"detection":"version du paquet openssh","mitigation":"LoginGraceTime 0 [E006]","remediation":"mettre à jour openssh vers la version corrigée de la distribution","evidence":["E001"]}`

func TestPrepareCacheAndChanges(t *testing.T) {
	prev := now
	now = func() time.Time { return time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC) }
	defer func() { now = prev }()
	cache := t.TempDir()
	s, _ := preparedStore(t, cache, nil)
	if !slices.Equal(s.Missing(), []string{"CVE-2024-6387"}) || s.NeedsWeb() {
		t.Fatalf("manquantes %v, web %v", s.Missing(), s.NeedsWeb())
	}
	brief := s.Brief()
	for _, want := range []string{"CVE.org : ok [E001]", "NVD : ok [E002]", "Red Hat Enterprise Linux 9 openssh fixed 0:8.7p1-38.el9_4.1 (RHSA-2024:4312)", "LoginGraceTime", "commandes de détection générées"} {
		if !strings.Contains(brief, want) {
			t.Fatalf("%q absent du brief:\n%s", want, brief)
		}
	}
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(narrative)); err != nil {
		t.Fatal(err)
	}
	a := s.Advisories()[0]
	if a.Score != "CVSS 3.1 8.1 HIGH" || a.Facts == nil || !a.Verified || a.Commands[0] != sources.OSRelease || len(a.Evidence) != 8 {
		t.Fatalf("fiche: %+v", a)
	}
	saved, err := os.ReadFile(filepath.Join(cache, "CVE-2024-6387.json"))
	if err != nil || strings.Contains(string(saved), "[E006]") {
		t.Fatalf("cache: %v %s", err, saved)
	}

	again, _ := preparedStore(t, cache, nil)
	if len(again.Missing()) != 0 {
		t.Fatalf("fiche non reprise du cache: %v", again.Missing())
	}
	b := again.Advisories()[0]
	if b.Cached != "2026-11-14" || b.Summary != a.Summary || b.Mitigation != "LoginGraceTime 0" || !slices.Equal(b.Commands, a.Commands) || b.Task != "t0" {
		t.Fatalf("fiche reprise: %+v", b)
	}

	changed, _ := preparedStore(t, cache, func(prefix string, body []byte) []byte {
		if prefix == "redhat" {
			return []byte(strings.Replace(string(body), "0:8.7p1-38.el9_4.1", "0:8.7p1-39.el9_4.1", 1))
		}
		return body
	})
	if len(changed.Missing()) != 1 {
		t.Fatalf("fiche reprise malgré une source modifiée")
	}
	if brief := changed.Brief(); !strings.Contains(brief, "Fiche précédente du 2026-11-14") || !strings.Contains(brief, "0:8.7p1-39.el9_4.1") {
		t.Fatalf("brief sans fiche précédente ni changement:\n%s", brief)
	}
	if _, err := changed.Tools()[0].Call(ctx, json.RawMessage(narrative)); err != nil {
		t.Fatal(err)
	}
	if c := changed.Advisories()[0]; len(c.Changes) == 0 || !strings.Contains(strings.Join(c.Changes, " "), "0:8.7p1-39.el9_4.1") {
		t.Fatalf("changements non joints: %+v", c.Changes)
	}
}

func TestUnknownIDNeedsWeb(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	s := New([]string{"CVE-2099-0001", "LiteLLM supply chain"}, memory.NewStore(), ev, audit.Nop())
	s.Sources = fixtureClient(t, t.TempDir(), nil)
	s.Prepare(context.Background())
	if !s.NeedsWeb() || !strings.Contains(s.Brief(), "Inconnu des sources officielles") {
		t.Fatalf("web %v brief %s", s.NeedsWeb(), s.Brief())
	}
}

func TestFicheIndicatorsAndPositives(t *testing.T) {
	prevLang := i18n.Report()
	i18n.SetReport("fr")
	defer i18n.SetReport(prevLang)
	s, ev := preparedStore(t, t.TempDir(), nil)
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(narrative)); err != nil {
		t.Fatal(err)
	}
	out := ev.Add("t1", "vm_exec", `{"host":"web1","argv":["sh","-c","rpm -qa --qf '%{NAME}' | grep openssh"]}`, "openssh-server 0:8.7p1-38.el9 openssh-8.7p1-38.el9.src.rpm", nil)
	clean := ev.Add("t1", "vm_exec", `{"host":"web2","argv":["dpkg-query","-W","openssh-server"]}`, "openssh-server 1:9.6p1-3ubuntu13.5", nil)
	if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"CVE-2024-6387","asset":"vm/web1","asset_type":"host","status":"vulnerable","os":"rhel 9.4","exposure":"limited","conditions":"port 22 joignable depuis le seul réseau d'administration","detail":"openssh 0:8.7p1-38.el9","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"CVE-2024-6387","asset":"vm/web2","asset_type":"host","status":"clean","os":"ubuntu 24.04 noble","detail":"1:9.6p1-3ubuntu13.5","evidence":["`+clean+`"]}`)); err != nil {
		t.Fatal(err)
	}
	blocks, _ := s.Blocks()
	fiche := blocks[BlockKey("CVE-2024-6387", BlockFiche)]
	pos := blocks[BlockKey("CVE-2024-6387", BlockPositives)]
	for want, in := range map[string]string{
		"| **8,1** | Élevé | CVSS 3.1 | par le réseau, complexité élevée, sans authentification, sans action d'un utilisateur |": fiche,
		"de probabilité d'exploitation sous 30 jours":                                                        fiche,
		"e percentile, mesure du 2026-11-13":                                                                 fiche,
		"- **CISA KEV** : absente du catalogue [E003]":                                                       fiche,
		"preuve de concept publique":                                                                         fiche,
		"> **Lire les indicateurs**":                                                                         fiche,
		"releases rencontrées sur les actifs (rhel 9.4, ubuntu 24.04 noble)":                                 fiche,
		"| Red Hat | Red Hat Enterprise Linux 9 | openssh | corrigé | 0:8.7p1-38.el9_4.1 | RHSA-2024:4312 |": fiche,
		"| Ubuntu | noble | openssh | corrigé | 1:9.6p1-3ubuntu13.3 |":                                       fiche,
		"> **CNA redhat · Red Hat** [E001][E006] : ":                                                         fiche,
		"**🚨 vm/web1** (hôte, rhel 9.4)\n\n- **Trouvé** : openssh 0:8.7p1-38.el9\n- **Corrigé dans** : 0:8.7p1-38.el9_4.1 (RHSA-2024:4312)": pos,
		"**limitée** : port 22 joignable": pos,
		"grep openssh`":                   pos,
	} {
		if !strings.Contains(in, want) {
			t.Fatalf("%q absent de\n%s", want, in)
		}
	}
	if strings.Contains(fiche, "jammy") || strings.Contains(fiche, "100,0") {
		t.Fatalf("lignes hors releases rencontrées ou EPSS arrondi à 100 :\n%s", fiche)
	}
}

func TestPercentAndVector(t *testing.T) {
	prev := i18n.Report()
	defer i18n.SetReport(prev)
	i18n.SetReport("fr")
	if got := percent(0.99506); got != "99,5" {
		t.Fatal(got)
	}
	if got := percent(0.99999); got != "> 99,9" {
		t.Fatal(got)
	}
	i18n.SetReport("en")
	if got := decodeVector("CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:H"); got != "local access, low complexity, attack requirements present, high privileges required, active user interaction" {
		t.Fatal(got)
	}
	for os, ok := range map[string]bool{"rocky 9.3": true, "rhel 8.10": false, "ubuntu 22.04": false, "ubuntu 24.04": true, "debian 12": false} {
		x := sources.Fix{Distro: sources.RedHat, Release: "Red Hat Enterprise Linux 9"}
		if strings.HasPrefix(os, "ubuntu") {
			x = sources.Fix{Distro: sources.Ubuntu, Release: "noble"}
		}
		if strings.HasPrefix(os, "debian") {
			x = sources.Fix{Distro: sources.Debian, Release: "Debian 13"}
		}
		if osMatch(os, x) != ok {
			t.Fatalf("%s %+v", os, x)
		}
	}
}
