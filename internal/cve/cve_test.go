package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

type sink struct {
	mu     sync.Mutex
	events []progress.Event
}

func (s *sink) Emit(e progress.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func TestExtract(t *testing.T) {
	got := Extract("failles cve-2026-109618 & CVE-2026-109619, puis CVE-2026-109618 ; pas CVE-26-1 ni XCVE-2026-1234")
	if !slices.Equal(got, []string{"CVE-2026-109618", "CVE-2026-109619"}) {
		t.Fatal(got)
	}
}

func TestAdvisoryReportAndInbox(t *testing.T) {
	mem := memory.NewStore()
	ev := evidence.Open(t.TempDir(), 1)
	src := ev.Add("t0", "web_search", "{}", "PHP 8.2.27 fixes CVE-2026-0001", nil)
	out := ev.Add("t1", "k8s_pod_exec", "{}", "PHP 8.2.4", nil)
	s := New([]string{"CVE-2026-0001"}, mem, ev, audit.Nop())
	events := &sink{}
	s.Events = events
	adv, rep := s.Tools()[0], s.Tools()[1]
	t0 := tools.WithCaller(context.Background(), tools.Caller{Task: "t0", Sovereign: true})
	t1 := tools.WithCaller(context.Background(), tools.Caller{Task: "t1", Sovereign: true})
	t2 := tools.WithCaller(context.Background(), tools.Caller{Task: "t2", Sovereign: true})

	if !slices.Equal(s.Missing(), []string{"CVE-2026-0001"}) {
		t.Fatal(s.Missing())
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-0001","product":"x","affected":"x","fixed":"x","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"x","summary":"s","mitigation":"m","remediation":"r"}`)); err == nil || !strings.Contains(err.Error(), "commands") {
		t.Fatalf("fiche sans commandes: %v", err)
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-9999","product":"x","affected":"x","fixed":"x","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"x","summary":"s","mitigation":"m","remediation":"r","commands":["x"]}`)); err == nil {
		t.Fatal("CVE hors demande acceptée")
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"cve-2026-0001","product":"PHP","affected":"8.2 < 8.2.27","fixed":"8.2.27","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"php -v","summary":"s","mitigation":"m","remediation":"r","commands":["php -v","rpm -qa  | grep -i php"],"evidence":["`+src+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Commands(), []string{"php -v", "rpm -qa | grep -i php"}) || !strings.Contains(s.Advisories()[0].line(), "`rpm -qa | grep -i php`") {
		t.Fatalf("commandes: %v", s.Commands())
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-0001","product":"x","affected":"x","fixed":"x","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"x","summary":"s","mitigation":"m","remediation":"r","commands":["a\nb"]}`)); err == nil {
		t.Fatal("commande multiligne acceptée")
	}
	if len(s.Missing()) != 0 || !s.Advisories()[0].Verified {
		t.Fatalf("fiche: %+v", s.Advisories())
	}

	bad := []string{
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"clean","detail":"d","evidence":[]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"maybe","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":" ","asset_type":"host","status":"clean","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"clean","detail":"d","evidence":["E999"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","status":"clean","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"pod","status":"clean","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"vulnerable","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"vulnerable","exposure":"exposed","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","asset_type":"host","status":"vulnerable","exposure":"maybe","conditions":"c","detail":"d","evidence":["` + out + `"]}`,
	}
	for _, b := range bad {
		if _, err := rep.Call(t1, json.RawMessage(b)); err == nil {
			t.Fatalf("accepté: %s", b)
		}
	}
	if _, err := rep.Call(t1, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"k8s/prod/web/app","asset_type":"workload","status":"unknown","detail":"php absent du PATH","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := rep.Call(t1, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"/k8s/prod/web/app/","asset_type":"workload","status":"vulnerable","exposure":"exposed","conditions":"ingress public","os":"debian 12 bookworm","detail":"php 8.2.4 < 8.2.27","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if res, err := rep.Call(t2, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"k8s/prod/web/app","asset_type":"workload","status":"vulnerable","exposure":"exposed","conditions":"ingress public","os":"debian 12 bookworm","detail":"php 8.2.4 < 8.2.27","evidence":["`+out+`"]}`)); err != nil || !strings.Contains(res, "déjà signalé par t1") {
		t.Fatalf("doublon: %q %v", res, err)
	}
	if _, err := rep.Call(t2, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"vm/web1","asset_type":"host","status":"clean","detail":"paquet php absent (rpm -q)","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	f := s.Findings()
	if len(f) != 2 || f[0].Status != Vulnerable || f[0].Previous != Unknown || f[0].Asset != "k8s/prod/web/app" {
		t.Fatalf("statuts: %+v", f)
	}
	last := events.events[len(events.events)-2]
	if last.Kind != "cve" || last.Status != Vulnerable || !strings.HasPrefix(last.Detail, "🚨 CVE-2026-0001 · k8s/prod/web/app") || !strings.Contains(last.Detail, "❓") {
		t.Fatalf("événement: %+v", last)
	}

	in1 := s.Inbox(tools.Caller{Task: "t1"})
	if strings.Contains(in1, "k8s/prod/web/app") || !strings.Contains(in1, "fiche") && !strings.Contains(in1, "CVE-2026-0001 : PHP") || !strings.Contains(in1, "[sain] CVE-2026-0001 · vm/web1") {
		t.Fatalf("inbox t1: %q", in1)
	}
	if s.Inbox(tools.Caller{Task: "t1"}) != "" {
		t.Fatal("inbox relue")
	}
	if n := len(mem.All()); n != 3 {
		t.Fatalf("%d entrées mémoire", n)
	}

	blocks, order := s.Blocks()
	if len(order) != len(BlockNames) {
		t.Fatalf("ordre des blocs: %v", order)
	}
	sec := strings.Join([]string{blocks[BlockKey("CVE-2026-0001", BlockVerdict)], blocks[BlockKey("CVE-2026-0001", BlockFiche)], blocks[BlockKey("CVE-2026-0001", BlockPositives)], blocks[BlockKey("CVE-2026-0001", BlockNegatives)]}, "\n")
	for _, want := range []string{"- **Score**: CVSS 3.1 9.8 CRITICAL", "🚨 1 vulnerable", "✅ 1 clean", "1 exposed", "**🚨 k8s/prod/web/app** (workload, debian 12 bookworm)\n\n- **Found**: php 8.2.4 < 8.2.27\n- **Exposure**: **exposed**: ingress public\n- **Deciding test**: `k8s_pod_exec` [E002]\n- **Evidence**: [E002]", "**Hosts** (1)", "- `vm` (1): web1"} {
		if !strings.Contains(sec, want) {
			t.Fatalf("%q absent de\n%s", want, sec)
		}
	}

}

func TestUnverifiedAdvisory(t *testing.T) {
	s := New([]string{"CVE-2026-0002"}, memory.NewStore(), evidence.Open(t.TempDir(), 1), audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0002","product":"x","affected":"y","fixed":"z","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"w","summary":"s","mitigation":"m","remediation":"r","commands":["x --version"]}`)); err != nil {
		t.Fatal(err)
	}
	if a := s.Advisories()[0]; a.Verified || !strings.Contains(a.line(), "NON VÉRIFIÉE") {
		t.Fatalf("%+v", a)
	}
	blocks, _ := s.Blocks()
	if !strings.Contains(blocks[BlockKey("CVE-2026-0002", BlockFiche)], "outside official sources") {
		t.Fatalf("fiche hors sources non signalée:\n%s", blocks[BlockKey("CVE-2026-0002", BlockFiche)])
	}
}

func TestReminder(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	s := New([]string{"CVE-2026-0003"}, memory.NewStore(), ev, audit.Nop())
	reader := tools.Caller{Task: "t2"}
	for i := range ReminderEvery - 1 {
		ev.Add("t2", "k8s_pod_exec", "{}", "out", nil)
		ev.Add("t2", "evidence_read", "{}", "out", nil)
		if i == 0 {
			ev.Add("t0", "k8s_pod_exec", "{}", "out", nil)
		}
	}
	if got := s.Inbox(reader); got != "" {
		t.Fatalf("rappel trop tôt: %q", got)
	}
	last := ev.Add("t2", "k8s_run_pod", "{}", "out", nil)
	got := s.Inbox(reader)
	if !strings.Contains(got, "Rappel : 4 sorties") || !strings.Contains(got, ReportTool) {
		t.Fatalf("rappel: %q", got)
	}
	if s.Inbox(reader) != "" {
		t.Fatal("rappel répété sans nouvelle sortie")
	}
	for range ReminderEvery - 1 {
		ev.Add("t2", "k8s_pod_exec", "{}", "out", nil)
	}
	ctx := tools.WithCaller(context.Background(), reader)
	if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0003","asset":"a/b","asset_type":"host","status":"unknown","detail":"d","evidence":["`+last+`"]}`)); err != nil {
		t.Fatal(err)
	}
	ev.Add("t2", "k8s_pod_exec", "{}", "out", nil)
	if got := s.Inbox(reader); strings.Contains(got, "Rappel") {
		t.Fatalf("compteur non remis à zéro par cve_report: %q", got)
	}
}

func TestTriageReminder(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	s := New([]string{"CVE-2026-0003", "CVE-2026-0004"}, memory.NewStore(), ev, audit.Nop())
	reader := tools.Caller{Task: "t0"}
	for range ReminderEvery - 1 {
		ev.Add("t0", "mcp_websearch_search", "{}", "out", nil)
		ev.Add("t0", "evidence_read", "{}", "out", nil)
	}
	if got := s.Inbox(reader); got != "" {
		t.Fatalf("rappel trop tôt: %q", got)
	}
	last := ev.Add("t0", "mcp_websearch_search", "{}", "out", nil)
	got := s.Inbox(reader)
	if !strings.Contains(got, "Rappel : 4 sorties") || !strings.Contains(got, AdvisoryTool) || !strings.Contains(got, "CVE-2026-0003, CVE-2026-0004") {
		t.Fatalf("rappel: %q", got)
	}
	if s.Inbox(reader) != "" {
		t.Fatal("rappel répété sans nouvelle sortie")
	}
	for range ReminderEvery {
		ev.Add("t0", "mcp_websearch_search", "{}", "out", nil)
	}
	ctx := tools.WithCaller(context.Background(), reader)
	fiche := func(id string) json.RawMessage {
		return json.RawMessage(`{"cve":"` + id + `","product":"p","affected":"a","fixed":"f","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"d","summary":"s","mitigation":"m","remediation":"r","commands":["p -v"],"evidence":["` + last + `"]}`)
	}
	if _, err := s.Tools()[0].Call(ctx, fiche("CVE-2026-0003")); err != nil {
		t.Fatal(err)
	}
	if got := s.Inbox(reader); strings.Contains(got, "Rappel") {
		t.Fatalf("compteur non remis à zéro par la fiche: %q", got)
	}
	for range ReminderEvery {
		ev.Add("t0", "mcp_websearch_search", "{}", "out", nil)
	}
	got = s.Inbox(reader)
	if !strings.Contains(got, "sujets sans fiche : CVE-2026-0004.") {
		t.Fatalf("sujets manquants: %q", got)
	}
	if _, err := s.Tools()[0].Call(ctx, fiche("CVE-2026-0004")); err != nil {
		t.Fatal(err)
	}
	for range ReminderEvery {
		ev.Add("t0", "mcp_websearch_search", "{}", "out", nil)
	}
	if got := s.Inbox(reader); strings.Contains(got, "Rappel") {
		t.Fatalf("rappel alors que toutes les fiches existent: %q", got)
	}
}

func TestBlocksCompact(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	e := ev.Add("t1", "k8s_pod_exec", `{"argv":["sh","-c","rpm -qa | grep php"]}`, "o", nil)
	s := New([]string{"CVE-2026-0010", "CVE-2026-0011"}, memory.NewStore(), ev, audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	rep := func(cve, asset, typ, status, detail string) {
		t.Helper()
		extra := ""
		if status == Vulnerable {
			extra = `,"exposure":"limited","conditions":"php-fpm non publié"`
		}
		if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"`+cve+`","asset":"`+asset+`","asset_type":"`+typ+`","status":"`+status+`","detail":"`+detail+`","evidence":["`+e+`"]`+extra+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 50 {
		a := fmt.Sprintf("k8s/prod/ns%d/app-%d/main", i%3, i)
		rep("CVE-2026-0010", a, "workload", "clean", strings.Repeat("aucun php dans l'image ", 10))
		rep("CVE-2026-0011", a, "workload", "clean", strings.Repeat("aucun php dans l'image ", 10))
	}
	rep("CVE-2026-0010", "k8s/prod/ns0/legacy/php", "workload", "vulnerable", "php 8.1.2")
	rep("CVE-2026-0011", "k8s/prod/ns0/legacy/php", "workload", "clean", "fpm absent")
	rep("CVE-2026-0010", "vm/web1", "host", "clean", "rpm sans php")
	rep("CVE-2026-0010", "vm/web2", "host", "unknown", "accès refusé")
	blocks, _ := s.Blocks()
	verdict := blocks[BlockKey("CVE-2026-0010", BlockVerdict)]
	pos := blocks[BlockKey("CVE-2026-0010", BlockPositives)]
	unk := blocks[BlockKey("CVE-2026-0010", BlockUnknown)]
	neg := blocks[BlockKey("CVE-2026-0010", BlockNegatives)]
	for want, in := range map[string]string{
		"🚨 1 vulnerable · ❓ 1 undetermined · ✅ 51 clean (53 assets)": verdict,
		"1 limited exposure": verdict,
		"**🚨 k8s/prod/ns0/legacy/php** (workload)\n\n- **Found**: php 8.1.2\n- **Exposure**: **limited**: php-fpm non publié\n- **Deciding test**: `rpm -qa | grep php` [E001]": pos,
		"**❓ vm/web2** (host)\n\n- **What is missing**: accès refusé": unk,
		"**Workloads** (50)":                             neg,
		"- `k8s/prod/ns0` (17): app-0/main, app-12/main": neg,
		"tests: `rpm -qa | grep php`":                    neg,
		"**Hosts** (1)":                                  neg,
	} {
		if !strings.Contains(in, want) {
			t.Fatalf("%q absent de\n%s", want, in)
		}
	}
	if strings.Contains(neg, "aucun php dans l'image") || len(neg) > 4000 {
		t.Fatalf("détails des sains repris ou bloc trop long (%d)", len(neg))
	}
	if got := blocks[BlockKey("CVE-2026-0011", BlockPositives)]; got != "No positive asset." {
		t.Fatalf("positifs CVE-2026-0011: %q", got)
	}
}

func TestSubjectsAndCompromise(t *testing.T) {
	if got := Extract("avis ghsa-ABCD-1234-wxyz et CVE-2026-0001"); !slices.Equal(got, []string{"GHSA-abcd-1234-wxyz", "CVE-2026-0001"}) {
		t.Fatal(got)
	}
	if got := Subjects("auto", "vérifie CVE-2026-0001"); !slices.Equal(got, []string{"CVE-2026-0001"}) {
		t.Fatal(got)
	}
	if got := Subjects("LiteLLM 1.107.0  supply chain", "vérifie les passerelles"); !slices.Equal(got, []string{"LiteLLM 1.107.0 supply chain"}) {
		t.Fatal(got)
	}
	if got := Subjects("", "rien"); len(got) != 0 {
		t.Fatal(got)
	}
	ev := evidence.Open(t.TempDir(), 1)
	e := ev.Add("t1", "x", "{}", "o", nil)
	subject := "LiteLLM 1.107.0 supply chain"
	s := New([]string{subject}, memory.NewStore(), ev, audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"litellm 1.107.0 SUPPLY chain","kind":"compromise","product":"litellm (PyPI)","affected":"1.107.0","fixed":"1.106.x","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"pip show litellm","summary":"s","mitigation":"m","remediation":"r","commands":["pip show litellm"],"iocs":["/tmp/.x","evil.example"]}`)); err != nil {
		t.Fatal(err)
	}
	a := s.Advisories()[0]
	if a.CVE != subject || a.Kind != KindCompr || len(a.IOCs) != 2 || !strings.Contains(a.line(), "(compromission)") || !strings.Contains(a.line(), "evil.example") {
		t.Fatalf("fiche: %+v", a)
	}
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"`+subject+`","kind":"ransomware","product":"x","affected":"x","fixed":"x","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"x","summary":"s","mitigation":"m","remediation":"r","commands":["x"]}`)); err == nil {
		t.Fatal("kind invalide accepté")
	}
	for asset, st := range map[string]string{"gw/alpha": "compromised", "gw/beta": "vulnerable", "gw/other": "clean"} {
		if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"`+subject+`","asset":"`+asset+`","asset_type":"service","status":"`+st+`","exposure":"unmeasured","conditions":"non mesuré","detail":"d","evidence":["`+e+`"]}`)); err != nil {
			t.Fatal(err)
		}
	}
	blocks, _ := s.Blocks()
	verdict, pos := blocks[BlockKey(subject, BlockVerdict)], blocks[BlockKey(subject, BlockPositives)]
	if !strings.Contains(verdict, "☠️ 1 compromised · 🚨 1 vulnerable") || strings.Index(pos, "| ☠️ | gw/alpha") > strings.Index(pos, "| 🚨 | gw/beta") || strings.Index(pos, "| ☠️ | gw/alpha") < 0 {
		t.Fatalf("blocs:\n%s\n%s", verdict, pos)
	}
	if f := s.Findings(); slices.ContainsFunc(f, func(x Finding) bool { return x.Status == Clean && x.Exposure != "" }) {
		t.Fatalf("exposition gardée sur un actif sain: %+v", f)
	}
}

func TestHostComponent(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	e := ev.Add("t1", "x", "{}", "o", nil)
	s := New([]string{"CVE-2026-0020"}, memory.NewStore(), ev, audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	adv, rep := s.Tools()[0], s.Tools()[1]
	base := `"cve":"CVE-2026-0020","product":"noyau","affected":"< 2","fixed":"2","score":"non publié","detection":"uname -r","commands":["uname -r"],"summary":"s","mitigation":"m","remediation":"r"`
	if _, err := adv.Call(ctx, json.RawMessage(`{`+base+`}`)); err == nil || !strings.Contains(err.Error(), "host_component") {
		t.Fatalf("fiche sans host_component: %v", err)
	}
	if _, err := adv.Call(ctx, json.RawMessage(`{`+base+`,"host_component":true}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Advisories()[0].line(), "composant de l'hôte") {
		t.Fatal(s.Advisories()[0].line())
	}
	report := func(asset, status, extra string) error {
		if status == Vulnerable {
			extra += `,"exposure":"exposed","conditions":"c"`
		}
		_, err := rep.Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0020","asset":"`+asset+`","status":"`+status+`","detail":"d","evidence":["`+e+`"]`+extra+`}`))
		return err
	}
	const work = `,"asset_type":"workload"`
	if err := report("k8s/prod/ns/web", "clean", ""); err == nil || !strings.Contains(err.Error(), "asset_type") {
		t.Fatalf("sans asset_type: %v", err)
	}
	if err := report("k8s/prod/ns/web", "clean", work); err == nil || !strings.Contains(err.Error(), "runs_on") {
		t.Fatalf("workload sain sans hôte: %v", err)
	}
	if err := report("k8s/prod/ns/web", "vulnerable", work+`,"runs_on":["vm/n1"]`); err == nil || !strings.Contains(err.Error(), "vm/n1") {
		t.Fatalf("hôte non signalé: %v", err)
	}
	if err := report("k8s/prod/ns/web", "unknown", work); err != nil {
		t.Fatalf("indéterminé sans hôte: %v", err)
	}
	for asset, status := range map[string]string{"vm/n1": "vulnerable", "vm/n2": "clean", "vm/n3": "unknown"} {
		if err := report(asset, status, `,"asset_type":"host"`); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		status, hosts string
		ok            bool
	}{
		{"clean", `"vm/n1"`, false},
		{"clean", `"vm/n3"`, false},
		{"clean", `"vm/n2","vm/n1"`, false},
		{"vulnerable", `"vm/n2"`, false},
		{"vulnerable", `"vm/n3"`, false},
		{"clean", `"VM/n2"`, true},
		{"vulnerable", `"vm/n2","vm/n3","vm/n1"`, true},
	} {
		err := report("k8s/prod/ns/web", c.status, work+`,"runs_on":[`+c.hosts+`]`)
		if (err == nil) != c.ok {
			t.Fatalf("%s sur %s: %v", c.status, c.hosts, err)
		}
	}
	for i := range 6 {
		if err := report(fmt.Sprintf("vm/x%d", i), "vulnerable", `,"asset_type":"host"`); err != nil {
			t.Fatal(err)
		}
	}
	if err := report("k8s/prod/ns/dae", "vulnerable", work+`,"runs_on":["vm/x0","vm/x1","vm/x2","vm/x3","vm/x4"]`); err != nil {
		t.Fatal(err)
	}
	blocks, _ := s.Blocks()
	if sec := blocks[BlockKey("CVE-2026-0020", BlockPositives)]; !strings.Contains(sec, "on vm/x0, vm/x1, vm/x2 +2 : d") {
		t.Fatalf("hôtes absents du tableau:\n%s", sec)
	}
	if err := report("k8s/prod/ns/img", "clean", `,"asset_type":"image"`); err == nil || !strings.Contains(err.Error(), "host ou workload") {
		t.Fatalf("image acceptée pour un composant de l'hôte: %v", err)
	}
	f := s.Findings()
	if got := f[len(f)-1].RunsOn; len(got) != 5 {
		t.Fatalf("runs_on: %v", got)
	}
}

func TestNotHostComponentKeepsImageRule(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	e := ev.Add("t1", "x", "{}", "o", nil)
	s := New([]string{"CVE-2026-0021"}, memory.NewStore(), ev, audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0021","product":"php","affected":"< 2","fixed":"2","score":"CVSS 3.1 9.8 CRITICAL","host_component":false,"detection":"php -v","summary":"s","mitigation":"m","remediation":"r","commands":["php -v"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0021","asset":"k8s/prod/ns/web","asset_type":"image","status":"clean","detail":"php absent de l'image","evidence":["`+e+`"]}`)); err != nil {
		t.Fatalf("image sans le composant: %v", err)
	}
}

func TestAdvisoryScoreAndCard(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	src := ev.Add("t0", "web", "{}", "avis", nil)
	s := New([]string{"CVE-2026-0005"}, memory.NewStore(), ev, audit.Nop())
	rec := &cardEvents{}
	s.Events = rec
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0"})
	base := `"cve":"CVE-2026-0005","product":"Noyau","affected":"< 6.6.159","fixed":"6.6.159","host_component":true,"detection":"version du noyau","summary":"s","mitigation":"m","remediation":"r","commands":["uname -r","rpm -q kernel"],"evidence":["` + src + `"]`
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{`+base+`}`)); err == nil || !strings.Contains(err.Error(), "score requis") {
		t.Fatalf("faille sans score acceptée: %v", err)
	}
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{`+base+`,"score":"CVSS 3.1 7.8 HIGH"}`)); err != nil {
		t.Fatal(err)
	}
	if rec.card == nil || rec.card.Title != "CVE-2026-0005" || rec.card.Score != "CVSS 3.1 7.8 HIGH" {
		t.Fatalf("carte: %+v", rec.card)
	}
	var commands []string
	for _, f := range rec.card.Fields {
		if f.Code {
			commands = f.Lines
		}
	}
	if !slices.Equal(commands, []string{"uname -r", "rpm -q kernel"}) {
		t.Fatalf("commandes: %v", commands)
	}
	if blocks, _ := s.Blocks(); !strings.Contains(blocks[BlockKey("CVE-2026-0005", BlockFiche)], "CVSS 3.1 7.8 HIGH") {
		t.Fatalf("score absent du rapport: %s", blocks[BlockKey("CVE-2026-0005", BlockFiche)])
	}
	if adv := s.Advisories()[0]; !strings.Contains(adv.line(), "score : CVSS 3.1 7.8 HIGH") {
		t.Fatalf("score absent de la fiche transmise: %s", adv.line())
	}
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0005","kind":"compromise","product":"p","affected":"1.0","fixed":"0.9","host_component":false,"detection":"d","summary":"s","mitigation":"m","remediation":"r","commands":["p -v"]}`)); err != nil {
		t.Fatalf("compromission sans score refusée: %v", err)
	}
}

type cardEvents struct {
	progress.Nop
	card *progress.Card
}

func (c *cardEvents) Emit(e progress.Event) {
	if e.Card != nil {
		c.card = e.Card
	}
}
