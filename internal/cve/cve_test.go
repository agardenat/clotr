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
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-0001","product":"x","affected":"x","fixed":"x","detection":"x"}`)); err == nil || !strings.Contains(err.Error(), "commands") {
		t.Fatalf("fiche sans commandes: %v", err)
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-9999","product":"x","affected":"x","fixed":"x","detection":"x","commands":["x"]}`)); err == nil {
		t.Fatal("CVE hors demande acceptée")
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"cve-2026-0001","product":"PHP","affected":"8.2 < 8.2.27","fixed":"8.2.27","detection":"php -v","commands":["php -v","rpm -qa  | grep -i php"],"evidence":["`+src+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Commands(), []string{"php -v", "rpm -qa | grep -i php"}) || !strings.Contains(s.Advisories()[0].line(), "`rpm -qa | grep -i php`") {
		t.Fatalf("commandes: %v", s.Commands())
	}
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-0001","product":"x","affected":"x","fixed":"x","detection":"x","commands":["a\nb"]}`)); err == nil {
		t.Fatal("commande multiligne acceptée")
	}
	if len(s.Missing()) != 0 || !s.Advisories()[0].Verified {
		t.Fatalf("fiche: %+v", s.Advisories())
	}

	bad := []string{
		`{"cve":"CVE-2026-0001","asset":"k/p","status":"clean","detail":"d","evidence":[]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","status":"maybe","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":" ","status":"clean","detail":"d","evidence":["` + out + `"]}`,
		`{"cve":"CVE-2026-0001","asset":"k/p","status":"clean","detail":"d","evidence":["E999"]}`,
	}
	for _, b := range bad {
		if _, err := rep.Call(t1, json.RawMessage(b)); err == nil {
			t.Fatalf("accepté: %s", b)
		}
	}
	if _, err := rep.Call(t1, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"k8s/prod/web/app","status":"unknown","detail":"php absent du PATH","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := rep.Call(t1, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"/k8s/prod/web/app/","status":"vulnerable","detail":"php 8.2.4 < 8.2.27","evidence":["`+out+`"]}`)); err != nil {
		t.Fatal(err)
	}
	if res, err := rep.Call(t2, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"k8s/prod/web/app","status":"vulnerable","detail":"php 8.2.4 < 8.2.27","evidence":["`+out+`"]}`)); err != nil || !strings.Contains(res, "déjà signalé par t1") {
		t.Fatalf("doublon: %q %v", res, err)
	}
	if _, err := rep.Call(t2, json.RawMessage(`{"cve":"CVE-2026-0001","asset":"vm/web1","status":"clean","detail":"paquet php absent (rpm -q)","evidence":["`+out+`"]}`)); err != nil {
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

	sec := s.Section()
	for _, want := range []string{"| CVE-2026-0001 | PHP | 8.2 < 8.2.27 | 8.2.27 | [E001] |", "🚨 1", "✅ 1", "| 🚨 | k8s/prod/web/app | 🚨 | php 8.2.4 < 8.2.27 | [E002] |", "- `vm` (1) : web1"} {
		if !strings.Contains(sec, want) {
			t.Fatalf("%q absent de\n%s", want, sec)
		}
	}

}

func TestUnverifiedAdvisory(t *testing.T) {
	s := New([]string{"CVE-2026-0002"}, memory.NewStore(), evidence.Open(t.TempDir(), 1), audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0002","product":"x","affected":"y","fixed":"z","detection":"w","commands":["x --version"]}`)); err != nil {
		t.Fatal(err)
	}
	if a := s.Advisories()[0]; a.Verified || !strings.Contains(a.line(), "NON VÉRIFIÉE") {
		t.Fatalf("%+v", a)
	}
	if s.Section() == "" {
		t.Fatal("section vide")
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
	for range ReminderEvery {
		ev.Add("t0", "k8s_pod_exec", "{}", "out", nil)
	}
	if s.Inbox(tools.Caller{Task: "t0"}) != "" {
		t.Fatal("rappel à la tâche des fiches")
	}
	for range ReminderEvery - 1 {
		ev.Add("t2", "k8s_pod_exec", "{}", "out", nil)
	}
	ctx := tools.WithCaller(context.Background(), reader)
	if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0003","asset":"a/b","status":"unknown","detail":"d","evidence":["`+last+`"]}`)); err != nil {
		t.Fatal(err)
	}
	ev.Add("t2", "k8s_pod_exec", "{}", "out", nil)
	if got := s.Inbox(reader); strings.Contains(got, "Rappel") {
		t.Fatalf("compteur non remis à zéro par cve_report: %q", got)
	}
}

func TestSectionCompact(t *testing.T) {
	ev := evidence.Open(t.TempDir(), 1)
	e := ev.Add("t1", "x", "{}", "o", nil)
	s := New([]string{"CVE-A-0001", "CVE-B-0002"}, memory.NewStore(), ev, audit.Nop())
	s.IDs = []string{"CVE-2026-0010", "CVE-2026-0011"}
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t1"})
	rep := func(cve, asset, status, detail string) {
		t.Helper()
		if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"`+cve+`","asset":"`+asset+`","status":"`+status+`","detail":"`+detail+`","evidence":["`+e+`"]}`)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 50 {
		a := fmt.Sprintf("k8s/prod/ns%d/app-%d/main", i%3, i)
		rep("CVE-2026-0010", a, "clean", strings.Repeat("aucun php dans l'image ", 10))
		rep("CVE-2026-0011", a, "clean", strings.Repeat("aucun php dans l'image ", 10))
	}
	rep("CVE-2026-0010", "k8s/prod/ns0/legacy/php", "vulnerable", "php 8.1.2")
	rep("CVE-2026-0011", "k8s/prod/ns0/legacy/php", "clean", "fpm absent")
	rep("CVE-2026-0010", "vm/web1", "clean", "rpm sans php")
	sec := s.Section()
	for _, want := range []string{"🚨 1 vulnerable · ❓ 1 undetermined · ✅ 50 clean (52 assets)", "| 🚨 | k8s/prod/ns0/legacy/php | 🚨 | ✅ | php 8.1.2 |", "| ❓ | vm/web1 | ✅ | — |", "- `k8s/prod/ns0` (17) : app-0/main, app-12/main"} {
		if !strings.Contains(sec, want) {
			t.Fatalf("%q absent de\n%s", want, sec)
		}
	}
	if strings.Contains(sec, "aucun php dans l'image") || len(sec) > 4000 {
		t.Fatalf("détails des sains repris ou tableau trop long (%d)", len(sec))
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
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"litellm 1.107.0 SUPPLY chain","kind":"compromise","product":"litellm (PyPI)","affected":"1.107.0","fixed":"1.106.x","detection":"pip show litellm","commands":["pip show litellm"],"iocs":["/tmp/.x","evil.example"]}`)); err != nil {
		t.Fatal(err)
	}
	a := s.Advisories()[0]
	if a.CVE != subject || a.Kind != KindCompr || len(a.IOCs) != 2 || !strings.Contains(a.line(), "(compromission)") || !strings.Contains(a.line(), "evil.example") {
		t.Fatalf("fiche: %+v", a)
	}
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"`+subject+`","kind":"ransomware","product":"x","affected":"x","fixed":"x","detection":"x","commands":["x"]}`)); err == nil {
		t.Fatal("kind invalide accepté")
	}
	for asset, st := range map[string]string{"gw/clovis": "compromised", "gw/onellm": "vulnerable", "gw/other": "clean"} {
		if _, err := s.Tools()[1].Call(ctx, json.RawMessage(`{"cve":"`+subject+`","asset":"`+asset+`","status":"`+st+`","detail":"d","evidence":["`+e+`"]}`)); err != nil {
			t.Fatal(err)
		}
	}
	sec := s.Section()
	if !strings.Contains(sec, "☠️ 1 compromised · 🚨 1 vulnerable") || strings.Index(sec, "| ☠️ | gw/clovis") > strings.Index(sec, "| 🚨 | gw/onellm") || strings.Index(sec, "| ☠️ | gw/clovis") < 0 {
		t.Fatalf("section:\n%s", sec)
	}
}
