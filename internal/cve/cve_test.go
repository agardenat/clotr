package cve

import (
	"context"
	"encoding/json"
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
	if _, err := adv.Call(t0, json.RawMessage(`{"cve":"CVE-2026-9999","product":"x","affected":"x","fixed":"x","detection":"x"}`)); err == nil {
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
	for _, want := range []string{"| CVE-2026-0001 | PHP | 8.2 < 8.2.27 | 8.2.27 | [E001] |", "🚨 1", "✅ 1", "| 🚨 | CVE-2026-0001 | k8s/prod/web/app |"} {
		if !strings.Contains(sec, want) {
			t.Fatalf("%q absent de\n%s", want, sec)
		}
	}
	if strings.Index(sec, "🚨 | CVE") > strings.Index(sec, "✅ | CVE") {
		t.Fatal("vulnérables d'abord")
	}
}

func TestUnverifiedAdvisory(t *testing.T) {
	s := New([]string{"CVE-2026-0002"}, memory.NewStore(), evidence.Open(t.TempDir(), 1), audit.Nop())
	ctx := tools.WithCaller(context.Background(), tools.Caller{Task: "t0"})
	if _, err := s.Tools()[0].Call(ctx, json.RawMessage(`{"cve":"CVE-2026-0002","product":"x","affected":"y","fixed":"z","detection":"w"}`)); err != nil {
		t.Fatal(err)
	}
	if a := s.Advisories()[0]; a.Verified || !strings.Contains(a.line(), "NON VÉRIFIÉE") {
		t.Fatalf("%+v", a)
	}
	if s.Section() == "" {
		t.Fatal("section vide")
	}
}
