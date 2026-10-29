package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/cve"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/memory"
)

func TestToolFilterFromAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	data := `{"kind":"other"}
{"kind":"run_start","tools":["prod_api_get","prod_ssh_tail","memory_write","mcp_tracker_issue_get","k8s_list","cve_report","cve_advisory"]}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := toolFilterFromAudit(path); !slices.Equal(got, []string{"prod", "mcp_tracker", "k8s"}) {
		t.Fatalf("filtre: %v", got)
	}
}

func TestCVEFromAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	data := `{"kind":"cve_advisory","advisory":{"cve":"CVE-2026-0010","product":"php","affected":"< 8.2.27","fixed":"8.2.27","kind":"vulnerability","detection":"php -v","task":"t0"}}
{"kind":"cve_report","finding":{"cve":"CVE-2026-0010","asset":"vm/web1","status":"unknown","detail":"pas d'inventaire","task":"t1"}}
{"kind":"cve_report","finding":{"cve":"CVE-2026-0010","asset":"vm/web2","status":"clean","detail":"rpm sans php","task":"t1"}}
{"kind":"cve_report","finding":{"cve":"CVE-2026-0010","asset":"VM/web1","status":"vulnerable","detail":"php 8.1.2","task":"t2"}}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s := cve.New([]string{"CVE-2026-0010"}, memory.NewStore(), evidence.Open(t.TempDir(), 1), audit.Nop())
	s.Restore(cveFromAudit(path))
	if len(s.Missing()) != 0 || len(s.Findings()) != 2 {
		t.Fatalf("fiches manquantes %v, statuts %v", s.Missing(), s.Findings())
	}
	sec := s.Section()
	if !strings.Contains(sec, "php 8.1.2") || strings.Contains(sec, "pas d'inventaire") {
		t.Fatalf("dernier statut non retenu :\n%s", sec)
	}
}
