package progress

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONPrinter(t *testing.T) {
	var buf bytes.Buffer
	p := NewJSON(&buf)
	p.Emit(Event{Task: "planner", Kind: "plan", Plan: []PlanItem{{ID: "t1", Role: "infra", Goal: "hôtes <acme>"}}})
	p.Emit(Event{Task: "t1", Kind: "stream", Detail: "ignored"})
	p.Emit(Event{Task: "t1", Kind: "cve", Detail: "✅ CVE-2026-1 · web01", Status: "clean"})
	p.Emit(Event{Task: "t1", Kind: "done", Cost: 0.5, Duration: 1500 * time.Millisecond})
	p.Close()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("3 lignes attendues, %d : %q", len(lines), buf.String())
	}
	var plan struct {
		Kind string `json:"kind"`
		Plan []struct {
			ID   string `json:"id"`
			Goal string `json:"goal"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &plan); err != nil || plan.Kind != "plan" || len(plan.Plan) != 1 || plan.Plan[0].ID != "t1" || plan.Plan[0].Goal != "hôtes <acme>" {
		t.Fatalf("plan : %v %+v", err, plan)
	}
	if !strings.Contains(lines[0], "<acme>") {
		t.Fatalf("HTML échappé : %s", lines[0])
	}
	var cve map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &cve); err != nil || cve["status"] != "clean" || cve["task"] != "t1" {
		t.Fatalf("cve : %v %v", err, cve)
	}
	var done map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &done); err != nil || done["duration"] != 1.5 || done["cost"] != 0.5 {
		t.Fatalf("done : %v %v", err, done)
	}
}
