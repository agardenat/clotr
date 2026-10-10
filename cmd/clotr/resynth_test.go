package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestToolFilterFromAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	data := `{"kind":"other"}
{"kind":"run_start","tools":["prod_api_get","prod_ssh_tail","memory_write","mcp_tracker_issue_get","k8s_list"]}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := toolFilterFromAudit(path); !slices.Equal(got, []string{"prod", "mcp_tracker", "k8s"}) {
		t.Fatalf("filtre: %v", got)
	}
}
