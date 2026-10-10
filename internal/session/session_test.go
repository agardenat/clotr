package session

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/memory"
)

func TestLifecycle(t *testing.T) {
	root := t.TempDir()
	s, err := Create(root, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-z]+-[a-z]+$`).MatchString(s.Name) {
		t.Fatalf("nom: %s", s.Name)
	}
	if s.History(1000) != "" {
		t.Fatal("historique non vide pour une session neuve")
	}
	turn, dir, err := s.NewTurn("état du cluster prod")
	if err != nil || turn.N != 1 || !strings.HasSuffix(dir, filepath.Join("turns", "001")) {
		t.Fatalf("tour: %+v %s %v", turn, dir, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "request.txt")); !strings.Contains(string(data), "prod") {
		t.Fatal("request.txt")
	}
	if s.History(1000) != "" {
		t.Fatal("un tour en cours ne doit pas apparaître dans l'historique")
	}
	s.Turns[0].Status = "ok"
	if err := s.WriteReport(dir, "# Rapport prod\n3 nodes"); err != nil {
		t.Fatal(err)
	}
	m := memory.NewStore()
	_, _ = m.Put(memory.Entry{Key: "prod/nodes", Content: "3 nodes", Kind: "note", Task: "t1", Sovereign: true})
	if err := s.SaveMemory(m); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	other, _ := Create(root, true, "require")
	_ = other

	re, err := Open(root, s.Name)
	if err != nil {
		t.Fatal(err)
	}
	h := re.History(5)
	if !strings.Contains(h, "tour 1") || !strings.Contains(h, "état du cluster prod") || !strings.Contains(h, "# Rap") || !strings.Contains(h, "[rapport tronqué]") {
		t.Fatalf("historique: %s", h)
	}
	entries, err := re.LoadMemory()
	if err != nil || len(entries) != 1 || entries[0].Key != "prod/nodes" || !entries[0].Sovereign {
		t.Fatalf("mémoire: %+v %v", entries, err)
	}
	m2 := memory.NewStore()
	m2.Load(entries)
	id, _ := m2.Put(memory.Entry{Key: "prod/pods", Content: "x", Kind: "note"})
	if id != 2 {
		t.Fatalf("id après chargement: %d", id)
	}
	if r, _ := re.Report(1); !strings.Contains(r, "3 nodes") {
		t.Fatal("rapport du tour 1")
	}
	last, err := Open(root, "last")
	if err != nil || last.Name != other.Name || !last.Confidential {
		t.Fatalf("last: %+v %v", last, err)
	}
	all, _ := List(root)
	if len(all) != 2 {
		t.Fatalf("list: %d", len(all))
	}
	if _, err := Open(root, "../etc"); err == nil {
		t.Fatal("nom invalide accepté")
	}
	if _, err := Open(root, "absent-name"); err == nil {
		t.Fatal("session absente acceptée")
	}
}

func TestGenerateNameUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		n := GenerateName(func(s string) bool { return seen[s] })
		if seen[n] {
			t.Fatalf("doublon %s", n)
		}
		seen[n] = true
	}
}
