package memory

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/tools"
)

func TestStore(t *testing.T) {
	s := NewStore()
	sov := tools.Caller{Task: "t1", Model: "local/x", Sovereign: true}
	foreign := tools.Caller{Task: "t2", Model: "go/y"}
	ctxSov := tools.WithCaller(context.Background(), sov)
	ctxForeign := tools.WithCaller(context.Background(), foreign)
	w, sr := s.Tools()[0], s.Tools()[1]
	if _, err := w.Call(ctxSov, json.RawMessage(`{"key":"prod/nodes","content":"3 nodes Ready","tags":["prod","nodes"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Call(ctxSov, json.RawMessage(`{"key":"prod/nodes","content":"3 nodes Ready, 1 cordoned","tags":["prod","nodes"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Call(ctxForeign, json.RawMessage(`{"key":"prod/pods","content":"2 CrashLoopBackOff","tags":["prod"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Call(ctxSov, json.RawMessage(`{"key":"","content":"x"}`)); err == nil {
		t.Fatal("key vide acceptée")
	}
	all := s.All()
	if len(all) != 2 || all[0].Content != "3 nodes Ready, 1 cordoned" || !all[0].Sovereign || all[1].Sovereign || all[1].Task != "t2" {
		t.Fatalf("%+v", all)
	}
	out, _ := sr.Call(ctxSov, json.RawMessage(`{"query":"cordoned"}`))
	if !strings.Contains(out, "#1") || strings.Contains(out, "#2") {
		t.Fatalf("search: %s", out)
	}
	if st := s.Stats(); st.ExposedToForeign != 0 {
		t.Fatalf("lecture souveraine comptée: %+v", st)
	}
	out, _ = sr.Call(ctxForeign, json.RawMessage(`{"tags":["nodes"]}`))
	if !strings.Contains(out, "souverain") {
		t.Fatalf("search tags: %s", out)
	}
	if st := s.Stats(); st.Entries != 2 || st.Sovereign != 1 || st.ExposedToForeign != 1 {
		t.Fatalf("stats: %+v", st)
	}
	path := filepath.Join(t.TempDir(), "m.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	var nilStore *Store
	if nilStore.All() != nil || nilStore.Stats().Entries != 0 {
		t.Fatal("store nil")
	}
}
