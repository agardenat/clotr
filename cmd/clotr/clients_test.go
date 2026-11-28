package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestWriteClients(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{
		{Name: "acme", Label: "Acme", Projects: []config.Project{{Name: "PRJ-AAAA", Label: "Data"}, {Name: "PRJ-BBBB"}}},
		{Name: "solo"},
	}}
	var buf bytes.Buffer
	if err := writeClients(&buf, cfg, true); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Clients []clientEntry `json:"clients"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Clients) != 2 || doc.Clients[0].Label != "Acme" || len(doc.Clients[0].Projects) != 2 || doc.Clients[0].Projects[0].Label != "Data" {
		t.Fatalf("clients : %+v", doc.Clients)
	}
	if doc.Clients[1].Projects == nil || len(doc.Clients[1].Projects) != 0 {
		t.Fatalf("projets vides attendus en liste : %+v", doc.Clients[1])
	}
	buf.Reset()
	if err := writeClients(&buf, cfg, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "PRJ-AAAA (Data), PRJ-BBBB") {
		t.Fatalf("texte : %q", buf.String())
	}
}
