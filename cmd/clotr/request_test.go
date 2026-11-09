package main

import (
	"testing"

	"github.com/agardenat/clotr/internal/session"
)

func TestWithRequest(t *testing.T) {
	one := []session.Turn{{N: 1, Request: "le cluster prod est-il sain ?\n\navec les nœuds"}}
	got := withRequest("## 1. Conclusion\n- ok", one)
	want := "> le cluster prod est-il sain ?\n>\n> avec les nœuds\n\n---\n\n## 1. Conclusion\n- ok"
	if got != want {
		t.Fatalf("un tour :\n%q\n%q", got, want)
	}
	if withRequest(got, one) != want {
		t.Fatal("le bloc ne doit pas être ajouté deux fois")
	}
	two := append(one, session.Turn{N: 2, Request: "ajoute les pods"})
	got = withRequest(got, two)
	want = "> **1.** le cluster prod est-il sain ?\n>\n> avec les nœuds\n>\n> **2.** ajoute les pods\n\n---\n\n## 1. Conclusion\n- ok"
	if got != want {
		t.Fatalf("affinage :\n%q\n%q", got, want)
	}
	if withRequest("", one) != "" {
		t.Fatal("rapport vide")
	}
	cve := "| CVE | statut |\n|---|---|\n\n---\n\n## 1. Conclusion"
	if stripRequest(cve) != cve {
		t.Fatal("un rapport sans bloc de demande ne doit pas être coupé")
	}
}
