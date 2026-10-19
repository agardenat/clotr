package main

import (
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestResolveExport(t *testing.T) {
	cases := []struct {
		name, flag, output string
		json               bool
		format, path, md   string
		err                bool
	}{
		{"rien", "", "", false, "", "", "", false},
		{"markdown", "", "r.md", false, "", "", "r.md", false},
		{"flag seul", "pdf", "", false, "pdf", "", "", false},
		{"flag + markdown", "docx", "r.md", false, "docx", "", "r.md", false},
		{"-o docx", "", "r.DOCX", false, "docx", "r.DOCX", "", false},
		{"-o pdf + flag", "pdf", "r.pdf", false, "pdf", "r.pdf", "", false},
		{"incohérent", "pdf", "r.docx", false, "", "", "", true},
		{"format inconnu", "odt", "", false, "", "", "", true},
		{"json vers docx", "", "r.docx", true, "", "", "", true},
	}
	for _, c := range cases {
		o := &options{exportFmt: c.flag, output: c.output, json: c.json}
		err := o.resolveExport()
		if (err != nil) != c.err {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !c.err && (o.exportFmt != c.format || o.exportPath != c.path || o.output != c.md) {
			t.Errorf("%s: format=%q path=%q output=%q", c.name, o.exportFmt, o.exportPath, o.output)
		}
	}
}

func TestCheckExport(t *testing.T) {
	cfg := &config.Config{Roles: config.DefaultRoles(), MCP: []config.MCPServer{{Name: "docs"}}, Export: config.ReportExport{MCP: "docs"}}
	if err := (&options{}).checkExport(&config.Config{}, true); err != nil {
		t.Fatalf("sans export: %v", err)
	}
	if err := (&options{exportFmt: "pdf"}).checkExport(cfg, false); err != nil {
		t.Fatalf("nominal: %v", err)
	}
	if err := (&options{exportFmt: "pdf"}).checkExport(cfg, true); err == nil {
		t.Fatal("session confidentielle acceptée")
	}
	if err := (&options{exportFmt: "pdf", exclude: []string{"mcp_docs"}}).checkExport(cfg, false); err == nil {
		t.Fatal("serveur exclu accepté")
	}
	if err := (&options{exportFmt: "pdf"}).checkExport(&config.Config{Roles: config.DefaultRoles()}, false); err == nil {
		t.Fatal("aucun serveur désigné accepté")
	}
}

func TestExportTitle(t *testing.T) {
	if got := exportTitle("intro\n# Titre du rapport\n## A", "demande"); got != "Titre du rapport" {
		t.Fatalf("H1: %q", got)
	}
	if got := exportTitle("## A\ntexte", "  analyse   du cluster "); got != "analyse du cluster" {
		t.Fatalf("demande: %q", got)
	}
}
