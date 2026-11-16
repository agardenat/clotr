package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/export"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/report"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools/mcp"
)

func outputFormat(path string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if slices.Contains(config.ExportFormats, ext) {
		return ext
	}
	return ""
}

func (o *options) resolveExport() error {
	if o.exportFmt != "" && !slices.Contains(config.ExportFormats, o.exportFmt) {
		return i18n.E("cli.err.export_format", o.exportFmt, strings.Join(config.ExportFormats, "|"))
	}
	f := outputFormat(o.output)
	if f == "" {
		return nil
	}
	if o.exportFmt != "" && o.exportFmt != f {
		return i18n.E("cli.err.export_output", o.output, o.exportFmt)
	}
	if o.json {
		return i18n.E("cli.err.export_json", o.output)
	}
	o.exportFmt, o.exportPath, o.output = f, o.output, ""
	return nil
}

func exportTitle(md, request string) string {
	for _, l := range strings.Split(md, "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(l), "# "); ok && strings.TrimSpace(t) != "" {
			return strings.TrimSpace(t)
		}
	}
	r := []rune(strings.Join(strings.Fields(request), " "))
	if len(r) > 80 {
		return string(r[:80]) + "…"
	}
	return string(r)
}

func reportLanguage(lang, md string) string {
	if lang == "fr" || lang == "en" {
		return lang
	}
	var prose strings.Builder
	fence := ""
	for _, l := range strings.Split(md, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case fence != "":
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
			continue
		case strings.HasPrefix(t, "```"):
			fence = "```"
			continue
		case strings.HasPrefix(t, "~~~"):
			fence = "~~~"
			continue
		}
		prose.WriteString(l)
		prose.WriteByte('\n')
	}
	fr, en := 0, 0
	for _, w := range strings.FieldsFunc(strings.ToLower(prose.String()), func(r rune) bool { return !unicode.IsLetter(r) }) {
		switch w {
		case "le", "la", "les", "des", "est", "une", "dans", "pour", "sur", "pas", "aucun", "avec":
			fr++
		case "the", "is", "are", "and", "of", "with", "for", "not", "no", "on", "this", "was":
			en++
		}
	}
	if en > fr {
		return "en"
	}
	return "fr"
}

func exportReport(ctx context.Context, o *options, cfg *config.Config, sess *session.Session, n int, md string) error {
	name := cmp.Or(o.exportTpl, cfg.Export.Template)
	if name == "" {
		return i18n.E("export.no_template")
	}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		return err
	}
	t, ok := set.Get(name)
	if !ok {
		for _, w := range set.Warnings {
			if strings.Contains(w, string(filepath.Separator)+name+".") {
				return i18n.E("export.template_invalid", name, w)
			}
		}
		return i18n.E("export.template_missing", name, cfg.Templates.Dir)
	}
	if !t.Document() {
		return i18n.E("export.template_kind", t.Name, t.Kind)
	}
	if sess.Confidential && t.External() {
		return i18n.E("export.template_external", t.Name)
	}
	params := cfg.Export.Params
	if name != cfg.Export.Template {
		params = nil
	}
	in, err := template.NewInstance(t.Name, t, params)
	if err != nil {
		return err
	}
	if closeMCP, err := connectStandaloneMCP(ctx, cfg, in); err != nil {
		return i18n.E("export.failed", err)
	} else {
		defer closeMCP()
	}
	turn := sess.Turns[n-1]
	mode := turn.Mode
	if mode == "" && len(turn.CVE) > 0 {
		mode = report.ModeCVE
	}
	if mode == "" {
		mode = report.ModeDefault
	}
	fmt.Fprintln(os.Stderr, i18n.T("export.start", o.exportFmt, t.Name))
	data, err := in.RenderDocument(ctx, template.DocumentInput{
		Images:   reportImages(md, sess.TurnDir(n)),
		Markdown: md,
		Title:    exportTitle(md, turn.Request),
		Mode:     mode,
		Language: reportLanguage(cmp.Or(o.langFlag, sess.Language), md),
		Request:  turn.Request,
		Ticket:   turn.Ticket,
		Date:     turn.Time.Local().Format("2006-01-02"),
		Session:  sess.Name,
	})
	if err != nil {
		return i18n.E("export.failed", err)
	}
	doc, err := export.Read("docx", data)
	if err != nil {
		return i18n.E("export.failed", err)
	}
	if o.exportFmt == "pdf" {
		pdf, err := export.PDF(ctx, data)
		if err != nil {
			path := filepath.Join(sess.TurnDir(n), "report.docx")
			if werr := os.WriteFile(path, data, 0o600); werr != nil {
				return err
			}
			if o.exportPath != "" {
				alt := strings.TrimSuffix(o.exportPath, filepath.Ext(o.exportPath)) + ".docx"
				if werr := os.WriteFile(alt, data, 0o644); werr == nil {
					path = alt
				}
			}
			return i18n.E("export.pdf_fallback", err, path)
		}
		data = pdf
	}
	path := filepath.Join(sess.TurnDir(n), "report."+o.exportFmt)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if o.exportPath != "" {
		if err := os.WriteFile(o.exportPath, data, 0o644); err != nil {
			return err
		}
		path = o.exportPath
	}
	res := export.Compare(md, doc)
	switch {
	case !res.Checked:
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("export.unchecked", "docx"))
	case res.Issues() > 0:
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("export.issues"))
		for _, g := range []struct {
			label string
			items []string
		}{
			{i18n.T("export.missing", len(res.Missing)), res.Missing},
			{i18n.T("export.moved", len(res.Moved)), res.Moved},
			{i18n.T("export.flat", len(res.Flat)), res.Flat},
			{i18n.T("export.artifacts", len(res.Artifacts)), res.Artifacts},
		} {
			if len(g.items) == 0 {
				continue
			}
			fmt.Fprintln(os.Stderr, "  "+g.label)
			for _, m := range g.items[:min(3, len(g.items))] {
				fmt.Fprintln(os.Stderr, "    - "+m)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, i18n.T("export.checked"))
	}
	fmt.Fprintln(os.Stderr, i18n.T("export.saved"), path)
	return nil
}

var imageRef = regexp.MustCompile(`!\[[^\]]*\]\(<?([^)\s>]+)>?(?:\s+"[^"]*")?\)`)

func reportImages(md, dir string) map[string]template.Image {
	out := map[string]template.Image{}
	for _, m := range imageRef.FindAllStringSubmatch(md, -1) {
		src := m[1]
		if _, seen := out[src]; seen || src != filepath.Base(src) || strings.HasPrefix(src, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, src))
		if err != nil || len(data) > 50<<20 {
			continue
		}
		cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			continue
		}
		out[src] = template.Image{Data: data, Format: format, Width: cfg.Width, Height: cfg.Height}
	}
	return out
}

func connectStandaloneMCP(ctx context.Context, cfg *config.Config, in *template.Instance) (func(), error) {
	var need []config.MCPServer
	for _, n := range in.MCPServers() {
		if m, ok := in.MCPInline(n); ok {
			need = append(need, m)
			continue
		}
		i := slices.IndexFunc(cfg.MCP, func(m config.MCPServer) bool { return m.Name == n })
		if i < 0 {
			return nil, i18n.E("tpl.mcp.unavailable", n)
		}
		need = append(need, cfg.MCP[i])
	}
	if len(need) == 0 {
		return func() {}, nil
	}
	servers, warnings := mcp.ConnectForTemplates(ctx, need, version)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), w)
	}
	byName := map[string]*mcp.Server{}
	for _, s := range servers {
		byName[s.Name()] = s
	}
	in.MCP = func(_ context.Context, server string) (template.MCPCaller, error) {
		s := byName[server]
		if s == nil {
			return nil, i18n.E("tpl.mcp.unavailable", server)
		}
		return templateMCPCaller{s}, nil
	}
	return func() {
		for _, s := range servers {
			_ = s.Close()
		}
	}, nil
}
