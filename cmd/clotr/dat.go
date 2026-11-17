package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/dat"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/session"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

func (o *options) datFlagName() string {
	if o.diagramOnly {
		return "diagram"
	}
	return "dat"
}

func (o *options) resolveDAT() error {
	if o.datFlag == "" && o.diagramFlag == "" {
		return nil
	}
	if o.datFlag != "" && o.diagramFlag != "" || o.incident || o.change || o.cveFlag != "" || o.ticketFlag != "" || o.chat || o.direct != "" {
		return i18n.E("cli.err.dat_modes")
	}
	o.datVariant, o.diagramOnly = o.datFlag, false
	if o.diagramFlag != "" {
		o.datVariant, o.diagramOnly = o.diagramFlag, true
	}
	o.datVariant = strings.ToLower(strings.TrimSpace(o.datVariant))
	if !dat.Valid(o.datVariant) {
		return i18n.E("cli.err.dat_variant", o.datFlagName(), o.datVariant)
	}
	return nil
}

func (o *options) restoreDAT(t session.Turn) bool {
	switch t.Mode {
	case dat.ModeDAT, dat.ModeDiagram:
		if !dat.Valid(t.DAT) {
			return false
		}
		o.datVariant, o.diagramOnly = t.DAT, t.Mode == dat.ModeDiagram
		return true
	}
	return false
}

type diagramRenderer struct{ in *template.Instance }

func (r diagramRenderer) Reference(ctx context.Context, cloud string) (string, error) {
	return r.in.DiagramReference(ctx, cloud)
}

func (r diagramRenderer) Shapes(ctx context.Context, query, cloud string) (string, error) {
	return r.in.DiagramShapes(ctx, query, cloud)
}

func (r diagramRenderer) Render(ctx context.Context, cloud string, spec map[string]any) (*dat.Rendered, error) {
	res, err := r.in.DiagramRender(ctx, cloud, spec)
	if err != nil {
		return nil, err
	}
	return &dat.Rendered{Drawio: res.Drawio, PNG: res.PNG, Warnings: res.Warnings, Notes: res.Notes}, nil
}

func (rt *app) setupDAT(o *options, warn func(string)) {
	if o.datVariant == "" {
		return
	}
	rt.dat = dat.New(o.datVariant, o.diagramOnly, nil, rt.audit)
	cfg := rt.cfg
	if cfg.Diagram.Template == "" {
		warn(i18n.T("dat.no_renderer"))
		return
	}
	off := func(err error) {
		warn(i18n.T("dat.renderer_off", err))
		rt.dat.Skipped = i18n.R("dat.renderer_off", err)
	}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		off(err)
		return
	}
	t, ok := set.Get(cfg.Diagram.Template)
	if !ok {
		off(i18n.E("cli.warn.template_missing", "diagram", cfg.Diagram.Template))
		return
	}
	if !t.Diagram() {
		off(i18n.E("diagram.not", t.Name))
		return
	}
	if rt.confidential && t.External() {
		warn(i18n.T("dat.renderer_confidential", t.Name))
		rt.dat.Skipped = i18n.R("dat.no_diagram_confidential")
		return
	}
	params := map[string]any{}
	for k, v := range cfg.Params {
		if _, declared := t.Params[k]; declared {
			params[k] = v
		}
	}
	maps.Copy(params, cfg.Diagram.Params)
	in, err := template.NewInstance("diagram", t, params)
	if err != nil {
		off(err)
		return
	}
	in.Audit = rt.audit.Log
	in.MCP = rt.templateMCP
	in.Warn = warn
	rt.diagramSrc = in
	rt.dat.Renderer = diagramRenderer{in}
}

func (rt *app) datScope(reg *tools.Registry, env string, o *options) (*tools.Registry, string, error) {
	if rt.dat == nil {
		return reg, env, nil
	}
	var all, iac, other []string
	for _, in := range rt.instances {
		if !slices.Contains(reg.Groups(), in.ToolPrefix()) || !in.T.DescribesArchitecture() {
			continue
		}
		all = append(all, in.Name)
		if in.T.IaC() {
			iac = append(iac, in.Name)
		} else {
			other = append(other, in.Name)
		}
	}
	if len(all) == 0 {
		return nil, "", i18n.E("cli.err.dat_empty", o.datFlagName())
	}
	switch {
	case rt.dat.Variant == dat.IaC && len(iac) == 0:
		return nil, "", i18n.E("cli.err.dat_no_iac", o.datFlagName())
	case rt.dat.Variant == dat.IaC:
		var lines []string
		for _, n := range other {
			lines = append(lines, fmt.Sprintf("- Instance %s : non proposée, le document décrit l'IaC seule.", n))
		}
		if len(lines) > 0 {
			env += "\n" + strings.Join(lines, "\n")
			reg = reg.Without(other...)
		}
		all = iac
	case len(iac) == 0:
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("dat.warn_no_iac"))
	}
	rt.dat.Instances, rt.dat.IaCOnes = all, iac
	rt.dat.Units = datUnits(rt.cfg.Instances, rt.dat.Variant, all, iac)
	rt.audit.Log("dat_scope", map[string]any{"variant": rt.dat.Variant, "diagram_only": rt.dat.DiagramOnly, "instances": all, "iac": iac, "units": len(rt.dat.Units), "renderer": rt.dat.Renderer != nil})
	return reg, env, nil
}

func datScopeFromAudit(path string) (instances, iac []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Kind      string   `json:"kind"`
			Instances []string `json:"instances"`
			IaC       []string `json:"iac"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Kind == "dat_scope" {
			instances, iac = ev.Instances, ev.IaC
		}
	}
	return instances, iac
}

func datUnits(cfg []config.Instance, variant string, all, iac []string) []dat.Unit {
	byName := map[string]config.Instance{}
	for _, c := range cfg {
		byName[c.Name] = c
	}
	covered := map[string][]string{}
	var units []dat.Unit
	for _, n := range all {
		if !slices.Contains(iac, n) {
			continue
		}
		u := dat.Unit{IaC: n, Instances: []string{n}}
		if variant != dat.IaC {
			for _, d := range byName[n].Describes {
				d = strings.TrimSpace(d)
				name, target, _ := strings.Cut(d, "/")
				if !slices.Contains(all, name) || slices.Contains(iac, name) {
					continue
				}
				u.Objects = append(u.Objects, d)
				if !slices.Contains(u.Instances, name) {
					u.Instances = append(u.Instances, name)
				}
				covered[name] = append(covered[name], target)
			}
		}
		units = append(units, u)
	}
	for _, n := range all {
		if slices.Contains(iac, n) || slices.Contains(covered[n], "") {
			continue
		}
		units = append(units, dat.Unit{Instances: []string{n}, Except: covered[n]})
	}
	return units
}
