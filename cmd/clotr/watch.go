package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/watch"
)

type watchInstance struct{ in *template.Instance }

func (w watchInstance) Host(target, host string) (watch.Host, error) {
	return w.in.WatchHost(target, host)
}

func (w watchInstance) Path(p string) (string, error) { return w.in.WatchPath(p) }

func (w watchInstance) Follow(ctx context.Context, tool string, args, cursor json.RawMessage) ([]string, json.RawMessage, error) {
	return w.in.Follow(ctx, tool, args, cursor)
}

func (rt *app) watchInstance(name string) (watch.Instance, bool) {
	for _, in := range rt.instances {
		if in.Name == name {
			return watchInstance{in}, true
		}
	}
	return nil, false
}

func watchScope(instances []*template.Instance, reg *tools.Registry) ([]string, func(string) bool) {
	names := reg.Names()
	offered := map[string]bool{}
	var followable []string
	for _, in := range instances {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, in.Name+"_") }) {
			continue
		}
		offered[in.Name] = true
		for _, t := range in.FollowTools() {
			if slices.Contains(names, t) {
				followable = append(followable, t)
			}
		}
	}
	return followable, func(name string) bool { return offered[name] }
}
