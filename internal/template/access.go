package template

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/netx"
	"github.com/agardenat/clotr/internal/tools"
)

type connLevel struct {
	methods   []string
	allow     []*regexp.Regexp
	argvParam string
}

var levelKeys = map[string][]string{
	"exec":   {"allow", "argv_param"},
	"create": {"methods", "allow"},
}

func checkLevelOptions(o options) error {
	for name := range o.sub("levels") {
		keys, ok := levelKeys[name]
		if !ok {
			return i18n.E("tpl.http.level", name)
		}
		lo := o.sub("levels").sub(name)
		for k := range lo {
			if !slices.Contains(keys, k) {
				return i18n.E("tpl.http.level_key", name, k, strings.Join(keys, ", "))
			}
		}
		if len(lo.list("allow")) == 0 {
			return i18n.E("tpl.http.level_allow", name)
		}
		for _, a := range lo.list("allow") {
			if _, err := regexp.Compile(a); err != nil {
				return fmt.Errorf("levels.%s.allow: %w", name, err)
			}
		}
		if name == "create" {
			methods := lo.list("methods")
			if len(methods) == 0 {
				return i18n.E("tpl.http.level_methods", name)
			}
			for _, m := range methods {
				if m != strings.ToUpper(m) || m == "" {
					return i18n.E("tpl.http.method_case", m)
				}
			}
		}
	}
	return nil
}

func newConnLevels(o options) (map[access.Level]*connLevel, error) {
	out := map[access.Level]*connLevel{}
	for name := range o.sub("levels") {
		l, err := access.Parse(name)
		if err != nil {
			return nil, err
		}
		lo := o.sub("levels").sub(name)
		cl := &connLevel{methods: lo.list("methods"), argvParam: lo.str("argv_param")}
		for _, a := range lo.list("allow") {
			re, err := regexp.Compile(a)
			if err != nil {
				return nil, err
			}
			cl.allow = append(cl.allow, re)
		}
		out[l] = cl
	}
	return out, nil
}

func (in *Instance) SetAccess(l access.Level) {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	in.access = l
}

func (in *Instance) SetCeiling(l access.Level) {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	in.ceiling = l
}

func (in *Instance) Access() access.Level {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	return in.access
}

func (in *Instance) offered() access.Level {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	return max(in.ceiling, in.access)
}

type grantKey struct{}

func withGrant(ctx context.Context, l access.Level) context.Context {
	return context.WithValue(ctx, grantKey{}, l)
}

func (in *Instance) allowed(ctx context.Context, required access.Level) bool {
	if in.Access().Allows(required) {
		return true
	}
	g, ok := ctx.Value(grantKey{}).(access.Level)
	return ok && g.Allows(required)
}

func (in *Instance) escalate(ctx context.Context, tool string, required access.Level, raw []byte) (context.Context, error) {
	granted := in.Access()
	if granted.Allows(required) {
		return ctx, nil
	}
	c := tools.CallerFrom(ctx)
	f := map[string]any{"tool": tool, "task": c.Task, "granted": granted.String(), "required": required.String()}
	if in.Confirm == nil {
		f["decision"] = "refused"
		in.audit("access_escalation", f)
		return ctx, i18n.E("tpl.escalate.no_confirm", tool, required, in.Name, granted)
	}
	ans, err := in.Confirm(ctx, i18n.T("escalate.ask", in.Name, granted, defaultStr(c.Task, "?"), in.highlight(tool), in.highlight(oneLine(string(raw), 300)), required))
	switch {
	case err != nil:
		f["decision"], f["error"] = "refused", err.Error()
		in.audit("access_escalation", f)
		return ctx, i18n.E("tpl.escalate.unconfirmed", tool, err)
	case ans == access.Always:
		in.accessMu.Lock()
		in.access = max(in.access, required)
		in.accessMu.Unlock()
		f["decision"] = "always"
	case ans == access.Once:
		f["decision"] = "confirmed"
	default:
		f["decision"] = "refused"
		in.audit("access_escalation", f)
		return ctx, i18n.E("tpl.escalate.refused", tool, required, in.Name, granted)
	}
	in.audit("access_escalation", f)
	return withGrant(ctx, required), nil
}

func (in *Instance) highlight(s string) string {
	if in.Highlight == nil {
		return s
	}
	return in.Highlight(s)
}

func (in *Instance) ExtendCommands(extra access.Rules) error {
	if len(extra.Allow) == 0 && len(extra.Deny) == 0 {
		return nil
	}
	c, err := in.commands.Extend(extra)
	if err != nil {
		return fmt.Errorf("instance %s: commands: %w", in.Name, err)
	}
	in.commands = c
	return nil
}

func (in *Instance) commandsDesc() string {
	src := in.commands.Source()
	allow := "aucune"
	if len(src.Allow) > 0 {
		allow = strings.Join(src.Allow, " ; ")
	}
	s := "Commandes exécutées sans confirmation : " + allow + "."
	if len(src.Deny) > 0 {
		s += " Refusées : " + strings.Join(src.Deny, " ; ") + "."
	}
	return s + " Toute autre commande est soumise à l'utilisateur, qui peut la refuser : ne demander que des commandes sans effet de bord (versions, inventaire de paquets, état), jamais de modification."
}

func (in *Instance) authorizeCommand(ctx context.Context, where string, argv []string) error {
	if err := access.CheckArgv(argv); err != nil {
		return err
	}
	shown := access.Display(argv)
	f := map[string]any{"where": where, "argv": argv}
	switch in.commands.Check(argv) {
	case access.Allowed:
		f["decision"] = "allowed"
		in.audit("exec_decision", f)
		return nil
	case access.Denied:
		f["decision"] = "denied"
		in.audit("exec_decision", f)
		return i18n.E("tpl.exec.denied", shown)
	}
	var trusted []string
	if in.Trusted != nil {
		trusted = in.Trusted()
	}
	if access.Matches(argv, trusted) {
		f["decision"] = "trusted"
		in.audit("exec_decision", f)
		return nil
	}
	roErr := access.ReadOnlyTrusting(argv, trusted)
	if roErr == nil {
		f["decision"] = "readonly"
		in.audit("exec_decision", f)
		return nil
	}
	f["not_readonly"] = roErr.Error()
	key := strings.Join(argv, "\x00")
	in.accessMu.Lock()
	ok := in.always[key]
	in.accessMu.Unlock()
	if ok {
		f["decision"] = "always"
		in.audit("exec_decision", f)
		return nil
	}
	if in.Confirm == nil {
		f["decision"] = "refused"
		in.audit("exec_decision", f)
		return i18n.E("tpl.exec.no_confirm", shown)
	}
	ans, err := in.Confirm(ctx, i18n.T("exec.ask", in.Name, where, in.highlight(shown), roErr))
	if err != nil {
		f["decision"], f["error"] = "refused", err.Error()
		in.audit("exec_decision", f)
		return i18n.E("tpl.exec.unconfirmed", shown, err)
	}
	switch ans {
	case access.Always:
		in.accessMu.Lock()
		if in.always == nil {
			in.always = map[string]bool{}
		}
		in.always[key] = true
		in.accessMu.Unlock()
		f["decision"] = "always"
	case access.Once:
		f["decision"] = "confirmed"
	default:
		f["decision"] = "refused"
		in.audit("exec_decision", f)
		return i18n.E("tpl.exec.refused", shown)
	}
	in.audit("exec_decision", f)
	return nil
}

type trackedRes struct {
	conn    string
	path    string
	base    string
	tls     *netx.TLS
	proxy   string
	headers map[string]string
}

func (in *Instance) track(r *trackedRes) {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	in.tracked = append(in.tracked, r)
}

func (in *Instance) untrack(conn, p string) {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	in.tracked = slices.DeleteFunc(in.tracked, func(r *trackedRes) bool { return r.conn == conn && r.path == p })
}

func (in *Instance) isTracked(conn, p string) bool {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	return slices.ContainsFunc(in.tracked, func(r *trackedRes) bool { return r.conn == conn && r.path == p })
}

func (in *Instance) underTracked(conn, p string) bool {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	return slices.ContainsFunc(in.tracked, func(r *trackedRes) bool {
		return r.conn == conn && strings.HasPrefix(p, strings.TrimSuffix(r.path, "/")+"/")
	})
}

func (in *Instance) checkHTTP(ctx context.Context, hc *httpConn, method, p, track string) (string, error) {
	clean, err := checkRequestPath(hc, method, p)
	if err == nil {
		if track != "" {
			return "", i18n.E("tpl.http.track_base", method, hc.name)
		}
		return clean, nil
	}
	cl := hc.levels[access.Create]
	if cl == nil || !slices.Contains(cl.methods, method) {
		return "", err
	}
	lclean, lerr := cleanRequestPath(hc, p)
	if lerr != nil {
		return "", lerr
	}
	if !matchAny(cl.allow, lclean) {
		return "", err
	}
	if !in.allowed(ctx, access.Create) {
		return "", i18n.E("tpl.access.required", method+" "+lclean, access.Create)
	}
	switch method {
	case http.MethodGet, http.MethodHead:
		if track != "" {
			return "", i18n.E("tpl.http.track_base", method, hc.name)
		}
	case http.MethodPost:
		if track == "" {
			return "", i18n.E("tpl.http.track_required", method, lclean)
		}
		t, terr := cleanRequestPath(hc, track)
		if terr != nil {
			return "", terr
		}
		if !matchAny(cl.allow, t) {
			return "", i18n.E("tpl.http.track_allow", t, hc.name)
		}
		if !strings.HasPrefix(t, strings.TrimSuffix(lclean, "/")+"/") {
			return "", i18n.E("tpl.http.track_under", t, lclean)
		}
	default:
		if track != "" {
			return "", i18n.E("tpl.http.track_base", method, hc.name)
		}
		if !in.isTracked(hc.name, lclean) {
			return "", i18n.E("tpl.http.untracked", method, lclean)
		}
	}
	return lclean, nil
}

type CleanupResult struct {
	Resource string
	Err      error
}

func (in *Instance) Cleanup(ctx context.Context) []CleanupResult {
	in.accessMu.Lock()
	pending := slices.Clone(in.tracked)
	in.accessMu.Unlock()
	var out []CleanupResult
	for i := len(pending) - 1; i >= 0; i-- {
		r := pending[i]
		err := in.deleteTracked(ctx, r)
		f := map[string]any{"connector": r.conn, "path": r.path}
		if err != nil {
			f["error"] = err.Error()
		} else {
			in.untrack(r.conn, r.path)
		}
		in.audit("cleanup", f)
		out = append(out, CleanupResult{Resource: in.Name + " " + r.conn + " " + r.path, Err: err})
	}
	return out
}

func (in *Instance) deleteTracked(ctx context.Context, r *trackedRes) error {
	hc, ok := in.https[r.conn]
	if !ok {
		return i18n.E("tpl.http.connector", r.conn, strings.Join(sortedKeys(in.https), ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, max(hc.timeout, 30*time.Second))
	defer cancel()
	rep, err := in.send(ctx, &httpCall{hc: hc, method: http.MethodDelete, base: r.base, clean: r.path, headers: r.headers, tls: r.tls, proxy: r.proxy, limit: maxRead, tool: "cleanup"})
	if err != nil {
		return err
	}
	if rep.status == http.StatusNotFound || (rep.status >= 200 && rep.status < 300) {
		return nil
	}
	return fmt.Errorf("DELETE %s: HTTP %d", r.path, rep.status)
}

func (in *Instance) Tracked() []string {
	in.accessMu.Lock()
	defer in.accessMu.Unlock()
	var out []string
	for _, r := range in.tracked {
		out = append(out, r.conn+" "+r.path)
	}
	return out
}
