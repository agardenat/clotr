package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/template"
)

func sessionsCommandsCmd(o *options) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "commands",
		Short: i18n.T("cli.sessions_commands.short"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(o)
			if err != nil {
				return err
			}
			rules := instanceRules(cfg, func(s string) { fmt.Fprintln(cmd.ErrOrStderr(), i18n.T("cli.warning"), s) })
			rep, err := replayCommands(cfg.Sessions.Dir, rules)
			if err != nil {
				return err
			}
			return rep.write(cmd.OutOrStdout(), all)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, i18n.T("cli.flag.commands_all"))
	return cmd
}

func instanceRules(cfg *config.Config, warn func(string)) map[string]*access.Commands {
	out := map[string]*access.Commands{}
	set, err := template.Load(cfg.Templates.Dir)
	if err != nil {
		warn(i18n.T("cli.warn.templates_off", err))
		return out
	}
	for _, in := range cfg.Instances {
		t, ok := set.Get(in.Template)
		if !ok {
			continue
		}
		c, err := access.CompileCommands(t.Commands)
		if err == nil {
			c, err = c.Extend(in.Commands)
		}
		if err != nil {
			warn(fmt.Sprintf("instance %s: commands: %v", in.Name, err))
			continue
		}
		out[in.Name] = c
	}
	return out
}

type askedCommand struct {
	Instance string
	Argv     []string
	Count    int
	Sessions map[string]bool
	Reason   string
}

type commandReplay struct {
	Asked    []*askedCommand
	Pending  []*askedCommand
	Passing  []*askedCommand
	Files    int
	Missing  map[string]bool
	Ignored  int
	Distinct int
}

var askedDecisions = []string{"always", "confirmed", "refused", "unanswered", "deferred"}

func replayCommands(dir string, rules map[string]*access.Commands) (*commandReplay, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*", "turns", "*", "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	rep := &commandReplay{Files: len(files), Missing: map[string]bool{}}
	byKey := map[string]*askedCommand{}
	var order []string
	for _, f := range files {
		sess := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(f))))
		if err := scanDecisions(f, func(instance string, argv []string) {
			if access.CheckArgv(argv) != nil || len(argv) == 1 && strings.Trim(argv[0], ",;:. ") == "" {
				rep.Ignored++
				return
			}
			key := instance + "\x00" + strings.Join(argv, "\x00")
			a, ok := byKey[key]
			if !ok {
				a = &askedCommand{Instance: instance, Argv: argv, Sessions: map[string]bool{}}
				byKey[key] = a
				order = append(order, key)
			}
			a.Count++
			a.Sessions[sess] = true
		}); err != nil {
			return nil, err
		}
	}
	for _, key := range order {
		a := byKey[key]
		rep.Asked = append(rep.Asked, a)
		c, ok := rules[a.Instance]
		if !ok {
			rep.Missing[a.Instance] = true
		}
		switch c.Check(a.Argv) {
		case access.Allowed:
			rep.Passing = append(rep.Passing, a)
			continue
		case access.Denied:
			a.Reason = i18n.T("commands.denied")
			rep.Pending = append(rep.Pending, a)
			continue
		}
		if err := access.ReadOnlyAllowing(a.Argv, nil, c); err != nil {
			a.Reason = err.Error()
			rep.Pending = append(rep.Pending, a)
		} else {
			rep.Passing = append(rep.Passing, a)
		}
	}
	rep.Distinct = len(rep.Asked)
	return rep, nil
}

func scanDecisions(path string, add func(instance string, argv []string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !strings.Contains(string(line), `"exec_decision"`) {
			continue
		}
		var e struct {
			Kind     string   `json:"kind"`
			Decision string   `json:"decision"`
			Instance string   `json:"instance"`
			Argv     []string `json:"argv"`
		}
		if json.Unmarshal(line, &e) != nil || e.Kind != "exec_decision" || !slices.Contains(askedDecisions, e.Decision) {
			continue
		}
		add(e.Instance, e.Argv)
	}
	return sc.Err()
}

type reasonGroup struct {
	reason string
	items  []*askedCommand
	count  int
}

func groupByReason(items []*askedCommand) []reasonGroup {
	idx := map[string]int{}
	var out []reasonGroup
	for _, a := range items {
		i, ok := idx[a.Reason]
		if !ok {
			i = len(out)
			idx[a.Reason] = i
			out = append(out, reasonGroup{reason: a.Reason})
		}
		out[i].items = append(out[i].items, a)
		out[i].count += a.Count
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].items) != len(out[j].items) {
			return len(out[i].items) > len(out[j].items)
		}
		return out[i].reason < out[j].reason
	})
	return out
}

func (r *commandReplay) write(w io.Writer, all bool) error {
	fmt.Fprintln(w, i18n.T("commands.summary", r.Files, r.Distinct, len(r.Pending), len(r.Passing)))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, g := range groupByReason(r.Pending) {
		fmt.Fprintf(tw, "\n%d\t%s\n", len(g.items), g.reason)
		for _, a := range g.items {
			fmt.Fprintf(tw, "\t%s\t×%d\t%s\n", a.Instance, a.Count, oneLineArgv(a.Argv))
		}
	}
	if all && len(r.Passing) > 0 {
		fmt.Fprintln(tw, "\n"+i18n.T("commands.passing"))
		for _, a := range r.Passing {
			fmt.Fprintf(tw, "\t%s\t×%d\t%s\n", a.Instance, a.Count, oneLineArgv(a.Argv))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(r.Missing) > 0 {
		names := make([]string, 0, len(r.Missing))
		for n := range r.Missing {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintln(w, "\n"+i18n.T("commands.missing", strings.Join(names, ", ")))
	}
	if r.Ignored > 0 {
		fmt.Fprintln(w, i18n.T("commands.ignored", r.Ignored))
	}
	fmt.Fprintln(w, i18n.T("commands.trusted_note"))
	return nil
}

func oneLineArgv(argv []string) string {
	s := strings.Join(strings.Fields(access.Display(argv)), " ")
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}
