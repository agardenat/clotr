package orchestrator

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/pending"
	"github.com/agardenat/clotr/internal/progress"
)

const ResumeID = "pending"

type Resume struct {
	From  int
	Items []pending.Item
	Goals map[string]string
	Roles map[string]string
	Call  func(context.Context, pending.Item) (string, error)
}

func PendingCommand(it pending.Item) string {
	if it.Kind == pending.KindExec {
		return access.Display(it.Argv)
	}
	args := strings.Join(strings.Fields(string(it.Args)), " ")
	if len(args) > 300 {
		args = args[:300] + "…"
	}
	return strings.TrimSpace(it.Tool + " " + args)
}

func (o *Orchestrator) runResume(ctx context.Context, request string) (*Report, error) {
	var results []Result
	if o.CVE != nil {
		o.CVE.Prepare(ctx)
		if ctx.Err() != nil {
			return &Report{Plan: &Plan{}, Results: results}, ctx.Err()
		}
		if len(o.CVE.Missing()) == 0 {
			t := o.cachedAdvisories()
			results = append(results, t)
			o.triaged = &t
		}
	}
	if o.PrepareTools != nil {
		var names []string
		for _, it := range o.Resume.Items {
			if it.Status == pending.StatusApproved && !slices.Contains(names, it.Instance) {
				names = append(names, it.Instance)
			}
		}
		if len(names) > 0 {
			o.PrepareTools(ctx, names)
		}
	}
	step := o.resumeStep(ctx)
	results = append(results, step)
	o.resumed = &step
	if ctx.Err() != nil {
		return &Report{Plan: &Plan{}, Results: results}, ctx.Err()
	}
	plan, err := o.resumePlan()
	if err != nil {
		return nil, err
	}
	if len(plan.Tasks) > 0 && !o.Runner.Concluding() {
		if o.PrepareTools != nil {
			var names []string
			for _, t := range plan.Tasks {
				names = append(names, t.Tools...)
			}
			o.PrepareTools(ctx, names)
		}
		results = append(results, o.Execute(ctx, request, plan)...)
	}
	if ctx.Err() != nil {
		return &Report{Plan: plan, Results: results}, ctx.Err()
	}
	if !o.Runner.Concluding() {
		o.Verify(ctx, results)
	}
	if ctx.Err() != nil {
		return &Report{Plan: plan, Results: results}, ctx.Err()
	}
	md, model, err := o.Synthesize(ctx, request, results)
	return &Report{Plan: plan, Results: results, Markdown: md, Model: model}, err
}

func (o *Orchestrator) resumeStep(ctx context.Context) Result {
	r := Result{TaskID: ResumeID, Goal: fmt.Sprintf("Exécution des commandes mises en attente au tour %d (run sans terminal) et validées depuis par l'utilisateur", o.Resume.From), Status: "ok"}
	label := i18n.T("pending.step", o.Resume.From)
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: ResumeID, Goal: label}}})
	o.Events.Emit(progress.Event{Task: ResumeID, Kind: "start"})
	for i := range o.Resume.Items {
		it := &o.Resume.Items[i]
		cmd := PendingCommand(*it)
		origin := fmt.Sprintf("tâche %s du tour %d, instance %s", defaultTask(it.Task), o.Resume.From, it.Instance)
		if it.Where != "" {
			origin += ", " + it.Where
		}
		switch it.Status {
		case pending.StatusApproved:
			if ctx.Err() != nil {
				return r
			}
			out, err := o.Resume.Call(ctx, *it)
			r.ToolCalls++
			id := o.Runner.Evidence.Add(ResumeID, it.Tool, string(it.Args), out, err)
			it.Evidence = id
			if err != nil {
				it.Status, it.Error = pending.StatusFailed, err.Error()
				r.Gaps = append(r.Gaps, fmt.Sprintf("Commande validée en échec (%s) : %s : %v [%s]", origin, cmd, err, id))
				continue
			}
			it.Status = pending.StatusDone
			r.Evidence = append(r.Evidence, id)
			r.Findings = append(r.Findings, fmt.Sprintf("Sortie de la commande validée par l'utilisateur (%s) : %s [%s]", origin, cmd, id))
		case pending.StatusRefused:
			r.Gaps = append(r.Gaps, fmt.Sprintf("Commande refusée par l'utilisateur (%s) : %s", origin, cmd))
		}
	}
	o.Audit.Log("pending_step", map[string]any{"from": o.Resume.From, "calls": r.ToolCalls, "findings": len(r.Findings), "gaps": len(r.Gaps)})
	o.Events.Emit(progress.Event{Task: ResumeID, Kind: "done", Detail: i18n.N(r.ToolCalls, "tool call")})
	return r
}

func defaultTask(t string) string {
	if t == "" {
		return "?"
	}
	return t
}

func (o *Orchestrator) resumePlan() (*Plan, error) {
	p := &Plan{fixed: true}
	tools := map[string][]string{}
	var order []string
	for _, it := range o.Resume.Items {
		if it.Status != pending.StatusDone && it.Status != pending.StatusFailed {
			continue
		}
		task := it.Task
		if task == "" || task == ResumeID {
			task = "t1"
		}
		if _, ok := tools[task]; !ok {
			order = append(order, task)
		}
		if !slices.Contains(tools[task], it.Instance) {
			tools[task] = append(tools[task], it.Instance)
		}
	}
	for _, task := range order {
		role := o.Resume.Roles[task]
		if r, ok := o.Cfg.Roles[role]; !ok || !r.Tools {
			var err error
			if role, err = o.DirectRole(""); err != nil {
				return nil, err
			}
		}
		goal := fmt.Sprintf("Reprise de la tâche %s du tour %d", task, o.Resume.From)
		if g := o.Resume.Goals[task]; g != "" {
			goal += " (« " + g + " »)"
		}
		goal += fmt.Sprintf(" : les commandes qu'elle n'avait pas pu exécuter faute de terminal ont été validées par l'utilisateur et exécutées par l'étape %s, dont le résultat t'est transmis avec leurs preuves (sorties ou erreurs). Lis ces preuves, établis ce qu'elles montrent pour le périmètre de cette tâche et ce qu'elles changent à ses constats et à ses points ouverts ; complète par d'autres commandes de lecture seulement si une sortie l'exige. En mode CVE, signale de nouveau avec cve_report le statut de chaque actif dont une sortie établit ou change le statut.", ResumeID)
		p.Tasks = append(p.Tasks, Task{ID: task, Role: role, Goal: goal, Tools: tools[task]})
	}
	if len(p.Tasks) == 0 {
		return p, nil
	}
	if err := o.Validate(p); err != nil {
		return nil, err
	}
	items := make([]progress.PlanItem, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		items = append(items, progress.PlanItem{ID: t.ID, Role: t.Role, Goal: t.Goal})
	}
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: items})
	o.Audit.Log("plan", map[string]any{"fixed": true, "resume": o.Resume.From, "tasks": p.Tasks})
	return p, nil
}
