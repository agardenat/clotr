package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

var (
	thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>`)
	fence      = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```")
)

type Router interface {
	Candidates(role string) ([]catalog.ModelInfo, error)
}

type Task struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	Goal      string   `json:"goal"`
	Tools     []string `json:"tools"`
	DependsOn []string `json:"depends_on"`
}

type Plan struct {
	Tasks []Task `json:"tasks"`
	Model string `json:"model,omitempty"`
}

type Result struct {
	TaskID        string   `json:"task_id"`
	Role          string   `json:"role"`
	Goal          string   `json:"goal"`
	Model         string   `json:"model,omitempty"`
	Status        string   `json:"status"`
	Findings      []string `json:"findings,omitempty"`
	Evidence      []string `json:"evidence,omitempty"`
	Gaps          []string `json:"gaps,omitempty"`
	Raw           string   `json:"raw,omitempty"`
	Error         string   `json:"error,omitempty"`
	Steps         int      `json:"steps"`
	Limited       bool     `json:"limited,omitempty"`
	Limit         string   `json:"limit,omitempty"`
	Continuations int      `json:"continuations,omitempty"`
	ToolCalls     int      `json:"tool_calls"`
	Cost          float64  `json:"cost"`
	Duration      string   `json:"duration"`
}

type Report struct {
	Plan     *Plan
	Results  []Result
	Markdown string
	Model    string
}

type Orchestrator struct {
	Cfg             *config.Config
	Router          Router
	Runner          *agent.Runner
	Tools           *tools.Registry
	Audit           *audit.Logger
	Events          progress.Sink
	Environment     string
	EvidenceDisplay func(string) string
	Memory          *memory.Store
	WebTools        []string
	History         string
	Turn            int
	AfterTask       func(ctx context.Context)
	Language        string
	OnAnswer        func(text string)
}

func (o *Orchestrator) langDirective() string {
	switch o.Language {
	case "fr":
		return "Rédige toute ta production (objectifs, constats, preuves, rapport) en français, quelle que soit la langue de la demande."
	case "en":
		return "Write all of your output (goals, findings, evidence, report) in English, whatever the language of the request."
	}
	return "Rédige dans la langue de la demande."
}

func (o *Orchestrator) afterTask(ctx context.Context) {
	if o.AfterTask != nil {
		o.AfterTask(ctx)
	}
}

func (o *Orchestrator) withHistory(request string) string {
	if o.History == "" {
		return "Demande:\n" + request
	}
	return fmt.Sprintf("Nouvelle demande (affinage d'une session existante):\n%s\n\nContexte de la session:\n%s\nLa mémoire partagée contient les faits établis aux tours précédents (memory_search).", request, o.History)
}

func (o *Orchestrator) Run(ctx context.Context, request string) (*Report, error) {
	plan, err := o.Plan(ctx, request)
	if err != nil {
		return nil, err
	}
	results := o.Execute(ctx, request, plan)
	if ctx.Err() != nil {
		return &Report{Plan: plan, Results: results}, ctx.Err()
	}
	o.Verify(ctx, results)
	if ctx.Err() != nil {
		return &Report{Plan: plan, Results: results}, ctx.Err()
	}
	md, model, err := o.Synthesize(ctx, request, results)
	return &Report{Plan: plan, Results: results, Markdown: md, Model: model}, err
}

func (o *Orchestrator) continuations() int {
	if o.Cfg.Limits.Continuations == nil {
		return 0
	}
	return *o.Cfg.Limits.Continuations
}

func needsContinuation(r Result) bool {
	if r.Limit == "stall" {
		return false
	}
	return r.Limited || (r.Status != "ok" && r.Steps > 1)
}

func continuationTask(t Task, n int) Task {
	c := t
	c.ID = fmt.Sprintf("%s.%d", t.ID, n)
	c.DependsOn = nil
	c.Goal = fmt.Sprintf("Suite de la tâche %s, interrompue par la limite d'étapes ou de temps. Objectif initial: %s\nLe résultat partiel est fourni ci-dessous: ne refais pas ce qui y est établi, traite en priorité ses gaps et ce qui manque à l'objectif, puis conclus.", t.ID, t.Goal)
	return c
}

var noteCite = regexp.MustCompile(`\[#\d+\]|\(#\d+\)|(?:mémoire|note)[^\]\n]{0,20}#\d+`)

const noteOnlyMark = " ⚠ *non vérifié : seule source une note de mémoire*"

var noteID = regexp.MustCompile(`#(\d+)`)

func (o *Orchestrator) noteContents() map[string]string {
	out := map[string]string{}
	if o.Memory == nil {
		return out
	}
	for _, e := range o.Memory.All() {
		out[fmt.Sprint(e.ID)] = e.Content
	}
	return out
}

func flagNoteOnlyLines(md string, ev *evidence.Store, notes map[string]string) (string, int) {
	lines := strings.Split(md, "\n")
	n := 0
	for i, l := range lines {
		if !noteCite.MatchString(l) || ev.Proven(l) || strings.Contains(l, noteOnlyMark) {
			continue
		}
		backed := false
		for _, m := range noteID.FindAllStringSubmatch(l, -1) {
			if ev.Proven(notes[m[1]]) {
				backed = true
				break
			}
		}
		if backed {
			continue
		}
		lines[i] = l + noteOnlyMark
		n++
	}
	return strings.Join(lines, "\n"), n
}

func checkWorkerJSON(content string) string {
	var parsed struct {
		Findings []string `json:"findings"`
		Evidence []string `json:"evidence"`
		Gaps     []string `json:"gaps"`
	}
	if err := ExtractJSON(content, &parsed); err != nil {
		return fmt.Sprintf("Ta réponse n'est pas un objet JSON valide (%v). Renvoie uniquement l'objet JSON complet {\"findings\":[…],\"evidence\":[…],\"gaps\":[…]}, sans texte autour, en échappant les guillemets et les antislashs dans les chaînes.", err)
	}
	return ""
}

func markUnproven(ev *evidence.Store, findings []string) int {
	if ev == nil {
		return 0
	}
	n := 0
	for i, f := range findings {
		if !strings.HasPrefix(f, UnprovenTag) && !ev.Proven(f) {
			findings[i] = UnprovenTag + " " + f
			n++
		}
	}
	return n
}

const UnprovenTag = "[NON PROUVÉ : aucune preuve citée n'existe dans la session]"

func synthInput(results []Result) string {
	var b strings.Builder
	list := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s:\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "- %s\n", strings.Join(strings.Fields(it), " "))
		}
	}
	for _, r := range results {
		fmt.Fprintf(&b, "\n### %s · %s · %s", r.TaskID, r.Role, r.Status)
		if r.Limited {
			fmt.Fprintf(&b, " · arrêtée par %s", r.Limit)
		}
		fmt.Fprintf(&b, "\nObjectif: %s\n", strings.Join(strings.Fields(r.Goal), " "))
		if r.Error != "" {
			fmt.Fprintf(&b, "Erreur: %s\n", r.Error)
		}
		list("Constats", r.Findings)
		list("Non vérifié", r.Gaps)
		if r.Raw != "" {
			fmt.Fprintf(&b, "Sortie non structurée:\n%s\n", r.Raw)
		}
	}
	return b.String()
}

func incompleteGap(r Result) string {
	return fmt.Sprintf("investigation incomplète: tâche arrêtée par la limite %s après %d suite(s); l'objectif n'est pas entièrement couvert", r.Limit, r.Continuations)
}

func mergeResults(prev, next Result) Result {
	out := next
	out.TaskID, out.Goal = prev.TaskID, prev.Goal
	out.Findings = appendUnique(prev.Findings, next.Findings)
	out.Evidence = appendUnique(prev.Evidence, next.Evidence)
	if next.Status != "ok" {
		out.Status, out.Error, out.Limited, out.Limit = prev.Status, prev.Error, prev.Limited, prev.Limit
		out.Gaps = appendUnique(prev.Gaps, next.Gaps)
		if prev.Status == "ok" {
			out.Gaps = append(out.Gaps, "suite interrompue: "+next.Error)
		}
	}
	if prev.Raw != "" && next.Raw != "" {
		out.Raw = prev.Raw + "\n\n" + next.Raw
	} else if out.Raw == "" {
		out.Raw = prev.Raw
	}
	out.Steps += prev.Steps
	out.ToolCalls += prev.ToolCalls
	out.Cost += prev.Cost
	out.Continuations = prev.Continuations + 1
	return out
}

func appendUnique(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func (o *Orchestrator) Plan(ctx context.Context, request string) (*Plan, error) {
	cands, err := o.Router.Candidates(config.RolePlanner)
	if err != nil {
		return nil, err
	}
	user := o.withHistory(request)
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		o.Events.Emit(progress.Event{Task: "planner", Kind: "start", Model: o.Runner.First(cands)})
		out, err := o.Runner.Run(ctx, agent.Spec{TaskID: "planner", Role: config.RolePlanner, System: o.plannerPrompt(), User: user, Candidates: cands})
		if err != nil {
			return nil, fmt.Errorf("planner: %w", err)
		}
		var plan Plan
		if err := ExtractJSON(out.Content, &plan); err != nil {
			lastErr = err
		} else if err := o.Validate(&plan); err != nil {
			lastErr = err
		} else {
			plan.Model = out.Model
			items := make([]progress.PlanItem, 0, len(plan.Tasks))
			for _, t := range plan.Tasks {
				items = append(items, progress.PlanItem{ID: t.ID, Role: t.Role, Goal: t.Goal, DependsOn: t.DependsOn})
			}
			o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Model: out.Model, Plan: items})
			o.Audit.Log("plan", map[string]any{"model": out.Model, "tasks": plan.Tasks})
			o.Events.Emit(progress.Event{Task: "planner", Kind: "done", Model: out.Model, Detail: i18n.N(len(plan.Tasks), "task")})
			o.afterTask(ctx)
			return &plan, nil
		}
		o.Audit.Log("plan_invalid", map[string]any{"attempt": attempt, "error": lastErr.Error(), "content": out.Content})
		user = fmt.Sprintf("%s\n\nTa réponse précédente était invalide:\n%s\n\nErreur: %s\nCorrige et renvoie uniquement le JSON.", o.withHistory(request), out.Content, lastErr)
	}
	return nil, fmt.Errorf("plan invalide: %w", lastErr)
}

func (o *Orchestrator) Validate(p *Plan) error {
	if len(p.Tasks) == 0 {
		return errors.New("aucune tâche")
	}
	if len(p.Tasks) > o.Cfg.Limits.MaxTasks {
		return fmt.Errorf("%d tâches, maximum %d", len(p.Tasks), o.Cfg.Limits.MaxTasks)
	}
	workers := o.Cfg.WorkerRoles()
	ids := map[string]bool{}
	for i := range p.Tasks {
		t := &p.Tasks[i]
		if t.ID == "" || ids[t.ID] {
			return fmt.Errorf("tâche %d: id vide ou dupliqué %q", i, t.ID)
		}
		ids[t.ID] = true
		if !slices.Contains(workers, t.Role) {
			return fmt.Errorf("tâche %s: rôle %q invalide (valides: %s)", t.ID, t.Role, strings.Join(workers, ", "))
		}
		if strings.TrimSpace(t.Goal) == "" {
			return fmt.Errorf("tâche %s: goal vide", t.ID)
		}
		role := o.Cfg.Roles[t.Role]
		if !role.Tools {
			if len(t.Tools) > 0 {
				return fmt.Errorf("tâche %s: le rôle %s n'utilise pas d'outils", t.ID, t.Role)
			}
			continue
		}
		if len(t.Tools) == 0 {
			t.Tools = o.Tools.Names()
			continue
		}
		expanded, err := o.Tools.Expand(t.Tools)
		if err != nil {
			return fmt.Errorf("tâche %s: %w", t.ID, err)
		}
		for _, n := range append(o.Tools.GroupMembers(expanded), o.Tools.Companions(expanded)...) {
			if !slices.Contains(expanded, n) {
				expanded = append(expanded, n)
			}
		}
		if o.Memory != nil {
			for _, n := range memory.ToolNames() {
				if !slices.Contains(expanded, n) && slices.Contains(o.Tools.Names(), n) {
					expanded = append(expanded, n)
				}
			}
		}
		extra := append([]string{evidence.ToolName, evidence.SearchName}, o.WebTools...)
		for _, n := range extra {
			if !slices.Contains(expanded, n) && slices.Contains(o.Tools.Names(), n) {
				expanded = append(expanded, n)
			}
		}
		t.Tools = expanded
	}
	for _, t := range p.Tasks {
		for _, d := range t.DependsOn {
			if d == t.ID || !ids[d] {
				return fmt.Errorf("tâche %s: dépendance invalide %q", t.ID, d)
			}
		}
	}
	return checkCycles(p.Tasks)
}

func checkCycles(tasks []Task) error {
	indeg := map[string]int{}
	children := map[string][]string{}
	inPlan := map[string]bool{}
	for _, t := range tasks {
		inPlan[t.ID] = true
	}
	for _, t := range tasks {
		indeg[t.ID] += 0
		for _, d := range t.DependsOn {
			if !inPlan[d] {
				continue
			}
			indeg[t.ID]++
			children[d] = append(children[d], t.ID)
		}
	}
	var queue []string
	for _, t := range tasks {
		if indeg[t.ID] == 0 {
			queue = append(queue, t.ID)
		}
	}
	seen := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		seen++
		for _, c := range children[id] {
			indeg[c]--
			if indeg[c] == 0 {
				queue = append(queue, c)
			}
		}
	}
	if seen != len(tasks) {
		return errors.New("cycle dans depends_on")
	}
	return nil
}

func (o *Orchestrator) Execute(ctx context.Context, request string, p *Plan) []Result {
	done := make(map[string]chan struct{}, len(p.Tasks))
	results := make(map[string]Result, len(p.Tasks))
	for _, t := range p.Tasks {
		done[t.ID] = make(chan struct{})
	}
	var mu sync.Mutex
	sem := semaphore.NewWeighted(int64(o.Cfg.Limits.MaxAgents))
	var wg sync.WaitGroup
	for _, t := range p.Tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done[t.ID])
			res := Result{TaskID: t.ID, Role: t.Role, Goal: t.Goal}
			for _, d := range t.DependsOn {
				select {
				case <-done[d]:
				case <-ctx.Done():
				}
			}
			if err := sem.Acquire(ctx, 1); err != nil {
				res.Status, res.Error = "failed", err.Error()
			} else {
				mu.Lock()
				var deps []Result
				for _, d := range t.DependsOn {
					deps = append(deps, results[d])
				}
				mu.Unlock()
				res = o.runTask(ctx, request, t, deps)
				for n := 2; n <= o.continuations()+1 && ctx.Err() == nil && needsContinuation(res); n++ {
					c := continuationTask(t, n)
					o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: c.ID, Role: c.Role, Goal: i18n.T("continuation", t.ID, t.Goal)}}})
					o.Audit.Log("continuation", map[string]any{"task": t.ID, "id": c.ID, "limited": res.Limited, "error": res.Error})
					next := o.runTask(ctx, request, c, append(append([]Result(nil), deps...), res))
					res = mergeResults(res, next)
				}
				if res.Limited && res.Status == "ok" {
					res.Gaps = append(res.Gaps, incompleteGap(res))
				}
				sem.Release(1)
			}
			mu.Lock()
			results[t.ID] = res
			mu.Unlock()
		}()
	}
	wg.Wait()
	out := make([]Result, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		out = append(out, results[t.ID])
	}
	return out
}

func (o *Orchestrator) runTask(ctx context.Context, request string, t Task, deps []Result) Result {
	start := time.Now()
	res := Result{TaskID: t.ID, Role: t.Role, Goal: t.Goal}
	finish := func() Result {
		res.Duration = time.Since(start).Truncate(time.Millisecond).String()
		o.Audit.Log("task_end", map[string]any{"task": t.ID, "status": res.Status, "model": res.Model, "error": res.Error, "steps": res.Steps, "tool_calls": res.ToolCalls, "duration": res.Duration})
		kind := "done"
		detail := i18n.N(len(res.Findings), "finding") + ", " + i18n.N(res.ToolCalls, "tool call")
		if len(res.Findings) == 0 && res.Raw != "" {
			detail = i18n.T("raw.output") + ", " + i18n.N(res.ToolCalls, "tool call")
		}
		if res.Status != "ok" {
			kind, detail = "failed", res.Error
		}
		o.Events.Emit(progress.Event{Task: t.ID, Kind: kind, Model: res.Model, Detail: detail, Cost: res.Cost, Step: res.Steps, Duration: time.Since(start)})
		o.afterTask(ctx)
		return res
	}
	cands, err := o.Router.Candidates(t.Role)
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return finish()
	}
	o.Events.Emit(progress.Event{Task: t.ID, Kind: "start", Model: o.Runner.First(cands), Detail: t.Goal})
	tctx, cancel := context.WithCancel(ctx)
	var deadline time.Time
	if timeout := o.Cfg.Limits.AgentTimeout.Duration; timeout > 0 {
		cancel()
		if o.Runner.ConcludeReserve > 0 {
			deadline = time.Now().Add(timeout)
			timeout += o.Runner.ConcludeReserve
		}
		tctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	out, err := o.Runner.Run(tctx, agent.Spec{
		TaskID:     t.ID,
		Role:       t.Role,
		System:     o.workerPrompt(t.Role),
		User:       workerInput(request, t, deps),
		Tools:      t.Tools,
		Candidates: cands,
		Deadline:   deadline,
		Check:      checkWorkerJSON,
	})
	if out != nil {
		res.Model, res.Steps, res.ToolCalls, res.Cost, res.Limited, res.Limit = out.Model, out.Steps, out.ToolCalls, out.Cost, out.Limited, out.Limit
	}
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return finish()
	}
	res.Status = "ok"
	var parsed struct {
		Findings []string `json:"findings"`
		Evidence []string `json:"evidence"`
		Gaps     []string `json:"gaps"`
	}
	if err := ExtractJSON(out.Content, &parsed); err != nil || len(parsed.Findings)+len(parsed.Evidence)+len(parsed.Gaps) == 0 {
		res.Raw = out.Content
	} else {
		res.Findings, res.Evidence, res.Gaps = parsed.Findings, parsed.Evidence, parsed.Gaps
	}
	if n := markUnproven(o.Runner.Evidence, res.Findings); n > 0 {
		o.Audit.Log("unproven_findings", map[string]any{"task": t.ID, "count": n, "total": len(res.Findings)})
	}
	if o.Memory != nil {
		for i, f := range res.Findings {
			_, _ = o.Memory.Put(memory.Entry{Key: fmt.Sprintf("tour%d/%s/finding/%d", max(o.Turn, 1), t.ID, i+1), Content: f, Kind: "finding", Task: t.ID, Model: out.Model, Sovereign: out.Sovereign})
		}
	}
	return finish()
}

func (o *Orchestrator) Synthesize(ctx context.Context, request string, results []Result) (string, string, error) {
	ok := 0
	var errs []string
	for _, r := range results {
		if r.Status == "ok" {
			ok++
		} else {
			errs = append(errs, r.TaskID+": "+r.Error)
		}
	}
	if ok == 0 {
		return "", "", fmt.Errorf("toutes les tâches ont échoué:\n%s", strings.Join(errs, "\n"))
	}
	cands, err := o.Router.Candidates(config.RoleSynthesizer)
	if err != nil {
		return "", "", err
	}
	user := fmt.Sprintf("%s\n\nRésultats des sous-agents:\n%s", o.withHistory(request), synthInput(results))
	if o.History != "" {
		user += "\n\nC'est un affinage: réponds à la nouvelle demande en t'appuyant sur le dernier rapport et les nouveaux résultats. Si la demande porte sur le rapport lui-même (compléter, corriger, restructurer), produis le rapport complet mis à jour."
	}
	var notes []memory.Entry
	for _, e := range o.Memory.All() {
		if e.Kind == "note" {
			notes = append(notes, e)
		}
	}
	if len(notes) > 0 {
		user += "\n\nNotes de la mémoire partagée (faits enregistrés par les agents):\n" + memory.Format(notes)
	}
	o.Events.Emit(progress.Event{Task: "synthesizer", Kind: "start", Model: o.Runner.First(cands)})
	out, err := o.Runner.Run(ctx, agent.Spec{
		TaskID:     "synthesizer",
		Role:       config.RoleSynthesizer,
		System:     o.synthesizerSystem(),
		User:       user,
		Candidates: cands,
		OnText:     o.OnAnswer,
	})
	if err != nil {
		return "", "", fmt.Errorf("synthesizer: %w", err)
	}
	o.Events.Emit(progress.Event{Task: "synthesizer", Kind: "done", Model: out.Model})
	o.afterTask(ctx)
	return o.finalize(out.Content), out.Model, nil
}

func (o *Orchestrator) finalize(content string) string {
	if o.Runner.Evidence == nil {
		return content
	}
	content, n := flagNoteOnlyLines(content, o.Runner.Evidence, o.noteContents())
	if n > 0 {
		o.Audit.Log("note_only_lines", map[string]any{"count": n})
	}
	return content + o.Runner.Evidence.Annex(content, i18n.T("evidence.title"), i18n.T("evidence.unknown"), o.displayPath)
}

const DirectTask = "direct"

func (o *Orchestrator) DirectRole(role string) (string, error) {
	workers := o.Cfg.WorkerRoles()
	if role != "" {
		if !slices.Contains(workers, role) {
			return "", fmt.Errorf("--direct: rôle %q invalide (valides: %s)", role, strings.Join(workers, ", "))
		}
		return role, nil
	}
	best := ""
	for _, name := range workers {
		r := o.Cfg.Roles[name]
		if !r.Tools {
			continue
		}
		if best == "" || config.TierRank(r.Tier) < config.TierRank(o.Cfg.Roles[best].Tier) {
			best = name
		}
	}
	if best == "" {
		return "", errors.New("--direct: aucun rôle outillé dans la configuration")
	}
	return best, nil
}

func (o *Orchestrator) Direct(ctx context.Context, request, role string) (*Report, error) {
	role, err := o.DirectRole(role)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	t := Task{ID: DirectTask, Role: role, Goal: request}
	if o.Cfg.Roles[role].Tools {
		t.Tools = o.Tools.Names()
	}
	plan := &Plan{Tasks: []Task{t}}
	res := Result{TaskID: t.ID, Role: role, Goal: request}
	cands, err := o.Router.Candidates(role)
	if err != nil {
		return nil, err
	}
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: t.ID, Role: role, Goal: request}}})
	o.Events.Emit(progress.Event{Task: t.ID, Kind: "start", Model: o.Runner.First(cands), Detail: request})
	o.Audit.Log("direct", map[string]any{"role": role, "tools": len(t.Tools)})
	out, err := o.Runner.Run(ctx, agent.Spec{
		TaskID:     t.ID,
		Role:       role,
		System:     o.directPrompt(role),
		User:       o.withHistory(request),
		Tools:      t.Tools,
		Candidates: cands,
		OnText:     o.OnAnswer,
	})
	if out != nil {
		res.Model, res.Steps, res.ToolCalls, res.Cost, res.Limited, res.Limit = out.Model, out.Steps, out.ToolCalls, out.Cost, out.Limited, out.Limit
		plan.Model = out.Model
	}
	res.Duration = time.Since(start).Truncate(time.Millisecond).String()
	report := &Report{Plan: plan, Model: res.Model}
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		report.Results = []Result{res}
		o.Events.Emit(progress.Event{Task: t.ID, Kind: "failed", Model: res.Model, Detail: res.Error, Step: res.Steps, Duration: time.Since(start)})
		o.Audit.Log("task_end", map[string]any{"task": t.ID, "status": res.Status, "model": res.Model, "error": res.Error, "steps": res.Steps, "tool_calls": res.ToolCalls, "duration": res.Duration})
		return report, err
	}
	res.Status, res.Raw = "ok", out.Content
	report.Results = []Result{res}
	report.Markdown = o.finalize(out.Content)
	o.Events.Emit(progress.Event{Task: t.ID, Kind: "done", Model: res.Model, Detail: i18n.N(res.ToolCalls, "tool call"), Cost: res.Cost, Step: res.Steps, Duration: time.Since(start)})
	o.Audit.Log("task_end", map[string]any{"task": t.ID, "status": res.Status, "model": res.Model, "steps": res.Steps, "tool_calls": res.ToolCalls, "duration": res.Duration})
	o.afterTask(ctx)
	return report, nil
}

func ExtractJSON(s string, v any) error {
	s = strings.TrimSpace(thinkBlock.ReplaceAllString(s, ""))
	if m := fence.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return errors.New("aucun objet JSON trouvé")
	}
	var candidates []string
	if end := strings.LastIndexByte(s, '}'); end > start {
		candidates = append(candidates, s[start:end+1])
	}
	candidates = append(candidates, s[start:])
	var first error
	for _, raw := range candidates {
		err := json.Unmarshal([]byte(raw), v)
		if err == nil || json.Unmarshal([]byte(repairJSON(raw)), v) == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return fmt.Errorf("JSON invalide: %w", first)
}

func repairJSON(s string) string {
	var b strings.Builder
	var open []byte
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inStr {
			switch c {
			case '"':
				inStr = true
			case '{', '[':
				open = append(open, c)
			case '}', ']':
				if len(open) > 0 {
					open = open[:len(open)-1]
				}
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '\\':
			if i+1 < len(s) && validEscape(s[i+1:]) {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
				i++
			} else {
				b.WriteString(`\\`)
			}
		case '"':
			inStr = false
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	if inStr {
		b.WriteByte('"')
	}
	for k := len(open) - 1; k >= 0; k-- {
		if open[k] == '{' {
			b.WriteByte('}')
		} else {
			b.WriteByte(']')
		}
	}
	return b.String()
}

func validEscape(rest string) bool {
	switch rest[0] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	case 'u':
		if len(rest) < 5 {
			return false
		}
		for _, h := range rest[1:5] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", h) {
				return false
			}
		}
		return true
	}
	return false
}

func workerInput(request string, t Task, deps []Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Demande globale (contexte):\n%s\n\nTa tâche (%s):\n%s\n", request, t.ID, t.Goal)
	if len(deps) > 0 {
		data, _ := json.MarshalIndent(deps, "", "  ")
		fmt.Fprintf(&b, "\nRésultats des tâches dont tu dépends:\n%s\n", data)
	}
	return b.String()
}

func (o *Orchestrator) plannerPrompt() string {
	var roles strings.Builder
	for _, name := range o.Cfg.WorkerRoles() {
		r := o.Cfg.Roles[name]
		fmt.Fprintf(&roles, "- %s (outils: %t): %s\n", name, r.Tools, r.Description)
	}
	return fmt.Sprintf(`Tu es le planificateur d'un agent d'analyse d'infrastructure en LECTURE SEULE, exécuté en autonomie totale.
Décompose la demande en tâches confiées à des sous-agents qui s'exécutent EN PARALLÈLE.

Rôles disponibles:
%s
Outils disponibles (un groupe peut être référencé par son préfixe: fs, mcp_<serveur>, <instance>):
%s
Environnement:
%s
Règles:
- un sous-agent travaille tant qu'il progresse (nouveaux appels d'outils) et conclut quand il n'apprend plus rien, avec un plafond de sécurité de %d étapes; %d sous-agents s'exécutent en même temps;
- une tâche = un périmètre cohérent, jamais un simple appel d'outil;
- au plus %d tâches; pour une demande ciblée simple, 2 ou 3 tâches suffisent; une tâche de collecte détaillée ne couvre qu'une cible (cluster, contexte, cible de template), deux au plus; pour une investigation (cause d'une anomalie, volume de logs, incident), découper davantage: par cible ou par hôte, et séparer configuration, logs, volumétrie/disque, métriques et événements;
- prévoir une tâche d'analyse (depends_on vers les collectes) quand il faut recouper des résultats;
- pour un problème ou un incident, la demande vise une solution de fond: prévoir des tâches qui cherchent la cause racine et le correctif durable (configuration effective et valeurs par défaut, dimensionnement, documentation de l'éditeur, cause en amont), pas seulement l'état actuel; ne pas replanifier ce que la demande présente comme déjà connu ou déjà fait;
- l'environnement ci-dessus est déjà connu: ne pas créer de tâche pour le redécouvrir (lister les contextes, vérifier l'accès);
- en affinage de session, ne planifier que ce qui manque pour la nouvelle demande: les faits déjà établis sont en mémoire partagée et les sorties d'outils des tours précédents restent consultables (evidence_search, evidence_read); ne replanifier une collecte déjà faite que si la donnée a pu changer depuis; si aucune collecte n'est nécessaire, une seule tâche de rôle sans outils ou analyste suffit;
- maximiser le parallélisme: depends_on uniquement si une tâche a réellement besoin des résultats d'une autre; les cibles, hôtes et nœuds listés dans l'environnement sont déjà connus: une tâche qui les examine n'attend pas une tâche d'inventaire ou de statut;
- choisir le rôle le plus léger suffisant (collecte factuelle -> rôle rapide, analyse/recoupement -> rôle plus puissant);
- tools: pour une instance de template ou un groupe (fs, mcp_<serveur>), donner le préfixe du groupe (ex: prod) plutôt qu'une sélection d'outils, pour que le sous-agent puisse suivre une piste imprévue (logs, événements, listing); ne restreindre que pour exclure un groupe sans rapport avec la tâche;
- aucune tâche ne doit modifier quoi que ce soit.

%s

Réponds UNIQUEMENT avec un objet JSON de la forme:
{"tasks":[{"id":"t1","role":"<rôle>","goal":"<objectif>","tools":["<outil ou préfixe>"],"depends_on":[]}]}`,
		roles.String(), o.Tools.Describe(), o.Environment, o.Cfg.Limits.MaxSteps, o.Cfg.Limits.MaxAgents, o.Cfg.Limits.MaxTasks, o.langDirective())
}

func (o *Orchestrator) workerPrompt(role string) string {
	r := o.Cfg.Roles[role]
	return fmt.Sprintf(`Tu es un sous-agent d'analyse en LECTURE SEULE (rôle %s: %s).
Tu travailles en autonomie complète: ne pose aucune question, n'attends aucune confirmation.
Tu ne modifies jamais rien; tes outils sont uniquement des outils de lecture.
Reste factuel : chaque affirmation repose sur une sortie d'outil citée [Exxx]. N'invente jamais une valeur par défaut, un comportement de produit, la signification d'un message ou d'un paramètre, ni une chronologie.
%s
Avant de classer un constat comme anomalie, vérifie qu'il ne s'explique pas par un comportement attendu décrit dans l'environnement. Si ta tâche porte sur un problème, cherche ce qui le cause et ce qui l'empêcherait durablement (paramètre, mécanisme, documentation), pas seulement son état actuel. Un lien de cause à effet doit être appuyé par une preuve (message d'erreur, configuration, chronologie) ; sinon présente-le comme hypothèse dans gaps. Distingue valeurs par défaut et valeurs modifiées.
Une erreur d'outil (paramètre ou nom refusé, réponse illisible, sortie tronquée) est une limite de ta collecte, pas un constat sur l'infrastructure : note-la dans gaps, jamais dans findings. Pour tout taux, ratio ou projection, écris l'opération avec les valeurs mesurées et leurs horodatages.
Tu travailles tant que tu progresses : la tâche s'arrête d'elle-même quand tes appels n'apportent plus rien de nouveau. Ne relis pas une donnée déjà obtenue; si un outil renvoie une erreur de syntaxe ou de paramètre, corrige au plus une fois en t'appuyant sur sa description, puis passe à autre chose et note le manque dans gaps; si une sortie est tronquée, affine la requête (filtre, match, chemin précis) plutôt que de la répéter.
Preuves déjà collectées : les sorties d'outils de tous les tours de la session sont archivées. Avant de collecter, cherche avec evidence_search si la donnée existe déjà (outil, hôte, chemin), relis-la avec evidence_read, et ne recollecte que ce qui a pu changer depuis son heure de collecte (taille, occupation, état courant, logs récents), en le disant. Cite les preuves existantes par leur identifiant.
Historique : au-delà des dernières étapes, les sorties d'outils sont raccourcies dans ta conversation ; la sortie complète reste archivée et se relit avec evidence_read (id, pattern ou offset) sans refaire l'appel. Dès qu'une sortie contient un fait nécessaire à ta conclusion (valeur, horodatage, message exact, chemin), note-le aussitôt avec memory_write : tes notes te sont rendues au moment de conclure.
Les notes de mémoire (#N) sont des résumés d'agents datés, pas des preuves : pour un fait chiffré, retrouve et cite la preuve [Exxx] d'origine ; une note contredite par une preuve ou une note plus récente est périmée, corrige-la avec memory_write (même key).
Mémoire partagée (si memory_search/memory_write sont disponibles): commence par memory_search pour réutiliser ce que les autres agents ont déjà établi; enregistre avec memory_write les faits utiles aux autres (inventaires, versions, anomalies), avec une key stable et des tags. Sois économe: requêtes ciblées (namespace, selector, view, chemins précis) plutôt que des listings massifs.
Environnement:
%s
Quand tu as terminé, réponds UNIQUEMENT avec un objet JSON:
{"findings":["[CRITIQUE|MAJEUR|MINEUR|INFO] constat [E012]"],"evidence":["[E012] outil + paramètres essentiels : extrait factuel"],"gaps":["ce qui n'a pas pu être vérifié et pourquoi"]}
Chaque sortie d'outil commence par son identifiant de preuve [Exxx] (archivée en entier) : cite-le au début de chaque evidence et à la fin de chaque finding qu'il établit.
%s`, role, r.Description, o.webRule(), o.Environment, o.langDirective())
}

func (o *Orchestrator) directPrompt(role string) string {
	r := o.Cfg.Roles[role]
	tools := "Tu n'as pas d'outil : réponds à partir de la demande et du contexte de session ; ce que tu ne peux pas établir, dis-le."
	if r.Tools {
		tools = `Tes outils sont uniquement des outils de lecture. Commence par déterminer, d'après l'environnement ci-dessous, quelle source couvre la demande, et n'utilise que ses outils. Si aucune source disponible ne la couvre (annuaire, application ou système non connecté), réponds-le tout de suite en citant les sources disponibles, sans explorer au hasard : ni recherche de noms dans des logs, ni listing exploratoire. Une instance non activée demande des identifiants à l'utilisateur au premier appel de l'un de ses outils : ne l'appelle que si la demande la concerne.
Va droit au but : les appels strictement nécessaires pour répondre, en parallèle quand ils sont indépendants, requêtes ciblées plutôt que listings massifs. Chaque sortie d'outil commence par son identifiant de preuve [Exxx] (archivée en entier) : cite-le à côté de chaque fait qui en vient.
Avant de collecter, regarde si la donnée existe déjà dans la session (evidence_search, evidence_read, memory_search) et ne recollecte que ce qui a pu changer depuis.
Une erreur d'outil est une limite de ta collecte, pas un constat sur l'infrastructure : signale-la comme telle.`
	}
	return fmt.Sprintf(`Tu es un agent d'analyse d'infrastructure en LECTURE SEULE (rôle %s: %s) qui répond directement à l'utilisateur, sans planification ni sous-agents.
Tu travailles en autonomie complète : ne pose aucune question, n'attends aucune confirmation, ne modifie jamais rien.
%s
Reste factuel : n'invente jamais une valeur par défaut, un comportement de produit, la signification d'un message ou d'un paramètre, ni une chronologie. Un lien de cause à effet doit être appuyé par une preuve, sinon présente-le comme hypothèse. Pour un problème, vise la cause et le correctif durable, pas seulement l'état actuel.
%s
Environnement:
%s
Réponse finale : Markdown, directe et concise, sans préambule ; si la demande impose une forme ou une longueur, respecte-la strictement. Les notes de mémoire (#N) ne sont pas des preuves : cite les preuves [Exxx]. Ne fais suivre aucune annexe de preuves : clotr l'ajoute.
%s`, role, r.Description, tools, o.webRule(), o.Environment, o.langDirective())
}

func (o *Orchestrator) webRule() string {
	if len(o.WebTools) == 0 {
		return "Recherche web non disponible pour ce run : ce que tes outils ne permettent pas d'établir va dans gaps, sans supposition."
	}
	return fmt.Sprintf("Recherche web disponible (%s) : en cas de doute ou d'inconnu sur un produit (valeur par défaut, comportement, message d'erreur, bug connu, compatibilité de versions), cherche avant de conclure, en privilégiant la documentation officielle de l'éditeur et ses bases de connaissances, et cite la preuve [Exxx] de la page lue. Dès qu'une page officielle pertinente apparaît, lis-la (extract) au lieu de reformuler la requête, et ne relance jamais une requête déjà faite. Les requêtes partent sur Internet : n'y mets jamais d'identifiant interne (nom d'hôte, IP, nom de cluster, d'environnement, de compte ou d'utilisateur, domaine ou chemin propre au client), seulement des termes génériques (produit, version, message d'erreur sans identifiant).", strings.Join(o.WebTools, ", "))
}

func (o *Orchestrator) displayPath(p string) string {
	if o.EvidenceDisplay != nil {
		return o.EvidenceDisplay(p)
	}
	return p
}

func (o *Orchestrator) synthesizerSystem() string {
	sys := synthesizerPrompt
	if strings.TrimSpace(o.Environment) != "" {
		sys += "\nEnvironnement et consignes (servent à distinguer comportement attendu et anomalie):\n" + o.Environment
	}
	return sys + "\n" + o.langDirective()
}

const synthesizerPrompt = `Tu rédiges la réponse finale d'une analyse d'infrastructure en lecture seule à partir des résultats des sous-agents (par tâche : constats citant leurs preuves [Exxx], points non vérifiés). Le texte des preuves n'est pas fourni : clotr ajoute lui-même l'annexe des preuves citées.
Si la demande impose une forme ou une longueur (une phrase, N puces, un tableau, oui/non…), respecte-la strictement et n'ajoute rien d'autre.
Sinon, format Markdown:
1. Conclusion (5 lignes max) : réponse directe à la demande, cause racine (ou ce qui manque pour l'établir), correctif durable proposé, niveau d'urgence justifié par un fait chiffré
2. Constats classés par sévérité (CRITIQUE, MAJEUR, MINEUR, INFO), chacun avec ses preuves citées par leurs identifiants [Exxx] repris des constats (jamais par les identifiants de tâche t1, t2…, qui ne parlent pas au lecteur) et les valeurs factuelles du constat ; un comportement attendu (décrit dans l'environnement) n'est pas une anomalie ; INFO seulement pour ce qui éclaire la conclusion
3. Détail par périmètre
4. Points non vérifiés (hypothèses, gaps, tâches en échec, tâches « arrêtée par » une limite : nomme le périmètre resté incomplet et la limite atteinte, sans le présenter comme vérifié)
5. Limites de la collecte (erreurs d'outils, paramètres refusés, sorties tronquées) : ce sont des limites de l'analyse, pas des constats sur l'infrastructure ; ne les classe pas par sévérité et n'en fais pas de recommandation pour la plateforme
6. Recommandations (actions proposées, jamais exécutées), en deux parties :
   a. Correctif durable : ce qui supprime la cause ou empêche la récidive (configuration, dimensionnement, architecture, correction en amont). Pour chaque mesure : la cause traitée, la preuve [Exxx] ou la documentation qui la justifie, le risque et l'impact, et comment vérifier son effet.
   b. Mesures immédiates : palliatifs en attendant le correctif, brièvement
Règles de cohérence :
- Une cause n'est présentée comme établie, dans la conclusion comme dans les constats, que si un constat la prouve (message d'erreur, configuration, chronologie). Si un constat la contredit ou si elle n'est qu'une hypothèse, écris « hypothèse » et place-la dans les points non vérifiés ; la conclusion ne dit rien que le reste du rapport contredit.
- Tout calcul (projection, taux, ratio, délai avant saturation) est refait à partir des valeurs citées, avec l'opération et l'hypothèse explicites (ex : 14 Go libres / 5,3 Go par jour ≈ 2,6 jours si la croissance reste linéaire). Ne reprends pas un résultat calculé par un sous-agent sans le vérifier.
- Si deux résultats donnent des valeurs incompatibles pour la même mesure, signale l'écart au lieu de choisir silencieusement.
- Les constats CRITIQUE et MAJEUR ont été relus contre leurs preuves par un vérificateur : « [VÉRIFIÉ] » = étayé ; « [PARTIEL : raison] » = ne reprendre que la partie étayée et présenter le reste comme hypothèse ; « [NON ÉTAYÉ : raison] » = uniquement en point non vérifié, avec la raison. Ne recopie pas ces marqueurs dans le rapport.
- Un constat marqué « [NON PROUVÉ … ] » ne cite aucune preuve existante (contrôle fait par clotr) : il ne peut figurer qu'en point non vérifié, jamais dans la conclusion, les constats ou comme cause.
- Les notes de mémoire (#N) sont des résumés datés, pas des preuves : ne les cite jamais comme source (clotr signale dans le rapport toute ligne qui ne s'appuie que sur une note) ; un fait chiffré se cite par sa preuve [Exxx] ; une note contredite par un résultat ou une note plus récente est périmée et ne doit pas être reprise. Une valeur susceptible d'avoir changé (occupation disque, taille, état) se présente avec l'heure de sa mesure, et le délai écoulé depuis.
- Ce que la demande ou l'historique présente comme déjà connu ou déjà fait (une purge réalisée, un symptôme connu) n'est ni une découverte ni une recommandation principale. Un palliatif ne remplace jamais le correctif durable : si la cause racine n'est pas établie, dis-le et précise ce qu'il faut établir pour proposer un correctif durable.
Reste factuel : n'ajoute aucune connaissance extérieure aux résultats fournis ; une information issue d'une source web est attribuée à sa preuve [Exxx]. Dédupliquer les constats redondants.`
