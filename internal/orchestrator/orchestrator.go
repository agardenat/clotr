package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/lead"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/dns"
	"github.com/agardenat/clotr/internal/websearch"
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
	Incident        bool
	Journal         bool
	triaged         *Result
	stopVerify      atomic.Pointer[context.CancelFunc]
}

const (
	triageID   = "t0"
	triageGoal = "Tri d'incident, avant toute planification : localise le composant en échec désigné par la demande (ressource, cible, hôte) ; pour un accès à une URL ou à un nom, vérifie d'abord vers quelle IP il pointe et si c'est le point d'entrée attendu. Lis ensuite son message d'erreur exact (opération en échec, code, sous-code, détails) et sa configuration effective. Dès qu'une sortie d'outil montre une cause, signale-la avec cause_report, avant toute autre recherche ; si la même sortie en montre plusieurs, signale-les toutes dans la même étape. Une piste sérieuse (élément précis de la demande, comme une IP, un nom ou un code, retrouvé dans une configuration ou un log) se signale aussi aussitôt, en status clue, puis se vérifie. Le tri se termine dès qu'une cause établie est signalée : l'explication détaillée des codes d'erreur et la recherche du correctif seront confiées aux tâches planifiées ensuite, qui partiront de ton résultat."
	triageDone = "Une cause établie est signalée : l'objectif du tri est atteint. Conclus maintenant, au format demandé, sans appeler d'outil : localisation du composant, message d'erreur exact et configuration utile, avec leurs preuves. Indique dans gaps ce qui reste à expliquer ou à corriger, pour les tâches suivantes."
)

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

func (o *Orchestrator) ConcludeNow() {
	o.Runner.ConcludeNow()
	if stop := o.stopVerify.Load(); stop != nil {
		(*stop)()
	}
	o.Audit.Log("conclude_requested", map[string]any{})
	o.Events.Emit(progress.Event{Kind: "concluding", Detail: i18n.T("concluding")})
}

func (o *Orchestrator) triage(ctx context.Context, request string) Result {
	role, err := o.DirectRole("")
	if err != nil {
		return Result{TaskID: triageID, Goal: triageGoal, Status: "failed", Error: err.Error()}
	}
	t := Task{ID: triageID, Role: role, Goal: triageGoal, Tools: o.Tools.Names()}
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: t.ID, Role: t.Role, Goal: i18n.T("triage")}}})
	o.Audit.Log("triage", map[string]any{"role": role})
	return o.runTask(ctx, request, t, nil, o.causeEstablished)
}

func (o *Orchestrator) causeEstablished() string {
	for _, e := range o.Memory.All() {
		if e.Kind == lead.Kind && e.Task == triageID && slices.Contains(e.Tags, lead.Established) {
			return triageDone
		}
	}
	return ""
}

func (o *Orchestrator) Run(ctx context.Context, request string) (*Report, error) {
	var results []Result
	if o.Incident {
		t := o.triage(ctx, request)
		results = append(results, t)
		if t.Status == "ok" {
			o.triaged = &t
		}
		if ctx.Err() != nil {
			return &Report{Plan: &Plan{}, Results: results}, ctx.Err()
		}
	}
	plan := &Plan{}
	if !o.Runner.Concluding() {
		var err error
		if plan, err = o.Plan(ctx, request); err != nil {
			return nil, err
		}
		results = append(results, o.Execute(ctx, request, plan)...)
	}
	if ctx.Err() != nil {
		return &Report{Plan: plan, Results: results}, ctx.Err()
	}
	if o.Runner.Concluding() {
		o.Audit.Log("verify_skipped", map[string]any{"reason": "conclusion demandée"})
	} else {
		o.Verify(ctx, results)
	}
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

func checkWorker(ev *evidence.Store) func(string) string {
	return func(content string) string {
		var parsed struct {
			Findings []string `json:"findings"`
			Evidence []string `json:"evidence"`
			Gaps     []string `json:"gaps"`
		}
		if err := ExtractJSON(content, &parsed); err != nil {
			return fmt.Sprintf("Ta réponse n'est pas un objet JSON valide (%v). Renvoie uniquement l'objet JSON complet {\"findings\":[…],\"evidence\":[…],\"gaps\":[…]}, sans texte autour, en échappant les guillemets et les antislashs dans les chaînes.", err)
		}
		var keys map[string]json.RawMessage
		if ExtractJSON(content, &keys) != nil || (keys["findings"] == nil && keys["evidence"] == nil && keys["gaps"] == nil) {
			return "Ta réponse n'est pas la réponse finale attendue : elle ne contient ni findings, ni evidence, ni gaps (un appel d'outil écrit en texte n'est pas exécuté). Appelle les outils par le mécanisme d'appel d'outils si tu dois encore collecter, sinon renvoie l'objet JSON complet {\"findings\":[…],\"evidence\":[…],\"gaps\":[…]}."
		}
		if ev == nil {
			return ""
		}
		var bad []string
		for i, f := range parsed.Findings {
			if !strings.HasPrefix(f, UnprovenTag) && !ev.Proven(f) {
				line := []rune(strings.Join(strings.Fields(f), " "))
				if len(line) > 160 {
					line = append(line[:160], '…')
				}
				bad = append(bad, fmt.Sprintf("%d. %s", i+1, string(line)))
			}
		}
		if len(bad) == 0 {
			return ""
		}
		return "Ces constats ne citent aucune preuve existante dans leur propre texte (une citation placée seulement dans evidence ne compte pas) :\n" + strings.Join(bad, "\n") + "\nRenvoie l'objet JSON complet en ajoutant dans chacun de ces constats l'identifiant de la preuve qui l'établit, tel qu'il figure dans les résultats d'outils (ex. [E012] ou [E2.012]) ; un constat qu'aucune preuve n'établit va dans gaps."
	}
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
	user := o.planInput(request)
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
			if dropped := pruneSameRoleDeps(&plan); len(dropped) > 0 {
				o.Audit.Log("plan_deps_dropped", map[string]any{"dependencies": dropped})
			}
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
		user = fmt.Sprintf("%s\n\nTa réponse précédente était invalide:\n%s\n\nErreur: %s\nCorrige et renvoie uniquement le JSON.", o.planInput(request), out.Content, lastErr)
	}
	return nil, i18n.E("orch.plan_invalid", lastErr)
}

func (o *Orchestrator) planInput(request string) string {
	user := o.withHistory(request)
	if o.triaged == nil {
		return user
	}
	return user + "\n\nRésultat du tri d'incident (tâche " + triageID + ", déjà exécutée ; son résultat est transmis à chaque tâche, qui n'a pas à relocaliser le composant):" + synthInput([]Result{*o.triaged}) + "\nNe replanifie pas ce que le tri a établi. Si la cause est établie par une preuve, ne planifie que la vérification de cette cause et la recherche du correctif durable; sinon, découpe l'investigation à partir de ce qu'il a trouvé. L'id " + triageID + " est réservé: ne l'utilise pas."
}

func (o *Orchestrator) Validate(p *Plan) error {
	if len(p.Tasks) == 0 {
		return i18n.E("orch.no_task")
	}
	if len(p.Tasks) > o.Cfg.Limits.MaxTasks {
		return i18n.E("orch.too_many", len(p.Tasks), o.Cfg.Limits.MaxTasks)
	}
	workers := o.Cfg.WorkerRoles()
	ids := map[string]bool{}
	for i := range p.Tasks {
		t := &p.Tasks[i]
		if t.ID == "" || ids[t.ID] {
			return i18n.E("orch.task_id", i, t.ID)
		}
		if o.triaged != nil && t.ID == triageID {
			return i18n.E("orch.task_triage_id", i, triageID)
		}
		if o.triaged != nil {
			t.DependsOn = slices.DeleteFunc(t.DependsOn, func(d string) bool { return d == triageID })
		}
		ids[t.ID] = true
		if !slices.Contains(workers, t.Role) {
			return i18n.E("orch.task_role", t.ID, t.Role, strings.Join(workers, ", "))
		}
		if strings.TrimSpace(t.Goal) == "" {
			return i18n.E("orch.task_goal", t.ID)
		}
		role := o.Cfg.Roles[t.Role]
		if !role.Tools {
			if len(t.Tools) > 0 {
				return i18n.E("orch.task_no_tools", t.ID, t.Role)
			}
			continue
		}
		if len(t.Tools) == 0 {
			t.Tools = o.Tools.Names()
			continue
		}
		expanded, err := o.Tools.Expand(t.Tools)
		if err != nil {
			return i18n.E("orch.task_err", t.ID, err)
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
		extra := append([]string{evidence.ToolName, evidence.SearchName, lead.ToolName, dns.ToolName}, o.WebTools...)
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
				return i18n.E("orch.task_dep", t.ID, d)
			}
		}
	}
	return checkCycles(p.Tasks)
}

func pruneSameRoleDeps(p *Plan) map[string][]string {
	roles := map[string]string{}
	for _, t := range p.Tasks {
		roles[t.ID] = t.Role
	}
	dropped := map[string][]string{}
	for i := range p.Tasks {
		t := &p.Tasks[i]
		var kept []string
		for _, d := range t.DependsOn {
			if roles[d] == t.Role {
				dropped[t.ID] = append(dropped[t.ID], d)
				continue
			}
			kept = append(kept, d)
		}
		t.DependsOn = kept
		if len(dropped[t.ID]) > 0 {
			t.Goal += fmt.Sprintf("\n(Les résultats de %s ne te sont pas transmis : cette tâche s'exécute en même temps qu'elles. Établis toi-même ce dont tu as besoin avec l'environnement, l'inventaire et tes outils.)", strings.Join(dropped[t.ID], ", "))
		}
	}
	return dropped
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
		return i18n.E("orch.cycle")
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
			} else if o.Runner.Concluding() {
				sem.Release(1)
				res.Status, res.Gaps = "skipped", []string{"tâche non lancée: conclusion demandée par l'utilisateur"}
				o.Events.Emit(progress.Event{Task: t.ID, Kind: "skipped", Detail: i18n.T("task.skipped")})
				o.Audit.Log("task_skipped", map[string]any{"task": t.ID})
			} else {
				mu.Lock()
				var deps []Result
				if o.triaged != nil {
					deps = append(deps, *o.triaged)
				}
				for _, d := range t.DependsOn {
					deps = append(deps, results[d])
				}
				mu.Unlock()
				res = o.runTask(ctx, request, t, deps, nil)
				for n := 2; n <= o.continuations()+1 && ctx.Err() == nil && !o.Runner.Concluding() && needsContinuation(res); n++ {
					c := continuationTask(t, n)
					o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: c.ID, Role: c.Role, Goal: i18n.T("continuation", t.ID, t.Goal)}}})
					o.Audit.Log("continuation", map[string]any{"task": t.ID, "id": c.ID, "limited": res.Limited, "error": res.Error})
					next := o.runTask(ctx, request, c, append(append([]Result(nil), deps...), res), nil)
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

func (o *Orchestrator) runTask(ctx context.Context, request string, t Task, deps []Result, reached func() string) Result {
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
		if o.Journal {
			for _, f := range res.Findings {
				o.Events.Emit(progress.Event{Task: t.ID, Kind: "finding", Detail: f})
			}
			for _, g := range res.Gaps {
				o.Events.Emit(progress.Event{Task: t.ID, Kind: "gap", Detail: g})
			}
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
	spec := agent.Spec{
		TaskID:     t.ID,
		Role:       t.Role,
		System:     o.workerPrompt(t.Role),
		User:       workerInput(request, t, deps),
		Tools:      t.Tools,
		Candidates: cands,
		Deadline:   deadline,
		Check:      checkWorker(o.Runner.Evidence),
		Reached:    reached,
	}
	out, err := o.Runner.Run(tctx, spec)
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
		return "", "", i18n.E("orch.all_failed", strings.Join(errs, "\n"))
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
	var leads []memory.Entry
	for _, e := range o.Memory.All() {
		if e.Kind == lead.Kind {
			leads = append(leads, e)
		}
	}
	if len(leads) > 0 {
		user += "\n\nCauses et pistes signalées par les agents en cours de run (à confirmer par les preuves citées et les constats ; une piste non établie se présente comme telle):\n" + memory.Format(leads)
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
	return content + o.Runner.Evidence.Annex(content, i18n.R("evidence.title"), i18n.R("evidence.unknown"), o.displayPath)
}

const DirectTask = "direct"

func (o *Orchestrator) DirectRole(role string) (string, error) {
	workers := o.Cfg.WorkerRoles()
	if role != "" {
		if !slices.Contains(workers, role) {
			return "", i18n.E("orch.direct_role", role, strings.Join(workers, ", "))
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
		return "", i18n.E("orch.direct_none")
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
		return i18n.E("orch.no_json")
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
	return i18n.E("orch.json_invalid", first)
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
- au plus %d tâches; pour une demande ciblée simple, 2 ou 3 tâches suffisent; une tâche de collecte détaillée ne couvre qu'une cible (cluster, contexte, cible de template), deux au plus; pour une investigation (cause d'une anomalie, volume de logs, incident), découper par périmètre disjoint (cible, hôte, ressource, composant), jamais par type de donnée sur un même composant: des tâches « configuration », « journal », « santé » d'un même composant suivent la même piste et relisent les mêmes ressources; séparer logs, disque et métriques seulement quand ce sont des sources distinctes qu'une seule tâche ne lirait pas;
- chaque objectif nomme les ressources dont la tâche a la charge, et une ressource n'apparaît que dans un objectif; si la cible doit d'abord être retrouvée (nom donné par l'utilisateur, ressource à localiser), la localisation et l'investigation du composant vont dans la même tâche, pas dans des tâches parallèles qui la referaient chacune;
- prévoir une tâche d'analyse (depends_on vers les collectes) quand il faut recouper des résultats;
- pour un problème ou un incident, la demande vise une solution de fond: prévoir des tâches qui cherchent la cause racine et le correctif durable (configuration effective et valeurs par défaut, dimensionnement, documentation de l'éditeur, cause en amont), pas seulement l'état actuel; ne pas replanifier ce que la demande présente comme déjà connu ou déjà fait;
- l'environnement ci-dessus est déjà connu: ne pas créer de tâche pour le redécouvrir (lister les contextes, vérifier l'accès);
- en affinage de session, ne planifier que ce qui manque pour la nouvelle demande: les faits déjà établis sont en mémoire partagée et les sorties d'outils des tours précédents restent consultables (evidence_search, evidence_read); ne replanifier une collecte déjà faite que si la donnée a pu changer depuis; si aucune collecte n'est nécessaire, une seule tâche de rôle sans outils ou analyste suffit;
- maximiser le parallélisme: depends_on uniquement si une tâche a réellement besoin des résultats d'une autre; les cibles, hôtes, nœuds, clusters et services listés dans l'environnement sont déjà connus: une tâche qui les examine (y compris « pour chaque cluster » ou « pour chaque service ») n'attend pas une tâche d'inventaire ou de statut, chaque tâche peut lire l'inventaire elle-même; ne pas créer de tâche dont le seul rôle est de redécouvrir cet inventaire; une dépendance ne relie que des rôles différents (une analyse attend des collectes) : clotr retire celles entre tâches du même rôle, une collecte qui a besoin d'un résultat le cherche elle-même;
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
%s%s%s
Avant de classer un constat comme anomalie, vérifie qu'il ne s'explique pas par un comportement attendu décrit dans l'environnement. Si ta tâche porte sur un problème, cherche ce qui le cause et ce qui l'empêcherait durablement (paramètre, mécanisme, documentation), pas seulement son état actuel. Pour un échec d'opération, lis d'abord le message d'erreur exact (code, sous-code, détails) : il donne souvent la cause, avant tout parcours de l'historique par fenêtres successives. Un lien de cause à effet doit être appuyé par une preuve (message d'erreur, configuration, chronologie) ; sinon présente-le comme hypothèse dans gaps. Distingue valeurs par défaut et valeurs modifiées.
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
%s`, role, r.Description, o.webRule(), o.incidentRule(), o.accessRule(), o.Environment, o.langDirective())
}

func (o *Orchestrator) accessRule() string {
	if !slices.Contains(o.Tools.Names(), dns.ToolName) {
		return ""
	}
	via := ""
	if slices.ContainsFunc(o.Tools.Names(), func(n string) bool { return strings.HasSuffix(n, "_ssh_resolve") }) {
		via = ", et aussi avec <instance>_ssh_resolve depuis un hôte du réseau concerné (vue DNS interne, à travers le proxy : un nom inconnu du poste peut exister dans le DNS interne)"
	}
	return "\nIncident d'accès à une URL ou à un nom (inaccessible, erreur TLS ou de certificat, page ou authentification inattendue) : vérifie d'abord la chaîne d'accès de bout en bout, avant les logs applicatifs : résous le nom avec " + dns.ToolName + via + ", et compare l'IP obtenue au point d'entrée attendu (adresse du load balancer de l'ingress ou du proxy, IP de la VM). Une IP inattendue est une cause en soi : signale-la telle quelle."
}

func (o *Orchestrator) incidentRule() string {
	if !o.Incident || !slices.Contains(o.Tools.Names(), lead.ToolName) {
		return ""
	}
	return "\nMode incident : dès qu'une sortie d'outil montre ce qui cause le dysfonctionnement décrit dans la demande (message d'erreur exact, configuration fautive), appelle " + lead.ToolName + " avec la preuve, sans attendre ta conclusion, puis poursuis ta tâche (vérification de la cause, correctif durable). Une piste sérieuse se signale de même, en status clue, dès qu'une preuve contient un élément précis de la demande (IP, nom, identifiant, code d'erreur) ou coïncide nettement avec la panne : l'utilisateur peut la reconnaître avant que tu l'aies établie. Une anomalie sans lien avec ce dysfonctionnement va dans tes constats, pas dans " + lead.ToolName + ". Les causes signalées par les autres tâches te sont transmises : ne refais pas leur collecte et ne les signale pas à nouveau."
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
%s`, role, r.Description, tools, o.webRule()+o.accessRule(), o.Environment, o.langDirective())
}

func (o *Orchestrator) webRule() string {
	if len(o.WebTools) == 0 {
		return "Recherche web non disponible pour ce run : ce que tes outils ne permettent pas d'établir va dans gaps, sans supposition."
	}
	read := "Dès qu'une page officielle pertinente apparaît, lis-la (extract) au lieu de reformuler la requête, et ne relance jamais une requête déjà faite."
	if slices.Equal(o.WebTools, []string{websearch.Name}) {
		read = "La réponse de " + websearch.Name + " cite les URL des pages lues : cite la preuve [Exxx] de cette réponse, et ne repose jamais une question déjà posée."
	}
	return fmt.Sprintf("Recherche web disponible (%s) : en cas de doute ou d'inconnu sur un produit (valeur par défaut, comportement, message d'erreur, bug connu, compatibilité de versions), cherche avant de conclure, en privilégiant la documentation officielle de l'éditeur et ses bases de connaissances, et cite la preuve [Exxx] de la page lue. %s Les requêtes partent sur Internet : n'y mets jamais d'identifiant interne (nom d'hôte, IP, nom de cluster, d'environnement, de compte ou d'utilisateur, domaine ou chemin propre au client), seulement des termes génériques (produit, version, message d'erreur sans identifiant).", strings.Join(o.WebTools, ", "), read)
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
Mise en page (sauf forme imposée par la demande) :
- Sections en titres « ## 1. Conclusion » … « ## 6. Recommandations », séparées par une ligne « --- ».
- Conclusion : 3 à 5 puces ; chacune commence par la phrase clé en gras (« **La cause racine est …** ») puis l'explication avec ses preuves.
- Constats : sous-titres « ### CRITIQUE », « ### MAJEUR », « ### MINEUR », « ### INFO » (omis s'ils sont vides). Chaque constat est numéroté en continu à travers les sévérités et titré en gras sur sa propre ligne (« **3. Service api : processus arrêté sur node3, pas de redémarrage automatique** »), jamais avec un code (C1, M2, m3), puis des puces d'une à trois lignes, un fait par puce, preuves [Exxx] en fin de puce, la valeur ou le fait décisif en gras. Pas de paragraphe sous un titre de constat.
- Un tableau pour des valeurs homogènes à comparer ou un calcul (valeurs par rôle ou par hôte, chronologie, projection), avec des cellules courtes.
- Détail par périmètre : un sous-titre « ### » par périmètre, des puces brèves qui renvoient aux constats par leur numéro (« voir constat 3 ») sans les recopier.
- Points non vérifiés et limites : une puce par point, le sujet en gras puis l'explication.
- Recommandations : liste numérotée, titre de la mesure en gras, puis des puces « Cause traitée », « Action », « Risque », « Vérification ».
Règles de cohérence :
- Une cause n'est présentée comme établie, dans la conclusion comme dans les constats, que si un constat la prouve (message d'erreur, configuration, chronologie). Si un constat la contredit ou si elle n'est qu'une hypothèse, écris « hypothèse » et place-la dans les points non vérifiés ; la conclusion ne dit rien que le reste du rapport contredit.
- Tout calcul (projection, taux, ratio, délai avant saturation) est refait à partir des valeurs citées, avec l'opération et l'hypothèse explicites (ex : 14 Go libres / 5,3 Go par jour ≈ 2,6 jours si la croissance reste linéaire). Ne reprends pas un résultat calculé par un sous-agent sans le vérifier.
- Si deux résultats donnent des valeurs incompatibles pour la même mesure, signale l'écart au lieu de choisir silencieusement.
- Les constats CRITIQUE et MAJEUR ont été relus contre leurs preuves par un vérificateur : « [VÉRIFIÉ] » = étayé ; « [PARTIEL : raison] » = ne reprendre que la partie étayée et présenter le reste comme hypothèse ; « [NON ÉTAYÉ : raison] » = uniquement en point non vérifié, avec la raison. Ne recopie pas ces marqueurs dans le rapport.
- Un constat marqué « [NON PROUVÉ … ] » ne cite aucune preuve existante (contrôle fait par clotr) : il ne peut figurer qu'en point non vérifié, jamais dans la conclusion, les constats ou comme cause.
- Les notes de mémoire (#N) sont des résumés datés, pas des preuves : ne les cite jamais comme source (clotr signale dans le rapport toute ligne qui ne s'appuie que sur une note) ; un fait chiffré se cite par sa preuve [Exxx] ; une note contredite par un résultat ou une note plus récente est périmée et ne doit pas être reprise. Une valeur susceptible d'avoir changé (occupation disque, taille, état) se présente avec l'heure de sa mesure, et le délai écoulé depuis.
- Ce que la demande ou l'historique présente comme déjà connu ou déjà fait (une purge réalisée, un symptôme connu) n'est ni une découverte ni une recommandation principale. Un palliatif ne remplace jamais le correctif durable : si la cause racine n'est pas établie, dis-le et précise ce qu'il faut établir pour proposer un correctif durable.
Reste factuel : n'ajoute aucune connaissance extérieure aux résultats fournis ; une information issue d'une source web est attribuée à sa preuve [Exxx]. Dédupliquer les constats redondants.`
