package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
)

var severeFinding = regexp.MustCompile(`^\s*\[(CRITIQUE|MAJEUR|CRITICAL|MAJOR)\b`)

const (
	tagVerified = "[VÉRIFIÉ]"
	tagPartial  = "[PARTIEL : %s]"
	tagRefuted  = "[NON ÉTAYÉ : %s]"
)

const verifierPrompt = `Tu es le vérificateur d'une analyse d'infrastructure en lecture seule. On te donne des constats rédigés par d'autres agents, chacun citant des preuves [Exxx] archivées.
Pour chaque constat, relis les preuves citées avec evidence_read (pattern ciblé sur les valeurs, noms et horodatages du constat) et, si besoin, retrouve une preuve avec evidence_search. Ne collecte rien d'autre et ne juge pas la pertinence du constat, seulement s'il est étayé.
Verdict par constat :
- "confirmé" : chaque fait et chaque valeur se retrouvent dans les preuves citées (un calcul refait à partir de valeurs présentes compte) ;
- "partiel" : une partie est étayée, une autre non ; dis laquelle ; une interprétation (cause, conséquence) que les preuves ne montrent pas rend le constat partiel ;
- "non étayé" : les preuves citées ne contiennent pas ce qui est affirmé, ou le contredisent.
Réponds UNIQUEMENT avec un objet JSON : {"verdicts":[{"n":1,"verdict":"confirmé|partiel|non étayé","raison":"courte : élément manquant, contredit ou déduit"}]}`

type verdict struct {
	N       int    `json:"n"`
	Verdict string `json:"verdict"`
	Raison  string `json:"raison"`
}

func (o *Orchestrator) verifierRole() string {
	if r, ok := o.Cfg.Roles["analyst"]; ok && r.Tools {
		return "analyst"
	}
	for _, name := range o.Cfg.WorkerRoles() {
		if o.Cfg.Roles[name].Tools {
			return name
		}
	}
	return ""
}

func (o *Orchestrator) Verify(ctx context.Context, results []Result) {
	if o.Cfg.Limits.VerifyFindings != nil && !*o.Cfg.Limits.VerifyFindings {
		return
	}
	ev := o.Runner.Evidence
	role := o.verifierRole()
	if ev == nil || role == "" {
		return
	}
	var tools []string
	for _, n := range []string{evidence.ToolName, evidence.SearchName} {
		if slices.Contains(o.Tools.Names(), n) {
			tools = append(tools, n)
		}
	}
	if len(tools) == 0 {
		return
	}
	cands, err := o.Router.Candidates(role)
	if err != nil {
		return
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	o.stopVerify.Store(&stop)
	defer o.stopVerify.Store(nil)
	if o.Runner.Concluding() {
		return
	}
	sem := semaphore.NewWeighted(int64(max(o.Cfg.Limits.MaxAgents, 1)))
	var wg sync.WaitGroup
	for i := range results {
		r := &results[i]
		var idx []int
		for k, f := range r.Findings {
			if severeFinding.MatchString(f) {
				idx = append(idx, k)
			}
		}
		if r.Status != "ok" || len(idx) == 0 {
			continue
		}
		id := "v-" + r.TaskID
		o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: id, Role: role, Goal: i18n.T("verify.goal", r.TaskID)}}})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem.Acquire(ctx, 1) != nil {
				return
			}
			defer sem.Release(1)
			o.verifyTask(ctx, id, role, tools, cands, r, idx)
		}()
	}
	wg.Wait()
}

func (o *Orchestrator) verifyTask(ctx context.Context, id, role string, tools []string, cands []catalog.ModelInfo, r *Result, idx []int) {
	start := time.Now()
	var in strings.Builder
	fmt.Fprintf(&in, "Constats de la tâche %s (%s) à vérifier :\n", r.TaskID, r.Goal)
	for n, k := range idx {
		fmt.Fprintf(&in, "%d. %s\n", n+1, r.Findings[k])
	}
	o.Events.Emit(progress.Event{Task: id, Kind: "start", Model: o.Runner.First(cands), Detail: i18n.T("verify.goal", r.TaskID)})
	out, err := o.Runner.Run(ctx, agent.Spec{
		TaskID:     id,
		Role:       role,
		System:     verifierPrompt + "\n" + o.langDirective(),
		User:       in.String(),
		Tools:      tools,
		Candidates: cands,
		Check:      func(c string) string { return checkVerdicts(c, len(idx)) },
	})
	done := progress.Event{Task: id, Duration: time.Since(start)}
	if out != nil {
		done.Model, done.Cost, done.Step = out.Model, out.Cost, out.Steps
	}
	var parsed struct {
		Verdicts []verdict `json:"verdicts"`
	}
	if err == nil {
		err = ExtractJSON(out.Content, &parsed)
	}
	if err != nil && ctx.Err() != nil && o.Runner.Concluding() {
		done.Kind, done.Detail = "skipped", i18n.T("verify.abandoned")
		o.Events.Emit(done)
		o.Audit.Log("verify_end", map[string]any{"task": r.TaskID, "abandoned": "conclusion demandée"})
		return
	}
	if err != nil {
		done.Kind, done.Detail = "failed", err.Error()
		o.Events.Emit(done)
		o.Audit.Log("verify_end", map[string]any{"task": r.TaskID, "error": err.Error()})
		return
	}
	confirmed, partial, refuted := applyVerdicts(r, idx, parsed.Verdicts)
	done.Kind, done.Detail = "done", i18n.T("verify.done", confirmed, partial, refuted)
	o.Events.Emit(done)
	o.Audit.Log("verify_end", map[string]any{"task": r.TaskID, "checked": len(idx), "confirmed": confirmed, "partial": partial, "refuted": refuted, "missing": len(idx) - confirmed - partial - refuted, "model": done.Model})
	if o.Memory != nil {
		for n, k := range idx {
			if strings.HasPrefix(r.Findings[k], "[PARTIEL") || strings.HasPrefix(r.Findings[k], "[NON ÉTAYÉ") {
				_, _ = o.Memory.Put(memory.Entry{Key: fmt.Sprintf("tour%d/%s/verification/%d", max(o.Turn, 1), r.TaskID, n+1), Content: r.Findings[k], Kind: "verification", Task: id, Model: done.Model, Sovereign: out.Sovereign})
			}
		}
	}
}

func normVerdict(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(v, "confirm"):
		return "confirmed"
	case strings.HasPrefix(v, "parti"):
		return "partial"
	case strings.HasPrefix(v, "non"), strings.HasPrefix(v, "unsupport"), strings.HasPrefix(v, "réfut"), strings.HasPrefix(v, "refut"), strings.HasPrefix(v, "contredit"), strings.HasPrefix(v, "infirm"):
		return "refuted"
	}
	return ""
}

func checkVerdicts(content string, want int) string {
	var parsed struct {
		Verdicts []verdict `json:"verdicts"`
	}
	if err := ExtractJSON(content, &parsed); err != nil {
		return fmt.Sprintf("Ta réponse n'est pas un objet JSON valide (%v). Renvoie uniquement l'objet JSON complet {\"verdicts\":[…]}, avec un verdict pour chacun des %d constats, en échappant les guillemets dans les raisons.", err, want)
	}
	got := map[int]bool{}
	var bad []string
	for _, v := range parsed.Verdicts {
		if v.N >= 1 && v.N <= want && normVerdict(v.Verdict) != "" {
			got[v.N] = true
		} else if v.N >= 1 && v.N <= want {
			bad = append(bad, fmt.Sprintf("%d (%q)", v.N, v.Verdict))
		}
	}
	var missing []string
	for n := 1; n <= want; n++ {
		if !got[n] {
			missing = append(missing, fmt.Sprint(n))
		}
	}
	if len(missing) == 0 {
		return ""
	}
	msg := fmt.Sprintf("Il manque un verdict valide pour les constats n° %s (sur %d).", strings.Join(missing, ", "), want)
	if len(bad) > 0 {
		msg += " Verdicts non reconnus : " + strings.Join(bad, ", ") + " ; valeurs admises : confirmé, partiel, non étayé."
	}
	return msg + " Relis les preuves si nécessaire, puis renvoie l'objet JSON complet avec un verdict pour chaque constat."
}

func applyVerdicts(r *Result, idx []int, verdicts []verdict) (confirmed, partial, refuted int) {
	done := map[int]bool{}
	for _, v := range verdicts {
		if v.N < 1 || v.N > len(idx) || done[v.N] {
			continue
		}
		k := idx[v.N-1]
		reason := strings.Join(strings.Fields(v.Raison), " ")
		switch normVerdict(v.Verdict) {
		case "confirmed":
			r.Findings[k] = tagVerified + " " + r.Findings[k]
			confirmed++
		case "partial":
			r.Findings[k] = fmt.Sprintf(tagPartial, reason) + " " + r.Findings[k]
			partial++
		case "refuted":
			r.Findings[k] = fmt.Sprintf(tagRefuted, reason) + " " + r.Findings[k]
			refuted++
		default:
			continue
		}
		done[v.N] = true
	}
	return
}
