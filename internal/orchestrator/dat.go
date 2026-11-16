package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/report"
)

const sectionRule = `
Rédaction section par section : chaque section du document est rédigée par un appel distinct, à partir des mêmes résultats. Tu rédiges uniquement la section qui t'est confiée, en commençant par sa ligne de titre telle qu'elle est donnée ; rien d'autre (ni les autres sections, ni introduction, ni conclusion du document). Ne répète pas ce qui relève d'une autre section du plan : renvoie-y par son titre si nécessaire.
`

func (o *Orchestrator) synthesizeSections(ctx context.Context, user string, cands []catalog.ModelInfo) (string, string, error) {
	p := report.Split(o.reportModel())
	sections := p.Sections
	if len(sections) == 0 {
		return "", "", i18n.E("dat.model_empty")
	}
	system := synthesizerPrompt + p.Preamble + "\n" + sectionRule + synthesizerRules + o.DAT.SynthRule()
	if env := strings.TrimSpace(o.Environment); env != "" {
		system += "\nEnvironnement et consignes:\n" + env
	}
	system += "\n" + o.langDirective()
	var toc strings.Builder
	for _, s := range sections {
		toc.WriteString("\n- " + report.Heading(s))
	}
	out := make([]string, len(sections))
	models := make([]string, len(sections))
	errs := make([]error, len(sections))
	sem := semaphore.NewWeighted(int64(max(o.Cfg.Limits.MaxAgents, 1)))
	var wg sync.WaitGroup
	for i, sec := range sections {
		chunk, lead := sec, ""
		if i == 0 && p.Head != "" {
			chunk, lead = p.Head+"\n\n"+sec, " (précédée du titre du document, à compléter)"
		}
		id := fmt.Sprintf("synthesizer.%d", i+1)
		in := user + "\n\nPlan du document (pour situer ta section ; ne rédige que la tienne) :" + toc.String() + "\n\nSection à rédiger" + lead + " :\n" + chunk
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				errs[i] = err
				return
			}
			defer sem.Release(1)
			model, effort := o.Runner.First(cands, config.RoleSynthesizer)
			o.Events.Emit(progress.Event{Task: id, Kind: "start", Model: model, Effort: effort, Detail: report.Heading(sec)})
			res, err := o.Runner.Run(ctx, agent.Spec{TaskID: id, Role: config.RoleSynthesizer, System: system, User: in, Candidates: cands})
			if err != nil {
				errs[i] = err
				o.Events.Emit(progress.Event{Task: id, Kind: "failed", Detail: err.Error()})
				o.Audit.Log("section_failed", map[string]any{"section": report.Heading(sec), "error": err.Error()})
				return
			}
			out[i] = strings.TrimSpace(thinkBlock.ReplaceAllString(res.Content, ""))
			models[i] = res.Model
			o.Events.Emit(progress.Event{Task: id, Kind: "done", Model: res.Model, Effort: res.Effort})
			o.afterTask(ctx)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	ok := 0
	var model string
	for i := range sections {
		if errs[i] != nil {
			out[i] = sections[i][:strings.Index(sections[i]+"\n", "\n")] + "\n\n*" + i18n.R("dat.section_failed", errs[i]) + "*"
			continue
		}
		ok++
		if model == "" {
			model = models[i]
		}
	}
	if ok == 0 {
		return "", "", fmt.Errorf("synthesizer: %w", errs[0])
	}
	md := strings.Join(out, "\n\n")
	return o.finalize(o.fillReport(md)), model, nil
}
