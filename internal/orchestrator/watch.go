package orchestrator

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/watch"
)

const watchPrepID = "watch"

const watchGoal = "Préparation d'un suivi en direct, avant l'attente : quelqu'un va reproduire l'action décrite dans la demande, et clotr lira en boucle les sources que tu déclares avec " + watch.ToolName + " pendant qu'elle se produit. Repère la chaîne de l'action dans le périmètre de la demande : d'où elle part (client, application), son point d'entrée (nom, IP, proxy, load balancer, ingress), le service qui la traite et ses dépendances (authentification, annuaire, base, stockage). Pour chaque maillon accessible, trouve la source où l'action laissera une trace : fichier de log courant (vérifie qu'il existe et qu'il est écrit, avec les outils de listing et de lecture de l'instance), journal systemd d'une unité, messages du noyau (OOM killer), relevé périodique de mémoire, CPU ou connexions pour une consommation, outil suivable d'une instance (logs de pods, événements). Appuie-toi sur les consignes des instances pour l'emplacement des logs. Déclare chaque source avec " + watch.ToolName + " en donnant why (son rôle dans l'action) et un filter sur ce que l'action produira (identifiant, utilisateur, IP, message d'erreur attendu, niveau ERROR/WARN) quand la source est bavarde. Lis aussi l'état de départ utile à la comparaison (configuration effective, dernières erreurs), sans enquêter : l'analyse se fera sur la capture. Une source non accessible avec tes outils va dans gaps avec ce qui permettrait de la lire. Arrête dès que les maillons accessibles sont couverts. findings : les sources déclarées (id wN) et l'état de départ, avec leurs preuves."

const watchPlan = "Suivi en direct : l'action décrite dans la demande a été reproduite pendant une capture, et ce qui est arrivé sur chaque source déclarée est archivé dans une preuve (résultat de l'étape " + watch.TaskID + " ci-dessous). Planifie l'analyse de ces captures : une tâche par maillon ou groupe de sources liées qui relit ses preuves (" + "evidence_read, evidence_search" + ") et établit ce que l'action y a produit, puis une tâche d'analyse qui reconstitue la chronologie de l'action de bout en bout et en tire la cause. Des vérifications complémentaires avec les outils des instances (configuration, résolution de noms, droits, certificats) ne se planifient que si les captures les désignent. Aucune nouvelle capture. Les id " + watchPrepID + " et " + watch.TaskID + " sont réservés : ne les utilise pas."

const watchRule = "\nSuivi en direct : les captures de l'action sont dans les preuves de la tâche " + watch.TaskID + " (une par source, chaque ligne précédée de l'heure du poste clotr à sa réception). Toute conclusion sur l'action s'appuie sur une ligne capturée pendant la fenêtre, citée avec sa preuve et son horodatage. Une source sans aucune ligne pendant la fenêtre est un fait : l'action n'y a laissé aucune trace (elle n'est pas arrivée jusque-là ou ce maillon ne journalise pas ce cas), à présenter comme tel. Une source en échec de lecture pendant la fenêtre est une limite de la capture, pas un constat."

func (o *Orchestrator) watchStep(ctx context.Context, request string) Result {
	role, err := o.DirectRole("")
	if err != nil {
		return Result{TaskID: watchPrepID, Goal: watchGoal, Status: "failed", Error: err.Error()}
	}
	names := slices.DeleteFunc(o.Tools.Names(), isDiagramTool)
	t := Task{ID: watchPrepID, Role: role, Goal: watchGoal, Tools: names, label: i18n.T("watch.step")}
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: t.ID, Role: t.Role, Goal: t.label}}})
	o.Audit.Log("watch_step", map[string]any{"role": role, "tools": names})
	return o.runTask(ctx, request, t, nil, nil)
}

func (o *Orchestrator) captureStep(ctx context.Context) Result {
	start := time.Now()
	label := i18n.T("watch.capture")
	r := Result{TaskID: watch.TaskID, Role: "clotr", Goal: label, Model: "clotr", Status: "ok"}
	if len(o.Watch.Sources()) == 0 {
		r.Status, r.Error = "skipped", i18n.T("watch.no_source")
		r.Gaps = []string{"aucune source déclarée par la préparation : rien n'a été capté pendant l'action"}
		o.Events.Emit(progress.Event{Kind: "concluding", Detail: i18n.T("watch.no_source")})
		return r
	}
	sum := o.Watch.Capture(ctx, o.WatchFor)
	dur := sum.End.Sub(sum.Start).Truncate(time.Second)
	r.Findings = append(r.Findings, fmt.Sprintf("[INFO] fenêtre de capture : %s → %s (%s, fin : %s), heure du poste clotr", sum.Start.Format(time.RFC3339), sum.End.Format("15:04:05"), dur, sum.Reason))
	for _, c := range sum.Sources {
		f := fmt.Sprintf("[INFO] %s %s : %d lignes captées, %d retenues par le filtre", c.ID, c.Label, c.Lines, c.Matched)
		if c.Samples > 0 {
			f = fmt.Sprintf("[INFO] %s %s : %d relevés, %d lignes retenues par le filtre", c.ID, c.Label, c.Samples, c.Matched)
		}
		if c.Filter != "" {
			f += " (" + c.Filter + ")"
		}
		if c.Why != "" {
			f += " — " + c.Why
		}
		r.Findings = append(r.Findings, f+" ["+c.Evidence+"]")
		r.Evidence = append(r.Evidence, "["+c.Evidence+"] "+c.Label)
		for _, e := range c.Errors {
			r.Gaps = append(r.Gaps, fmt.Sprintf("%s %s : lecture en échec pendant la capture (%s)", c.ID, c.Label, e))
		}
	}
	r.Duration = time.Since(start).Truncate(time.Millisecond).String()
	if o.OnResult != nil {
		o.OnResult(r)
	}
	o.Events.Emit(progress.Event{Kind: "concluding", Detail: i18n.T("watch.stopped", i18n.T("watch.reason."+sum.Reason), dur, i18n.N(len(sum.Sources), "source"))})
	return r
}

func (o *Orchestrator) watchInput() string {
	var b strings.Builder
	b.WriteString("\n\n" + watchPlan)
	if o.watchPrep != nil {
		b.WriteString("\n\nRésultat de la préparation (tâche " + watchPrepID + ") :" + synthInput([]Result{*o.watchPrep}))
	}
	if o.capture != nil {
		b.WriteString("\n\nRésultat de la capture (tâche " + watch.TaskID + ") :" + synthInput([]Result{*o.capture}))
	}
	return b.String()
}

func (o *Orchestrator) Interrupt() bool {
	if o.Watch != nil && o.Watch.Waiting() {
		o.Watch.Stop()
		o.Audit.Log("watch_stop_requested", map[string]any{})
		return true
	}
	o.ConcludeNow()
	return false
}
