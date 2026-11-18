package orchestrator

import (
	"context"
	"slices"

	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
)

const procedureID = "procedure"

const procedureGoal = "Documentation de mise à jour, avant toute planification. Tire de la demande les composants à mettre à jour dans cette phase, ceux reportés à une phase ultérieure, la version cible et le produit. Lis ensuite la documentation officielle de l'éditeur de ce produit pour la version cible (pages d'entrée données par les consignes des instances quand il y en a) et établis, un constat par fait avec la preuve [Exxx] de la page lue : chemins de mise à jour supportés vers la version cible et versions de départ admises ; ordre imposé entre composants ; prérequis (versions minimales des dépendances, santé, espace, droits, opérations interdites pendant la mise à jour) ; sauvegardes demandées et comment les faire ; étapes de la procédure avec leurs commandes, opérations d'API ou actions d'interface, recopiées telles que la page les donne ; durée et interruption annoncées ; retour arrière prévu ou impossible ; coexistence de composants restés à l'ancienne version avec ceux mis à jour ; problèmes connus et changements de la version cible. Tes seuls outils sont la recherche web, les preuves et la mémoire : n'interroge pas l'infrastructure, les tâches suivantes mesureront l'état actuel et les prérequis à partir de ton résultat. Les requêtes web ne contiennent aucun identifiant interne (nom de cluster, d'environnement, d'hôte, de client) : seulement produit, composant, version et termes de la documentation. Arrête dès que ces points sont couverts ou que la documentation ne répond plus. gaps : chaque point que la documentation lue n'établit pas."

const upgradePlan = "Mode opératoire de mise à jour : rien n'est modifié par ce run, le rapport décrira la procédure à suivre. Le périmètre du plan est celui de la demande : les composants mis à jour dans cette phase, ce dont ils dépendent (identité, base de données, image, gestionnaire) et les composants reportés à une phase ultérieure, seulement pour leur version et leur compatibilité. Planifie l'établissement de leur état actuel (versions de chaque couche, santé, sauvegardes existantes, personnalisations, opérations en cours) et la mesure, avec leurs preuves, de chaque prérequis établi par la documentation et de chaque point à relever donné par les consignes des instances ; sans inventaire des systèmes hors de ce périmètre. Ne planifie aucune lecture de documentation déjà faite par l'étape " + procedureID + ". Une information absente de la demande (fenêtre de maintenance, version cible exacte) ne se recherche pas dans l'infrastructure : elle va dans les points à confirmer. L'id " + procedureID + " est réservé : ne l'utilise pas."

const upgradeRefine = "Affinage d'une session : la documentation lue et les faits établis aux tours précédents sont dans la mémoire partagée et les preuves (memory_search, evidence_search). Un plan vide (aucune tâche) quand la demande ne porte que sur la rédaction ou la mise en forme du mode opératoire ; sinon, seulement les tâches qui établissent les faits nouveaux que la demande exige, y compris une lecture de documentation avec la recherche web si elle porte sur un point que les preuves ne couvrent pas."

const upgradeRule = "\nMode opératoire de mise à jour : tu ne modifies rien, tu établis ce que la procédure de mise à jour doit prendre en compte. Établis la version actuelle de chaque couche des composants de ta tâche (logiciel, gestionnaire, image ou système) et leur état avec leurs preuves. Mesure chaque prérequis de ta tâche et formule-le avec l'attendu (source), la valeur constatée et sa preuve, ou indique qu'il n'est pas mesurable avec tes outils et ce qui le mesurerait. La documentation lue avant la planification t'est transmise : appuie-toi sur elle ; ne rédige aucune commande, opération ou option qu'une page lue ou une preuve ne donne pas."

func (o *Orchestrator) procedureStep(ctx context.Context, request string) Result {
	goal := procedureGoal
	if len(o.WebTools) == 0 {
		o.Audit.Log("procedure_skipped", map[string]any{"reason": "recherche web indisponible"})
		o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: procedureID, Goal: i18n.T("upgrade.step")}}})
		o.Events.Emit(progress.Event{Task: procedureID, Kind: "skipped", Detail: i18n.T("upgrade.no_web")})
		return Result{TaskID: procedureID, Goal: goal, Status: "skipped", Gaps: []string{"documentation officielle non lue : recherche web indisponible pour ce run ; chaque prérequis et chaque étape du mode opératoire restent à confirmer dans la documentation de l'éditeur"}}
	}
	role, err := o.strongRole()
	if err != nil {
		return Result{TaskID: procedureID, Goal: goal, Status: "failed", Error: err.Error()}
	}
	names := o.procedureTools()
	t := Task{ID: procedureID, Role: role, Goal: goal, Tools: names, label: i18n.T("upgrade.step")}
	o.Events.Emit(progress.Event{Task: "planner", Kind: "plan", Plan: []progress.PlanItem{{ID: t.ID, Role: t.Role, Goal: t.label}}})
	o.Audit.Log("procedure_step", map[string]any{"role": role, "tools": names})
	return o.runTask(ctx, request, t, nil, nil)
}

func (o *Orchestrator) procedureTools() []string {
	allowed := append(append(slices.Clone(o.WebTools), evidence.ToolName, evidence.SearchName), memory.ToolNames()...)
	return slices.DeleteFunc(o.Tools.Names(), func(n string) bool { return !slices.Contains(allowed, n) })
}

func (o *Orchestrator) priorResults() []Result {
	var out []Result
	if o.triaged != nil {
		out = append(out, *o.triaged)
	}
	if o.procedure != nil {
		out = append(out, *o.procedure)
	}
	return out
}

func reservedID(id string) bool { return id == triageID || id == procedureID }
