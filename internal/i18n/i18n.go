package i18n

import (
	"fmt"
	"strings"
)

var lang = "en"

func Set(l string) {
	if l == "fr" {
		lang = "fr"
		return
	}
	lang = "en"
}

func Lang() string {
	return lang
}

type msg struct{ en, fr string }

var msgs = map[string]msg{
	"state.running":        {"running", "en cours"},
	"state.done":           {"done", "terminé"},
	"header.tasks":         {"tasks %d/%d", "tâches %d/%d"},
	"header.failed":        {" (%d failed)", " (%d en échec)"},
	"step.n":               {"step %d", "étape %d"},
	"thinking":             {"thinking…", "réflexion…"},
	"tool":                 {"tool %s", "outil %s"},
	"waiting":              {"waiting for %s", "attend %s"},
	"fallback":             {"fallback to %s (%s)", "bascule vers %s (%s)"},
	"fallback.after":       {"after error on %s: %s", "après erreur sur %s : %s"},
	"limit":                {"%d-step limit reached, forced conclusion", "limite de %d étapes atteinte, conclusion forcée"},
	"evidence.title":       {"Appendix — cited evidence", "Annexe — preuves citées"},
	"evidence.unknown":     {"not found in this turn's archive (earlier turn or invented identifier)", "absente de l'archive de ce tour (tour précédent ou identifiant inventé)"},
	"evidence.line":        {"evidence: %d tool outputs archived in %s (clotr session %s --evidence <id>)", "preuves : %d sorties d'outils archivées dans %s (clotr session %s --evidence <id>)"},
	"stopped.steps":        {"step limit", "limite d'étapes"},
	"stopped.stall":        {"no more progress", "plus de progression"},
	"limit.stall":          {"no new tool call for %d steps, conclusion", "aucun appel nouveau depuis %d étapes, conclusion"},
	"stopped.time":         {"time limit", "limite de temps"},
	"limit.time":           {"time almost up, forced conclusion", "temps presque écoulé, conclusion forcée"},
	"continuation":         {"continuation of %s: %s", "suite de %s : %s"},
	"dropped":              {"dropped: unavailable for this run: %s", "écarté : indisponible pour ce run : %s"},
	"budget.dropped":       {"provider dropped for the rest of the run: %s", "provider écarté pour la suite du run : %s"},
	"budget.prefix":        {"budget: %s %s", "budget : %s %s"},
	"stream.reasoning":     {"reasoning… %s", "raisonnement… %s"},
	"stream.writing":       {"writing… %s", "rédaction… %s"},
	"stream.tools":         {"preparing %d tool call(s)… %s", "préparation de %d appel(s) d'outil… %s"},
	"models.used":          {"models used: %s", "modèles utilisés : %s"},
	"models.foreign":       {"NON-sovereign models used: %s", "modèles NON souverains utilisés : %s"},
	"models.allsov":        {"all models used are sovereign", "tous les modèles utilisés sont souverains"},
	"cost.line":            {"cost %s", "coût %s"},
	"cost.run":             {"%s: %s, run cost %.4f $", "%s : %s, coût du run %.4f $"},
	"cost.estimated":       {"%s: %s, run cost ~%.4f $ (estimated from token usage × /model/info prices)", "%s : %s, coût du run ~%.4f $ (estimé : tokens × prix /model/info)"},
	"cost.unreported":      {"%s: %s, cost not reported by provider", "%s : %s, coût non communiqué par le provider"},
	"cost.key":             {" — key %.4f / %.2f $ (%.4f $ left)", " — clé %.4f / %.2f $ (reste %.4f $)"},
	"cost.unlimited":       {" — unlimited", " — illimité"},
	"cost.dropped":         {" — DROPPED: %s", " — ÉCARTÉ : %s"},
	"memory.line":          {"memory: %s (%d sovereign), %d sovereign read by non-sovereign models", "mémoire : %s (%d souveraines), %d souveraines lues par des modèles non souverains"},
	"session.start":        {"session: %s (turn %d) · audit: %s", "session : %s (tour %d) · audit : %s"},
	"web.ask":              {"Allow web search for this run (generic queries sent to %s)? [y/N] ", "Autoriser la recherche web pour ce run (requêtes génériques envoyées à %s) ? [o/N] "},
	"web.on":               {"web search: allowed (%s)", "recherche web : autorisée (%s)"},
	"web.off":              {"web search: not allowed (%s)", "recherche web : non autorisée (%s)"},
	"web.confidential":     {"confidential session", "session confidentielle"},
	"web.denied":           {"refused", "refusée"},
	"web.notty":            {"no terminal to ask", "aucun terminal pour demander"},
	"web.flag":             {"--web no", "--web no"},
	"web.policy":           {"web_search.policy: deny", "web_search.policy : deny"},
	"fallback.round":       {"all models failed temporarily, new round in %s", "tous les modèles en échec temporaire, nouveau tour dans %s"},
	"raw.output":           {"unstructured output", "sortie non structurée"},
	"verify.goal":          {"verify the critical and major findings of %s against their evidence", "vérifier les constats critiques et majeurs de %s contre leurs preuves"},
	"verify.done":          {"%d confirmed, %d partial, %d unsupported", "%d confirmés, %d partiels, %d non étayés"},
	"answer.rejected":      {"answer rejected by the check, new attempt", "réponse refusée par le contrôle, nouvelle tentative"},
	"session.resynth":      {"session: %s (turn %d) · regenerating the report · connectors: %s", "session : %s (tour %d) · régénération du rapport · connecteurs : %s"},
	"session.line":         {"session: %s (turn %d) → %s", "session : %s (tour %d) → %s"},
	"session.refine":       {"refine: clotr run -s %s \"…\"", "affiner : clotr run -s %s \"…\""},
	"session.header":       {"session %s · created %s · %d turn(s)%s", "session %s · créée %s · %d tour(s)%s"},
	"session.conf":         {" · confidential", " · confidentielle"},
	"session.turn":         {"  turn %d · %s · %s%s", "  tour %d · %s · %s%s"},
	"session.noreport":     {"(no report)", "(pas de rapport)"},
	"sessions.none":        {"no session in %s", "aucune session dans %s"},
	"sessions.head":        {"SESSION\tUPDATED\tTURNS\tCONF\tLAST REQUEST", "SESSION\tMAJ\tTOURS\tCONF\tDERNIÈRE DEMANDE"},
	"yes":                  {"yes", "oui"},
	"models.head":          {"PROVIDER\tMODEL\tTIER\tCONTEXT\tTOOLS\tSOV\tSCORE\tSOURCE", "PROVIDER\tMODÈLE\tTIER\tCONTEXTE\tOUTILS\tSOUV\tSCORE\tSOURCE"},
	"models.fetched":       {"(%s at %s)", "(%s du %s)"},
	"models.discovery":     {"discovery", "découverte"},
	"models.routing":       {"ROUTING", "ROUTAGE"},
	"models.budget":        {"BUDGET", "BUDGET"},
	"models.budget.head":   {"PROVIDER\tSPENT\tMAX\tLEFT\tPERIOD\tRESET\tTHRESHOLDS", "PROVIDER\tDÉPENSÉ\tMAX\tRESTE\tPÉRIODE\tRESET\tSEUILS"},
	"budget.unlimited":     {"unlimited", "illimité"},
	"budget.undeclared":    {"not declared", "non déclaré"},
	"budget.error":         {"ERROR: %s", "ERREUR : %s"},
	"yesno.yes":            {"yes", "oui"},
	"yesno.no":             {"no", "non"},
	"prompt.user":          {"%s — user: ", "%s — utilisateur : "},
	"prompt.password":      {"%s — password for %s: ", "%s — mot de passe de %s : "},
	"instance.discovering": {"instance %s: activation (template %s)…", "instance %s : activation (template %s)…"},
	"templates.head":       {"TEMPLATE\tVERSION\tSOURCE\tINSTANCES\tDESCRIPTION", "TEMPLATE\tVERSION\tSOURCE\tINSTANCES\tDESCRIPTION"},
	"templates.dir":        {"templates directory: %s (clotr templates <name> prints a template)", "répertoire des templates : %s (clotr templates <nom> affiche un template)"},
	"instances.title":      {"INSTANCES", "INSTANCES"},
	"instances.head":       {"INSTANCE\tTEMPLATE\tSTATE", "INSTANCE\tTEMPLATE\tÉTAT"},
	"instances.enabled":    {"enabled", "active"},
	"instances.disabled":   {"disabled", "désactivée"},
	"instances.missing":    {"template not found", "template introuvable"},
	"followup":             {"follow-up round %d: planning…", "tour de complément %d : planification…"},
	"followup.none":        {"no follow-up needed", "aucun complément nécessaire"},
	"tools.env":            {"ENVIRONMENT", "ENVIRONNEMENT"},
	"tools.exposed":        {"EXPOSED TOOLS", "OUTILS EXPOSÉS"},
	"tools.skipped":        {"MCP %s — skipped (no readOnlyHint nor allow, or denied):", "MCP %s — écartés (ni readOnlyHint ni allow, ou deny) :"},
	"plan.task":            {"%s [%s → %s]\n  goal: %s\n", "%s [%s → %s]\n  but : %s\n"},
	"plan.fallbacks":       {" (+%d fallback)", " (+%d en secours)"},
	"plan.tools":           {"  tools: %s\n", "  outils : %s\n"},
	"plan.deps":            {"  depends on: %s\n", "  dépend de : %s\n"},
	"progress.unavailable": {"progress: dynamic display unavailable: %v", "progression : affichage dynamique indisponible : %v"},
	"chat.placeholder":     {"Your request…", "Votre demande…"},
	"chat.interrupted":     {"interrupted", "interrompu"},
	"chat.interrupting":    {"interrupting… (ctrl+c again to quit)", "interruption… (ctrl+c à nouveau pour quitter)"},
	"chat.copied":          {"copied as Markdown: %d characters (%s)", "copié en Markdown : %d caractères (%s)"},
	"chat.copy.none":       {"no answer to copy", "aucune réponse à copier"},
	"chat.logs.more":       {"… %d earlier lines", "… %d lignes précédentes"},
	"chat.help.input":      {"enter send · alt+enter new line · pgup/pgdown scroll · esc cancel · ctrl+c quit", "entrée envoyer · alt+entrée nouvelle ligne · pgup/pgdown défiler · échap annuler · ctrl+c quitter"},
	"chat.help.running":    {"ctrl+c interrupt · ↑/↓ pgup/pgdown scroll", "ctrl+c interrompre · ↑/↓ pgup/pgdown défiler"},
	"chat.help.idle":       {"r reply · c copy as Markdown · q quit · ↑/↓ pgup/pgdown home/end scroll", "r répondre · c copier en Markdown · q quitter · ↑/↓ pgup/pgdown début/fin défiler"},
	"chat.report":          {"report: %s", "rapport : %s"},
}

var plurals = map[string]msg{
	"task":      {"task|tasks", "tâche|tâches"},
	"step":      {"step|steps", "étape|étapes"},
	"tool call": {"tool call|tool calls", "appel d'outil|appels d'outils"},
	"finding":   {"finding|findings", "constat|constats"},
	"call":      {"call|calls", "appel|appels"},
	"entry":     {"entry|entries", "entrée|entrées"},
}

func pick(m msg) string {
	if lang == "fr" {
		return m.fr
	}
	return m.en
}

func T(key string, args ...any) string {
	m, ok := msgs[key]
	if !ok {
		return key
	}
	if len(args) == 0 {
		return pick(m)
	}
	return fmt.Sprintf(pick(m), args...)
}

func N(n int, key string) string {
	m, ok := plurals[key]
	if !ok {
		return fmt.Sprintf("%d %s", n, key)
	}
	one, many, _ := strings.Cut(pick(m), "|")
	if n == 1 || (lang == "fr" && n == 0) {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
