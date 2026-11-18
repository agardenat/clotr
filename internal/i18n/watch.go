package i18n

func init() {
	add(watchMsgs)
}

var watchMsgs = map[string]msg{
	"cli.flag.watch":         {"live follow of an action: clotr finds the logs and states tied to the action described in the request, waits while the action is reproduced and captures everything that arrives on them (matching lines shown live), then Ctrl-C ends the wait and the capture is analysed; alias --suivi", "suivi en direct d'une action : clotr repère les logs et états liés à l'action décrite dans la demande, attend pendant qu'elle est reproduite et capte tout ce qui y arrive (lignes retenues affichées en direct), puis Ctrl-C arrête l'attente et la capture est analysée ; alias --watch"},
	"cli.flag.watch_for":     {"with --watch: end the wait after this duration (e.g. 10m) instead of waiting for Ctrl-C", "avec --suivi : arrête l'attente après cette durée (ex. 10m) au lieu d'attendre Ctrl-C"},
	"cli.flag.watch_every":   {"with --watch: delay between two reads of each source (default 5s)", "avec --suivi : délai entre deux lectures de chaque source (défaut 5s)"},
	"cli.err.watch_modes":    {"--watch/--suivi: incompatible with --incident, --panic, --change, --cve, --ticket, --upgrade, --dat, --diagram, --chat and --direct", "--watch/--suivi : incompatible avec --incident, --panic, --change, --cve, --ticket, --upgrade, --dat, --diagram, --chat et --direct"},
	"cli.err.watch_for":      {"--watch-for and --watch-every require --watch", "--watch-for et --watch-every exigent --suivi"},
	"watch.mode":             {"live follow", "suivi en direct"},
	"watch.step":             {"Sources tied to the action", "Sources liées à l'action"},
	"watch.capture":          {"Live capture", "Capture en direct"},
	"watch.waiting":          {"waiting: reproduce the action now — Ctrl-C ends the capture and starts the analysis", "en attente : reproduisez l'action maintenant — Ctrl-C arrête la capture et lance l'analyse"},
	"watch.live_dir":         {"live capture files: %s", "fichiers de capture en direct : %s"},
	"watch.more":             {"… %d more retained lines (all archived)", "… %d autres lignes retenues (toutes archivées)"},
	"watch.error":            {"read failed: %s", "lecture en échec : %s"},
	"watch.source":           {"source %s: %s — %s", "source %s : %s — %s"},
	"watch.no_source":        {"no source declared: nothing to capture", "aucune source déclarée : rien à capter"},
	"watch.stopped":          {"capture ended (%s, %s): %s", "capture terminée (%s, %s) : %s"},
	"watch.reason.stopped":   {"Ctrl-C", "Ctrl-C"},
	"watch.reason.duration":  {"duration reached", "durée atteinte"},
	"watch.reason.cancelled": {"run cancelled", "run annulé"},
	"kind.captured":          {"captured", "capté"},
	"kind.source":            {"source", "source"},
	"kind.waiting":           {"waiting", "attente"},
}
