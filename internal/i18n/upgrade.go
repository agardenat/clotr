package i18n

func init() {
	add(upgradeMsgs)
}

var upgradeMsgs = map[string]msg{
	"cli.flag.upgrade":      {"upgrade procedure: current state of the components to upgrade and of their dependencies, official upgrade documentation read before planning, measured prerequisites, then a step-by-step procedure (backups, steps, checks, rollback, later phases); alias --modop", "mode opératoire de mise à jour : état actuel des composants à mettre à jour et de leurs dépendances, documentation officielle lue avant la planification, prérequis mesurés, puis procédure pas à pas (sauvegardes, étapes, vérifications, retour arrière, phases suivantes) ; alias --upgrade"},
	"cli.err.upgrade_modes": {"--upgrade/--modop: incompatible with --incident, --panic, --change, --cve, --ticket, --dat, --diagram, --chat and --direct", "--upgrade/--modop : incompatible avec --incident, --panic, --change, --cve, --ticket, --dat, --diagram, --chat et --direct"},
	"upgrade.mode":          {"upgrade preparation", "préparation de mise à jour"},
	"upgrade.step":          {"Upgrade documentation", "Documentation de mise à jour"},
	"upgrade.frame":         {"common frame: retained procedure variant", "cadrage commun : variante de procédure retenue"},
	"upgrade.no_web":        {"upgrade procedure without web search: the official documentation will not be read, every step will remain to be confirmed", "mode opératoire sans recherche web : la documentation officielle ne sera pas lue, chaque étape restera à confirmer"},
}
