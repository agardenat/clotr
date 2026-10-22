package i18n

func init() {
	add(cveMsgs)
	for k, v := range cveReportMsgs {
		if _, dup := reportMsgs[k]; dup {
			panic("i18n: duplicate key " + k)
		}
		reportMsgs[k] = v
	}
}

var cveMsgs = map[string]msg{
	"cve.advisory": {"advisory %s", "fiche %s"},
	"cve.previous": {" (was %s)", " (était %s)"},
	"cve.mode":     {"CVE mode: %s (tools above an instance's access level are authorized call by call)", "Mode CVE : %s (outils au-delà du niveau d'accès d'une instance autorisés appel par appel)"},
	"cve.no_id":    {"--cve: no CVE or GHSA identifier in the request; for a compromise without CVE, name it: --cve=\"<subject>\"", "--cve : aucun identifiant CVE ou GHSA dans la demande ; pour une compromission sans CVE, la nommer : --cve=\"<sujet>\""},
	"cve.no_web":   {"--cve without web search: advisories will be marked unverified", "--cve sans recherche web : les fiches seront marquées non vérifiées"},
	"cve.modes":    {"--cve is not available with --incident, --panic, --chat or --direct", "--cve n'est pas disponible avec --incident, --panic, --chat ou --direct"},
	"cve.triage":   {"CVE advisories", "fiches CVE"},
	"kind.cve":     {"cve", "cve"},
	"cli.flag.cve": {"CVE mode: advisories of the CVE or GHSA identifiers of the request (or of --cve=\"<subject>\" for a compromise without CVE) first, then status of each asset shown as it is found (✅ clean, 🚨 vulnerable, ☠️ compromised, ❓ undetermined); tools above an instance's access level are offered and authorized call by call", "mode CVE : fiche des identifiants CVE ou GHSA de la demande (ou du sujet --cve=\"<sujet>\" pour une compromission sans CVE) d'abord, puis statut de chaque actif affiché dès qu'il est établi (✅ sain, 🚨 vulnérable, ☠️ compromis, ❓ indéterminé) ; les outils au-delà du niveau d'accès d'une instance sont proposés et autorisés appel par appel"},
}

var cveReportMsgs = map[string]msg{
	"cve.section":        {"CVE status", "Statut des CVE"},
	"cve.col.product":    {"Product", "Produit"},
	"cve.col.affected":   {"Affected", "Versions touchées"},
	"cve.col.fixed":      {"Fixed", "Versions corrigées"},
	"cve.col.sources":    {"Sources", "Sources"},
	"cve.col.asset":      {"Asset", "Actif"},
	"cve.col.detail":     {"Detail", "Détail"},
	"cve.col.evidence":   {"Evidence", "Preuves"},
	"cve.assets":         {"assets", "actifs"},
	"cve.clean_title":    {"Clean assets", "Actifs sains"},
	"cve.clean_note":     {"details in the session memory and --json", "détail dans la mémoire de session et --json"},
	"cve.unverified":     {"unverified", "non vérifiée"},
	"cve.st.vulnerable":  {"vulnerable", "vulnérable(s)"},
	"cve.st.compromised": {"compromised", "compromis"},
	"cve.st.unknown":     {"undetermined", "indéterminé(s)"},
	"cve.st.clean":       {"clean", "sain(s)"},
}
