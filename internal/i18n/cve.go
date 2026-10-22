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
	"cve.no_id":    {"--cve: no CVE identifier (CVE-YYYY-NNNN) in the request", "--cve : aucun identifiant CVE (CVE-AAAA-NNNN) dans la demande"},
	"cve.no_web":   {"--cve without web search: advisories will be marked unverified", "--cve sans recherche web : les fiches seront marquées non vérifiées"},
	"cve.modes":    {"--cve is not available with --incident, --panic, --chat or --direct", "--cve n'est pas disponible avec --incident, --panic, --chat ou --direct"},
	"cve.triage":   {"CVE advisories", "fiches CVE"},
	"kind.cve":     {"cve", "cve"},
	"cli.flag.cve": {"CVE mode: advisories of the CVE identifiers of the request first, then status of each asset shown as it is found (✅ clean, 🚨 vulnerable, ❓ undetermined); tools above an instance's access level are offered and authorized call by call", "mode CVE : fiche des identifiants CVE de la demande d'abord, puis statut de chaque actif affiché dès qu'il est établi (✅ sain, 🚨 vulnérable, ❓ indéterminé) ; les outils au-dessus du niveau d'accès d'une instance sont proposés et autorisés appel par appel"},
}

var cveReportMsgs = map[string]msg{
	"cve.section":       {"CVE status", "Statut des CVE"},
	"cve.col.product":   {"Product", "Produit"},
	"cve.col.affected":  {"Affected", "Versions touchées"},
	"cve.col.fixed":     {"Fixed", "Versions corrigées"},
	"cve.col.sources":   {"Sources", "Sources"},
	"cve.col.asset":     {"Asset", "Actif"},
	"cve.col.detail":    {"Detail", "Détail"},
	"cve.col.evidence":  {"Evidence", "Preuves"},
	"cve.unverified":    {"unverified", "non vérifiée"},
	"cve.st.vulnerable": {"vulnerable", "vulnérable(s)"},
	"cve.st.unknown":    {"undetermined", "indéterminé(s)"},
	"cve.st.clean":      {"clean", "sain(s)"},
}
