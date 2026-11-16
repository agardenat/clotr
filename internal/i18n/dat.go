package i18n

func init() {
	add(datMsgs)
	for k, v := range datReportMsgs {
		reportMsgs[k] = v
	}
}

var datMsgs = map[string]msg{
	"cli.flag.dat":              {"technical architecture document of the requested scope, without questions: iac (declared state, IaC instances only), drift (real state and every gap with the IaC), clean (real state completed by the IaC, no gap mentioned, no evidence id: for the customer)", "document d'architecture technique du périmètre de la demande, sans question : iac (état déclaré, instances IaC seules), drift (état réel et chaque écart avec l'IaC), clean (état réel complété par l'IaC, sans écart ni identifiant de preuve : pour le client)"},
	"cli.flag.diagram":          {"architecture diagram only of the requested scope, same sources as --dat: iac|drift|clean", "schéma d'architecture seul du périmètre de la demande, mêmes sources que --dat : iac|drift|clean"},
	"cli.flag.export_template":  {"document template used by --export instead of report_export.template", "template de document utilisé par --export à la place de report_export.template"},
	"cli.err.dat_variant":       {"--%s %q: expected iac, drift or clean", "--%s %q : attendu iac, drift ou clean"},
	"cli.err.dat_modes":         {"--dat/--diagram: incompatible with each other and with --incident, --panic, --change, --cve, --ticket, --chat and --direct", "--dat/--diagram : incompatibles entre eux et avec --incident, --panic, --change, --cve, --ticket, --chat et --direct"},
	"cli.err.dat_no_iac":        {"--%s iac: no IaC instance in the scope of the request (instances whose template declares a target of kind iac)", "--%s iac : aucune instance IaC dans le périmètre de la demande (instances dont le template déclare une cible de type iac)"},
	"cli.err.dat_empty":         {"--%s: no instance in the scope of the request: name a client, a project or an instance", "--%s : aucune instance dans le périmètre de la demande : nommer un client, un projet ou une instance"},
	"dat.warn_no_iac":           {"no IaC instance in the scope: the document describes the real state only", "aucune instance IaC dans le périmètre : le document décrira l'état réel seul"},
	"dat.mode.dat":              {"technical architecture document", "document d'architecture technique"},
	"dat.mode.diagram":          {"architecture diagram", "schéma d'architecture"},
	"dat.no_renderer":           {"no diagram template (diagram.template): the document has no diagram", "aucun template de schéma (diagram.template) : le document n'aura pas de schéma"},
	"dat.renderer_off":          {"diagram template unavailable: %v; the document has no diagram", "template de schéma indisponible : %v ; le document n'aura pas de schéma"},
	"dat.renderer_confidential": {"confidential session: the diagram template %s sends the diagram to an external MCP server; no diagram", "session confidentielle : le template de schéma %s envoie le schéma à un serveur MCP externe ; pas de schéma"},
	"dat.diagram_step":          {"architecture diagram", "schéma d'architecture"},
	"dat.diagram_done":          {"diagram %s rendered", "schéma %s rendu"},
	"dat.diagram_warnings":      {"diagram %s: %d warning(s), spec to fix", "schéma %s : %d avertissement(s), spec à corriger"},
	"dat.diagram_files":         {"diagram: %s", "schéma : %s"},
	"dat.model_empty":           {"document model without any ## section", "modèle de document sans aucune section ##"},
	"diagram.not":               {"template %s is not of kind diagram", "le template %s n'est pas de kind diagram"},
	"diagram.fn":                {"%s: function %s(…) missing", "%s : fonction %s(…) absente"},
	"diagram.result":            {"%s: unexpected result: %v", "%s : résultat inattendu : %v"},
	"export.template_external":  {"confidential session: the document template %s sends the report to an external MCP server", "session confidentielle : le template de document %s envoie le rapport à un serveur MCP externe"},
}

var datReportMsgs = map[string]msg{
	"dat.renderer_off":            {"diagram template unavailable: %v; the document has no diagram", "template de schéma indisponible : %v ; le document n'aura pas de schéma"},
	"dat.figure":                  {"Figure %d — %s", "Figure %d — %s"},
	"dat.no_diagram":              {"No diagram: no diagram template available for this run.", "Pas de schéma : aucun template de schéma disponible pour ce run."},
	"dat.no_diagram_confidential": {"No diagram: confidential session, the diagram template sends data outside.", "Pas de schéma : session confidentielle, le template de schéma envoie les données à l'extérieur."},
	"dat.section_failed":          {"Section not written: %v", "Section non rédigée : %v"},
}
