package i18n

func init() {
	add(ticketMsgs)
	for k, v := range ticketReportMsgs {
		if _, dup := reportMsgs[k]; dup {
			panic("i18n: duplicate key " + k)
		}
		reportMsgs[k] = v
	}
}

var ticketMsgs = map[string]msg{
	"cli.flag.change":         {"change request: state of what the request modifies and its IaC source, then a report of the changes to make (IaC, configuration), impacts and implementation plan; alias --demande", "demande de changement : état de ce que la demande modifie et de sa source IaC, puis rapport des modifications à réaliser (IaC, configuration), impacts et plan de mise en œuvre ; alias --change"},
	"cli.flag.ticket":         {"ticket of the request, read in the ticketing tool of the configuration (tickets:); without a value, identifier found in the request; alone, the ticket type chooses the mode (incident or change request)", "ticket de la demande, lu dans l'outil de tickets de la configuration (tickets:) ; sans valeur, identifiant relevé dans la demande ; seul, le type du ticket choisit le mode (incident ou demande de changement)"},
	"cli.err.change_modes":    {"--change/--demande: incompatible with --incident, --panic, --cve, --chat and --direct", "--change/--demande : incompatible avec --incident, --panic, --cve, --chat et --direct"},
	"cli.err.ticket_modes":    {"--ticket: incompatible with --cve, --chat and --direct", "--ticket : incompatible avec --cve, --chat et --direct"},
	"ticket.none":             {"--ticket: no ticketing tool in the configuration (tickets: template of kind tickets)", "--ticket : aucun outil de tickets dans la configuration (tickets : template de kind tickets)"},
	"ticket.no_id":            {"--ticket: no ticket identifier in the request (expected format: %s)", "--ticket : aucun identifiant de ticket dans la demande (format attendu : %s)"},
	"ticket.bad_id":           {"--ticket: %q does not match the ticket identifiers (%s)", "--ticket : %q ne correspond pas aux identifiants de ticket (%s)"},
	"ticket.not_found":        {"ticket %s not found in the ticketing tool", "ticket %s introuvable dans l'outil de tickets"},
	"ticket.error":            {"ticketing tool: %v", "outil de tickets : %v"},
	"ticket.off":              {"ticketing tool unavailable for this run: %v", "outil de tickets indisponible pour ce run : %v"},
	"ticket.read":             {"Ticket %s · %s · %s", "Ticket %s · %s · %s"},
	"ticket.switch":           {"ticket %s is of type %s: mode switched from %s to %s", "le ticket %s est de type %s : bascule du mode %s vers le mode %s"},
	"ticket.mode.incident":    {"incident", "incident"},
	"ticket.mode.change":      {"change request", "demande de changement"},
	"ticket.mode.other":       {"other ticket", "autre ticket"},
	"ticket.mode_line":        {"%s mode", "Mode %s"},
	"ticket.step":             {"related tickets", "tickets liés"},
	"ticket.related.similar":  {"similar ticket %s · %s · %s", "ticket similaire %s · %s · %s"},
	"ticket.related.current":  {"probable ticket of this incident %s · %s · %s", "ticket probable de cet incident %s · %s · %s"},
	"ticket.comment":          {"Internal comment for %s", "Commentaire interne pour %s"},
	"ticket.comment_noticket": {"Internal comment", "Commentaire interne"},
	"ticket.comment_saved":    {"internal comment: %s", "commentaire interne : %s"},
	"ticket.comment_failed":   {"internal comment not written: %v", "commentaire interne non rédigé : %v"},
	"kind.ticket":             {"ticket", "ticket"},
}

var ticketReportMsgs = map[string]msg{
	"ticket.label":          {"Ticket", "Ticket"},
	"ticket.probable":       {"Probable ticket (to confirm)", "Ticket probable (à confirmer)"},
	"ticket.status":         {"status %s", "statut %s"},
	"ticket.opened":         {"opened %s", "ouvert le %s"},
	"ticket.customer":       {"customer %s", "client %s"},
	"ticket.kind.incident":  {"incident", "incident"},
	"ticket.kind.change":    {"change request", "demande de changement"},
	"ticket.kind.other":     {"other", "autre"},
	"ticket.col.ticket":     {"Ticket", "Ticket"},
	"ticket.col.relation":   {"Relation", "Relation"},
	"ticket.col.status":     {"Status", "Statut"},
	"ticket.col.summary":    {"In common", "Point commun"},
	"ticket.col.resolution": {"Resolution", "Résolution"},
	"ticket.rel.similar":    {"similar", "similaire"},
	"ticket.rel.current":    {"probable, same incident", "probable, même incident"},
}
