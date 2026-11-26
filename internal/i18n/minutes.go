package i18n

func init() {
	add(minutesMsgs)
}

var minutesMsgs = map[string]msg{
	"cli.flag.minutes":      {"meeting minutes: the meeting named in the request is read from the meeting instances of the scope (transcript, attendees, meeting chat), then written up as minutes (decisions, actions with owner and due date, open points, risks), each point tied to its passage; alias --cr", "compte rendu de réunion : la réunion désignée par la demande est lue par les instances de réunions du périmètre (transcription, participants, chat de la réunion), puis rédigée en compte rendu (décisions, actions avec responsable et échéance, points ouverts, risques), chaque point rattaché à son passage ; alias --minutes"},
	"cli.err.minutes_modes": {"--minutes/--cr: incompatible with --incident, --panic, --change, --upgrade, --watch, --cve, --ticket, --dat, --diagram, --chat and --direct", "--minutes/--cr : incompatible avec --incident, --panic, --change, --upgrade, --watch, --cve, --ticket, --dat, --diagram, --chat et --direct"},
	"minutes.mode":          {"meeting minutes", "compte rendu de réunion"},
	"session.word.minutes":  {"minutes", "cr"},
}
