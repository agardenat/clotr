package orchestrator

import "github.com/agardenat/clotr/internal/ticket"

const minutesPlan = "Compte rendu de réunion : le run lit la ou les réunions désignées par la demande et en rédige le compte rendu ; il n'investigue pas l'infrastructure. Planifie une tâche par réunion à lire, avec les outils de réunions de l'instance du périmètre : retrouver l'occurrence (date, sujet) puis lire sa transcription entière, ses participants et le chat de la réunion. Ajoute une tâche de vérification d'un fait technique cité en réunion (version, état, configuration) seulement si la demande le demande explicitement. Une réunion introuvable ou sans transcription ne se remplace par aucune autre source : elle va dans les points à confirmer. L'id " + ticket.TaskID + " est réservé: ne l'utilise pas."

const minutesRule = "\nMode compte rendu de réunion : lis la transcription entière ; une sortie tronquée se relit par plages avec evidence_read (offset, lines) jusqu'à la dernière ligne, avant de conclure. Tes constats, tous en [INFO], reprennent ce qui a été dit, sans rien ajouter : un constat par décision prise, par action décidée (qui, quoi, échéance si elle est dite), par point resté ouvert ou question sans réponse, par risque ou blocage évoqué, et un constat pour la prochaine échéance ; chacun avec sa preuve [Exxx] et l'horodatage du passage [hh:mm:ss]. Un premier constat donne la réunion : sujet, date, organisateur, présents et absents parmi les invités. Distingue ce qui est décidé de ce qui est seulement proposé ou envisagé. Un participant anonyme (@1, @2…) garde son alias, sauf indice cité qui permet de le nommer (il se présente, il est appelé par son nom, un message signé du chat reprend ses propos, un seul candidat possible) : donne alors le nom avec l'indice et son horodatage. Un terme technique douteux de la transcription automatique se signale comme tel, sans être corrigé par supposition."

func (o *Orchestrator) minutesRoles(p *Plan) {
	if !o.Minutes {
		return
	}
	role, err := o.strongRole()
	if err != nil {
		return
	}
	var changed []string
	for i := range p.Tasks {
		if p.Tasks[i].Role != role {
			p.Tasks[i].Role = role
			changed = append(changed, p.Tasks[i].ID)
		}
	}
	if len(changed) > 0 {
		o.Audit.Log("minutes_roles", map[string]any{"role": role, "tasks": changed})
	}
}
