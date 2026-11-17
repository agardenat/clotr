package dat

import (
	"fmt"
	"strings"
)

func (s *Store) sources() string {
	switch s.Variant {
	case IaC:
		return "Sources : le code d'infrastructure seul (instances IaC du périmètre) ; le document décrit l'état déclaré, sans interroger l'infrastructure."
	case Drift:
		return "Sources : le code d'infrastructure et l'état réel (instances IaC et instances réelles du périmètre) ; le document décrit l'état réel et relève chaque écart entre le déclaré et l'observé."
	}
	return "Sources : le code d'infrastructure et l'état réel (instances IaC et instances réelles du périmètre) ; le document décrit l'état réel, l'IaC complétant ce qui ne s'observe pas (intention, paramètres, dépendances) ; une différence entre l'IaC et le réel ne se mentionne pas, le réel fait foi."
}

func (s *Store) PlanRule() string {
	what := "Document d'architecture technique (DAT)"
	if s.DiagramOnly {
		what = "Schéma d'architecture"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s du périmètre de la demande : rien n'est modifié, rien n'est investigué, il s'agit d'un relevé exhaustif et factuel de l'architecture. %s\n", what, s.sources())
	if len(s.Instances) > 0 {
		fmt.Fprintf(&b, "Instances du périmètre, toutes à couvrir : %s.", strings.Join(s.Instances, ", "))
		if len(s.IaCOnes) > 0 {
			fmt.Fprintf(&b, " Instances IaC : %s.", strings.Join(s.IaCOnes, ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("Découpage : une tâche par objet décrit (cluster, réseau, environnement, groupe d'hôtes)")
	if s.Variant != IaC {
		b.WriteString(", qui réunit l'instance IaC de cet objet et ses instances réelles (voir le contexte des instances), pour que la même tâche lise le déclaré et l'observé")
	}
	b.WriteString(" ; une tâche par instance sans objet commun. Un dépôt IaC qui décrit tout un abonnement ou plusieurs piles (réseau, clusters, plateformes, filtrage) ne se lit pas en marge d'une tâche d'inventaire : il a ses propres tâches, une par pile quand le contexte les nomme, sinon une tâche dédiée au dépôt entier")
	if s.Variant == Drift {
		b.WriteString(", avec les outils de l'instance réelle correspondante pour comparer")
	}
	b.WriteString(". Chaque instance du périmètre figure dans les tools d'au moins une tâche (par son préfixe) ; une instance qui ne décrit pas l'architecture (tickets, alertes de supervision) n'a pas de tâche. Chaque objectif nomme les instances et l'objet qu'il couvre et demande le relevé complet de cet objet : composants, versions, réseau, sécurité, identités, données, sauvegarde et supervision, selon ce que l'instance expose. Pas de tâche d'analyse ni de recoupement : la rédaction s'en charge.")
	b.WriteString(" Le schéma et la rédaction se font après les tâches, par une étape dédiée qui dispose seule des outils de schéma et lit les résultats, la mémoire partagée et les preuves : aucune tâche ne dessine, ne prépare de spec ni ne relit le relevé existant pour le schéma ou le document. En affinage d'une session, les faits des tours précédents sont en mémoire : un plan vide (aucune tâche) quand la demande ne porte que sur le rendu, la mise en forme ou la rédaction ; sinon, seulement les tâches qui collectent les faits nouveaux que la demande exige.")
	if s.DiagramOnly {
		b.WriteString(" Le relevé se limite à ce que montre un schéma : composants, regroupements (réseau, sous-réseau, zone, cluster), points d'entrée et flux entre composants avec leur protocole et port ; pour un service partagé (stockage de fichiers, NFS, annuaire, base mutualisée), ses volumes ou exports et la liste de ses consommateurs. Jamais deux tâches sur la même instance ou la même pile d'un dépôt.")
	}
	return b.String()
}

func (s *Store) CoverGoal(instance string) string {
	return fmt.Sprintf("Relevé d'architecture complet de l'instance %s pour le %s : composants, versions, réseau, sécurité, identités, données, sauvegarde et supervision, selon ce que l'instance expose. %s", instance, s.docName(), s.sources())
}

func (s *Store) docName() string {
	if s.DiagramOnly {
		return "schéma d'architecture"
	}
	return "document d'architecture technique"
}

func (s *Store) WorkerRule() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nMode %s : tu ne cherches ni cause ni anomalie, tu relèves l'architecture telle qu'elle est. %s\n", s.docName(), s.sources())
	b.WriteString("Extraction exhaustive, sans échantillonner : établis d'abord la liste de ce que couvre ta tâche (chaque racine de code, chaque cluster, chaque groupe de ressources, chaque répertoire de déploiement), puis parcours-la élément par élément ; ce qui manque à tes constats manquera au document. Un composant déployé compte quel que soit son mode de déploiement (chart Helm, manifestes ou kustomization, module ou ressource Terraform, paquet) : ne te limite pas à un seul mode. Entre éléments pairs (plusieurs clusters, environnements ou hôtes semblables), vérifie chaque composant sur chacun et dis où il est présent ou absent. Une ressource définie à un endroit et utilisée ailleurs (registre d'images, coffre de secrets, identité et ses rôles, base de données) se relève avec ses producteurs et ses consommateurs. Une source attendue mais illisible (accès refusé, fichier chiffré, dépôt absent) se signale dans gaps.\n")
	b.WriteString("Code d'infrastructure : parcours chaque racine (répertoire qui contient des déclarations) de ta tâche et relève ses ressources ; la pile réseau d'abord (réseaux, appairages, passerelles VPN ou liaisons privées, tables de routage, DNS). Avant de conclure, gaps liste les racines non parcourues.\n")
	b.WriteString("Accès d'exploitation : relève par où les administrateurs et l'exploitant entrent (VPN, bastion, rebond, appairage, plages sources nommées dans les règles de filtrage), avec les plages et ports lus ; c'est un point d'entrée au même titre que celui des utilisateurs.\n")
	b.WriteString("Stockage partagé (serveur NFS, service de fichiers managé, volumes partagés) : relève les adresses par lesquelles il se monte (adresse IP et nom DNS de chaque cible de montage ou de son répartiteur) ; chez un consommateur, relève l'adresse montée telle qu'elle est lue et rattache-la au service dont c'est l'adresse.\n")
	if s.DiagramOnly {
		b.WriteString("Relevé pour un schéma : inventaires, configuration réseau et d'exposition, versions et tailles ; pas de journaux, d'événements, de métriques, de commandes sur les hôtes ni de recherche web, qui n'apportent rien au schéma. Conclus dès que les composants, leurs regroupements et leurs flux sont établis.\n")
	}
	b.WriteString("Constats : des faits d'architecture, marqués [INFO], un fait par constat, avec le nom exact de la ressource, ses valeurs lues (version, taille, adresse, port, nombre) et sa preuve [Exxx]. Une série homogène (nœuds, règles, composants par cluster) peut tenir dans un constat, sous la forme « élément : valeurs ; élément : valeurs ». N'invente aucune valeur : ce qui n'est pas lu n'est pas écrit.")
	switch s.Variant {
	case IaC:
		b.WriteString(" Tu lis le code, pas l'infrastructure : présente les valeurs comme déclarées (dépôt, fichier).")
	case Drift:
		b.WriteString(" Compare le déclaré et l'observé pour chaque ressource que les deux couvrent : valeur différente, ressource déclarée mais absente, ressource présente mais non déclarée. Chaque écart est un constat distinct qui commence par " + DriftMark + " (au lieu de [INFO]), avec la valeur déclarée et sa preuve (dépôt, fichier), la valeur observée et sa preuve. Une ressource qui n'est pas censée être dans l'IaC (créée par un service managé, par un opérateur) n'est pas un écart : dis-le comme un fait.")
	case Clean:
		b.WriteString(" L'état réel fait foi : décris ce qui est observé ; l'IaC sert à compléter ce que le réel ne montre pas. Ne relève pas les différences entre l'IaC et le réel.")
	}
	return b.String()
}

func (s *Store) DiagramGoal() string {
	var b strings.Builder
	b.WriteString("Schéma d'architecture du périmètre, à partir des résultats des tâches de relevé (fournis ci-dessous) et de leurs preuves (evidence_read, evidence_search, memory_search ; en affinage de session, les constats des tours précédents sont dans la mémoire partagée). N'interroge pas l'infrastructure : tes seuls outils sont ceux du schéma et la lecture des preuves.\n")
	b.WriteString("1. Pour chaque cloud ou plateforme présent dans les résultats, appelle " + ReferenceTool + " : elle donne le format de la spec, les types valides et les règles de placement. Respecte-les.\n")
	b.WriteString("2. Construis la spec à partir des seules ressources établies par les preuves : les regroupements (cloud, région ou abonnement, réseau, zone, sous-réseau, cluster) en groupes imbriqués, les composants en nœuds, les flux en liens. Rien d'inventé : aucune taille, aucun nombre, aucune adresse ni aucun port qui ne soit lu. Un type incertain se cherche avec " + ShapesTool + ".\n")
	b.WriteString("Points d'entrée : les utilisateurs et l'exploitation (VPN, bastion, rebond, avec les plages sources lues) figurent chacun en acteur relié au groupe qu'il atteint, avec protocole et port.\n")
	b.WriteString("Lisibilité, prioritaire sur l'exhaustivité (le détail va dans les tableaux du document, pas sur le schéma) :\n")
	b.WriteString("- flux : une quinzaine au plus par schéma, seulement les flux principaux (entrée des utilisateurs, chaîne applicative, accès aux données, authentification) ; un lien relie de préférence deux groupes (réseau, sous-réseau, cluster) plutôt que chaque nœud, et un même flux vers plusieurs nœuds d'un groupe se dessine une seule fois vers le groupe ; aucun flux transverse de supervision, de sauvegarde ou de tirage d'images (il traverse tout le schéma) : le citer dans la notice ;\n")
	b.WriteString("- nœuds : au-delà de trois ressources de même type dans un même groupe, un seul nœud « <catégorie> (×N) » ; une adresse IP publique ou un point d'entrée se met dans le libellé du répartiteur ou de l'ingress qu'il sert, pas en nœud séparé ; trois acteurs externes au plus ;\n")
	b.WriteString("- groupes : aucun groupe vide ou traversé seulement par des flux ; un groupe de sécurité seulement s'il enveloppe les nœuds qu'il protège ;\n")
	b.WriteString("- un lien se trace en angles droits à travers tout ce qui se trouve entre ses deux extrémités : un acteur relié à plusieurs composants d'un même réseau est relié une seule fois au groupe qui les contient ; un flux déjà dessiné sur un autre schéma ne se répète pas ;\n")
	b.WriteString("- un composant du cloud dessiné en détail sur un autre schéma garde ici son groupe (parent), il n'est jamais un acteur externe ;\n")
	b.WriteString("- le type d'un nœud décrit la ressource elle-même : un répartiteur de charge a le type du répartiteur, pas l'icône du service qu'il sert ; un nœud qui porte des services (rôle d'un cluster, serveur applicatif) prend le type de son service principal trouvé par " + ShapesTool + " sur ce service, un type générique (hôte, nœud, machine) seulement quand la recherche ne trouve rien ;\n")
	b.WriteString("- un acteur externe ou un service d'un autre cloud qui n'a pas d'icône dans le jeu de la plateforme se dessine sur le schéma du cloud porteur ; le schéma de la plateforme garde son point d'entrée (répartiteur, passerelle) avec la source dans le libellé ;\n")
	b.WriteString("- un renvoi vers un autre schéma nomme ce schéma (« détail : schéma Kubernetes »), jamais un numéro de figure, attribué à la rédaction ;\n")
	b.WriteString("- libellés courts (40 caractères au plus) : nom et une valeur clé, pas de liste ;\n")
	b.WriteString("- un composant n'est détaillé que sur un schéma : quand une plateforme a son propre schéma, le schéma du cloud la représente par un seul nœud ou groupe.\n")
	b.WriteString("Un service partagé par de nombreux composants (stockage de fichiers ou NFS, volumes partagés, annuaire, base mutualisée) a son propre schéma : le service, ses volumes, partages ou exports (regroupés par usage au-delà de trois, avec leur nombre), et chacun de ses consommateurs établis par les preuves (montages, volumes persistants, exports, clients), regroupés par réseau ou cluster, un lien par groupe consommateur avec protocole et port. Un seul schéma réunit les services de stockage de fichiers (serveurs NFS et service de fichiers managé), chacun en nœud. Avant la spec, rattache chaque adresse montée relevée chez un consommateur au service dont c'est l'adresse (cibles de montage, répartiteur, nom DNS) ; une adresse rattachée à aucun service devient son propre nœud libellé par l'adresse. Dresse ensuite la liste des couples consommateur → serveur ou volume monté : chaque couple a son lien, un consommateur de deux serveurs a deux liens, et le lien va du consommateur vers le service (par son répartiteur quand il en a un). Sur les autres schémas, ce service est un seul nœud relié une seule fois.\n")
	b.WriteString("3. Appelle " + RenderTool + " ; corrige la spec et rappelle-le avec le même name tant qu'il renvoie des avertissements. Un schéma par cloud ou plateforme (le cloud et ses réseaux, puis une plateforme qui y tourne et a son propre jeu d'icônes) et un par service partagé : name architecture pour le premier, architecture-<plateforme ou service> pour les suivants.\n")
	switch s.Variant {
	case IaC:
		b.WriteString("Le schéma représente l'état déclaré par le code.\n")
	case Drift:
		b.WriteString("Le schéma représente l'état réel. Les écarts (constats " + DriftMark + ") se voient : suffixe « (hors IaC) » au libellé d'une ressource présente mais non déclarée, « (absente) » à celui d'une ressource déclarée mais absente, et un flux en écart en rouge pointillé.\n")
	case Clean:
		b.WriteString("Le schéma représente l'état réel, sans marquer de différence avec l'IaC.\n")
	}
	b.WriteString("Conclus quand chaque schéma est rendu sans avertissement : findings, un constat par schéma rendu (name, cloud, ce qu'il montre) ; gaps, ce qui n'a pas pu être représenté et pourquoi.")
	return b.String()
}

func (s *Store) SynthRule() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nMode %s. %s\n", s.docName(), s.sources())
	b.WriteString("Le document décrit l'architecture : il ne contient ni sévérité, ni cause, ni recommandation, ni jugement sur la qualité de l'infrastructure. Chaque tableau est précédé d'une phrase qui dit ce qu'il contient. Une valeur non relevée ne s'écrit pas : « non relevé ».")
	switch s.Variant {
	case Clean:
		b.WriteString(" Ce document est destiné au client : ne cite aucun identifiant de preuve [Exxx] ni de tâche, ne mentionne aucune différence entre l'IaC et l'état réel, ni les limites de la collecte autrement que par le périmètre non couvert.")
	case Drift:
		b.WriteString(" Les constats marqués " + DriftMark + " ne vont que dans la section des écarts ; ailleurs, décris l'état réel. Cite les preuves [Exxx].")
	default:
		b.WriteString(" Cite les preuves [Exxx].")
	}
	return b.String()
}

func (s *Store) CitesEvidence() bool { return s.Variant != Clean }
