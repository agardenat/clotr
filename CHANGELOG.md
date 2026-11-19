# Changelog
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versionnement : [SemVer](https://semver.org/lang/fr/).
## [0.81.1] - 2026-11-19

### Corrigé
- `host_key: accept-changed` : une clé d'hôte changée est de nouveau remplacée quand le connecteur SSH a aussi un mot de passe de secours (bloc `auth`) ; jusqu'ici elle restait refusée dès qu'un mot de passe pouvait être envoyé, même si l'authentification se faisait par clé. La nouvelle clé n'est acceptée que pendant la tentative par clé et n'est enregistrée qu'après son succès ; si la clé est refusée, la connexion échoue sans envoyer de mot de passe à l'hôte dont la clé a changé.

## [0.81.0] - 2026-11-18

### Ajouté
- Suivi en direct : `run --watch` (alias `--suivi`) observe une action pendant qu'elle se produit. Une tâche de préparation déclare les sources liées à l'action avec l'outil `watch_source` (fichier de log en SSH, journal systemd ou du noyau, relevé de mémoire, CPU ou connexions, outil suivable d'une instance) ; clotr se met en attente et lit ces sources en boucle sans modèle de langage, à partir de leur état au début de l'attente (rotation des fichiers suivie), affiche en direct les lignes retenues par le filtre de chaque source et archive toutes les lignes (une preuve par source, copie au fil de l'eau dans `turns/NNN/watch/`). Le premier Ctrl-C (ou `--watch-for`) arrête l'attente et lance l'analyse des captures ; le rapport suit le nouveau modèle `watch` (capture, chronologie de l'action, cause, résolution). `--watch-every` règle le délai entre deux lectures (5 s par défaut). Le mode est enregistré dans la session, repris par `run -s` et par `session --synthesize`.
- Templates : `follow = fn(args, cursor)` sur un outil de script de niveau `read` le rend suivable par le mode suivi (curseur libre rendu à chaque appel) ; `inst.follow(outil, args, cursor)` dans les tests ; `modes.watch` pour les consignes propres au suivi.

### Modifié
- Ctrl-C : le crochet d'interruption peut rester armé ; en mode suivi, le premier Ctrl-C arrête l'attente, le suivant demande la conclusion de l'analyse, le troisième coupe tout.

## [0.80.2] - 2026-11-18

### Corrigé
- Mode opératoire de mise à jour, cadrage et rédaction (y compris `session --synthesize` sur un tour existant) : la durée ou l'interruption d'une variante ne sert plus d'estimation pour une autre ; une variante dont la commande lue porte l'option (par exemple une mise à jour progressive) est « à confirmer », pas « non documentée » ; une version absente d'une page de documentation n'est plus un bloquant mais un critère du premier go/no-go, tranché par la liste des versions proposées par l'outil de mise à jour.

## [0.80.1] - 2026-11-18

### Corrigé
- Mode opératoire de mise à jour : quand la documentation propose plusieurs variantes de procédure (progressive sans interruption, classique avec arrêt…), le document suit la variante retenue au lieu de mêler leurs prérequis. L'étape `procedure` relève chaque variante avec ses conditions d'application, ses prérequis et son interruption ; les tâches mesurent ces conditions ; un cadrage commun, fixé avant la rédaction section par section, retient pour chaque composant la variante dont toutes les conditions sont mesurées, en préférant celle qui interrompt le moins, et toutes les sections le suivent (l'autre variante n'apparaît que comme repli). Auparavant, les arrêts et l'indisponibilité d'une procédure classique pouvaient figurer dans le document alors que la variante progressive s'appliquait.
- Une version absente d'une page de documentation n'est plus traitée comme indisponible : c'est un point à confirmer par la liste des versions que propose l'outil de mise à jour.

## [0.80.0] - 2026-11-18

### Ajouté
- Mode opératoire de mise à jour : `run --upgrade` (alias `--modop`) prépare la montée de version des composants de la demande, avec un phasage éventuel (composants reportés à une phase ultérieure), sans rien modifier. Une étape `procedure` lit la documentation officielle de la version cible avant la planification (recherche web, preuves et mémoire seulement) ; les tâches établissent l'état actuel et mesurent chaque prérequis ; le rapport suit le nouveau modèle `upgrade`, rédigé section par section : état actuel, compatibilité et chemin de mise à jour, prérequis, sauvegardes, étapes numérotées avec commandes et points go/no-go, vérifications, retour arrière, impacts, phases suivantes. Une commande n'y figure que si une page lue ou une preuve la donne. Le mode est enregistré dans la session, repris par `run -s` et par `session --synthesize`.
- Templates : champ `modes` (`hints` et `checklist` par mode, `upgrade` pour l'instant), présenté aux agents seulement quand le run est dans ce mode.

### Modifié
- Affinage d'une session sans aucune tâche planifiée : le rapport est réécrit à partir de la session au lieu d'échouer sur « toutes les tâches ont échoué ».

## [0.79.5] - 2026-11-18

### Corrigé
- Driver shell : une question de connexion suivie d'un retour à la ligne (par exemple un motif de connexion demandé par un script de login avant le shell) est reconnue par la regex `prompt` de l'instance et posée au terminal. Auparavant seule la dernière ligne, vide dans ce cas, était examinée, et la session expirait. Une question n'est reposée que si une nouvelle sortie non vide est arrivée depuis la réponse envoyée.

## [0.79.4] - 2026-11-18

### Corrigé
- Identifiants partagés d'un rebond shell : un hôte qui refuse un mot de passe déjà accepté par un autre hôte du même label n'efface plus ces identifiants. Seul cet hôte est écarté pour le reste du run, sans nouvel essai (aucun échec d'authentification supplémentaire) et sans redemander le mot de passe pour les autres hôtes. Auparavant, le mot de passe était oublié et redemandé à chaque nouvelle connexion, en boucle.
- Une demande d'identifiants laissée vide écarte l'hôte concerné pour le reste du run au lieu d'être reposée à chaque connexion vers lui.

## [0.79.3] - 2026-11-18

### Modifié
- Schéma : un acteur est relié à chacun de ses points d'entrée établis par les preuves, un lien par accès (par exemple HTTPS vers les ingress et SSH vers les edges pour les mêmes utilisateurs) ; la consigne n'en demandait qu'un. Un namespace ou un tenant n'est jamais dessiné comme un cluster.
- Schéma : le libellé d'un lien se place de préférence sur un segment qu'aucun autre trait ne longe ni ne croise, pour qu'on sache à quel trait il appartient.

## [0.79.2] - 2026-11-18

### Modifié
- Consignes du schéma relues et mises en cohérence : chaque lien porte son libellé (la règle « ne libeller que le premier » du serveur ne s'applique plus, clotr n'affiche qu'un libellé par tronc commun) ; une flèche va du client vers le service appelé ; couleur fixe par nature de flux (vert utilisateurs, violet exploitation, bleu applicatif, orange données et stockage, gris identité, DNS et appairages), rappelée par une phrase de légende dans le document ; groupes selon la topologie réseau, pas les groupes de ressources ; un répartiteur qui ne sert qu'un composant va dans le libellé de ce composant ; un service partagé n'a plus, sur les autres schémas, de lien unique choisi au hasard ; pas de titre dans la spec ; relecture de la spec contre les preuves avant chaque rendu. En mode schéma, les lectures de configuration des hôtes (ports, montages) restent permises.
- Notice du schéma destinée au client (`--diagram clean`) : « Hors périmètre » réduit aux composants non représentés, comme le DAT.

### Corrigé
- Schémas : un lien ne perd son libellé que s'il emprunte réellement le tronc d'un lien de même libellé déjà libellé. Auparavant, tout lien qui partageait sa source ou sa cible et son libellé avec un lien libellé restait muet, même sur un tracé séparé : des flèches sans aucune indication.

## [0.79.1] - 2026-11-18

### Modifié
- DAT destiné au client (`--dat clean`) : la demande du run n'est plus citée en tête du rapport ni transmise au template de document (plus de sous-titre de couverture tiré de la demande). Un rapport déjà enregistré perd sa citation à l'affichage et à l'export (`clotr session <nom> --export docx`).

## [0.79.0] - 2026-11-18

### Modifié
- Identifiants à saisir demandés dès que le plan est établi, avant le lancement des tâches, pour les instances du plan : authentification des connecteurs `http` (API de gestion par exemple) et `oauth2`, mot de passe `ssh` sans clé, identifiants du driver `shell`. En `--dat` et `--diagram`, ils sont demandés au démarrage. La question n'arrive plus au premier appel de l'instance, plusieurs minutes après le début du run. Rien ne change pour ce que fournissent les variables ou Vault.
- Schéma d'architecture : un composant nommé et distinct par son rôle (cluster, base, serveur applicatif) reste un nœud à lui seul ; seuls des éléments interchangeables (nœuds d'un même pool, réplicas, machines d'un même rôle) se regroupent en « (×N) », et un même composant n'est jamais dessiné deux fois. La consigne regroupait toute série de plus de trois ressources de même type.

### Ajouté
- `checklist` dans un template : faits d'architecture que ses instances permettent d'établir. En `--dat` et `--diagram`, chaque tâche reçoit la liste de ses instances et doit établir chaque point ou dire pourquoi il ne l'est pas : le relevé ne dépend plus des choix de lecture de l'agent (un appairage ou un objet de filtrage pouvait manquer d'un run à l'autre).

## [0.78.5] - 2026-11-17

### Modifié
- DAT destiné au client (`--dat clean`) : la section « Hors périmètre » ne cite que les composants entiers non décrits, sans raison ni détail ; ce qui n'a été vu qu'en partie n'y figure plus (une valeur inconnue est absente des tableaux). Les variantes `iac` et `drift` gardent la section détaillée « Périmètre non couvert et limites ». Une section vide porte « Non décrit dans ce document. »
- Modèles de rapport : une section peut viser plusieurs variantes (`<!-- variant: iac, drift -->`).

### Corrigé
- Contrôle de fidélité de l'export : un texte entre chevrons dans le rapport (`app_<env>_id`) n'est plus signalé comme absent du document ; le contrôle l'ignorait alors que le document le reproduit.

## [0.78.4] - 2026-11-17

### Modifié
- DAT destiné au client (`--dat clean`) : le document ne dit plus comment il a été établi. L'introduction ne présente que l'objet et le périmètre, sans tableau des sources interrogées ni date de relevé, et le texte ne parle ni de relevé, ni de collecte, ni d'outils, ni de tâches. La section du périmètre non couvert dit ce que le document ne décrit pas et pourquoi ; les variantes `iac` et `drift` y gardent les sources illisibles et les tâches en échec.

## [0.78.3] - 2026-11-17

### Corrigé
- Schéma d'architecture : un acteur (utilisateurs, exploitation par VPN) est relié à son point d'entrée établi par les preuves (jumpbox, bastion ou rebond ; répartiteur, ingress ou passerelle), puis ce point d'entrée à ce qu'il atteint. La consigne demandait de relier l'acteur au groupe atteint : l'exploitation pouvait arriver sur tout un sous-réseau au lieu de la jumpbox établie par le relevé.
- Schéma d'architecture : un lien relie les éléments qui échangent, et ne remonte au groupe que pour un même flux d'une source vers trois nœuds ou plus de ce groupe (les consignes poussaient à relier des groupes « de préférence », ce qui perdait la précision du relevé). Chaque lien doit reposer sur une preuve de ce couple précis, sans extension d'un composant à ses voisins. Pour un service partagé, une seule règle : un lien par couple consommateur → service établi (la consigne demandait aussi un lien par groupe consommateur).

## [0.78.2] - 2026-11-17

### Corrigé
- Rendu PNG des schémas : les liens gardent une épaisseur régulière. Les segments d'un lien se recouvraient à leurs jonctions et les bords lissés des recouvrements s'additionnaient : traits épaissis au départ de chaque lien et dans les coins.

## [0.78.1] - 2026-11-17

### Corrigé
- Plan fixe des modes `--dat` et `--diagram` : la ligne du planner s'affiche en tête du tableau avec une durée nulle, au lieu de la dernière place avec une durée aberrante (2562047h…). Une ligne terminée sans début reçoit désormais l'heure de fin comme début.

## [0.78.0] - 2026-11-17

### Modifié
- Modes `--dat` et `--diagram` : clotr construit le plan sans planner, identique d'un run à l'autre et immédiat : une tâche par instance IaC réunie avec ce qu'elle décrit, puis une par instance réelle restante, hors cibles déjà décrites. Le planner découpait différemment à chaque run, oubliait des instances et prenait de 45 s à 9 min. Il reste utilisé en affinage de session.

### Ajouté
- `describes` sur une instance : ce que décrit un dépôt IaC (`<instance>` ou `<instance>/<cible>`, une valeur ou une liste), vérifié au chargement.
- `architecture: false` dans un template : ses instances (alertes, tickets) n'ont pas de tâche dans le plan des modes `--dat` et `--diagram`.

## [0.77.1] - 2026-11-17

### Corrigé
- Mot de passe refusé : clotr le redemande aussitôt et réessaie la connexion, jusqu'à trois saisies, pour SSH, les rebonds d'un tunnel, sudo et le driver shell. Auparavant l'appel en cours échouait et la question ne revenait qu'à l'appel suivant : l'agent recevait le refus et abandonnait l'instance, et les tâches parallèles échouaient de même. Un refus arrivé pendant qu'une autre connexion a déjà obtenu un nouveau mot de passe n'efface plus ce dernier.

## [0.77.0] - 2026-11-17

### Ajouté
- Module `drawio` des templates : `drawio.route` retrace les liens d'un fichier `.drawio` à angles droits en contournant icônes, libellés et bordures, avec un écart entre liens parallèles et un tronc commun pour les liens de même libellé vers une même cible ; il écarte au préalable les éléments (`spread_x`, `spread_y`). `drawio.png` rend le fichier en PNG sur le poste, en Go, sans draw.io ni autre programme. Les liens d'un schéma rendu par un serveur qui ne les trace pas (lignes superposées, collées aux bordures, traversant icônes et libellés) deviennent lisibles.
- `render` d'un template de schéma peut renvoyer `notes` : affichées à l'utilisateur et consignées dans l'audit, sans être renvoyées au modèle comme les avertissements.

## [0.76.0] - 2026-11-17

### Ajouté
- `clotr export <fichier.md|->` met en forme un fichier Markdown quelconque en `.docx` ou `.pdf` avec le template de document de `report_export.template` (ou `--export-template`), sans session, modèle ni instance : format par `-o` ou `-f`, document écrit à côté du fichier source par défaut, images citées par un chemin relatif lues dans le dossier du fichier, titre tiré de l'unique titre de niveau 1 ou du nom du fichier. Le template reçoit le mode `document`.

### Corrigé
- `markdown.blocks` garde l'ordre du contenu d'un élément de liste : un paragraphe placé après une sous-liste (ou après un bloc de code) dans le même élément était collé à la première ligne de l'élément, avant la sous-liste. Il devient un bloc `para` avec `indent` (niveau de l'élément) et `item` (`bullet` ou `numbered`), après la sous-liste.

## [0.75.0] - 2026-11-17

### Ajouté
- `max_requests_per_minute` par provider : au plus N requêtes sur toute fenêtre de 61 s, relances comprises, partagées par tous les agents du run ; les requêtes en trop attendent leur tour avant l'envoi au lieu de recevoir un 429 de la passerelle (limite de 30 requêtes par minute d'une clé dépassée par les agents en parallèle).

### Modifié
- Un 429 met en pause toutes les requêtes du provider, pas seulement celle de l'agent qui l'a reçu, jusqu'à la reprise annoncée (en-tête `Retry-After`, ou « Limit resets at » dans le message d'une passerelle LiteLLM), au plus 61 s : les autres agents ne renvoient plus de requête vouée au refus. La date de reprise LiteLLM sert aussi de délai avant le nouvel essai.

## [0.74.4] - 2026-11-17

### Modifié
- Schéma d'un service partagé : chaque consommateur reste dans son propre réseau, sous-réseau ou cluster, jamais dans le sous-réseau du service.

### Corrigé
- Une même commande à confirmer, lancée en parallèle sur plusieurs hôtes, n'est plus demandée une fois par hôte : les demandes identiques attendent la réponse à la première, et une réponse « toujours » vaut pour toutes (la même question pouvait revenir une dizaine de fois de suite).

## [0.74.3] - 2026-11-17

### Modifié
- Les extraits de réponse HTTP affichés dans les erreurs (limite de débit 429 d'une passerelle, erreurs de catalogue ou de jeton) raccourcissent toute chaîne opaque de 32 caractères ou plus en ses 4 premiers et 4 derniers caractères : une clé d'API renvoyée par le serveur n'apparaît plus en entier et le message reste court.

## [0.74.2] - 2026-11-17

### Modifié
- Stockage partagé : les adresses de montage de chaque service (cibles de montage, répartiteur, nom DNS) sont relevées, l'adresse montée chez un consommateur est rattachée au service dont c'est l'adresse, et un seul schéma réunit les services de stockage de fichiers ; une adresse rattachée à aucun service devient son propre nœud (un service de fichiers managé monté par adresse IP disparaissait du schéma).

## [0.74.1] - 2026-11-17

### Modifié
- Schéma d'un service partagé : la liste des couples consommateur → serveur ou volume monté est dressée depuis les résultats avant la spec, et chaque couple a son lien (un consommateur de deux serveurs de fichiers n'était relié qu'à l'un).
- Type des nœuds : un nœud qui porte des services prend l'icône de son service principal trouvée dans le jeu d'icônes, un type générique seulement à défaut ; un acteur externe sans icône dans le jeu d'une plateforme se dessine sur le schéma du cloud porteur.

## [0.74.0] - 2026-11-16

### Modifié
- Un modèle qui épuise sa limite de sortie en raisonnant, sans répondre, est relancé avec un niveau de raisonnement plus bas (`max` ou `xhigh` → `high` → `medium` → `low`) avant de passer au modèle suivant ou d'échouer (audit `output_exhausted` avec `effort` et `next_effort`) : un planner en `max` sur un modèle limité à 32 000 tokens de sortie arrêtait le run.

## [0.73.1] - 2026-11-16

### Corrigé
- `inst.render(images=…)` des tests de templates accepte les images en `bytes` (par exemple `base64.decode(…)`), comme le documente le README : seul le texte était accepté.

## [0.73.0] - 2026-11-16

### Ajouté
- `run --dat iac|drift|clean` : document d'architecture technique du périmètre de la demande, sans question. `iac` décrit l'état déclaré par les instances IaC seules ; `drift` décrit l'état réel et relève chaque écart avec l'IaC, déclaré et observé avec leurs preuves ; `clean` décrit l'état réel complété par l'IaC, sans écart, sans identifiant de preuve ni annexe, pour le client. Pas de variante par défaut.
- `run --diagram iac|drift|clean` : schémas d'architecture seuls, avec la liste des composants, des flux et les limites.
- Plan couvrant : une tâche par objet réunissant son IaC et ses instances réelles, une tâche ajoutée pour chaque instance du périmètre que le planner oublie (audit `plan_covered`) ; consignes d'extraction exhaustive (chaque racine de code, pile réseau, accès d'exploitation, éléments pairs, producteurs et consommateurs).
- Étape de schéma après les tâches : spec construite par un agent à partir des constats et des preuves, un schéma par cloud, plateforme ou service partagé, rendu jusqu'à disparition des avertissements ; fichiers `architecture*.drawio` et `.png` et `diagrams.json` dans le tour.
- Templates `kind: diagram` (`render(spec, cloud)`, `reference(cloud)`, `shapes(query, cloud)`, connecteurs `mcp` ou `http`), désignés par la section `diagram` de la configuration ; `inst.diagram_render`, `inst.diagram_reference` et `inst.diagram_shapes` dans les tests de templates.
- Modèles de rapport `dat` (rédigé section par section en parallèle) et `diagram`, bloc `{{diagram}}` des figures, sections réservées à une variante (`<!-- variant: drift -->`) retirées et renumérotées.
- `--export-template <nom>` : template de document de `--export` à la place de `report_export.template`.
- Templates `kind: document` : connecteurs `mcp` et `http` facultatifs, et `doc.images`, les images du tour citées par le rapport (`data`, `format`, `width`, `height`) ; `inst.render(images=…)` dans les tests.

### Modifié
- `run -s` et `session --synthesize` reprennent le mode DAT ou schéma et sa variante ; en affinage, le plan peut être vide quand la demande ne porte que sur le rendu ou la rédaction.
- Un template de document ou de schéma doté d'un connecteur envoie le contenu hors du poste : il est refusé en session confidentielle (export en erreur, document sans schéma).

## [0.72.0] - 2026-11-16

### Ajouté
- `min_version` (et `update_hint` dans la configuration) : version minimale de clotr exigée par la configuration ou par un template, vérifiée avant le reste du fichier. Un clotr plus ancien affiche la version exigée, la sienne et la commande de mise à jour, au lieu d'une erreur sur un champ inconnu ; après une mise à jour au démarrage, le retour arrière l'affiche aussi.
- Entrée `mcp` de passerelle avec `servers` : une seule URL (motif `{alias}`, ou en-tête `x-mcp-servers`) et des en-têtes communs pour plusieurs serveurs, développée en une entrée par alias avec ses propres `allow`, `deny`, `auth`, `timeout` et `enabled`.
- Outils de template `kind: mcp` (`connector: <connecteur mcp>`, `name` et `description` optionnels) : les outils de lecture du serveur MCP du connecteur sont publiés sous le nom de l'instance, avec leur schéma, sans script.
- Connecteur `mcp` de template avec `url`, `headers`, `allow`, `deny` et `timeout` à la place de `server` : le serveur MCP est déclaré par le template et paramétré par l'instance (site, variables des clés), sans entrée dans la section `mcp` de la configuration. Permet de rattacher à un client un serveur MCP qui lui est propre.
- `clotr tools` liste aussi les outils écartés des serveurs MCP connectés pour un template. Une instance dont le serveur MCP n'a pas pu être connecté et qui n'a pas d'autre outil n'est pas annoncée au planner.

### Corrigé
- Connexion aux serveurs MCP HTTP sans flux SSE permanent (GET) : clotr n'utilise pas les messages spontanés du serveur, et une passerelle qui ne répond à ce GET qu'au premier keep-alive retardait chaque démarrage d'une quinzaine de secondes par serveur.

## [0.71.1] - 2026-11-15

### Corrigé
- `run -s` reprend le mode du dernier tour en mode incident ou demande de changement, et son ticket quand la nouvelle demande n'en cite pas : une relance d'une session d'incident ne repartait pas en mode incident sans `--incident`. Un mode explicite, `--ticket`, `--direct` ou `--chat` l'emporte ; un tour CVE plus récent arrête la reprise.

## [0.71.0] - 2026-11-14

### Modifié
- `--export docx|pdf` construit le document sur le poste avec un template `kind: document` désigné par `report_export.template` (et `report_export.params`), à la place de l'agent et du serveur MCP de `report_export.mcp` : plus de modèle, de coût ni de transfert du rapport, l'export est donc permis en session confidentielle. `report_export.mcp` et `report_export.role` sont ignorés.
- PDF converti depuis le `.docx` par LibreOffice (`soffice`), table des matières et renvois de page mis à jour avant la conversion ; sans LibreOffice, le `.docx` est enregistré à la place.
- Langue du document : `--lang` de l'export, sinon celle de la session ; `auto` est déduit du texte du rapport, hors blocs de code. Un tour CVE est exporté en mode `cve`.
- Contrôle du document : les numéros en tête de titre sont ignorés et les lignes de code courtes comptées.

### Ajouté
- Templates `kind: document` : fonction `render(doc)` qui rend le `.docx` ; modules `asset`, `zip`, `xml` et `markdown`, sans accès au réseau ni aux fichiers du poste ; `inst.render(...)` dans les tests de templates.

## [0.70.2] - 2026-11-14

### Corrigé
- `idle_timeout` n'était remis à zéro que par une ligne reçue, lignes de maintien de connexion comprises : un modèle qui ne produisait rien derrière une passerelle envoyant ces lignes bloquait sa tâche, et le run, jusqu'à `request_timeout`. Seules les données du flux le remettent à zéro ; l'appel muet bascule sur le modèle suivant.
- Le premier Ctrl-C n'agissait qu'à l'étape suivante d'une tâche : un appel au modèle ou un outil en cours la bloquait. Il interrompt désormais les appels en cours et demande la conclusion ; si le modèle ne la rend pas sous 2 minutes, la tâche se termine avec ses notes, marquées non vérifiées, et le rapport est produit.
- `session --synthesize` refusait un tour en mode incident ou demande de changement (« -t/-x ticket : aucun groupe d'outils ») : les outils internes `ticket_*` et `cause_report` ne sont plus pris pour des connecteurs ; `cve` et `ticket` sont réservés comme noms d'instance.
- `session --synthesize` affichait le rapport en Markdown brut dans le terminal : il est mis en forme comme avec `run` et `session` (`--raw` le garde brut).
- Commentaire interne : rédigé aussi après un run conclu par Ctrl-C et par `session --synthesize`, et réaffiché par `session <nom>`.
- Le mode et le ticket d'un tour sont enregistrés dans la session dès son début : `session --synthesize` les reprend aussi après un run coupé.

## [0.70.1] - 2026-11-14

### Modifié
- Progression : quand les appels d'outils d'une étape sont terminés, la ligne de la tâche indique l'attente du modèle au lieu de garder le dernier outil affiché.
- Mode demande de changement : le plan se limite à la ressource modifiée et à sa source IaC ; une information absente de la demande ou du ticket (adresse, port, pièce jointe) va dans les points à confirmer au lieu d'être cherchée sur les hôtes et les clusters.

## [0.70.0] - 2026-11-14

### Ajouté
- Mode demande de changement : `run --change` (alias `--demande`) établit l'état actuel de ce que la demande modifie et sa source IaC, sans tri d'incident, et produit un rapport des modifications à réaliser (extraits IaC avant/après), impacts, prérequis, risques, retour arrière et plan de mise en œuvre (modèle `change`).
- Rapport d'incident propre au mode (modèle `incident`) : synthèse, chronologie, cause racine et pistes écartées, constats annexes, résolution, incidents similaires, points non vérifiés et limites.
- Templates `kind: tickets` : outil de tickets décrit par un template (`id_pattern`, fonctions `get(id)` et `search(q)`, connecteurs `mcp` ou `http`), déclaré sous `tickets` dans la configuration ; `inst.ticket_get` et `inst.ticket_search` dans les tests de templates.
- `run --ticket [id]` : lecture du ticket de la demande (ou du premier identifiant relevé dans la demande), enregistré comme preuve et transmis au planner, aux tâches et au synthesizer ; le type du ticket choisit le mode ou le fait basculer entre incident et demande de changement (audit `mode_switch`).
- Périmètre déduit du ticket : sans client ni projet cité dans la demande, les identifiants client et projet du ticket, son titre et sa description servent à proposer les instances.
- Tickets liés : en modes incident et demande de changement, une tâche `tickets` cherche avant le tri les tickets passés semblables et leur résolution (outils `ticket_search`, `ticket_get`, `ticket_related`), et en incident sans ticket un ticket ouvert récent sur le même sujet ; affichés en direct, transmis aux tâches comme pistes, repris dans le rapport (blocs `{{ticket}}` et `{{tickets.related}}`) et dans `--json`.
- Commentaire interne : en fin de run incident ou demande de changement, commentaire pour le ticket (état, actions, tickets similaires, points non vérifiés), affiché en jaune et écrit dans `comment.txt` du tour.
- `session --synthesize` reprend le mode et les tickets du tour.

### Modifié
- `--incident` et `--panic` utilisent le modèle de rapport `incident` au lieu de `default`.
- Les serveurs MCP connectés pour les templates seuls ne signalent plus leurs outils non exposés aux agents.

## [0.69.1] - 2026-11-14

### Corrigé
- Windows : les modèles de rapport embarqués gardaient les fins de ligne CRLF du checkout ; ils sont normalisés au chargement (fichiers de `report_models` compris) et les modèles du dépôt sont forcés en LF.

## [0.69.0] - 2026-11-14

### Ajouté
- Modèles de rapport par mode (`internal/report`) : squelette Markdown avec consignes de section et blocs `{{…}}` que clotr remplit après la rédaction par des données établies ; un bloc omis par le modèle de langage est ajouté en fin de rapport (audit `report_block_missing`). Modèles embarqués `default` (format inchangé) et `cve` ; `report_models` en remplace un par un fichier.
- Mode CVE, procédure fixe de récupération des fiches : clotr interroge lui-même CVE.org, NVD, CISA KEV, EPSS, GitHub, Red Hat, Ubuntu et Debian (via OSV), chaque réponse étant une preuve (`cve_source`) ; scores, sévérités, exploitation connue, versions corrigées par distribution et textes des éditeurs sont extraits par le code, et les commandes de détection des paquets (`rpm`, `dpkg-query` sur le paquet source, `cat /etc/os-release`) sont générées. Le modèle de langage ne rédige que le récit, sans recherche web ; un sujet inconnu des sources garde la recherche web.
- Cache des fiches (`~/.local/state/clotr/cve/`) : fiche reprise mot pour mot, sans appel au modèle de langage, tant que les sources n'ont pas changé ; sinon fiche précédente et liste des changements transmises pour une mise à jour minimale.
- `cve.sources` (configuration) et `cve_sources` (client) : distributions interrogées.
- Rapport CVE : verdict, fiche (indicateurs expliqués, en quoi consiste la faille, analyses des éditeurs, versions par distribution limitées aux releases rencontrées, détection, mitigation temporaire, correctif), actifs positifs avec test déterminant, version corrigée pour leur distribution et exposition mesurée, actifs indéterminés, actifs négatifs regroupés par type d'élément avec les tests lancés, plan d'action par actif, limites.
- Indicateurs calculés et expliqués : CVSS par source avec niveau et vecteur en clair, sévérité des éditeurs, CISA KEV, SSVC, EPSS formaté (« 99,5 % … (99,9e percentile) », jamais arrondi à 100 %), encadré « Lire les indicateurs ».

### Modifié
- `cve_advisory` : `summary`, `mitigation` et `remediation` (obligatoires pour une faille ; `remediation` toujours) ; `score` et `commands` facultatifs quand les sources officielles fournissent scores et commandes ; `iocs` accepte aussi les traces d'exploitation d'une faille.
- `cve_report` : `asset_type` obligatoire (`host`, `workload`, `image`, `service`), `os` (distribution lue), et pour un actif vulnérable ou compromis `exposure` (`exposed`, `limited`, `unmeasured`) et `conditions`.
- Consigne de style dans tous les prompts qui produisent du texte (agents, réponse directe, synthèse de tous les modes, fiche CVE) : factuel et neutre, actions formulées par ce qu'il faut faire (« mettre à jour X sur Y ») et jamais par qui doit le faire ou à qui s'adresser, explications concises mais claires.
- Démarrage : une ligne d'état par template de démarrage à chaque lancement, une seule fois par lancement, « à jour » compris (`configuration (acme-sync) : à jour — ~/.config/clotr (1a2b3c4), …`), ou le résultat de la dernière vérification et son ancienneté quand `every` n'est pas écoulé ; un échec ou un dépôt laissé tel quel reste signalé jusqu'à la vérification suivante. `--quiet` masque les lignes « à jour ».
- Recherche web en session confidentielle : un client confidentiel sans `web_search` suit `web_search.policy` ; avec `policy: allow`, la recherche est active pour tous les clients, sauf ceux qui déclarent `web_search: deny`. Avant, chaque client confidentiel devait déclarer `allow` ou `ask` lui-même.
- Rapport CVE : actifs positifs et indéterminés présentés en fiches par actif (version trouvée, version corrigée pour la distribution, exposition, test déterminant, autres vérifications avec leur preuve), précédées d'un récapitulatif court s'il y a plusieurs positifs, au lieu d'un tableau large illisible dans un terminal ; outils sans commande (`ssh_list`, `ssh_grep`) affichés par leurs arguments.
- Langue `auto` : les textes fixes de clotr (blocs du rapport, annexe des preuves) suivent la langue de la demande, comme la rédaction ; ponctuation selon la langue.
- Noms de clients en majuscules dans l'affichage et dans l'environnement décrit aux agents (`run confidentiel : client ACME (REGULATED)`) ; inchangés dans les identifiants (`-t`), la validation de la configuration et l'audit.
- `session --synthesize` : connecteurs du tour limités à ceux du run d'origine (instances hors portée écartées), message réduit à leur nombre.
- Mode CVE : si toutes les fiches sont reprises du cache, la tâche de tri ne fait pas appel au modèle de langage ; l'avertissement « sans recherche web » ne concerne plus que les sujets inconnus des sources officielles.

## [0.68.1] - 2026-11-14

### Modifié
- `clotr models` : niveau de raisonnement (`reasoning_effort` du profil pour le rôle) entre parenthèses après chaque modèle du routage, comme dans le tableau de progression.

## [0.68.0] - 2026-11-14

### Ajouté
- Templates de démarrage (`kind: startup`) : déclarés sous `startup` dans le fichier principal, ils s'exécutent au lancement de clotr (au plus une fois par `every`, défaut 1h) pour tenir à jour configuration, clients et templates. Primitive `git.sync(url, dir, ref)` : clone ou avance rapide d'un dépôt avec le `git` du poste, confinée au répertoire de configuration et à `templates.dir` ; un répertoire qui n'est pas un clone, modifié localement, sur une autre branche ou divergent n'est jamais touché. Si les fichiers récupérés ne se chargent plus avec la version installée, la mise à jour est annulée avec un avertissement.
- `ca_vault` sur les connecteurs `http` : autorité de certification en PEM lue dans Vault (`chemin#champ`) au lieu d'un fichier du poste, exclusive avec `ca_file`.
- `clotr sync` : exécute aussitôt les templates de démarrage et affiche l'état de chaque dépôt. `--no-startup` et `CLOTR_NO_STARTUP=1` désactivent l'étape.

### Corrigé
- Driver shell avec rebonds (`then`) : un ssh qui échoue depuis l'hôte de rebond (`ssh: connect to host … Connection timed out`, `Could not resolve hostname`…) arrête l'ouverture de la session avec ce message. Avant, la chaîne tombée laissait la commande de la première étape demander un mot de passe (repli de l'outil de bastion sur l'authentification par mot de passe) : clotr y envoyait le mot de passe des VM, puis signalait un mot de passe refusé et oubliait des identifiants pourtant valides.

## [0.67.0] - 2026-11-13

### Ajouté
- Saisie des identifiants SSH et shell plus explicite : la première question indique l'hôte, l'instance, le chemin de connexion (commande et rebonds), le partage des identifiants pendant le run, le compte attendu et où le configurer. Après un mot de passe refusé, la question suivante donne la raison (compte, hôte, réponse de l'hôte) et propose le compte précédent par défaut.
- `auth.hint` sur les connecteurs `ssh` et `shell` (et `shell.auth` d'une instance) : compte attendu, affiché à la saisie.

## [0.66.0] - 2026-11-13

### Ajouté
- `host_key: accept-changed` (connecteur `ssh` des templates et `tunnel`) : une clé d'hôte changée, par exemple après la recréation d'une VM par une mise à jour d'image, remplace l'ancienne dans le `known_hosts` de clotr au lieu de bloquer la connexion. Avertissement affiché et événement d'audit `host_key_replaced` avec les deux empreintes. Le remplacement n'a lieu que si l'authentification se fait par clé seule ; si un mot de passe peut être envoyé, la clé changée reste refusée.

### Corrigé
- Tunnel de client ou de projet : une cible qui ne répond pas au rebond dans le délai de connexion ne ferme plus la chaîne SSH. Avant, ce délai dépassé était pris pour une panne du tunnel : la chaîne était rouverte et toutes les connexions en cours par le tunnel coupées (`handshake failed: EOF`, `use of closed network connection` sur d'autres hôtes), plusieurs fois de suite quand plusieurs cibles étaient injoignables.

## [0.65.0] - 2026-11-13

### Ajouté
- `web_search` par client (`ask`, `allow`, `deny`) : remplace `web_search.policy` pour les runs qui citent le client, la plus stricte l'emportant entre plusieurs clients cités. Sur un client de type confidentiel, `allow` ou `ask` autorise la recherche web en session confidentielle, si chaque client confidentiel cité l'autorise ; un modèle de recherche n'y sert que si son fournisseur est souverain.

## [0.64.0] - 2026-11-11

### Ajouté
- Primitives de script `vault.secret("chemin#champ")` et `vault.read("chemin#champ")` : un template lit un champ de secret Vault avec la configuration du poste. `vault.secret` renvoie une valeur opaque, utilisable par `crypto.sign` et `crypto.key_type` mais jamais affichée (`<secret …>` dans `str()` et les sorties d'outils) ; `vault.read` est réservé aux identifiants non secrets. Lecture une fois par instance, refusée à la découverte hors ligne. Permet par exemple de signer les appels à une API avec une clé d'accès rangée dans Vault au lieu d'un fichier du poste. `template.instance(vault=…)` dans les tests de templates.

## [0.63.0] - 2026-11-11

### Ajouté
- `auth.oauth2` sur un connecteur `http` de template : jeton obtenu par le flux *client credentials* avec un identifiant et un secret client lus dans Vault (`{champ}` remplacé par un champ du secret dans `token_url`, `client_id`, `client_secret` et `scope`), envoyé en `Authorization: Bearer`. Le jeton est gardé en mémoire le temps du run, partagé entre connecteurs et renouvelé avant son expiration. Permet par exemple de se connecter à Azure avec un principal de service rangé dans Vault, sans `az login`.

## [0.62.0] - 2026-11-11

### Ajouté
- `params` dans le fichier principal : valeurs par défaut des paramètres de toutes les instances, propres au poste (par exemple le chemin du kubeconfig). Les `params` du client, du projet puis de l'instance l'emportent, et les fichiers `clients/` partagés n'ont plus à contenir de chemin propre à un poste.

## [0.61.0] - 2026-11-11

### Ajouté
- `tunnel` sur un client ou un projet : clotr ouvre lui-même le tunnel vers le réseau du client au lieu d'un proxy SOCKS lancé à la main avant le run. Les rebonds SSH (`hops`) sont joints l'un à travers l'autre, avec un compte et un mot de passe lus dans Vault (`password_vault`, `username` du même secret) ou une clé (`key_path`, `key_vault`). Le proxy SOCKS5 local écoute sur `127.0.0.1` (`port` fixe pour les outils lancés hors de clotr, comme le `proxy-url` d'un kubeconfig, sinon libre) et `{{.tunnel_url}}` le désigne dans les `params` des instances. Les connexions SSH s'ouvrent à la première utilisation et se rouvrent après une coupure. Si le port fixe est déjà ouvert, clotr l'utilise tel quel.

## [0.60.0] - 2026-11-10
### Modifié
- Noms de session en français quand l'interface est en français (`ui_language: fr` ou `--ui-lang fr`), par exemple `fieffe-coquin`, sans accents ; en anglais sinon.

### Corrigé
- Connexion OAuth et Vault par le navigateur : la page de retour s'affiche en entier au lieu d'une connexion coupée, le serveur local attend la fin de la réponse avant de s'arrêter.

## [0.59.0] - 2026-11-10

### Ajouté
- `auth: oauth` sur une entrée `mcp` en transport `http` : au premier lancement, clotr s'enregistre auprès du serveur d'autorisation, ouvre le navigateur pour la connexion et conserve le client et le jeton dans `$XDG_STATE_HOME/clotr/oauth/<serveur>.json` (droits 600). Les lancements suivants réutilisent et rafraîchissent le jeton sans navigateur. Permet notamment d'utiliser le serveur MCP natif de GitLab, qui n'accepte pas les jetons d'accès personnels classiques. La connexion n'est demandée qu'au démarrage : pendant le run, un rafraîchissement refusé fait échouer l'appel avec une consigne de relance.
- Connecteur de template `mcp` (`server` : entrée `mcp` de la configuration) et primitive `mcp.call(conn, tool, args)` : un script lit par les outils en lecture d'un serveur MCP (`readOnlyHint` ou `allow`), connecté au démarrage dès qu'une instance active l'utilise. `template.instance(mcp=…)` et `mcp_calls()` dans les tests de templates.
- `vault.login` (`method: oidc`, `path`, `role`, `port`, `min_ttl`) : au démarrage, jeton Vault absent, refusé ou proche de l'expiration renouvelé, sinon connexion OIDC dans le navigateur, jeton écrit dans `~/.vault-token`.

### Corrigé
- Question restée sans réponse : à l'expiration du délai, clotr attend la fin de la lecture interrompue avant de fermer le terminal, au lieu de le fermer pendant qu'elle lisait encore.

## [0.58.0] - 2026-11-09

### Ajouté
- Le rapport commence par la demande en citation, suivie d'une ligne `---` : sur un affinage, toutes les demandes de la session sont reprises, numérotées par tour. Le bloc est ajouté par clotr à l'écriture de `report.md` (run, chat, `session --synthesize`), et à l'affichage ou à l'export d'un rapport plus ancien qui n'en a pas.
- Le tableau de progression et le journal affichent le niveau de raisonnement entre parenthèses après le modèle d'un agent, par exemple `fournisseur/modele (max)`, quand le profil du modèle en définit un pour le rôle de l'agent (`reasoning_effort`). Le modèle est tronqué avant le niveau si la colonne est trop étroite. `results.json` reprend le niveau par tâche (`reasoning_effort`).

## [0.57.0] - 2026-11-05

### Ajouté
- `limits.confirm_timeout` (défaut 60 s, une valeur négative attend sans limite) : une commande ou une élévation d'accès restée sans réponse est refusée, et la tâche continue. L'agent la note dans ses lacunes, et la commande n'est pas reposée pendant le run.

### Modifié
- La réponse « toujours » à une commande vaut pour toutes les instances du run.
- Une tâche reprise après une limite ne recherche plus ce que couvrent les autres tâches du plan.
- Analyse de lecture seule : `rke2` et `k3s` avec une option de version, `rpm -V` avec ses options groupées, `dnf`, `yum` et `dnf5` en `history`, `repolist`, et `list`, `info`, `repoquery`, `check-update` avec `-C` ou `--cacheonly`, passent sans question.
- Analyse de lecture seule : les historiques de commandes (`.bash_history`, `.zsh_history`…) sont soumis à question.

### Corrigé
- Une question en attente ne bloque plus la lecture des identifiants, ni donc l'activation des instances par les autres tâches.

## [0.56.0] - 2026-11-05

### Modifié
- `run` : le premier Ctrl-C demande la conclusion dans tous les modes avec plan, plus seulement avec `--incident` et `--cve`. Le rapport est produit avec ce que les tâches ont déjà trouvé ; le second Ctrl-C interrompt tout.

## [0.55.0] - 2026-11-05

### Modifié
- Analyse de lecture seule : `namei` passe sans question.
- Analyse de lecture seule : `date -d`, `--date`, `-r` et `-f` passent sans question ; une valeur d'option n'est plus prise pour une nouvelle heure.

### Corrigé
- Analyse de lecture seule : `date -s@1`, `date -us@1` et les abréviations comme `--se=` passaient pour de la lecture alors qu'ils changent l'heure. Ils sont maintenant soumis à l'utilisateur, comme toute option de `date` non reconnue.

## [0.54.0] - 2026-11-05

### Ajouté
- `run --cve` : `cve_advisory` exige `score` pour une faille, le score publié par la source (CVSS avec sa version et sa sévérité) ou « non publié ». Il figure dans la fiche transmise aux tâches et dans une colonne du tableau du rapport.

### Modifié
- `run --cve` : la fiche s'affiche en colonnes au-dessus du tableau, le score en tête, coloré selon la sévérité. `--plain` garde la ligne compacte.
- `run --cve` : la tâche des fiches ne reçoit plus que la recherche web, les preuves, la mémoire et `cve_advisory`, ce qui réduit fortement son premier prompt et évite une compaction de l'historique dès la première étape.
- `run --cve` : après quatre sorties de recherche sans nouvelle fiche, un rappel demande à cette tâche d'enregistrer ce que les sources établissent déjà ; les versions propres à une distribution se vérifient une fois l'actif lu.

## [0.53.0] - 2026-11-04

### Ajouté
- `profiles[].reasoning_effort` : niveau de raisonnement par rôle pour un modèle, envoyé tel quel au provider et tracé dans l'audit. Un rôle absent et un modèle de repli sans réglage n'envoient pas le paramètre.

## [0.52.0] - 2026-11-03

### Modifié
- Analyse de lecture seule : `kubectl` et `oc` en consultation passent sans question. Le filtre des chemins et motifs sensibles reste actif, donc les Secrets restent soumis à l'utilisateur.

## [0.51.0] - 2026-11-03

### Modifié
- Analyse de lecture seule : `sudo` et `sudo -n` sont transparents, c'est la commande qui suit qui est analysée, y compris `sudo -n sh -c '…'` et dans un script. Une commande de consultation n'est plus soumise à l'utilisateur à chaque variation de ses arguments, comme une date. Les autres options de `sudo` restent soumises à l'utilisateur.
- Les motifs `commands` s'appliquent aussi derrière `sudo` et à chaque commande simple littérale d'un `sh -c` : un motif `allow` l'admet, un motif `deny` fait passer tout le script en confirmation.

## [0.50.0] - 2026-11-03

### Modifié
- `run --cve` : `cve_advisory` exige `host_component`, vrai si le composant est fourni par l'hôte et partagé avec ses conteneurs, comme le noyau.
- `run --cve` : pour un tel composant, `cve_report` exige `asset_type` (`host` ou `workload`) et n'accepte un statut sain ou vulnérable pour un workload que si c'est celui des hôtes cités dans `runs_on`, déjà signalés. Les hôtes s'affichent dans le détail du statut et du tableau du rapport.
- `run --cve` : les agents signalent les hôtes, puis les workloads réunissant une condition d'exposition de la fiche, mesurée dans leur propre réseau. Une version de compilateur ou un fichier absent ne suffisent plus à conclure.

### Corrigé
- `run --cve` : un conteneur pouvait être déclaré sain pour une faille du noyau parce que son image ne contient pas de paquet noyau, alors que son hôte est vulnérable.

## [0.49.0] - 2026-11-03

### Ajouté
- `run --incident` : les constats de chaque tâche s'affichent dès sa fin, au-dessus du tableau de progression.
- `results.json` est écrit à la fin de chaque tâche, hors `--direct`, et plus seulement à la fin du run : un échec du planificateur ou une interruption ne fait plus perdre les résultats déjà obtenus.

### Modifié
- Non-progression : `evidence_read` ne compte comme un appel nouveau que si elle couvre des lignes pas encore lues dans la tâche. Changer `offset` ou `lines` sur des lignes déjà lues ne relance plus le compteur de `limits.stall_steps`.
- `run --incident` : une cause établie au tri limite le plan aux instances utilisées par le tri ; une tâche prévue uniquement sur d'autres instances est écartée (audit `plan_limited`).
- Un jeton HTTP saisi sans Vault (`auth` avec `header`) est partagé par libellé et hôte de `base_url`, et n'est plus redemandé pour chaque instance. Un jeton différent sur le même hôte se donne par `password_env`.
- Un argument absent du schéma d'un outil est refusé avec la liste des arguments acceptés, au lieu d'être ignoré. Les schémas qui autorisent des propriétés supplémentaires ou composent des sous-schémas ne sont pas concernés.

### Corrigé
- `ssh_grep` et `ssh.grep` sur un répertoire sans `recursive` répondaient `0` ou « aucune correspondance » : ils échouent désormais avec un message explicite.

## [0.48.0] - 2026-10-29

### Ajouté
- Option de connecteur `exec_sudo` (drivers `ssh` et `shell`, conservée par `shell` sur une instance) : `ssh_exec` lance ses commandes en `sudo -n`, ce que sa description annonce aux agents. Sans elle, `ssh_exec` reste sans sudo et bute sur les répertoires réservés à root. Le contrôle des commandes ne change pas (motifs `commands`, analyse de lecture seule, confirmation).
- Analyse de lecture seule : `findmnt` et `lsblk` reconnus comme programmes de lecture.

## [0.47.2] - 2026-10-29

### Corrigé
- Tableau de progression : certains terminaux affichaient un cadenas en bas du tableau pendant tout le run. Depuis la 0.47.0, l'écho était coupé mais le terminal restait en mode ligne, combinaison que ces terminaux prennent pour une saisie de mot de passe. Le mode ligne est maintenant coupé lui aussi pendant le tableau, comme pendant les questions, puis rétabli à la fermeture.

## [0.47.1] - 2026-10-29

### Corrigé
- Tableau de progression : en répondant à une question, la lettre tapée puis Entrée pouvaient laisser au-dessus du tableau une copie de ses premières lignes. Le cadre se refermait juste après l'affichage de la lettre, et le moteur de rendu remontait trop peu pour redessiner le tableau, devenu plus court. La bibliothèque de rendu `github.com/charmbracelet/ultraviolet` passe au commit `a45b7c86333f`, qui corrige ce calcul (dépendances entraînées : `x/ansi` v0.11.9, `go-runewidth` v0.0.30, `xo/terminfo` v1.0.0).

## [0.47.0] - 2026-10-29

### Modifié
- `-t` : les instances que la demande cite mais que `-t` écarte font l'objet d'un seul avertissement au démarrage, avec leur nombre, au lieu d'une ligne par instance qui noyait le début du run quand la demande cite un client ou un mot courant. Le détail reste dans l'audit (`instance_filtered`).

### Corrigé
- Tableau de progression : une touche tapée hors d'une question (Entrée par exemple) n'est plus renvoyée en écho par le terminal. Cet écho décalait le curseur et laissait des copies partielles du tableau au-dessus de lui. Les frappes faites avant l'ouverture d'une question sont écartées et ne peuvent plus y répondre à la place de l'utilisateur.

## [0.46.1] - 2026-10-29

### Corrigé
- Tableau de progression : pendant le run, il ne dépasse plus la hauteur du terminal. Les tâches en cours ou en échec restent affichées, les autres sont résumées sur une ligne. Une question posée sous un tableau arrivé en bas de l'écran faisait défiler le terminal et laissait une copie du tableau au-dessus.
- `session <nom> --synthesize` sur un tour lancé avec `--cve` : il échouait sur `-t/-x cve: no tool group with this name`. Il reprend désormais le mode CVE du tour, avec ses fiches et ses statuts, et le rapport régénéré garde le tableau des statuts en tête.

## [0.46.0] - 2026-10-27

### Ajouté
- Clé `shell` d'une instance : `auth` (identifiants du rebond, comme l'option `auth` du driver `shell`), pour joindre par rebond les hôtes d'un template prévu pour SSH.

### Modifié
- Option `auth` du driver `shell` : un `label` explicite désigne les identifiants tels quels, partagés par toutes les instances qui donnent le même ; sans `label`, ils restent propres à l'instance.

## [0.45.0] - 2026-10-27

### Ajouté
- Types de plateforme : section `compliance` de la configuration (`<type>: {confidential: true}`) et clé `compliance` d'un client. Un run qui cite un client d'un type confidentiel (client, alias, projet, instance, `-t`, tours précédents) devient confidentiel avant le premier appel de modèle ; hors run confidentiel, les instances de ce client ne sont pas proposées.

## [0.44.0] - 2026-10-27

### Ajouté
- Driver `shell` et clé `shell` d'une instance : option `then`, lignes tapées dans la session après l'invite, chacune attendue à l'invite suivante, pour rebondir par un hôte intermédiaire (ex. `exec ssh %h`) ; les questions de mot de passe du rebond sont relayées comme celles de la commande.
- Driver `shell` : option `auth` (`user`, `user_env`, `password_env`, `password_vault`, `label`) pour les identifiants du rebond : `%u` dans `then` est remplacé par le compte, et la demande de mot de passe pendant un rebond reçoit le mot de passe (variable, Vault ou saisie une fois par run) ; un mot de passe refusé est oublié et la session échoue avec la sortie du rebond.

## [0.43.1] - 2026-10-27

### Corrigé
- Tableau de progression : une saisie (identifiants, mot de passe, autorisation d'une commande) ne suspend plus le tableau ; la question s'affiche dans un cadre sous le tableau, la saisie d'un secret n'est pas affichée, et les lignes émises pendant la saisie (activation d'instance, journal) continuent de s'imprimer au-dessus. Une suspension simultanée à l'impression d'une ligne laissait une copie figée du tableau à l'écran. Le mode `--chat` et `--plain` ne changent pas.

## [0.43.0] - 2026-10-27

### Modifié
- Questions d'autorisation (commande hors liste, outil au-delà du niveau d'accès) : la commande ou l'outil demandé et ses arguments sont affichés en jaune gras.

## [0.42.0] - 2026-10-27

### Modifié
- Nom de session surligné (gras, vidéo inverse) dans l'entête du tableau de progression et du mode conversation, ainsi que dans les lignes `session : …` et `affiner : clotr run -s …` ; sans mise en forme si stderr n'est pas un terminal ou avec `--plain`.

## [0.41.2] - 2026-10-26

### Corrigé
- Chemin des requêtes du connecteur `http`, en accès direct comme par `via` : les séquences `%XX` déjà présentes (nom encodé par le template avec `url.path_escape`) sont gardées et seuls les autres caractères sont encodés ; la 0.41.1 réencodait `%20` en `%2520` par `via`, et l'accès direct le faisait déjà, ce qui rendait introuvable un nom contenant un espace (HTTP 500 de l'API, découverte en échec).

## [0.41.1] - 2026-10-26

### Corrigé
- Option `via` du connecteur `http` : le chemin de la requête est encodé dans `%u` (`%20` pour un espace), comme en accès direct ; un chemin contenant un espace, tel qu'un nom de cluster, partait brut dans la commande et le serveur répondait HTTP 400.
- Aide de `-t` : un projet vaut pour toutes ses instances.

## [0.41.0] - 2026-10-26

### Ajouté
- Projets d'un client : `projects` dans `clients/<client>.yaml`, chacun avec son code (`name`), ses `aliases`, son `context`, ses `vars` et `params` (qui complètent et remplacent ceux du client) et ses `instances`. Dans un projet, `{{.project}}` vaut le code du projet. Nommer un projet dans une demande propose ses instances et celles du client hors projet, pas celles des autres projets ; `-t`/`-x` acceptent le code d'un projet. L'environnement transmis aux agents donne le projet de chaque instance proposée, avec son contexte et ses références.

## [0.40.0] - 2026-10-26

### Ajouté
- Option `headers: stdin` de `via` (connecteur `http`) : les en-têtes de la requête, authentification comprise, passent par l'entrée standard de la commande (`curl -H @-`), pas par sa ligne de commande, invisible dans la liste des processus de l'hôte.
- Driver `shell` et clé `shell` d'une instance : `%s` dans `command`, nom court de l'hôte (avant le premier point), pour un outil d'accès qui attend le nom court quand l'inventaire donne le nom complet.

## [0.39.0] - 2026-10-26

### Ajouté
- Analyse de lecture seule : `node -p` et `node -e` limités à la lecture de `process.version` ou `process.versions` ; en mode CVE, une commande de la fiche placée dans un `sh -c` (`node --version; node -p 'process.versions.brotli'`) compte comme fiable, commande par commande, sans élargir le reste du script.

### Modifié
- Tableau de progression : la fiche du mode CVE s'affiche en gras bleu vif, l'activation d'une instance en gras cyan vif (événement `activation`, aussi dans `--plain` et dans le journal du chat), pour ressortir du défilement.

## [0.38.0] - 2026-10-26

### Ajouté
- Primitive `ssh.exec(prefix=[…])` : enveloppe fixe choisie par le template (ex. `kubectl exec … --`), placée devant la commande ; l'analyse de lecture seule, les listes `commands` et la confirmation portent sur la seule commande, l'enveloppe est montrée dans la question.

## [0.37.0] - 2026-10-26

### Ajouté
- Clé `shell` d'une instance : remplace le connecteur `ssh` du template par un connecteur `shell` (`command`, `%h` = hôte, `ready`, `prompt`, `open_timeout`, `max_conns`), `sudo` du template conservé. Les hôtes d'un template prévu pour SSH se joignent alors par une passerelle d'accès, sans modifier le template.
- Option `via` du connecteur `http` (`host`, `command`) : les requêtes `GET` et `HEAD` passent par une commande lancée sur un hôte à travers le connecteur `ssh`, `local` ou `shell` du template (`%u` = chemin et requête, `%a` = en-tête `Accept`), qui écrit une réponse HTTP complète comme `curl -i`. `allow`, `deny` et `max_bytes` s'appliquent ; `http.stream` et les autres méthodes sont refusés. Pour une API joignable seulement depuis un hôte.

## [0.36.0] - 2026-10-26

### Ajouté
- Driver de connecteur `local` : un template peut cibler le poste qui exécute clotr. Les outils `ssh_*` et les primitives `ssh.*` y passent par `sh -c`, avec l'utilisateur et l'environnement de clotr, sous les mêmes contrôles qu'en SSH (`ssh_paths`, `commands`, niveaux d'accès, mode CVE) ; option `max_conns` seulement, un seul connecteur `ssh`, `local` ou `shell` par template. Une commande annulée est arrêtée avec ses processus enfants.
- Driver de connecteur `shell` : les outils `ssh_*` passent par un programme local qui ouvre un shell interactif sur l'hôte (`command`, `%h` = hôte) et gère lui-même l'authentification. Une question posée avant l'invite (`prompt`, mot de passe par défaut) est relayée sur le terminal de clotr ; les commandes s'exécutent ensuite sans terminal, stdout, stderr et code retour séparés. Sessions réutilisées, `max_conns` sessions au plus, `open_timeout`, `sudo -n`. Linux et macOS.
- Analyse de lecture seule : `snap` et `flatpak` en interrogation (`list`, `info`…), `ldd`.

### Corrigé
- Mode CVE : une commande de détection de la fiche lancée en argv sans les guillemets de la fiche (`node -p process.versions.brotli` pour `node -p "process.versions.brotli"`) n'était pas reconnue comme fiable et demandait une confirmation.

## [0.35.0] - 2026-10-22

### Ajouté
- Mode CVE étendu aux compromissions : identifiants GHSA en plus des CVE, et `--cve="<sujet>"` pour une compromission sans identifiant (paquet malveillant, chaîne d'approvisionnement), dont le libellé sert d'identifiant. Fiche avec `kind` (`vulnerability` ou `compromise`) et indicateurs de compromission (`iocs`) ; statut ☠️ `compromised` quand un indicateur est observé sur un actif ; recommandations de retrait, de rotation des secrets et de recherche de traces pour les actifs exposés ou compromis.
- Analyse de lecture seule : `ss` (sans `-K`), `netstat`, `lsof`, `crontab -l`, `systemctl` en consultation, `journalctl` sans rotation ni purge, `ip` en affichage, `last`, `who`, `w`, `pgrep`, `getfacl`, `lsattr`.

## [0.34.0] - 2026-10-22

### Modifié
- Historique des agents : le raccourcissement des étapes anciennes se renforce quand l'appel précédent occupe plus de la moitié (300 caractères) puis des trois quarts (120 caractères) du contexte du modèle, sorties sans preuve, texte et arguments des appels d'outils compris (audit `history_compacted`). Une longue tâche ne dépasse plus le contexte du modèle (cas réel : 257 000 tokens après 64 étapes, tâche en échec).
- Mode CVE : tableau du rapport compact, une ligne par actif vulnérable ou indéterminé avec une colonne par CVE, actifs sains regroupés par périmètre sans leur détail (cas réel : 349 Ko pour 463 actifs, export impossible ; environ 20 Ko désormais).

## [0.33.0] - 2026-10-22

### Modifié
- Mode CVE : une tâche qui accumule 4 sorties d'outils de vérification sans `cve_report` reçoit un rappel de clotr de signaler aussitôt les actifs établis (audit `cve_reminder`), pour que les statuts s'affichent au fil de l'eau et non à la conclusion.
- Mode CVE : `commands` est obligatoire dans `cve_advisory` et demandé par la consigne des fiches.

## [0.32.0] - 2026-10-22

### Ajouté
- Analyse de lecture seule des commandes au niveau `exec` : une commande, ou un script `sh -c` analysé par un analyseur shell (pipes, `;`, `&&`, `$(…)`, `if`, `for`), faite uniquement de programmes de lecture connus avec des options sans écriture, sans redirection en écriture et sans chemin sensible, s'exécute sans confirmation ; la question n'est posée que pour le reste, avec la raison. Les listes `commands` des templates restent un complément.
- Mode CVE : `commands` de `cve_advisory`, commandes de détection de la fiche, affichées avec elle et exécutées sans confirmation (réputées fiables).

### Modifié
- Mode CVE : consigne de passer par une ressource éphémère (pod sur l'image du conteneur) avant de conclure « indéterminé ».

## [0.31.0] - 2026-10-22

### Ajouté
- `run --cve` : vérification de l'exposition à des CVE à partir de leurs identifiants dans la demande. Une tâche `t0` établit d'abord la fiche de chaque CVE (produit, versions touchées et corrigées, détection, sources) avec `cve_advisory`, affichée et transmise à toutes les tâches ; puis chaque actif est signalé avec `cve_report` dès que son statut est établi et affiché aussitôt : ✅ sain, 🚨 vulnérable (en rouge), ❓ indéterminé. Tableau des fiches et statuts en tête du rapport, généré par clotr ; `cve` dans la sortie `--json` ; premier Ctrl-C pour conclure.
- Mode CVE : les outils au-delà du niveau d'accès d'une instance (jusqu'à `create`) sont proposés et soumis à l'autorisation de l'utilisateur à chaque appel (oui, non, toujours pour ce run), refusés sans terminal ; audit `access_escalation`.

## [0.30.0] - 2026-10-22

### Ajouté
- `access` dans le fichier d'un client (`read`, `exec`, `create`) : niveau d'accès de ses instances quand `--access` n'est pas donné ; `--access` le remplace pour toutes les instances, `--access read` compris. Les instances proposées hors `read` sont affichées au démarrage avec leur niveau, enregistrées dans le tour et l'audit, et la consigne du niveau est donnée aux agents par instance.
- Une configuration qui utilise `access` dans un client est refusée par les versions antérieures.

## [0.29.0] - 2026-10-22

### Ajouté
- Niveaux d'accès choisis au lancement avec `run --access read|exec|create` (défaut `read`, jamais lu dans la configuration ni repris par `run -s`) : `exec` ouvre les commandes sur les hôtes et pods existants, `create` en plus les ressources éphémères créées et supprimées par clotr. Le niveau est affiché au démarrage, enregistré dans le tour de la session et l'audit, et décrit aux agents.
- Templates : `commands` (`allow`, `deny`, motifs d'argv avec `*`, `?` et `**` final), étendu par l'instance. Une commande de `allow` s'exécute sans question, une commande de `deny` est refusée, toute autre est soumise à l'utilisateur sur le terminal (oui, non, toujours pour ce run) et refusée sans terminal ; décisions tracées dans l'audit (`exec_decision`).
- Templates : `tool(..., access = "exec"|"create")` réserve un outil à un niveau ; outil générique `ssh_exec` et primitive `ssh.exec(host, argv)` (argv quoté, sans shell ni sudo) au niveau `exec`.
- Templates : `levels` d'un connecteur `http`. `levels.exec` (`allow`, `argv_param`) ouvre `http.stream`, connexion WebSocket dont l'argv est contrôlé par `commands` ; `levels.create` (`methods`, `allow`) ouvre l'écriture au niveau `create` : un POST déclare l'objet créé (`track`, sous le chemin du POST), toute autre écriture ne vise qu'un objet créé pendant le run, et les objets encore suivis sont supprimés en fin de tour, y compris après Ctrl-C (audit `cleanup`). Le `deny` du connecteur reste appliqué à tous les niveaux.
- Templates : primitive `sleep(seconds)` (60 s au plus par appel, interrompue avec le run), par exemple pour suivre un objet créé.
- `clotr templates test` : `template.instance(access=, confirm=)`, réponses `messages` du faux serveur pour `http.stream`, `inst.questions()`, `inst.tracked()`, `inst.cleanup()`.
- Une configuration ou un template qui utilise `commands` ou `levels` est refusé par les versions antérieures.

## [0.28.0] - 2026-10-20

### Ajouté
- `ssh_paths` sur une instance (`allow`, `deny`) : ajoute des chemins lisibles ou interdits à ceux de son template, dont les `deny` restent appliqués, par exemple pour lire `/srv/nfs` sur les VM d'un client sans modifier le template.

## [0.27.0] - 2026-10-19

### Ajouté
- Templates : `auth.header` (et `auth.scheme`) d'un connecteur `http` envoie le secret seul dans un en-tête, par exemple un jeton d'API, lu dans `password_env`, dans `password_vault` ou saisi sur le terminal, sans utilisateur.
- Templates : `when` sur un connecteur, comme sur un outil ; un connecteur dont la condition est fausse n'est pas créé et ses identifiants ne sont pas demandés.
- Templates : une entrée de `files` terminée par `/**` autorise la lecture de tout un répertoire, confinée après résolution des liens symboliques ; `file.list(path, depth=, max=)` en parcourt le contenu.

## [0.26.0] - 2026-10-19

### Ajouté
- `run --panic` : mode incident avec journal en direct, pour vérifier en parallèle. Le dossier des preuves du tour est affiché au démarrage ; chaque appel d'outil terminé s'affiche avec son id de preuve, ses arguments, la taille de sa sortie et sa durée (ou son erreur), et chaque tâche affiche ses constats et ce qu'elle n'a pas couvert dès sa fin, sans attendre la synthèse.

## [0.25.0] - 2026-10-19

### Ajouté
- `--export docx|pdf` (`run`, `session`, `session --synthesize`) : le rapport est aussi produit en document Word ou PDF par le serveur MCP désigné dans `report_export.mcp`. `-o fichier.docx` ou `-o fichier.pdf` l'implique ; sans `-o`, le document est écrit dans le tour de la session. Un agent dédié (`report_export.role`) ne voit que les outils de ce serveur, réservé à l'export et soustrait au filtre de lecture seule (seul `deny` s'applique). clotr récupère le fichier depuis les URL renvoyées par les outils et compare son texte au rapport (passages absents, déplacés, titres aplatis, syntaxe Markdown littérale) ; les écarts sont renvoyés à l'agent pour correction, puis affichés s'il en reste. Refusé en session confidentielle.
- `session` accepte `-q/--quiet` et `--plain`, pour la progression de l'export et de `--synthesize`.

## [0.24.0] - 2026-10-16

### Ajouté
- Langue de l'interface choisie indépendamment de celle des réponses : `ui_language` (config) ou `--ui-lang`, `en` (défaut) ou `fr`. Toute l'interface passe par le catalogue `internal/i18n` : aide des commandes (y compris `help`, `completion` et les titres de l'aide), erreurs et avertissements (config, routage, LLM, Vault, SSH, moteur de templates, `templates test`), tableaux et bilan. Auparavant l'aide et les erreurs restaient en français alors que le tableau et le bilan suivaient `--lang`, d'où un affichage mélangé.

### Modifié
- `language` / `--lang` ne règle plus que la langue des réponses et des rapports ; l'interface ne bascule plus en français avec `--lang fr` (utiliser `--ui-lang fr` ou `ui_language: fr`).
- Les messages du moteur de templates sont en anglais par défaut : une assertion de `*_test.star` qui cite un de ces messages en français échoue avec `ui_language: en`.

## [0.23.0] - 2026-10-16

### Ajouté
- `run --incident` : `cause_report` accepte `status: clue` pour une piste sérieuse, c'est-à-dire un élément précis de la demande (IP, nom, identifiant, code d'erreur) retrouvé dans une configuration, un log ou un historique d'installation, sans preuve encore que c'est la cause actuelle. Elle est affichée aussitôt (« piste sérieuse #N »), transmise aux autres tâches, n'arrête pas le tri, et se remplace (`replaces`) par la cause établie ou réfutée. Auparavant seule une cause établie ou probable était signalée : une piste que l'utilisateur aurait reconnue restait invisible jusqu'au rapport.

## [0.22.0] - 2026-10-16

### Ajouté
- Audit : chaque `llm_call` enregistre, quand elles sont mesurées, l'attente d'une place auprès du provider (`queue_ms`, limite de requêtes simultanées), l'arrivée des en-têtes HTTP (`headers_ms`) et celle du premier morceau du flux (`first_chunk_ms`), y compris quand l'appel échoue. `queue_ms` absent : pas d'attente ; `headers_ms` ou `first_chunk_ms` absent : étape non atteinte. `headers_ms` sans `first_chunk_ms` sur un échec « aucune donnée reçue » indique un modèle qui accepte la requête sans rien envoyer.

### Corrigé
- Affichage : chaque tentative en échec temporaire (429, 5xx, réseau, aucune donnée reçue) est annoncée sur la ligne de la tâche avec l'erreur et le délai avant le nouvel essai, et l'annonce d'un nouveau tour indique la dernière erreur. Auparavant l'erreur n'était affichée qu'en cas de bascule vers un autre modèle : avec un seul candidat, rien n'apparaissait avant le tour suivant.

## [0.21.1] - 2026-10-15

### Corrigé
- `run --incident` : un premier Ctrl-C pendant la vérification des constats abandonne les vérifications en cours, y compris celles en attente de nouvel essai, et produit le rapport. Auparavant elles continuaient jusqu'à leur fin, et il fallait un second Ctrl-C qui interrompait le run sans rapport.

## [0.21.0] - 2026-10-15

### Ajouté
- `run --incident` : `cause_report` accepte `replaces` (numéro `#N` d'une cause signalée plus tôt dans le run) pour corriger ou infirmer une cause : l'ancienne est marquée remplacée, l'affichage indique la correction et les autres tâches reçoivent la cause corrigée. Les causes affichées et transmises portent leur numéro. Auparavant une cause infirmée par une preuve plus récente restait affichée comme établie à côté de celle qui la contredisait.

## [0.20.0] - 2026-10-14

### Ajouté
- `providers[].persistent_retry` : quand tous les candidats sont en échec temporaire (429, 5xx, réseau, flux coupé) et que l'un d'eux appartient à ce provider, les tours de nouvel essai continuent jusqu'à une réponse ou une interruption, avec une pause doublée de 30 s à 5 min. Sans l'option, deux tours comme avant.

## [0.19.0] - 2026-10-14

### Modifié
- Sortie épuisée sans réponse (modèle à raisonnement qui atteint sa limite de sortie sans texte) : un modèle qui a déjà échoué ainsi n'est plus rappelé pour la même étape, et sans autre modèle disponible l'appel échoue aussitôt. Auparavant clotr redemandait une suite puis relançait pour réponse vide, jusqu'à 7 appels identiques (45 min observées pour une synthèse).
- Audit : `llm_call` enregistre le `max_tokens` envoyé.

### Corrigé
- Ligne « Client » transmise aux agents : plus de double point quand le `context` se termine par un point.

## [0.18.0] - 2026-10-14

### Ajouté
- SSH : option `key_vault` du connecteur (et attribut `ssh_key_vault` d'une cible) : clé privée lue dans un secret Vault (`chemin[#champ]`, champ par défaut `private_key`), gardée en mémoire ; sans utilisateur fixé, le champ `username` du même secret est utilisé.

## [0.17.0] - 2026-10-14

### Ajouté
- Vault : quand l'utilisateur n'est pas fixé (`ssh_user` vide, pas de `user_env`), il est lu dans le champ `username` du secret `password_vault`, au lieu d'être saisi.

## [0.16.0] - 2026-10-14

### Ajouté
- Clients : `vars` (codes client, projet…) remplacées par `{{.<clé>}}` dans les `params` du client et de ses instances, par exemple dans le chemin `password_vault` d'un secret ; une clé inconnue désactive l'instance avec un avertissement. Les références sont transmises aux agents avec le `context` du client.
- Section `vault` (`addr`, `namespace`) : adresse Vault utilisée quand `VAULT_ADDR` n'est pas exporté (par exemple défini seulement dans une fonction du shell).

## [0.15.1] - 2026-10-14

### Corrigé
- `-t <client>` forçait aussi les instances `enabled: false` du client ; il ne vaut plus que pour ses instances activées, une instance désactivée se force toujours par son nom.

## [0.15.0] - 2026-10-14

### Ajouté
- Clients : un fichier `clients/<client>.yaml` à côté du fichier de configuration regroupe les instances d'un client, avec `aliases`, un `context` transmis aux agents et des `params` par défaut pour ses instances (proxy, compte SSH…, appliqués aux seuls paramètres que le template déclare). Nommer le client ou un alias dans la demande propose toutes ses instances ; `-t <client>` et `-x <client>` valent pour toutes.

### Modifié
- Quand la demande nomme un client, une instance d'un autre client ou sans client n'est plus proposée sur le seul nom de son template ou ses `keywords` : il faut son nom, une cible ou une IP de ses `networks`.

## [0.14.0] - 2026-10-13

### Ajouté
- Templates : les entrées `allow` et `deny` de `ssh_paths` sont rendues avec les paramètres de l'instance, comme les chemins de `files` (une entrée rendue vide est ignorée, `..` refusé), pour autoriser un répertoire dont l'emplacement dépend de l'installation ; la description des outils SSH donne les chemins rendus.
- Outils SSH (`ssh_read`, `ssh_tail`, `ssh_grep`, `log_stats`) et primitives `ssh.read`, `ssh.tail`, `ssh.grep`, `ssh.stat_tail` : un fichier `.gz` est décompressé à la lecture, après vérification par `gzip -t` ; auparavant, une recherche y renvoyait 0 sans erreur. En récursif, les fichiers compressés restent ignorés.

## [0.13.0] - 2026-10-13

### Ajouté
- Outil intégré `dns_resolve` (CNAME, A, AAAA, par le résolveur du poste), proposé à toutes les tâches (`-x dns` l'écarte), et consigne pour les incidents d'accès à une URL : vérifier d'abord que le nom pointe vers le point d'entrée attendu, une IP inattendue étant une cause en soi.
- Outil de template `ssh_resolve` : `getent ahosts` sur un hôte en SSH, donc à travers le proxy de l'instance et avec le DNS interne de son réseau, plus le résolveur configuré sur l'hôte (`/etc/resolv.conf` si `ssh_paths` l'autorise).

### Modifié
- `dns` devient un nom d'instance réservé.
- SSH : un hôte qui déclare une IP est joint par son IP, le nom ne servant plus qu'à l'affichage et à la désignation ; un nom non résolvable par le proxy SOCKS ne bloque plus la connexion. Avec `host_key: strict`, une clé enregistrée sous le nom de l'hôte n'est plus reconnue.

## [0.12.0] - 2026-10-13

### Ajouté
- Avertissement au démarrage quand `-t` écarte une instance que la demande cite (nom, mot-clé, cible ou IP comprise dans ses `networks`), avec ce qui a été reconnu ; l'instance reste écartée.

## [0.11.0] - 2026-10-13

### Ajouté
- `run --incident` : tri d'incident `t0` avant le plan (composant en échec, message d'erreur exact, configuration), terminé dès qu'il signale une cause établie, dont le résultat guide le planner et est transmis à chaque tâche ; outil `cause_report` qui affiche une cause dès qu'un agent la signale avec une preuve, l'enregistre en mémoire et l'envoie aux autres tâches en cours ; premier Ctrl-C pour conclure tout de suite (tâches en cours conclues, tâches non lancées abandonnées, vérification sautée, rapport produit), second Ctrl-C pour interrompre. Incompatible avec `--direct` et `--chat`.

### Modifié
- Planner : une investigation est découpée par périmètre disjoint (cible, hôte, ressource, composant), plus par type de donnée sur un même composant ; chaque objectif nomme ses ressources, et la localisation d'une cible reste dans la tâche qui l'investigue.
- Sous-agents : pour un échec d'opération, le message d'erreur exact (code, sous-code, détails) est lu avant tout parcours de l'historique.
- `cause` devient un nom d'instance réservé.

### Corrigé
- Une sortie d'outil plus longue que `limits.tool_output_max_chars` est archivée en entier dans sa preuve ; seule la copie envoyée au modèle est tronquée, avec la ligne de coupure et l'appel `evidence_read` qui relit la suite. Auparavant la preuve gardait la sortie tronquée, et la partie coupée était perdue.

## [0.10.0] - 2026-10-12

### Ajouté
- Recherche web native : `web_search.model` (`provider/modèle`) et `web_search.api` (`messages` ou `responses`) exposent l'outil `web_search`, qui interroge un modèle doté d'une recherche web intégrée (outil serveur `web_search_20250305` de l'API Messages, ou outil `web_search` de l'API Responses). La réponse rapporte les URL citées, les requêtes lancées, le nombre de recherches et les tokens, et est archivée comme preuve. Le modèle sert quand le serveur MCP de `web_search.mcp` n'est pas utilisable (absent, désactivé ou exclu par `-x`) ; la politique, `--web` et les sessions confidentielles s'appliquent comme pour le MCP.

### Modifié
- `web` devient un nom d'instance réservé.

## [0.9.1] - 2026-10-12

### Modifié
- Homebrew : la formule déclare des bottles (macOS arm64 et Intel à partir de macOS 13, Linux arm64 et x86_64), publiés avec la release. Homebrew installe le binaire sans préparer d'environnement de compilation : l'installation ne dépend plus de la version des Command Line Tools d'Xcode, qui bloquait quand ils ne fournissaient pas de SDK pour la version de macOS en cours.

## [0.9.0] - 2026-10-11

### Ajouté
- Templates : condition `when` sur les outils de `tools`, rendue avec les paramètres de l'instance (`when: "{{.ssh}}"`) ; l'outil n'est créé que si elle vaut vrai. Une valeur non booléenne rend l'instance invalide. Un template qui l'utilise exige cette version.

### Modifié
- Réponse des sous-agents : un constat qui ne cite dans son propre texte aucune preuve existante est renvoyé à l'agent (au plus deux reprises) pour qu'il ajoute l'identifiant de la preuve ou le passe en point non vérifié. Auparavant il était seulement marqué « [NON PROUVÉ] », même quand la preuve figurait dans la liste `evidence` de la réponse.
- Agents : un appel d'outil écrit dans le texte de la réponse au format harmony (`to=functions.<outil>{…}`, modèles gpt-oss) au lieu d'un appel structuré est exécuté comme un appel d'outil, s'il désigne un outil de la tâche. La réponse finale d'un sous-agent doit contenir `findings`, `evidence` ou `gaps` : sinon elle est renvoyée à l'agent au lieu d'être acceptée comme sortie non structurée.
- Planner : les clusters et services listés dans l'environnement ne justifient plus une tâche d'inventaire préalable ni un `depends_on` vers elle (« pour chaque cluster », « pour chaque service ») ; chaque tâche lit l'inventaire elle-même. Les dépendances entre deux tâches du même rôle (une collecte qui attend une autre collecte) sont retirées du plan par clotr et tracées dans l'audit (`plan_deps_dropped`) : seules restent celles d'une analyse vers ses collectes. Aucune tâche n'est supprimée ; l'objectif d'une tâche dont une dépendance est retirée indique que ces résultats ne lui sont pas transmis et qu'elle doit établir elle-même ce dont elle a besoin.
- Synthèse : mise en page imposée hors forme demandée : sections séparées, conclusion en puces ouvertes par une phrase clé en gras, constats numérotés en continu avec un titre en gras (sans code C1/M2) puis une puce par fait, tableaux pour les valeurs comparables et les calculs, renvois aux constats par numéro, recommandations numérotées avec cause, action, risque et vérification.
- Rendu du rapport dans le terminal : la suite d'une puce ou d'un élément numéroté est indentée sous son texte, les lignes ne sont plus coupées sur la ponctuation (identifiants de preuve et noms entiers), espaces insécables devant la ponctuation française (« », :, ;, ?, !) hors code. Les tableaux gardent la largeur du terminal.

## [0.8.0] - 2026-10-11

### Ajouté
- `-x, --exclude` (`plan`, `run`, `tools`, `session --synthesize`) : exclut des groupes d'outils (mêmes préfixes que `-t`), prioritaire sur `-t` et `enabled`. L'exclusion est enregistrée avec le tour et reprise par `--synthesize`. Exclure le serveur de recherche web équivaut à `--web no`.
- `--with-evidence` (`run`, `session`, `session --synthesize`) : l'annexe des preuves citées contient la sortie complète de chaque preuve. Produite à l'affichage depuis l'archive de la session (le `report.md` n'est pas modifié), elle peut être demandée après coup. Rapport en Markdown brut. `session -o` écrit aussi le rapport d'un tour existant.

### Modifié
- `-t` et `-x` refusent un nom qui ne correspond à aucun groupe d'outils, et indiquent `mcp_<nom>` quand le nom est celui d'un serveur MCP (auparavant : « aucun outil disponible »).
- `-t mcp_<serveur>` et `-t <instance>` activent le serveur ou l'instance cité même s'il est `enabled: false` : `enabled: false` signifie désormais « coupé sauf demande explicite ». `-t mcp` et l'absence de `-t` respectent toujours `enabled`.

## [0.7.0] - 2026-10-11

### Ajouté
- Connecteurs `http` et `ssh` : option `auth.password_vault` (`chemin[#champ]`, champ `password` par défaut). Le mot de passe est lu dans Vault (KV v1 ou v2) avec la configuration du poste (`VAULT_ADDR`, `VAULT_TOKEN` ou `~/.vault-token`, `VAULT_NAMESPACE`) quand `password_env` est vide. Option absente ou secret illisible : saisie sur le terminal comme avant, avec la raison de l'échec. Un mot de passe Vault refusé n'est pas relu : le suivant est saisi.
- Templates : `http.request` accepte `tls` (`ca`, `cert`, `key` en PEM, `insecure`) et `proxy` pour un appel, ce qui permet d'utiliser des identifiants et une URL lus par le script (certificat client compris) ; module `yaml` (`decode`, `encode`) ; les chemins de `files` sont rendus avec les paramètres.
- Connecteur `http` : option `deny` (expressions régulières de chemins refusés). Déclarée, elle remplace le refus par défaut des chemins contenant `keytab`, `secret`, `password` ou `token`.
- `clotr templates test` : `inst.requests()` indique le `proxy` et le `tls` passés à chaque appel.

### Supprimé
- Outils Kubernetes intégrés (`k8s_*`) et section `k8s` de la configuration, désormais refusée. client-go n'est plus une dépendance (binaire environ 2,5 fois plus petit). Un cluster se décrit par un template, avec les primitives ci-dessus. Le nom d'instance `k8s` n'est plus réservé.

## [0.6.0] - 2026-10-11

### Ajouté
- Templates : une cible renvoyée par `discover` peut déclarer `networks` (plages CIDR). Les outils SSH acceptent alors toute IP de ces plages, même absente de l'inventaire ; une IP de plage citée dans la demande fait proposer l'instance.
- Connecteur `ssh` : option `auth` (`user_env`, `password_env`, `label`). Le mot de passe sert à se connecter quand la clé est absente ou refusée, et à `sudo` quand `sudo -n` exige un mot de passe (commande relancée avec `sudo -S`, mot de passe sur l'entrée standard). Il n'est demandé que s'il est nécessaire.

### Modifié
- Sans inventaire en cache, `discover` est exécuté hors ligne au démarrage (accès réseau refusés) et son résultat est retenu s'il n'a tenté aucun accès réseau : les cibles et plages d'un template qui ne dépend que de ses paramètres sont connues avant l'activation, et une IP de plage citée dans la demande fait proposer l'instance dès le premier run.
- `run -s` : une instance forcée par `-t` lors d'un tour précédent de la session reste proposée aux tours suivants.

## [0.5.2] - 2026-10-11

### Modifié
- k8s : les contextes ne sont plus testés au démarrage de chaque run. Un contexte est testé au premier appel d'un outil qui le vise ; une demande sans rapport avec Kubernetes ne contacte aucun cluster et n'affiche plus d'avertissement pour un tunnel fermé.

### Corrigé
- SSH : une commande dont la session se ferme sans code de sortie (« remote command exited without exit status ») est relancée jusqu'à 3 fois, avec un délai croissant. Observé quand plusieurs commandes partent en même temps vers le même hôte : une seule aboutissait.
- Un modèle qui épuise sa limite de sortie sans produire de contenu (tout en raisonnement) n'est plus relancé à l'identique : l'appel passe au modèle candidat suivant.

## [0.5.1] - 2026-10-11

### Modifié
- Planner : les cibles, hôtes et nœuds déjà listés dans l'environnement ne justifient plus une dépendance ; une tâche qui les examine démarre en parallèle de la tâche d'inventaire ou de statut.

### Corrigé
- Tableau de progression en bas du terminal : les lignes imprimées au-dessus (session, avertissements) décalaient le tableau d'une ligne (en-tête perdu, ligne dupliquée, texte écrasé). Le tableau ne se termine plus par une ligne vide pendant le run.

## [0.5.0] - 2026-10-11

### Ajouté
- `ssh_grep` : option `count` qui renvoie le nombre exact de lignes correspondantes de chaque fichier, lu en entier (`grep -c`), au lieu de lignes plafonnées par `max_matches`. Disponible aussi dans les scripts (`ssh.grep(…, count=True)`).

### Corrigé
- `run` (hors `--chat`) n'efface plus le contenu du terminal au démarrage du tableau de progression. Les lignes affichées avant le premier rendu du tableau (session, avertissements) étaient insérées en haut de l'écran, et le tableau effaçait tout ce qui suivait ; elles sont désormais imprimées après ce premier rendu.

## [0.4.0] - 2026-10-10

### Ajouté
- `run --direct[=<rôle>]` : réponse directe par un seul agent, sans planner, vérification ni synthèse, pour une question rapide. Preuves, annexe et contrôle de progression conservés.
- `run --chat` : mode conversation plein écran. La réponse s'affiche en direct, mise en forme ; `r` pour répondre (nouveau tour de la même session), `c` pour copier la réponse en Markdown dans le presse-papiers, `q` pour quitter. Les connecteurs sont préparés une seule fois pour la conversation.
- `--max-agents`, `--max-tasks`, `--max-steps` (`plan`, `run`) : remplacent les valeurs de `limits` pour un run.
- Rapport mis en forme dans le terminal (titres, tableaux, listes, code coloré) pour `run` et `session`, thème selon le fond du terminal ou `GLAMOUR_STYLE` ; `--raw` garde le Markdown brut, toujours utilisé hors terminal.

### Modifié
- Un `run` dont la préparation échoue (aucun outil disponible) n'ajoute plus de tour en échec à la session.
- L'outil `inventory` d'une instance non activée lit l'inventaire en cache, s'il a déjà été découvert, sans demander d'identifiants.
- Une instance n'est proposée aux agents que si la demande (ou une demande précédente de la session) la mentionne : nom de l'instance, du template, d'une cible, ou l'un des `keywords` du template (nouveau champ facultatif). `-t <instance>` la force. Une question sans rapport ne peut plus activer une instance ni demander ses identifiants.

## [0.3.0] - 2026-10-10

### Ajouté
- `evidence_read` : paramètre `exclude` pour retirer des lignes par expression régulière, seul ou combiné à `pattern`. Les expressions RE2 ne gèrent pas le lookahead négatif `(?!…)` que les modèles utilisaient pour ça ; l'erreur renvoyée oriente désormais vers `exclude`.

### Modifié
- Une instance de template n'est activée (identifiants, découverte) qu'au premier appel de l'un de ses outils par une tâche, et non plus au démarrage du run : une demande qui ne la concerne pas ne demande plus ses identifiants. Le planner reçoit l'inventaire en cache, ou à défaut les cibles de la configuration.
- La saisie des identifiants en cours de run suspend le tableau de progression et se fait sur l'écran alternatif du terminal.

### Corrigé
- Un nom d'outil suivi d'un jeton de format du modèle (ex. `evidence_search<|channel|>commentary`, produit par gpt-oss) est nettoyé avant l'appel au lieu d'être refusé comme outil inconnu.
- Ctrl-C pendant la saisie des identifiants interrompt le run au lieu d'enchaîner sur la saisie suivante puis d'échouer sur un contexte annulé.

## [0.2.0] - 2026-10-10

### Ajouté
- Support de Windows (amd64, arm64) : archives `.zip` dans les releases, saisie des identifiants sur la console Windows, répertoires par défaut sous `%AppData%` et `%LocalAppData%`.

## [0.1.0] - 2026-10-10

### Ajouté
- Agent CLI en lecture seule : planner, sous-agents concurrents, synthèse Markdown ou JSON.
- Découverte des modèles sur des endpoints OpenAI-compatibles, routage par rôle avec fallback, politique souveraine et suivi de budget.
- Outils Kubernetes, fichiers locaux et serveurs MCP ; recherche web optionnelle.
- Moteur de templates : cibles décrites en YAML et en scripts Starlark (découverte, outils), primitives HTTP et SSH en lecture seule, tests de templates (`clotr templates test`). Aucun template fourni.
- Sessions multi-tours avec mémoire partagée, preuves archivées citées dans les rapports et vérification des constats majeurs.
- Binaires statiques linux et darwin (amd64, arm64), paquets `.deb` et `.rpm` (amd64, arm64) et formule Homebrew.
