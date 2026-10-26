# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versionnement : [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

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
