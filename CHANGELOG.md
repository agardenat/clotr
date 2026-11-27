# Changelog

## [0.90.2] - 2026-11-27
- Correction : surcharge personnelle invalide, mise à jour de la configuration faite avec la configuration partagée seule et signalée, puis surcharge revalidée.

## [0.90.1] - 2026-11-27
- Correction : référence vers une source de secrets désactivée signalée comme telle, plus envoyée à Vault.

## [0.90.0] - 2026-11-27
- Ajout : section `secrets` de la configuration, sources de secrets globales par templates `kind: secrets` (`read(ref)`), chargées à chaque démarrage.
- Ajout : références `<source>:<ref>` dans les champs `*_vault`, `vault:` explicite, sans préfixe toujours vers Vault.
- Ajout : `user_vault` sur les blocs `auth` et `proxy_auth`.
- Ajout : `proxy_auth` sur les connecteurs `http`.
- Ajout : `auth.oauth2` `grant: password` (`username`, `password_env`, `password_vault`, `form`).
- Ajout : commande `clotr secrets test <ref>`.
- Modification : compte déduit d'un secret aussi depuis le champ `user`.

## [0.89.1] - 2026-11-26
- Ajout : compte rendu de réunion, suivi du compte rendu précédent et écarts avec un compte rendu déjà diffusé.

## [0.89.0] - 2026-11-26
- Modification : compte rendu de réunion sans identifiants de preuve ni annexe, `--with-evidence` les rétablit.
- Ajout : compte rendu de réunion, ordre du jour et points non abordés.

## [0.88.1] - 2026-11-26
- Correction : serveurs MCP en OAuth, refus de rafraîchissement imbriqué dans `detail` reconnu.

## [0.88.0] - 2026-11-26
- Ajout : mode compte rendu de réunion `run --minutes` (alias `--cr`), modèle `minutes`, `modes.minutes` des templates.
- Correction : serveurs MCP en OAuth derrière une passerelle, en-têtes du serveur envoyés sur les requêtes OAuth.
- Correction : serveurs MCP en OAuth, méthode d'authentification du client prise dans les métadonnées.
- Correction : serveurs MCP en OAuth, rafraîchissement non pris en charge plus retenté.

## [0.87.0] - 2026-11-24
- Ajout : mode suivi, relevés système `kind: sample` (sondes `system`, `cpu`, `memory`, `disk`, `network`, `connections`).
- Ajout : mode suivi, attribution de l'iowait (threads bloqués, NFS par montage, E/S par processus, fichiers ouverts).
- Ajout : mode suivi, seuils d'alerte et chiffres clés du dernier relevé dans le tableau.

## [0.86.0] - 2026-11-24
- Ajout : `vault.credentials_cache`, identifiants saisis conservés dans Vault sous `cubbyhole/`.

## [0.85.1] - 2026-11-23
- Modification : clé SSH lue dans Vault acceptée en base64.

## [0.85.0] - 2026-11-23
- Ajout : surcharge personnelle `local/config.yaml` et `local/clients/<client>.yaml`.
- Ajout : compte Vault lu dans le champ déduit de celui du mot de passe (`admin_password` → `admin_username`).

## [0.84.0] - 2026-11-19
- Modification : `max_requests_per_minute` et pause après 429 partagés entre les instances de clotr du poste.
- Modification : mode CVE, récapitulatif et document exporté copiés dans le répertoire courant.

## [0.83.1] - 2026-11-19
- Correction : récapitulatif CVE, conditions de tous les positifs recopiées dans chaque ligne.
- Modification : récapitulatif CVE en fiches par positif, sans troncature.

## [0.83.0] - 2026-11-19
- Modification : nom de session `<client>-<mot>-<adjectif>-<nom>`.
- Modification : récapitulatif CVE en tableau Markdown au lieu d'un PDF.
- Ajout : mode CVE, exposition `neutralized` et icônes 🚨/🟠/🟡.
- Ajout : récapitulatif CVE, colonne « En l'état » et tableau des indéterminés.
- Modification : modèle CVE, plan d'action en « Pourquoi positif », « Mitigation immédiate », « Correctif définitif », « Vérification ».

## [0.82.1] - 2026-11-19
- Correction : titre de l'export d'un rapport portant sur plusieurs CVE.

## [0.82.0] - 2026-11-19
- Ajout : mode CVE, récapitulatif des positifs.
- Ajout : noms de rapport `<CLIENT>-CVE-…`, `<CLIENT>-DAT-…`, `<CLIENT>-DIAGRAM-…`.
- Modification : modèle CVE, plan d'action limité aux actifs positifs.

## [0.81.1] - 2026-11-19
- Correction : `host_key: accept-changed` avec un mot de passe de secours sur le connecteur SSH.

## [0.81.0] - 2026-11-18
- Ajout : mode suivi `run --watch` (alias `--suivi`), outil `watch_source`, `--watch-for`, `--watch-every`, modèle `watch`.
- Ajout : templates, `follow` sur un outil, `inst.follow` dans les tests, `modes.watch`.
- Modification : Ctrl-C réarmable (arrêt de l'attente, puis conclusion, puis interruption).

## [0.80.2] - 2026-11-18
- Correction : mode opératoire de mise à jour, durées et statut des variantes de procédure.

## [0.80.1] - 2026-11-18
- Correction : mode opératoire de mise à jour, variantes de procédure mêlées dans le document.
- Correction : version absente de la documentation traitée comme indisponible.

## [0.80.0] - 2026-11-18
- Ajout : mode opératoire de mise à jour `run --upgrade` (alias `--modop`), étape `procedure`, modèle `upgrade`.
- Ajout : templates, champ `modes` (`hints` et `checklist` par mode).
- Correction : affinage sans tâche planifiée en échec.

## [0.79.5] - 2026-11-18
- Correction : driver shell, question de connexion suivie d'un retour à la ligne non reconnue.

## [0.79.4] - 2026-11-18
- Correction : rebond shell, identifiants partagés effacés par un hôte qui les refuse.
- Correction : demande d'identifiants vide reposée à chaque connexion.

## [0.79.3] - 2026-11-18
- Modification : schéma, un lien par point d'entrée d'un acteur.
- Modification : schéma, libellé de lien placé sur un segment libre.

## [0.79.2] - 2026-11-18
- Modification : consignes du schéma (libellés, sens des liens, couleurs par flux, légende, groupes réseau).
- Modification : `--diagram clean`, « Hors périmètre » réduit aux composants non représentés.
- Correction : schéma, liens sans libellé.

## [0.79.1] - 2026-11-18
- Modification : `--dat clean`, demande retirée du rapport et du document.

## [0.79.0] - 2026-11-18
- Modification : identifiants demandés avant le lancement des tâches.
- Modification : schéma, regroupement `(×N)` limité aux éléments interchangeables.
- Ajout : `checklist` dans les templates.

## [0.78.5] - 2026-11-17
- Modification : `--dat clean`, « Hors périmètre » limité aux composants non décrits.
- Ajout : modèles de rapport, section pour plusieurs variantes.
- Correction : contrôle de l'export, texte entre chevrons signalé à tort.

## [0.78.4] - 2026-11-17
- Modification : `--dat clean`, introduction limitée à l'objet et au périmètre.

## [0.78.3] - 2026-11-17
- Correction : schéma, acteur relié à son point d'entrée.
- Correction : schéma, liens entre éléments plutôt qu'entre groupes.

## [0.78.2] - 2026-11-17
- Correction : rendu PNG, épaisseur des liens.

## [0.78.1] - 2026-11-17
- Correction : plan fixe, ligne du planner et durée affichées.

## [0.78.0] - 2026-11-17
- Modification : `--dat` et `--diagram`, plan construit par clotr sans planner.
- Ajout : `describes` sur une instance.
- Ajout : `architecture: false` dans un template.

## [0.77.1] - 2026-11-17
- Correction : mot de passe refusé redemandé aussitôt (SSH, tunnel, sudo, shell).

## [0.77.0] - 2026-11-17
- Ajout : module `drawio` (`drawio.route`, `drawio.png`).
- Ajout : `notes` dans le rendu d'un template de schéma.

## [0.76.0] - 2026-11-17
- Ajout : `clotr export <fichier.md|->`.
- Correction : `markdown.blocks`, ordre d'un paragraphe après une sous-liste.

## [0.75.0] - 2026-11-17
- Ajout : `max_requests_per_minute` par provider.
- Modification : un 429 met en pause toutes les requêtes du provider.

## [0.74.4] - 2026-11-17
- Modification : schéma, consommateur d'un service partagé dans son propre réseau.
- Correction : même commande à confirmer demandée une fois par hôte.

## [0.74.3] - 2026-11-17
- Modification : chaînes opaques raccourcies dans les extraits de réponse HTTP des erreurs.

## [0.74.2] - 2026-11-17
- Modification : stockage partagé, adresses de montage rattachées à leur service.

## [0.74.1] - 2026-11-17
- Modification : schéma d'un service partagé, un lien par couple consommateur → serveur.
- Modification : type des nœuds selon le service principal.

## [0.74.0] - 2026-11-16
- Modification : sortie épuisée en raisonnant, relance avec un niveau de raisonnement plus bas.

## [0.73.1] - 2026-11-16
- Correction : `inst.render(images=…)` accepte des `bytes`.

## [0.73.0] - 2026-11-16
- Ajout : `run --dat iac|drift|clean`.
- Ajout : `run --diagram iac|drift|clean`.
- Ajout : étape de schéma et templates `kind: diagram`.
- Ajout : modèles de rapport `dat` et `diagram`.
- Ajout : `--export-template`.
- Ajout : templates `kind: document`, connecteurs facultatifs et `doc.images`.
- Modification : `run -s` et `session --synthesize` reprennent le mode DAT ou schéma.
- Modification : template de document ou de schéma avec connecteur refusé en session confidentielle.

## [0.72.0] - 2026-11-16
- Ajout : `min_version` et `update_hint`.
- Ajout : entrée `mcp` de passerelle avec `servers`.
- Ajout : outils de template `kind: mcp`.
- Ajout : connecteur `mcp` de template avec `url`.
- Ajout : `clotr tools` liste les outils MCP écartés.
- Correction : démarrage retardé par le flux SSE des serveurs MCP HTTP.

## [0.71.1] - 2026-11-15
- Correction : `run -s` reprend le mode incident ou demande de changement et son ticket.

## [0.71.0] - 2026-11-14
- Modification : `--export` construit le document sur le poste avec un template `kind: document`.
- Modification : PDF converti par LibreOffice.
- Modification : langue du document.
- Ajout : templates `kind: document` et modules `asset`, `zip`, `xml`, `markdown`.

## [0.70.2] - 2026-11-14
- Correction : `idle_timeout` remis à zéro par les lignes de maintien de connexion.
- Correction : premier Ctrl-C sans effet pendant un appel en cours.
- Correction : `session --synthesize` refusé sur un tour incident ou demande de changement.
- Correction : `session --synthesize` sans mise en forme.
- Correction : commentaire interne absent après Ctrl-C ou `--synthesize`.
- Correction : mode et ticket d'un tour enregistrés dès son début.

## [0.70.1] - 2026-11-14
- Modification : progression, attente du modèle affichée après les appels d'outils.
- Modification : demande de changement, plan limité à la ressource modifiée et à son IaC.

## [0.70.0] - 2026-11-14
- Ajout : mode demande de changement `run --change` (alias `--demande`), modèle `change`.
- Ajout : modèle de rapport `incident`.
- Ajout : templates `kind: tickets`.
- Ajout : `run --ticket [id]`.
- Ajout : périmètre déduit du ticket.
- Ajout : tickets liés.
- Ajout : commentaire interne pour le ticket.
- Ajout : `session --synthesize` reprend le mode et les tickets.
- Modification : `--incident` et `--panic` utilisent le modèle `incident`.
- Modification : serveurs MCP des templates sans avertissement sur leurs outils non exposés.

## [0.69.1] - 2026-11-14
- Correction : Windows, fins de ligne CRLF des modèles de rapport.

## [0.69.0] - 2026-11-14
- Ajout : modèles de rapport par mode et `report_models`.
- Ajout : mode CVE, fiches établies depuis les sources officielles.
- Ajout : mode CVE, cache des fiches.
- Ajout : `cve.sources` et `cve_sources`.
- Ajout : modèle de rapport CVE.
- Ajout : indicateurs CVE calculés et expliqués.
- Modification : champs de `cve_advisory` et `cve_report`.
- Modification : consigne de style des prompts.
- Modification : une ligne d'état par template de démarrage.
- Modification : recherche web en session confidentielle selon `web_search.policy`.
- Modification : rapport CVE en fiches par actif.
- Modification : langue `auto` appliquée aux textes fixes de clotr.
- Modification : noms de clients en majuscules à l'affichage.
- Modification : `session --synthesize` limité aux connecteurs du tour.
- Modification : mode CVE, tri sans appel au modèle quand les fiches viennent du cache.

## [0.68.1] - 2026-11-14
- Modification : `clotr models` affiche le niveau de raisonnement.

## [0.68.0] - 2026-11-14
- Ajout : templates de démarrage `kind: startup` et `git.sync`.
- Ajout : `ca_vault` sur les connecteurs `http`.
- Ajout : `clotr sync`, `--no-startup`, `CLOTR_NO_STARTUP`.
- Correction : driver shell, rebond en échec non détecté.

## [0.67.0] - 2026-11-13
- Ajout : questions d'identifiants SSH et shell détaillées.
- Ajout : `auth.hint`.

## [0.66.0] - 2026-11-13
- Ajout : `host_key: accept-changed`.
- Correction : tunnel fermé par une cible injoignable.

## [0.65.0] - 2026-11-13
- Ajout : `web_search` par client.

## [0.64.0] - 2026-11-11
- Ajout : primitives `vault.secret` et `vault.read`.

## [0.63.0] - 2026-11-11
- Ajout : `auth.oauth2` sur un connecteur `http`.

## [0.62.0] - 2026-11-11
- Ajout : `params` dans le fichier principal.

## [0.61.0] - 2026-11-11
- Ajout : `tunnel` sur un client ou un projet.

## [0.60.0] - 2026-11-10
- Modification : noms de session en français avec l'interface en français.
- Correction : page de retour OAuth et Vault coupée.

## [0.59.0] - 2026-11-10
- Ajout : `auth: oauth` sur une entrée `mcp`.
- Ajout : connecteur de template `mcp` et `mcp.call`.
- Ajout : `vault.login`.
- Correction : terminal fermé pendant une lecture à l'expiration d'une question.

## [0.58.0] - 2026-11-09
- Ajout : demande citée en tête du rapport.
- Ajout : niveau de raisonnement affiché après le modèle.

## [0.57.0] - 2026-11-05
- Ajout : `limits.confirm_timeout`.
- Modification : réponse « toujours » valable pour toutes les instances.
- Modification : tâche reprise limitée à son périmètre.
- Modification : analyse de lecture seule, `rke2`, `k3s`, `rpm -V`, `dnf`/`yum` en consultation.
- Modification : analyse de lecture seule, historiques de commandes soumis à question.
- Correction : question en attente bloquant la lecture des identifiants.

## [0.56.0] - 2026-11-05
- Modification : premier Ctrl-C conclut dans tous les modes avec plan.

## [0.55.0] - 2026-11-05
- Modification : analyse de lecture seule, `namei` et `date` en lecture.
- Correction : analyse de lecture seule, réglage de l'heure par `date` non détecté.

## [0.54.0] - 2026-11-05
- Ajout : mode CVE, `score` obligatoire dans `cve_advisory`.
- Modification : mode CVE, fiche affichée en colonnes.
- Modification : mode CVE, outils réduits pour la tâche des fiches.
- Modification : mode CVE, rappel d'enregistrer les fiches.

## [0.53.0] - 2026-11-04
- Ajout : `profiles[].reasoning_effort`.

## [0.52.0] - 2026-11-03
- Modification : analyse de lecture seule, `kubectl` et `oc` en consultation.

## [0.51.0] - 2026-11-03
- Modification : analyse de lecture seule, `sudo` transparent.
- Modification : motifs `commands` appliqués derrière `sudo` et dans `sh -c`.

## [0.50.0] - 2026-11-03
- Modification : mode CVE, `host_component` dans `cve_advisory`.
- Modification : mode CVE, statut d'un workload repris de ses hôtes pour un composant de l'hôte.
- Modification : mode CVE, ordre de signalement hôtes puis workloads exposés.
- Correction : mode CVE, conteneur déclaré sain pour une faille du noyau.

## [0.49.0] - 2026-11-03
- Ajout : `run --incident`, constats affichés à la fin de chaque tâche.
- Ajout : `results.json` écrit à la fin de chaque tâche.
- Modification : `evidence_read` compté comme progrès seulement sur des lignes nouvelles.
- Modification : `run --incident`, plan limité aux instances du tri.
- Modification : jeton HTTP saisi partagé par libellé et hôte.
- Modification : argument inconnu d'un outil refusé.
- Correction : `ssh_grep` sur un répertoire sans `recursive`.

## [0.48.0] - 2026-10-29
- Ajout : `exec_sudo` sur les connecteurs `ssh` et `shell`.
- Ajout : analyse de lecture seule, `findmnt` et `lsblk`.

## [0.47.2] - 2026-10-29
- Correction : tableau de progression, cadenas affiché par certains terminaux.

## [0.47.1] - 2026-10-29
- Correction : tableau de progression, copie laissée après une réponse.

## [0.47.0] - 2026-10-29
- Modification : `-t`, un seul avertissement pour les instances écartées.
- Correction : tableau de progression, écho des frappes.

## [0.46.1] - 2026-10-29
- Correction : tableau de progression limité à la hauteur du terminal.
- Correction : `session --synthesize` sur un tour CVE.

## [0.46.0] - 2026-10-27
- Ajout : `auth` sur la clé `shell` d'une instance.
- Modification : `label` du driver `shell` partagé entre instances.

## [0.45.0] - 2026-10-27
- Ajout : types de plateforme `compliance`.

## [0.44.0] - 2026-10-27
- Ajout : driver `shell`, option `then`.
- Ajout : driver `shell`, option `auth`.

## [0.43.1] - 2026-10-27
- Correction : tableau de progression, saisie affichée dans un cadre sous le tableau.

## [0.43.0] - 2026-10-27
- Modification : commande à autoriser affichée en jaune.

## [0.42.0] - 2026-10-27
- Modification : nom de session surligné.

## [0.41.2] - 2026-10-26
- Correction : connecteur `http`, séquences `%XX` réencodées dans le chemin.

## [0.41.1] - 2026-10-26
- Correction : `via`, chemin non encodé dans `%u`.
- Correction : aide de `-t` pour les projets.

## [0.41.0] - 2026-10-26
- Ajout : projets d'un client.

## [0.40.0] - 2026-10-26
- Ajout : `via`, option `headers: stdin`.
- Ajout : driver `shell`, `%s` dans `command`.

## [0.39.0] - 2026-10-26
- Ajout : analyse de lecture seule, `node -p` et `node -e` sur `process.versions`.
- Modification : couleurs de la fiche CVE et de l'activation d'une instance.

## [0.38.0] - 2026-10-26
- Ajout : `ssh.exec(prefix=[…])`.

## [0.37.0] - 2026-10-26
- Ajout : clé `shell` d'une instance.
- Ajout : option `via` du connecteur `http`.

## [0.36.0] - 2026-10-26
- Ajout : driver de connecteur `local`.
- Ajout : driver de connecteur `shell`.
- Ajout : analyse de lecture seule, `snap`, `flatpak`, `ldd`.
- Correction : mode CVE, commande de la fiche sans guillemets non reconnue.

## [0.35.0] - 2026-10-22
- Ajout : mode CVE, identifiants GHSA et compromissions sans identifiant.
- Ajout : analyse de lecture seule, `ss`, `netstat`, `lsof`, `systemctl`, `journalctl`, `ip` et autres.

## [0.34.0] - 2026-10-22
- Modification : historique raccourci selon le remplissage du contexte.
- Modification : mode CVE, tableau du rapport compact.

## [0.33.0] - 2026-10-22
- Modification : mode CVE, rappel de signaler les actifs.
- Modification : mode CVE, `commands` obligatoire dans `cve_advisory`.

## [0.32.0] - 2026-10-22
- Ajout : analyse de lecture seule des commandes au niveau `exec`.
- Ajout : mode CVE, commandes de détection de la fiche exécutées sans confirmation.
- Modification : mode CVE, ressource éphémère avant de conclure « indéterminé ».

## [0.31.0] - 2026-10-22
- Ajout : `run --cve`.
- Ajout : mode CVE, élévation d'accès sur autorisation.

## [0.30.0] - 2026-10-22
- Ajout : `access` dans le fichier d'un client.

## [0.29.0] - 2026-10-22
- Ajout : `run --access read|exec|create`.
- Ajout : templates, `commands`.
- Ajout : templates, outils `access = "exec"|"create"`, `ssh_exec`, `ssh.exec`.
- Ajout : templates, `levels` d'un connecteur `http` et `http.stream`.
- Ajout : templates, `sleep`.
- Ajout : `clotr templates test`, `access`, `confirm`, `questions`, `tracked`, `cleanup`.

## [0.28.0] - 2026-10-20
- Ajout : `ssh_paths` sur une instance.

## [0.27.0] - 2026-10-19
- Ajout : `auth.header` et `auth.scheme` sur un connecteur `http`.
- Ajout : `when` sur un connecteur.
- Ajout : `files` avec `/**` et `file.list`.

## [0.26.0] - 2026-10-19
- Ajout : `run --panic`.

## [0.25.0] - 2026-10-19
- Ajout : `--export docx|pdf` par serveur MCP.
- Ajout : `session -q` et `--plain`.

## [0.24.0] - 2026-10-16
- Ajout : `ui_language` et `--ui-lang`.
- Modification : `language` et `--lang` limités aux réponses et rapports.
- Modification : messages du moteur de templates en anglais par défaut.

## [0.23.0] - 2026-10-16
- Ajout : `cause_report` avec `status: clue`.

## [0.22.0] - 2026-10-16
- Ajout : audit, `queue_ms`, `headers_ms`, `first_chunk_ms`.
- Correction : relances non affichées.

## [0.21.1] - 2026-10-15
- Correction : premier Ctrl-C pendant la vérification des constats.

## [0.21.0] - 2026-10-15
- Ajout : `cause_report` avec `replaces`.

## [0.20.0] - 2026-10-14
- Ajout : `providers[].persistent_retry`.

## [0.19.0] - 2026-10-14
- Modification : sortie épuisée, pas de rappel du même modèle.
- Modification : audit, `max_tokens` dans `llm_call`.
- Correction : double point dans la ligne « Client ».

## [0.18.0] - 2026-10-14
- Ajout : `key_vault` sur le connecteur SSH.

## [0.17.0] - 2026-10-14
- Ajout : utilisateur lu dans le champ `username` du secret Vault.

## [0.16.0] - 2026-10-14
- Ajout : `vars` des clients.
- Ajout : section `vault` (`addr`, `namespace`).

## [0.15.1] - 2026-10-14
- Correction : `-t <client>` forçait les instances désactivées.

## [0.15.0] - 2026-10-14
- Ajout : fichiers `clients/<client>.yaml`.
- Modification : instances d'un autre client non proposées sur le seul nom du template.

## [0.14.0] - 2026-10-13
- Ajout : `ssh_paths` rendus avec les paramètres.
- Ajout : lecture des fichiers `.gz` par les outils SSH.

## [0.13.0] - 2026-10-13
- Ajout : outil `dns_resolve`.
- Ajout : outil de template `ssh_resolve`.
- Modification : `dns` nom d'instance réservé.
- Modification : SSH, hôte joint par son IP.

## [0.12.0] - 2026-10-13
- Ajout : avertissement quand `-t` écarte une instance citée.

## [0.11.0] - 2026-10-13
- Ajout : `run --incident` et `cause_report`.
- Modification : planner, découpage par périmètre disjoint.
- Modification : sous-agents, message d'erreur exact lu en premier.
- Modification : `cause` nom d'instance réservé.
- Correction : preuve tronquée comme la sortie envoyée au modèle.

## [0.10.0] - 2026-10-12
- Ajout : recherche web native `web_search.model` et `web_search.api`.
- Modification : `web` nom d'instance réservé.

## [0.9.1] - 2026-10-12
- Modification : bottles Homebrew.

## [0.9.0] - 2026-10-11
- Ajout : `when` sur les outils de template.
- Modification : constat sans preuve renvoyé à l'agent.
- Modification : appels d'outils au format harmony exécutés.
- Modification : dépendances entre tâches du même rôle retirées.
- Modification : mise en page imposée du rapport.
- Modification : rendu du rapport dans le terminal.

## [0.8.0] - 2026-10-11
- Ajout : `-x, --exclude`.
- Ajout : `--with-evidence`.
- Modification : `-t` et `-x` refusent un nom inconnu.
- Modification : `-t` active un serveur ou une instance `enabled: false`.

## [0.7.0] - 2026-10-11
- Ajout : `auth.password_vault` sur les connecteurs `http` et `ssh`.
- Ajout : `http.request` avec `tls` et `proxy`, module `yaml`.
- Ajout : `deny` sur le connecteur `http`.
- Ajout : `inst.requests()` avec `proxy` et `tls`.
- Suppression : outils Kubernetes intégrés et section `k8s`.

## [0.6.0] - 2026-10-11
- Ajout : `networks` sur une cible.
- Ajout : `auth` sur le connecteur `ssh`.
- Modification : `discover` exécuté hors ligne sans cache.
- Modification : instance forcée par `-t` reprise par `run -s`.

## [0.5.2] - 2026-10-11
- Modification : contextes k8s testés au premier appel.
- Correction : SSH, commande sans code de sortie relancée.
- Correction : sortie épuisée relancée à l'identique.

## [0.5.1] - 2026-10-11
- Modification : planner, pas de dépendance sur les cibles déjà listées.
- Correction : tableau de progression décalé en bas du terminal.

## [0.5.0] - 2026-10-11
- Ajout : `ssh_grep` avec `count`.
- Correction : terminal effacé au démarrage du tableau.

## [0.4.0] - 2026-10-10
- Ajout : `run --direct`.
- Ajout : `run --chat`.
- Ajout : `--max-agents`, `--max-tasks`, `--max-steps`.
- Ajout : rapport mis en forme dans le terminal.
- Modification : préparation en échec sans tour enregistré.
- Modification : `inventory` lu en cache sans activation.
- Modification : instance proposée seulement si la demande la mentionne, `keywords`.

## [0.3.0] - 2026-10-10
- Ajout : `evidence_read` avec `exclude`.
- Modification : instance activée au premier appel de ses outils.
- Modification : saisie des identifiants sur l'écran alternatif.
- Correction : nom d'outil suivi d'un jeton de format.
- Correction : Ctrl-C pendant la saisie des identifiants.

## [0.2.0] - 2026-10-10
- Ajout : Windows (amd64, arm64).

## [0.1.0] - 2026-10-10
- Ajout : agent CLI en lecture seule (planner, sous-agents, synthèse).
- Ajout : découverte des modèles, routage par rôle, politique souveraine, budget.
- Ajout : outils fichiers locaux, MCP, recherche web.
- Ajout : moteur de templates Starlark et `clotr templates test`.
- Ajout : sessions, mémoire partagée, preuves, vérification des constats.
- Ajout : binaires, paquets `.deb`/`.rpm`, formule Homebrew.
