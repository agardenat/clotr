# clotr

Agent CLI d'analyse d'infrastructure, en lecture seule par défaut, multi-modèles sur endpoints OpenAI-compatibles. Binaire Go statique.

## Installation

```sh
brew install agardenat/clotr/clotr
```

```sh
sudo apt install ./clotr_<version>_amd64.deb
```

```sh
sudo dnf install ./clotr-<version>-1.x86_64.rpm
```

Windows : `clotr.exe` de `clotr_<version>_windows_amd64.zip` dans le `PATH`.

Releases : `.deb`, `.rpm`, archives linux/darwin/windows (amd64, arm64), `SHA256SUMS`.

## Build

Go ≥ 1.27.

```sh
make build
```

```sh
make test
```

```sh
make cross
```

```sh
make dist
```

## Release

1. Ajouter la section `## [X.Y.Z] - AAAA-MM-JJ` dans [CHANGELOG.md](CHANGELOG.md).
2. Committer, tagger, pousser :

```sh
git tag vX.Y.Z
```

```sh
git push origin main vX.Y.Z
```

Le workflow `release` publie la release GitHub (notes = section du CHANGELOG) et met à jour le tap Homebrew (`HOMEBREW_TAP_TOKEN`).

## Configuration

`--config`, puis `$CLOTR_CONFIG`, puis `~/.config/clotr/config.yaml` (`%AppData%\clotr\config.yaml` sous Windows). Référence : [clotr.example.yaml](clotr.example.yaml).

- `providers`, `profiles`, `roles`, `routing` : endpoints, capacités des modèles, rôles, politique souveraine.
- `limits`, `catalog`, `audit`, `sessions` : limites d'exécution, cache, répertoires.
- `language`, `ui_language` : langue des rapports, langue de l'interface.
- `instances`, `params`, `templates` : cibles et paramètres par défaut.
- `clients/<client>.yaml` : instances d'un client, projets, `vars`, `params`, `tunnel`, `access`, `compliance`.
- `local/` : surcharge personnelle non versionnée ; invalide, ignorée et signalée pour la mise à jour de la configuration.
- `vault` : adresse, connexion OIDC, cache d'identifiants.
- `secrets` : sources de secrets globales, instances de templates `kind: secrets` chargées à chaque démarrage.
- `mcp` : serveurs MCP (stdio, HTTP, SSE, OAuth, passerelle `servers`).
- `web_search`, `report_export`, `diagram`, `report_models`, `tickets`, `cve`, `compliance`, `startup`, `min_version`.

## Commandes

| Commande | Effet |
|---|---|
| `clotr models` | catalogue et routage par rôle |
| `clotr tools` | outils disponibles |
| `clotr templates [nom]` | templates et instances chargés |
| `clotr templates test <nom>` | tests Starlark d'un template |
| `clotr plan "<demande>"` | plan sans exécution |
| `clotr run "<demande>"` | plan, sous-agents, rapport |
| `clotr run -s <session\|last> "<demande>"` | nouveau tour d'une session |
| `clotr cve <CVE\|GHSA>… [--force] [--json]` | fiche CVE seule, sources officielles et cache partagé avec `run --cve`, `--force` la rédige de nouveau |
| `clotr sessions` | liste des sessions |
| `clotr sessions commands [--all]` | commandes soumises à l'utilisateur dans les audits, rejouées avec l'analyse de lecture seule et les templates actuels |
| `clotr session <nom\|last>` | rapport d'un tour, `--evidence`, `--synthesize`, `--export` |
| `clotr export <fichier.md\|->` | Markdown vers `.docx` ou `.pdf` |
| `clotr sync` | exécution des templates de démarrage |
| `clotr secrets test <ref>` | lecture d'une référence de secret, longueur et compte déduit, jamais la valeur |
| `clotr secrets check [cible…]` | résolution sans saisie des identifiants de Vault, des sources, tunnels et instances des cibles, code retour 1 si une saisie serait nécessaire |

## Options de `run`

| Option | Effet |
|---|---|
| `-t`, `-x` | inclusion, exclusion de groupes d'outils, instances, clients, projets |
| `-m role=provider/model` | modèle forcé pour un rôle |
| `--sovereign any\|prefer\|require`, `--confidential` | politique souveraine |
| `--access read\|exec\|create` | niveau d'accès |
| `--pending` | avec `-s`, validation et exécution des commandes mises en attente par un run sans terminal, rapport mis à jour |
| `--lang`, `--ui-lang` | langue du rapport, de l'interface |
| `--web yes\|no` | recherche web |
| `-o`, `--json`, `--raw`, `-q`, `--plain` | sortie et progression |
| `--with-evidence` | annexe complète des preuves citées |
| `--export docx\|pdf`, `--export-template` | export du rapport |
| `--direct[=<rôle>]` | réponse par un seul agent |
| `--chat` | conversation plein écran |
| `--incident`, `--panic` | investigation d'incident, journal en direct |
| `--change` (`--demande`) | demande de changement |
| `--upgrade` (`--modop`) | mode opératoire de mise à jour |
| `--watch` (`--suivi`), `--watch-for`, `--watch-every` | suivi en direct, minuté par `--watch-for` ou par une durée dans la demande |
| `--minutes` (`--cr`) | compte rendu de réunion |
| `--cve[="<sujet>"]` | exposition à des CVE, GHSA ou compromissions |
| `--dat iac\|drift\|clean` | document d'architecture technique |
| `--diagram iac\|drift\|clean` | schéma d'architecture |
| `--ticket [id]` | ticket de la demande |
| `--max-agents`, `--max-tasks`, `--max-steps` | limites du run |

## Fonctions

### Exécution

- Catalogue des modèles par `GET /models`, capacités par profils ou `/model/info` LiteLLM, cache.
- Routage par rôle (`tier`, outils, contexte), poids et priorité, chaîne de fallback.
- Politique souveraine `any`, `prefer`, `require`.
- Planner en tâches JSON avec dépendances, sous-agents concurrents, synthèse Markdown.
- Arrêt d'une tâche sur absence de progression (`stall_steps`), `max_steps` en plafond.
- Contrôle des preuves dans les réponses, vérification des constats CRITIQUE et MAJEUR.
- Relances sur 408/425/429/5xx, `persistent_retry`, `max_requests_per_minute` partagé sur le poste.
- `reasoning_effort` par rôle et par modèle, abaissé si la sortie est épuisée.
- Streaming SSE, `idle_timeout`, `request_timeout`.
- Budget par provider (`/key/info` LiteLLM), coût par run.
- Historique des agents raccourci selon le contexte.
- Premier Ctrl-C : conclusion ; second : interruption.

### Sessions et preuves

- Session par `run` avec tours, mémoire, rapport, plan, résultats, audit.
- Nom de session `<client>-<mot>-<adjectif>-<nom>`.
- Sortie complète de chaque outil archivée en preuve (`E001`…), citée dans le rapport.
- `evidence_read`, `evidence_search` sur les preuves de tous les tours.
- Mémoire partagée `memory_write`, `memory_search`.
- Rapports nommés `<PROJET>_<CLIENT>_CVE-…_<AAAAMMJJ>` (idem `DAT`, `DIAGRAM`, `CR`), projet(s) du périmètre en tête du titre du document.
- Audit JSONL par tour.

### Modes

- Incident : tri `t0`, `cause_report` en direct, modèle `incident`.
- Panique : incident avec journal des preuves et constats.
- Demande de changement : état actuel, source IaC, modèle `change`.
- Mise à jour : documentation de l'éditeur, prérequis mesurés, modèle `upgrade`.
- Suivi : sources déclarées par `watch_source`, capture sans modèle, modèle `watch`.
- Relevés système : sondes `system`, `cpu`, `memory`, `disk`, `network`, `connections`, attribution de l'iowait.
- Compte rendu de réunion : transcription, décisions, actions, suivi du compte rendu précédent, modèle `minutes`.
- CVE : fiches depuis les sources officielles, cache des fiches (établi aussi par `clotr cve` sur les distributions de tous les clients), `cve_report` par actif, récapitulatif des positifs (.md, et document client au format de `--export`).
- DAT et schéma : plan fixe par instance, variantes `iac`, `drift`, `clean`, rendu drawio et PNG.
- Réponse directe : un agent, sans planner.
- Conversation : écran plein terminal, un tour par échange.
- Tickets : ticket de la demande, tickets liés, commentaire interne.

### Templates

- Cible décrite en YAML et Starlark, chargée depuis `templates.dir`.
- Connecteurs `http`, `ssh`, `local`, `shell`, `mcp`.
- Primitives `http`, `ssh`, `mcp`, `jq`, `vault`, `crypto`, `file`, `drawio`, `parallel`, `sleep`.
- Outils génériques `ssh_list`, `ssh_read`, `ssh_tail`, `ssh_grep`, `ssh_disk`, `ssh_resolve`, `log_stats`, `ssh_exec`.
- Outils `kind: mcp` publiés depuis un serveur MCP.
- Activation d'une instance au premier appel, proposée seulement si la demande la cite.
- Identifiants par variable, Vault ou saisie, demandés avant les tâches.
- `checklist`, `modes`, `keywords`, `companions`, `hints`, `min_version`, `architecture`.
- Kinds `startup` (`git.sync`), `tickets`, `secrets`, `document`, `diagram`.
- Tests sans réseau par `clotr templates test`.

### Accès

- Niveaux `read`, `exec`, `create` par client ou par `--access`.
- `exec` : motifs `commands`, analyse de lecture seule, confirmation sur le terminal.
- Sans terminal : commande non reconnue mise en attente (`pending.json`, section du rapport), reprise par `run -s <session> --pending`.
- `create` : ressources éphémères suivies et supprimées en fin de tour.
- `ssh_paths` autorisés et interdits, valeurs sensibles masquées.
- `known_hosts` propre à clotr, `accept-new`, `accept-changed`, `strict`, `insecure`.
- Tunnel SSH par client ou projet avec proxy SOCKS5 local.

### Intégrité

- Activée par `/etc/clotr/allowed_signers` (format `ssh-keygen` allowed signers), fichier et répertoires parents à root, non modifiables par le groupe ni les autres ; binaires de release, Linux et macOS.
- Clés matérielles seulement (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`), présence exigée, options `namespaces` et `verify-required`.
- Templates, modules Starlark, ressources de document, tests de template et configuration partagée lus seulement s'ils sont identiques au HEAD de leur clone, commit signé par une clé de `allowed_signers` ; sinon arrêt.
- Signature et objets git vérifiés par clotr, sans `git verify-commit` ni configuration git de l'utilisateur.
- Exécutable clotr et répertoires parents à root exigés sous Linux ; sous macOS (Homebrew), avertissement, templates et configuration contrôlés, exécutable non contrôlé.
- Surcharge `local/` limitée à `language`, `ui_language`, `params`, `secrets`, `instances` (`name`, `template`, `enabled`, `params`, `describes`), `mcp` (`name`, `enabled`, `servers` : `alias`, `name`, `enabled`, `auth`) ; client : `label`, `aliases`, `context`, `vars`, `params`, `cve_sources`, `instances`, `projects`.
- `clotr templates test --dir` exempté (réseau, Vault, environnement et fichiers simulés).

### Secrets et authentification

- Vault KV v1/v2 avec la configuration du poste, connexion OIDC au démarrage.
- Identifiants saisis conservés dans `cubbyhole/`.
- Références `<source>:<ref>` vers une source de la section `secrets` dans tout champ `*_vault`.
- `user_vault` : compte lu dans une référence, à côté de `password_vault`.
- Clé SSH `key_vault` : champ `#champ` de la référence, sinon `key_field` du connecteur ou du tunnel, sinon `private_key`.
- `auth.oauth2` client credentials ou password sur les connecteurs `http`.
- `proxy_auth` : proxy authentifié sur les connecteurs `http`.
- OAuth des serveurs MCP avec enregistrement dynamique.
- Sans terminal ou en arrière-plan : aucune saisie ni connexion par navigateur, échec immédiat.

### Autres

- Recherche web par serveur MCP ou modèle à recherche native, politique par client.
- `dns_resolve` depuis le poste.
- Export `.docx`/`.pdf` par template `kind: document` et LibreOffice.
- Types de plateforme confidentiels (`compliance`).
- Interface en français ou en anglais (`internal/i18n`).
- Rapport mis en forme dans le terminal (glamour).

## Limites

- Pas d'anonymisation avant envoi à un modèle non souverain (`Boundary` = `Passthrough`).
- Mémoire partagée limitée à une session.
- Tâches non relancées après un échec.
- SSH : clés avec passphrase et agent SSH non supportés.
- Intégrité : pas de contrôle sous Windows ; retour à un commit signé plus ancien non détecté ; alias ou `PATH` du shell vers un autre exécutable hors de portée.
