# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versionnement : [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

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
