# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versionnement : [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

## [0.1.0] - 2026-10-10

### Ajouté
- Agent CLI en lecture seule : planner, sous-agents concurrents, synthèse Markdown ou JSON.
- Découverte des modèles sur des endpoints OpenAI-compatibles, routage par rôle avec fallback, politique souveraine et suivi de budget.
- Outils Kubernetes, fichiers locaux et serveurs MCP ; recherche web optionnelle.
- Moteur de templates : cibles décrites en YAML et en scripts Starlark (découverte, outils), primitives HTTP et SSH en lecture seule, tests de templates (`clotr templates test`). Aucun template fourni.
- Sessions multi-tours avec mémoire partagée, preuves archivées citées dans les rapports et vérification des constats majeurs.
- Binaires statiques linux et darwin (amd64, arm64), paquets `.deb` et `.rpm` (amd64, arm64) et formule Homebrew.
