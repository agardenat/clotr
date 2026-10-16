# clotr

Agent CLI d'analyse d'infrastructure en lecture seule (fichiers de configuration, serveurs MCP et toute cible décrite par un template), exécuté sans interaction une fois lancé. Les modèles sont découverts sur un ou plusieurs endpoints OpenAI-compatibles, puis chaque sous-agent reçoit le modèle adapté à son rôle.

Binaire Go statique, sans dépendance d'exécution.

## Fonctionnement

1. **Catalogue** : `GET {base_url}/models` sur chaque provider, en parallèle. Les capacités (tier, contexte, tool-calling) viennent des `profiles` de la config, ou de `/model/info` si le provider est un proxy LiteLLM (`model_info: true`). Le résultat est mis en cache (`~/.cache/clotr/catalog.json`, TTL `catalog.cache_ttl`).
2. **Planner** (rôle `planner`) : découpe la demande en tâches JSON `{id, role, goal, tools, depends_on}`. Le plan est validé (rôles, outils, dépendances, cycles), avec une nouvelle tentative si le plan est invalide. Une dépendance entre deux tâches du même rôle est retirée (seule une analyse attend des collectes) : la tâche concernée démarre tout de suite et son objectif précise qu'elle ne reçoit pas ces résultats (audit `plan_deps_dropped`). Pour une investigation, le planner découpe par périmètre disjoint (cible, hôte, ressource, composant) et non par type de donnée sur un même composant, chaque objectif nomme les ressources dont la tâche a la charge, et la localisation d'une cible à retrouver reste dans la tâche qui l'investigue.
3. **Sous-agents** : une goroutine par tâche. Une tâche démarre dès que ses dépendances sont terminées, et reçoit leurs résultats en entrée. La concurrence est bornée globalement (`limits.max_agents`) et par provider (`max_concurrency`). Chaque agent exécute une boucle de tool-calling, et les appels d'outils d'un même tour sont lancés en parallèle.
4. **Durée des tâches** : une tâche n'est pas arrêtée parce qu'elle dure, mais parce qu'elle ne progresse plus. Une étape progresse si elle lance au moins un appel d'outil nouveau (outil et paramètres jamais utilisés dans la tâche). Après `limits.stall_steps` étapes sans appel nouveau (défaut 3), l'agent conclut avec ce qu'il a, et la tâche est marquée « plus de progression ». `limits.max_steps` (défaut 100) n'est qu'un plafond de sécurité contre les boucles. `limits.agent_timeout` est désactivé par défaut ; s'il est réglé, l'agent conclut avant ce délai, avec une réserve de `min(5 min, request_timeout)` pour la conclusion. Seuls les appels individuels restent bornés : `request_timeout` pour un appel trop long, `idle_timeout` pour un flux muet. Une tâche arrêtée par `max_steps` ou `agent_timeout` est poursuivie par une suite (`tN.2`, `limits.continuations`, défaut 1) qui reçoit le résultat partiel ; pas de suite après un arrêt pour absence de progression. Une tâche encore limitée après ses suites reçoit un gap « investigation incomplète ».
5. **Contrôle des preuves** (par clotr) : la réponse d'un sous-agent doit contenir `findings`, `evidence` ou `gaps`, et chaque constat citer dans son texte une preuve existante ; sinon la réponse est renvoyée à l'agent (deux reprises au plus). Un constat encore sans preuve est marqué « [NON PROUVÉ] ». Un appel d'outil écrit dans le texte au format harmony (`to=functions.<outil>{…}`) est exécuté comme un appel d'outil.
6. **Vérification** (`limits.verify_findings`, activée par défaut) : pour chaque tâche, un agent de vérification (rôle `analyst`, sinon le premier rôle outillé) relit, avec `evidence_read` et `evidence_search` uniquement, les preuves citées par les constats CRITIQUE et MAJEUR. Il les marque « [VÉRIFIÉ] », « [PARTIEL : raison] » ou « [NON ÉTAYÉ : raison] ». Les verdicts partiels et négatifs sont enregistrés en mémoire de session. Le synthesizer ne reprend un constat non étayé que dans les points non vérifiés.
7. **Synthesizer** : produit le rapport Markdown à partir des résultats `{findings, evidence, gaps}`, avec une mise en page fixe (conclusion en puces, constats numérotés par sévérité, détail par périmètre, points non vérifiés, limites, recommandations) sauf si la demande impose une forme. Une ligne du rapport qui ne s'appuie que sur une note de mémoire, sans preuve existante, est suffixée « ⚠ non vérifié ».

Une tâche en échec n'interrompt pas les autres. Elle apparaît dans le rapport comme point non vérifié.

### Routage

Pour chaque rôle, `roles.<nom>` définit `tier` minimal (`fast` < `balanced` < `deep`), `tools` (tool-calling requis) et `min_context`. Chaque modèle reçoit un score égal au `weight` de son provider plus la `priority` de son profil. Les modèles éligibles sont triés par tier croissant (le plus léger suffisant d'abord), puis par score décroissant, puis par ordre des providers et par nom.

Chaque modèle porte aussi un indicateur souverain : `sovereign` du provider, surchargeable par profil. La politique souveraine se règle à trois niveaux, du moins au plus prioritaire : `routing.sovereign`, puis `roles.<nom>.sovereign`, puis `--sovereign`. Elle prend l'une de ces valeurs :
- `any` (défaut) : sans effet sur le tri ;
- `prefer` : les modèles souverains passent en tête, quel que soit leur tier, et les autres restent en fallback ;
- `require` : seuls les modèles souverains sont éligibles. Un `--model` non souverain est alors refusé.

Cette liste ordonnée sert aussi de chaîne de fallback :
- sur 408/425/429/5xx ou une erreur réseau, le même modèle est retenté une fois (backoff, ou `Retry-After` plafonné à 30 s), puis l'appel bascule sur le suivant. Le modèle reste candidat pour les appels suivants, y compris en cas de 429 quota. Si tous les candidats sont en échec temporaire, un second tour a lieu après 30 s ; avec `persistent_retry: true` sur le provider d'un modèle qui a échoué ainsi, les tours continuent jusqu'à une réponse ou une interruption (Ctrl-C), avec une pause doublée à chaque tour de 30 s à 5 min (`Retry-After` respecté dans cette limite) ;
- sur 400/404/422, on bascule directement ;
- sur 401/403, l'exécution s'arrête ;
- sur 403 lié au quota ou au budget (corps contenant quota, budget ou insufficient), la bascule est immédiate ;
- sur 404, la bascule est immédiate et le modèle est écarté pour le reste du run ;
- sortie épuisée sans réponse (limite de sortie atteinte pendant le raisonnement, sans texte ni appel d'outil) : bascule sur un modèle disponible qui n'a pas encore échoué ainsi pour cette étape ; s'il n'y en a plus, l'appel échoue aussitôt, sans demande de suite ni nouvel essai, qui reproduiraient le même raisonnement. Le `max_tokens` envoyé figure dans l'événement `llm_call` de l'audit.

Les profils sont évalués dans l'ordre : le premier glob qui correspond à `model` ou `provider/model` (insensible à la casse) s'applique. `exclude: true` retire le modèle du catalogue. Un modèle sans profil reçoit `tier=balanced` et `tools=false`. Un profil final `match: "*"` avec `exclude: true` transforme la liste en liste blanche.

## Sessions

Chaque `run` ouvre une session au nom aléatoire (par exemple `cosmic-walrus`) dans `sessions.dir` (défaut `~/.local/state/clotr/sessions`) :

```
<session>/
  session.json        méta, politique souveraine et confidentialité, liste des tours (demande, statut, modèles, coût)
  memory.json         mémoire partagée cumulée de la session
  report.md           dernier rapport
  turns/001/          request.txt, plan.json, results.json, report.md, summary.json, audit.jsonl
    evidence/         E001.txt… (sortie complète de chaque appel d'outil), index.json
```

`clotr run -s <session|last> "…"` ajoute un tour à une session existante pour l'affiner. Le nouveau tour démarre avec :
- la mémoire de la session ;
- les demandes précédentes et le dernier rapport, transmis au planner et au synthesizer.

Le planner ne planifie que ce qui manque. Le synthesizer répond à la nouvelle demande, ou produit le rapport complet mis à jour si c'est ce qui est demandé.

`clotr session <nom|last> --synthesize [--turn N] [-o fichier]` régénère le rapport d'un tour à partir de son `results.json`, sans relancer les tâches (par exemple après un rapport coupé ou une synthèse en échec). Seuls les connecteurs du tour d'origine sont préparés (même filtre `-t`, modifiable avec `-t`), car le contexte des templates sert à la synthèse. Aucune instance n'est activée : la synthèse n'appelle pas d'outil.

Une session ouverte avec `--confidential` (ou `--sovereign require`) reste confidentielle pour tous ses tours. Un `--sovereign any` ou `prefer` y est refusé.

```sh
clotr run "état du cluster prod"
```

```sh
clotr run -s last "détaille les pods en CrashLoopBackOff"
```

```sh
clotr sessions
```

```sh
clotr session cosmic-walrus --turn 1
```

## Preuves

Pendant un `run`, chaque sortie d'outil (hors mémoire) est archivée en entier dans `turns/NNN/evidence/` sous un identifiant : `E001`, `E002`… au premier tour, `E2.001`… aux tours suivants. Le fichier contient la tâche, l'outil, les arguments, l'heure et la sortie telle que le modèle l'a reçue.

- L'identifiant est placé en tête de la sortie transmise au modèle.
- Les sous-agents citent cet identifiant dans `evidence` et `findings`, et le synthesizer le reprend dans le rapport.
- clotr ajoute ensuite une annexe « preuves citées » : outil, arguments et fichier de chaque identifiant cité. Un identifiant absent de l'archive y est signalé.

```sh
clotr session <nom|last> --evidence E012
```

`--with-evidence` (`run`, `session`, `session --synthesize`) remplace cette annexe par la sortie complète de chaque preuve citée, sans troncature. Le `report.md` de la session n'est pas modifié : l'annexe complète est produite à l'affichage depuis l'archive, et peut donc être demandée après coup, sans appel au modèle. Le rapport est alors en Markdown brut, et `-o` est l'usage naturel : les preuves citées pèsent couramment dix fois le rapport. Ce sont des sorties brutes (hôtes, adresses, comptes, extraits de configuration) : un rapport complet est plus sensible que le rapport seul.

```sh
clotr session last --with-evidence -o rapport-complet.md
```

Les preuves de tous les tours d'une session restent consultables : `evidence_search` les retrouve (termes sur l'outil et ses arguments, filtre optionnel sur le contenu, heure de collecte), et l'annexe d'un rapport résout aussi les identifiants des tours précédents. Pendant un run, les agents relisent une preuve avec l'outil `evidence_read` (`id`, puis `pattern` pour garder et `exclude` pour retirer des lignes, en expressions régulières RE2, ou `offset`/`lines`), sans refaire l'appel distant.

### Historique allégé

Chaque étape d'un agent renvoie toute sa conversation au modèle. Pour éviter que le contexte enfle à chaque appel d'outil (plus de 100 000 tokens sur les longues tâches), les sorties d'outils plus anciennes que `limits.history_keep_steps` étapes (défaut 2) sont raccourcies à `limits.history_tool_chars` caractères (défaut 1500), suivies de l'identifiant de preuve à relire avec `evidence_read`. Les agents notent au fil de l'eau avec `memory_write` les faits nécessaires à leur conclusion, et ces notes leur sont rendues dans le message de conclusion. `history_tool_chars: 0` désactive le raccourcissement. Mesuré sur un run réel de 11 tâches : 62 % de caractères de sorties d'outils renvoyés en moins.

## Mémoire partagée

Pendant un run, les agents partagent une mémoire interne :
- `memory_write` enregistre un fait (`key`, `content`, `tags`) ; réutiliser la même `key` met l'entrée à jour ;
- `memory_search` interroge la mémoire par mots-clés et tags.

Ces deux outils sont ajoutés à chaque tâche outillée. Les constats de chaque tâche terminée y sont versés automatiquement, et les notes (`kind: note`) sont transmises au synthesizer. La mémoire n'écrit que dans le processus clotr, jamais sur l'infrastructure.

Chaque entrée garde la tâche, le modèle et l'indicateur souverain de son auteur. À la fin du `run`, stderr affiche le nombre d'entrées, dont les souveraines, ainsi que le nombre d'entrées souveraines lues via `memory_search` par un modèle non souverain. La mémoire est sauvegardée dans le `memory.json` de la session, puis rechargée au tour suivant.

## Résolution DNS

L'outil intégré `dns_resolve` résout un nom depuis le poste qui exécute clotr, par le résolveur du système : nom canonique (CNAME) et adresses IPv4/IPv6. Il est proposé à toutes les tâches, et `-x dns` l'écarte. Pour un incident d'accès à une URL (inaccessible, erreur TLS, authentification inattendue), la consigne des agents est de vérifier d'abord la chaîne d'accès : résoudre le nom et comparer l'IP obtenue au point d'entrée attendu (load balancer de l'ingress, proxy, VM) ; une IP inattendue est signalée comme cause. Le résultat reflète la vue DNS du poste : un nom résolu seulement par le DNS interne d'un autre réseau apparaît comme inexistant. Pour la vue d'un réseau joint par un proxy, `<instance>_ssh_resolve` (templates SSH) résout le nom sur un hôte de ce réseau ; la consigne des agents le cite quand une instance le propose.

## Recherche web

Les agents doivent rester factuels : chaque affirmation repose sur une preuve `[Exxx]`, et aucune valeur par défaut, aucun comportement de produit ni aucune signification de message n'est supposé. En cas de doute, ils cherchent sur le web si la recherche est autorisée pour le run. Sinon, le point va dans les non vérifiés.

- `web_search.mcp` désigne le serveur MCP qui fournit la recherche. Ce serveur n'est connecté que si la recherche est autorisée, même avec `-t`. Sans `web_search.model`, `-x mcp_<serveur>` (ou `-x mcp`) l'écarte comme `--web no`.
- `web_search.model` (`provider/modèle`) et `web_search.api` (`messages` ou `responses`) désignent un modèle doté d'une recherche web native, interrogé par l'outil `web_search`. Les agents gardent leur modèle en `/chat/completions` : l'outil pose la question au modèle de recherche par l'API indiquée (`/messages` avec l'outil serveur `web_search_20250305`, ou `/responses` avec l'outil `web_search`) et renvoie sa réponse, les URL citées, les requêtes lancées, le nombre de recherches et les tokens consommés. Le modèle sert quand le serveur MCP n'est pas utilisable : `web_search.mcp` vide, serveur désactivé (`enabled: false`) ou exclu par `-x`. La politique, `--web` et la règle des sessions confidentielles s'appliquent de la même façon. La question part chez le fournisseur du modèle : les consignes sur les identifiants internes valent aussi pour elle.
- `web_search.policy` : `ask` (défaut, question au démarrage de `run` et `plan`, refus sans terminal), `allow` ou `deny`. `--web yes|no` l'emporte sur la politique pour un run.
- Une session confidentielle n'autorise jamais la recherche web (`--web yes` y est refusé).
- Les outils web sont ajoutés à chaque tâche outillée. Les consignes demandent de privilégier la documentation officielle de l'éditeur, et de ne jamais mettre d'identifiant interne (hôte, IP, cluster, compte, domaine) dans les requêtes.
- Chaque page lue est archivée comme preuve, comme toute sortie d'outil.

## Passage souverain → non souverain

Tout ce qu'un agent envoie à un modèle non souverain passe par un point unique de l'agent, l'interface `agent.Boundary`, qui couvre :
- le prompt ;
- les résultats d'outils ;
- les résultats de dépendances ;
- le contenu lu dans la mémoire.

`Outbound` transforme les messages sortants, `Inbound` la réponse, arguments d'appels d'outils compris. La mémoire stocke la version souveraine, en clair. L'implémentation fournie, `Passthrough`, ne transforme rien : c'est le point d'insertion d'une anonymisation.

## Templates

Un template décrit un type de cible ; une instance de la config l'applique à un environnement réel. Le binaire n'embarque aucun template : il charge à chaque exécution les fichiers `*.yaml` de `templates.dir` (défaut `~/.config/clotr/templates`) et les scripts qu'ils référencent. Deux fichiers portant le même `name` sont refusés, et un fichier invalide est ignoré avec un avertissement. `clotr templates` liste les templates chargés et les instances, `clotr templates <nom>` affiche le YAML et le script.

Le moteur ne connaît aucun produit. Toute la logique propre à une cible (appels d'API, authentification, découverte, interprétation des réponses, outils) est écrite dans le script du template, en [Starlark](https://github.com/google/starlark-go/blob/master/doc/spec.md). Le moteur fournit des primitives génériques et applique les garde-fous de lecture seule. Les templates ne sont pas fournis avec l'outil ; `templates.dir` peut être un clone d'un dépôt de templates.

### Format

- `keywords` : termes qui, présents dans une demande, font proposer l'instance aux agents (en plus du nom de l'instance, du template et des cibles), voir Activation d'une instance ;
- `params` : paramètres de l'instance, typés (`string`, `url`, `int`, `bool`, `env`, `path`, `enum`, `list` avec `item`), avec `required` et `default`. Un paramètre inconnu est rejeté ;
- `connectors` : connexions nommées, dont les options sont rendues avec les paramètres (`{{.proxy_url}}`) :
  - `http` : `base_url`, `methods` (défaut `[GET]`), `allow` (expressions régulières sur le chemin), `headers`, `auth` (`user_env`, `password_env`, `password_vault`, `label` : authentification basic, saisie sur le terminal si les variables sont vides, voir Secrets Vault), `deny` (expressions régulières de chemins refusés, voir Garde-fous), `proxy`, `proxy_port`, `verify_tls`, `ca_file`, `timeout` (défaut 60s), `max_bytes` (défaut 32 Mio) ;
  - `ssh` (un seul par template) : `user`, `key`, `key_vault` (clé privée lue dans un secret Vault, `chemin[#champ]`, champ par défaut `private_key`), `auth` (`user_env`, `password_env`, `password_vault`, `label` : mot de passe saisi sur le terminal seulement s'il est nécessaire, voir Outils SSH), `port`, `proxy`, `proxy_port`, `host_key`, `sudo`, `max_conns`, `known_hosts` ;
- `targets` : cibles statiques. `foreach: <paramètre list>` crée une cible par élément ; un champ vide de l'élément hérite du paramètre de même nom. Les attributs `ssh_user`, `ssh_key_path`, `ssh_key_vault` et `ssh_port` d'une cible remplacent ceux du connecteur ssh ;
- `script` : fichier Starlark, chemin relatif au YAML ;
- `files`, `env` : fichiers et variables d'environnement que le script peut lire ; les chemins de `files` sont rendus avec les paramètres (`"{{.config_path}}"`) ;
- `tools` : outils génériques du moteur (`inventory`, `ssh_list`, `ssh_read`, `ssh_tail`, `ssh_grep`, `ssh_disk`, `ssh_resolve`, `log_stats`), avec `name` et `description` optionnels, et `when` : condition rendue avec les paramètres (`"{{.ssh}}"`), l'outil n'est créé que si elle vaut vrai (vide = faux, valeur non booléenne refusée) ;
- `companions` : outils ajoutés d'office à toute tâche qui utilise un outil de l'instance ;
- `ssh_paths` : `allow` et `deny` (globs, `**` récursif), rendus avec les paramètres (`"{{.data_dir}}/logs/**"`) : une entrée rendue vide est ignorée (`"{{if .data_dir}}…{{end}}"`), une entrée rendue doit rester sans `..` et, dans `allow`, absolue ;
- `hints` : consignes transmises au planner et aux agents.

Les outils sont préfixés par le nom de l'instance (`<instance>_<outil>`).

```yaml
instances:
  - name: prod
    template: mon-template
    params:
      api_url: https://api.example.com/
      proxy_url: socks5h://localhost:1080
```

### Script

Le script définit `discover(ctx)` et déclare ses outils au chargement :

```python
def discover(ctx):
    nodes = http.request("api", "GET", "/v1/nodes", jq = ".nodes").data[0]
    return {"targets": [{
        "name": n["name"],
        "kind": "node",
        "status": n["state"],
        "summary": "%d services" % len(n["services"]),
        "hosts": [{"name": n["fqdn"], "ip": n["ip"]}],
    } for n in nodes]}

def node_status(args):
    t = instance.target(args["target"])
    return http.request("api", "GET", "/v1/nodes/" + t["name"]).body

tool(
    name = "node_status",
    description = "État d'un nœud",
    schema = {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
    fn = node_status,
)
```

`discover` reçoit `ctx.params` et `ctx.targets` (cibles statiques). Il renvoie :
- `targets` : `name`, `kind`, `status`, `error`, `summary` (ligne d'environnement), `attrs`, `hosts` (`name`, `ip`, `group`, `state`, `roles`, `attrs`), `networks` (plages CIDR dont toute IP est acceptée par les outils SSH, même hors de `hosts`) et `data` (libre). Une cible avec `error` est retirée pour le run ;
- `lines` : lignes d'environnement globales ;
- `warnings` et `data` (libre).

`description` peut être une fonction, appelée après la découverte. Un outil renvoie un texte, ou une valeur convertie en JSON. `fail()` renvoie une erreur à l'agent.

| Primitive | Rôle |
|---|---|
| `http.request(conn, method, path, base=, query=, json=, body=, headers=, jq=, max_bytes=, tls=, proxy=)` | requête via un connecteur `http` ; renvoie `status`, `headers`, `body`, `url` et `data` (résultats de `jq`). `base` remplace `base_url`, `proxy` le proxy du connecteur, `tls` (`ca`, `cert`, `key` en PEM, `insecure`) l'autorité de certification et ajoute un certificat client, pour cet appel |
| `http.snippet(text, max)` | résumé d'un corps de réponse (titre si page HTML) |
| `ssh.list`, `ssh.read`, `ssh.tail` (`filter`), `ssh.grep`, `ssh.disk`, `ssh.stat_tail`, `ssh.recent` | commandes SSH fixes sur un hôte de l'inventaire ; `ssh.format(res)` met en forme un résultat, `ssh.allowed(path)` teste `ssh_paths` |
| `jq(expr, data)` | filtre JSON exécuté en Go ; renvoie la liste des résultats |
| `json`, `yaml`, `time`, `math`, `re`, `url`, `base64` | encodage (`yaml.decode`, `yaml.encode`), dates et durées, calcul, expressions régulières, URL |
| `crypto.sign(key, msg)`, `crypto.key_type(key)` | signature ed25519 (graine base64 ou PKCS#8) ou RSA SHA-256 |
| `file.read`, `file.exists`, `env` | fichiers et variables déclarés dans `files` et `env` |
| `parallel(fn, items, limit=4)` | exécution concurrente ; `value` ou `error` par élément |
| `catch(fn, *args)` | appel protégé ; `value` ou `error` |
| `instance.name`, `instance.params`, `instance.inventory()`, `instance.target(nom)`, `instance.find_host(hôte, target=)`, `instance.memo(clé, fn)` | instance courante, inventaire, cache par instance |
| `sprintf`, `compact_json`, `logstats`, `redact` | formatage à la Go, JSON compact, statistiques de log, masquage des secrets |
| `load("module.star", …)` | bibliothèque `.star` du même répertoire |

### Garde-fous

- `http` : la méthode doit figurer dans `methods`, et toute méthode autre que GET ou HEAD exige une liste `allow`. Le chemin est absolu et sans `..`. Un chemin qui contient `keytab`, `secret`, `password` ou `token` est refusé, sauf si le connecteur déclare `deny` : ses expressions régulières remplacent alors cette liste (`deny: []` la retire, le script devient seul responsable des données sensibles). La réponse est plafonnée à `max_bytes` (512 Mio au plus). Chaque requête est tracée dans l'audit (`http_call`).
- `ssh` : voir Outils SSH.
- Le script n'accède au disque, au réseau et à l'environnement qu'à travers ces primitives. Il est interrompu avec le run et soumis à un plafond de pas d'exécution.

### Tests

`clotr templates test <nom> [--dir <répertoire>]` exécute les fonctions `test_*` de `<script>_test.star`, sans réseau :
- `template.instance(params=, http=, ssh=, env=, files=, creds=, now=)` crée une instance avec un faux serveur HTTP (dict `"MÉTHODE /chemin"` → réponse, ou fonction) et un faux SSH (fonction `(hôte, commande)`) ;
- `inst.discover()`, `inst.call(outil, args)`, `inst.error(outil, args)`, `inst.environment()`, `inst.tools()`, `inst.requests()` (requêtes reçues, avec `proxy` et `tls` passés à l'appel), `inst.commands()`, `inst.fn(nom, *args)` ;
- `assert.eq`, `assert.true`, `assert.contains`, `assert.not_contains`, `assert.fails`.

### Activation d'une instance

Au démarrage d'un run, une instance est seulement déclarée : ses outils et son environnement sont transmis au planner, sans identifiants ni appel réseau. L'environnement reprend l'inventaire en cache du même template, script et paramètres, quel que soit son âge. Sans cache, `discover` est exécuté hors ligne (10 s au plus, `http.request` et `ssh.*` refusés) : son résultat est retenu s'il n'a tenté aucun accès réseau, ce qui donne dès le départ les cibles et plages d'un template qui ne dépend que de ses paramètres ; sinon, les cibles statiques de la configuration. Une instance n'est activée qu'au premier appel de l'un de ses outils par une tâche. Un outil `inventory` lit l'inventaire en cache sans activer l'instance, s'il a déjà été découvert (sa date figure dans la réponse).

Une instance n'est proposée aux agents (outils et environnement) que si la demande du tour ou une demande précédente de la session la mentionne : nom de l'instance, nom du template, nom d'une cible de l'inventaire ou l'un des `keywords` du template (mot entier, sans tenir compte de la casse). Une IP comprise dans les `networks` d'une cible compte comme mention. Le nom ou un alias d'un client (voir Clients) mentionne toutes ses instances. Quand la demande nomme un client, le nom du template et les `keywords` ne suffisent plus pour les instances des autres clients ni pour celles sans client : seuls leur nom, une cible ou une IP de leurs `networks` les mentionnent. « pods en erreur sur k8s acme » propose donc l'instance k8s d'acme, pas celle d'un autre client. `-t <instance>` la force, y compris pour les tours suivants de la session (`run -s`), et une instance déjà activée dans le processus (tour précédent d'une conversation) reste proposée. Sinon, l'environnement indique seulement qu'elle existe et comment l'utiliser : une question sans rapport ne peut ni l'activer ni demander ses identifiants. Le choix est tracé dans l'audit (`instances_scope`).

À l'activation :

1. **Identifiants** des connecteurs `http` avec `auth` : `user_env`/`password_env` si les variables sont définies, puis le secret `password_vault` pour le mot de passe, sinon saisie sur le terminal (mot de passe masqué). Pendant la saisie, le tableau de progression est suspendu et la saisie se fait sur l'écran alternatif du terminal. Ctrl-C interrompt le run (en mode conversation : la conversation entière). Des identifiants vides, ou l'absence de terminal et de variables, rendent l'instance indisponible pour le run.
2. **Découverte** (`discover` du script), sauf si l'inventaire en cache (`templates.cache_dir`) a moins de `templates.cache_ttl` et correspond au même template, au même script et aux mêmes paramètres. `--refresh` force la découverte. Un inventaire incomplet (cible injoignable, avertissement) n'est pas mis en cache.
3. **Cibles injoignables** : retirées pour le run, avec un avertissement. Si aucune cible ne répond, l'instance est indisponible pour le run.

Une instance indisponible renvoie une erreur à chaque appel de ses outils, sans nouvelle saisie ni nouvelle découverte. L'activation est tracée dans l'audit (`instance_activation`).

### Secrets Vault

`password_vault` (connecteurs `http` et `ssh`, option `auth`) désigne un secret Vault sous la forme `chemin[#champ]`, comme `vault kv get -field=<champ> <chemin>` ; le champ par défaut est `password`. clotr utilise la configuration du poste, sans appeler le binaire `vault` :

- adresse : `VAULT_ADDR` (variable exportée ; une fonction ou un alias du shell n'est pas visible), sinon `vault.addr` de la configuration ;
- jeton : `VAULT_TOKEN`, sinon `~/.vault-token` écrit par `vault login` (un `token_helper` n'est pas pris en charge) ; `VAULT_NAMESPACE` si défini, sinon `vault.namespace` ;
- moteur KV v1 ou v2, détecté comme le fait `vault kv get` (`sys/internal/ui/mounts`) ;
- utilisateur non fixé (`ssh_user` vide, ou `user_env` absent pour un connecteur `http`) : lu dans le champ `username` du même secret, sinon saisi ;
- lecture seulement quand le mot de passe est nécessaire, une fois par utilisateur. Vide, l'option est ignorée. Un secret illisible (variable absente, jeton expiré, accès refusé, champ absent) est signalé sur le terminal et le mot de passe est saisi ; un mot de passe Vault refusé par SSH ou sudo est oublié et le suivant est saisi.

Le secret est lu par clotr et n'est jamais transmis aux modèles ni archivé dans les preuves. Ne pas faire lire un secret par un outil MCP : sa réponse irait au modèle et dans les preuves. Le chemin peut reprendre les `vars` du client (voir Clients).

### Outils SSH

- Commandes possibles : `find` (liste triable par taille ou date, fichiers de log récents, comptage), `head -c`, `sed -n 'A,Bp'`, `tail -n`, `tail -c` et `stat` (statistiques de log), `grep -n -E -I`, `grep -c -E -I` (comptage), `df -hP`, `du -xh`, `getent ahosts` (résolution d'un nom), `gzip -t` et `gzip -cd` (fichier `.gz`). Elles sont construites par clotr et chaque argument fourni par le modèle est quoté ;
- un fichier `.gz` est vérifié (`gzip -t`) puis décompressé vers `head`, `sed`, `tail` ou `grep` pour la lecture, la fin, la recherche, le comptage et les statistiques de log (taille décompressée) ; un fichier absent, illisible ou corrompu donne une erreur. En recherche récursive, les fichiers compressés restent ignorés comme les autres fichiers binaires ;
- `host` doit appartenir à l'inventaire de l'instance (FQDN, nom court ou IP), ou être une IP comprise dans les `networks` d'une cible. Une IP de plage présente dans la demande fait proposer l'instance ;
- `path` doit être absolu, sans `..`, couvert par `ssh_paths.allow` et par aucun `ssh_paths.deny` (keytabs, jceks, jks, clés, `*password*`…). En récursif, les motifs `deny` sont aussi passés en `--exclude` ;
- `sudo -n` est ajouté si `sudo: true`. Si sudo exige un mot de passe et que le connecteur déclare `auth`, la commande est relancée avec `sudo -S` sous `sh -c` : le mot de passe passe par l'entrée standard, jamais dans la ligne de commande, et l'hôte reste en mode mot de passe pour le run. Un mot de passe refusé est oublié et redemandé à l'appel suivant ;
- authentification : la clé d'abord (`key_vault`, sinon le fichier `key`), puis le mot de passe si la clé est absente ou refusée et que `auth` est déclaré (méthodes `password` et `keyboard-interactive`). Le mot de passe vient de `password_env`, sinon du secret `password_vault`, sinon il est saisi sur le terminal, une fois par utilisateur ; sans `user`, l'utilisateur est lu dans le champ `username` du secret (`key_vault`, sinon `password_vault`), sinon demandé. Une clé lue dans Vault reste en mémoire, sans fichier ni passphrase ;
- les valeurs de type `password=…`, `token: …` et `<name>…password…</name><value>…</value>` sont masquées dans les sorties ;
- connexions via le proxy SOCKS5 de l'instance, clé privée sans passphrase, `max_conns` sessions simultanées par instance. Aucun fichier `ssh_config` n'est lu. Un hôte qui déclare une IP est joint par son IP (le nom ne sert qu'à l'affichage et à la désignation) ; sinon par son nom, résolu par le proxy SOCKS ;
- `known_hosts` propre à clotr (`~/.local/state/clotr/known_hosts`) : `accept-new` (défaut) enregistre une clé inconnue et refuse une clé changée, `strict` refuse les hôtes inconnus, `insecure` ne vérifie pas ;
- chaque commande est tracée dans l'audit (`remote_exec` : hôte, utilisateur, commande, durée, exit, taille).

`<instance>_log_stats` lit la fin d'un log (4 Mio par défaut, 16 Mio au plus) et calcule localement :
- la taille du fichier ;
- la période couverte et le débit (lignes et octets par heure, extrapolés par jour) ;
- la répartition par niveau et par heure ;
- les loggers les plus bavards ;
- les messages les plus répétés, après normalisation des nombres, IP, UUID et identifiants hexadécimaux.

Les hôtes SSH peuvent être désignés par leur nom complet, leur IP, leur nom court ou la fin de leur nom court (`node0`) ; un nom ambigu est refusé avec la liste des candidats.

`<instance>_ssh_grep` avec `count` renvoie le nombre exact de lignes correspondantes de chaque fichier, lu en entier, sans le plafond de `max_matches` (en récursif, seuls les fichiers avec au moins une correspondance sont listés). `ssh.grep(…, count=True)` fait de même dans un script.

`<instance>_ssh_disk` donne `df`, les sous-répertoires les plus gros (`du`) et le nombre de fichiers d'un répertoire.

`<instance>_ssh_resolve` résout un nom tel que le voit un hôte : `getent ahosts` sur l'hôte (sans sudo), donc à travers le proxy de l'instance et avec le DNS du réseau de l'hôte, `/etc/hosts` compris. Il donne le nom canonique, les adresses et, si `ssh_paths` autorise `/etc/resolv.conf`, les lignes `nameserver`/`search` de l'hôte. Le nom est validé (lettres, chiffres, `-`, `_`, `.`) avant d'être passé à la commande.

## Lecture seule

Le CLI n'expose aucun outil d'écriture et n'exécute aucune commande locale. Les seules commandes distantes sont celles des outils SSH des templates, construites par clotr à partir d'une liste fixe (voir Templates).

| Groupe | Outils | Mécanisme |
|---|---|---|
| `fs` | `fs_list`, `fs_read`, `fs_grep` | chemins résolus (`EvalSymlinks`) et confinés à `files.roots`. Fichiers binaires et fichiers au-delà de `max_file_bytes` refusés. |
| `mcp_<serveur>` | outils du serveur | seuls sont exposés les outils annotés `readOnlyHint: true` ou listés dans `allow`. `deny` est prioritaire. |
| `<instance>_*` | outils du template | voir Templates : requêtes HTTP limitées par les garde-fous des connecteurs, SSH limité à des commandes fixes, aux hôtes de l'inventaire et aux chemins autorisés. |

Les sorties d'outils envoyées au modèle sont tronquées à `limits.tool_output_max_chars` ; la preuve archive la sortie complète, que `evidence_read` relit par motif ou par plage de lignes sans refaire l'appel. Les droits effectifs dépendent des comptes utilisés (connecteurs des templates, serveurs MCP), qui doivent être en lecture seule.

## Installation

```sh
brew install agardenat/clotr/clotr
```

Debian, Ubuntu :

```sh
sudo apt install ./clotr_<version>_amd64.deb
```

RHEL, Fedora, Rocky, SUSE :

```sh
sudo dnf install ./clotr-<version>-1.x86_64.rpm
```

Windows : extraire `clotr.exe` de `clotr_<version>_windows_amd64.zip` (ou `_arm64`) dans un répertoire du `PATH`.

La page Releases du dépôt publie les paquets `.deb` et `.rpm` (amd64 et arm64 ; `aarch64` pour le `.rpm`), les archives `clotr_<version>_<os>_<arch>.tar.gz` (linux et darwin, amd64 et arm64), les archives `.zip` Windows (amd64 et arm64) et `SHA256SUMS`. Les paquets installent `/usr/bin/clotr` et la documentation dans `/usr/share/doc/clotr/`, dont `clotr.example.yaml`.

## Build

Prérequis : Go ≥ 1.27.

```sh
make build
```

```sh
make test
```

```sh
make cross
```

Les binaires sont produits dans `bin/` (`clotr`, puis `clotr-<os>-<arch>` pour linux, darwin et windows, amd64 et arm64, avec `.exe` pour windows). La version est injectée par `VERSION=...`, sinon `git describe`, sinon `dev`.

`make dist` produit les archives, les bottles Homebrew (macOS arm64 et Intel étiquetés `BOTTLE_MACOS`, `ventura` par défaut, version minimale de macOS des binaires Go ; Linux arm64 et x86_64), les paquets `.deb` et `.rpm` (via nfpm, lancé avec `go run`) et `SHA256SUMS` dans `dist/`, `make formula` la formule Homebrew `dist/clotr.rb` à partir de `SHA256SUMS`, et `make notes` la section du CHANGELOG correspondant à `VERSION`.

## Release

1. Dans [CHANGELOG.md](CHANGELOG.md), renommer `[Unreleased]` en `[X.Y.Z] - AAAA-MM-JJ` et rouvrir une section `[Unreleased]` vide.
2. Committer, puis tagger et pousser :

```sh
git tag vX.Y.Z
```

```sh
git push origin main vX.Y.Z
```

Le workflow `release` vérifie que la section `[X.Y.Z]` existe dans le CHANGELOG, lance `vet` et les tests, publie la release GitHub (notes = section du CHANGELOG, archives, bottles, `SHA256SUMS`), puis pousse `Formula/clotr.rb` dans le dépôt `agardenat/homebrew-clotr`. Un tag avec suffixe (`v1.2.0-rc.1`) donne une pré-release, sans mise à jour du tap.

La publication dans le tap utilise le secret `HOMEBREW_TAP_TOKEN` du dépôt : jeton fine-grained limité au dépôt `homebrew-clotr`, permission Contents en lecture et écriture.

## Configuration

Le fichier est cherché dans cet ordre : `--config`, puis `$CLOTR_CONFIG`, puis `~/.config/clotr/config.yaml` (`%AppData%\clotr\config.yaml` sous Windows). Voir [clotr.example.yaml](clotr.example.yaml).

Répertoires par défaut sous Windows : `%AppData%\clotr` pour la configuration et les templates, `%LocalAppData%\clotr` pour le cache, les sessions, l'audit et `known_hosts`. Les chemins de la configuration acceptent `~\` comme `~/`. Les clés inconnues sont rejetées. Si le fichier contient des clés en clair, le protéger avec `chmod 600`.

| Section | Rôle |
|---|---|
| `providers` | endpoints OpenAI-compatibles : `name`, `base_url` (jusqu'à `/v1`), `api_key` (clé en clair ou `${VAR}`) ou `api_key_env` (nom de variable), `weight`, `sovereign`, `budget`, `session_header`, `stream` (défaut true), `max_concurrency`, `model_info`, `headers`, `persistent_retry` (erreurs temporaires retentées sans limite de tours, voir Routage) |
| `profiles` | `match` (glob), `tier`, `context`, `tools`, `priority`, `sovereign`, `exclude` |
| `routing` | `sovereign` : `any`, `prefer` ou `require` |
| `roles` | `tier`, `tools`, `min_context`, `sovereign`, `description`. `planner` et `synthesizer` obligatoires, plus au moins un rôle de travail. Défauts : `collector` (fast, outils) et `analyst` (balanced, outils, 32k) |
| `limits` | `max_agents`, `max_tasks` (par tour de planification), `max_steps` (plafond de sécurité, défaut 100), `stall_steps` (étapes sans appel nouveau avant conclusion, défaut 3, 0 désactive), `verify_findings` (vérification des constats CRITIQUE et MAJEUR, défaut true), `continuations` (défaut 1), `agent_timeout` (désactivé par défaut), `request_timeout` (plafond par appel LLM, défaut 10m ; dépassé, l'appel bascule sur le modèle suivant sans nouvel essai), `idle_timeout` (silence max du flux, défaut 2m), `tool_output_max_chars`, `history_keep_steps` (défaut 2), `history_tool_chars` (défaut 1500, 0 désactive), voir Historique allégé |
| `catalog` | `cache_ttl` |
| `audit` | `dir` (défaut `~/.local/state/clotr/audit`), utilisé par `plan`. L'audit d'un `run` est écrit dans le tour de sa session. |
| `sessions` | `dir` (défaut `~/.local/state/clotr/sessions`) |
| `language` | `auto` (défaut), `fr` ou `en` : langue des réponses et rapports, voir Langues |
| `ui_language` | `en` (défaut) ou `fr` : langue de l'interface, voir Langues |
| `files` | `roots`, `max_file_bytes` |
| `templates` | `dir` (défaut `~/.config/clotr/templates`, seule source des templates), `cache_dir` (défaut `~/.cache/clotr/inventory`), `cache_ttl` (défaut 15m) |
| `instances` | `name` (préfixe des outils, `[a-z][a-z0-9-]*`), `template`, `params`, `enabled` (défaut true ; false : activée seulement par `-t <instance>`) |
| `vault` | `addr`, `namespace` : adresse et namespace Vault utilisés quand `VAULT_ADDR` / `VAULT_NAMESPACE` ne sont pas définis, voir Secrets Vault |
| `clients/*.yaml` | fichiers à part, un par client, dans le répertoire `clients/` à côté du fichier de configuration : voir Clients |
| `web_search` | `policy` (`ask` par défaut, `allow`, `deny`), `mcp` (nom d'un serveur de `mcp`), `model` (`provider/modèle` à recherche native, utilisé sans serveur MCP utilisable) et `api` (`messages` ou `responses`, requis avec `model`). Voir Recherche web. |
| `mcp` | `name`, `command`/`args`/`env` (stdio) ou `url`/`headers` (`transport: http` ou `sse`), `allow`, `deny`, `timeout`, `enabled` (défaut true ; false : connecté seulement par `-t mcp_<serveur>`). `${VAR}` est développé dans `args`, `env`, `url` et `headers`. Les entrées `mcp` d'opencode se transposent directement : `remote` devient `url` + `headers`, `local` devient `command` + `args`, `environment` devient `env`. |

Une section absente désactive les outils correspondants. Un outil dont l'initialisation échoue est désactivé, avec un avertissement.

### Clients

Les instances d'un même client se déclarent dans `clients/<client>.yaml`, à côté du fichier de configuration (`~/.config/clotr/clients/` par défaut, ou à côté de `--config` / `$CLOTR_CONFIG`). Un fichier par client ; `name` doit être le nom du fichier sans `.yaml`.

```yaml
name: acme
aliases: [acmecorp, lakehouse]
context: "Acme, projet Lakehouse : plateforme de données et VM d'administration derrière le bastion du client"
vars:
  cmp: CMP-0000
  project: PRJ-0000
params:
  proxy_url: socks5h://localhost:1080
  ssh_user: admin
  ssh_key_path: ~/.ssh/acme_ed25519
instances:
  - name: k8s-acme
    template: k8s
    params:
      contexts: [{name: acme-prod}]
  - name: vm-acme
    template: ssh-hosts
    params:
      networks: [{cidr: 10.20.0.0/24}]
      sudo: true
      ssh_user: ""
      password_vault: "kv/{{.cmp}}/{{.project}}/adm-acme"
```

| Clé | Rôle |
|---|---|
| `name` | nom du client (`[a-z][a-z0-9-]*`), distinct des noms d'instances et des préfixes réservés |
| `aliases` | autres termes qui désignent le client dans une demande ; un alias n'appartient qu'à un client |
| `context` | description transmise aux agents avec les instances du client |
| `vars` | références du client (codes client, projet…), clés `[a-z][a-z0-9_]*` : `{{.<clé>}}` est remplacé dans les valeurs des `params` du client et de ses instances (une clé inconnue désactive l'instance, avec un avertissement), et les références sont transmises aux agents avec le `context`, pour les outils qui les attendent (serveurs MCP de tickets ou d'inventaire) |
| `params` | valeurs par défaut des paramètres de ses instances (proxy, compte et clé SSH…) : appliquées seulement aux paramètres que le template de l'instance déclare, la valeur de l'instance l'emporte |
| `instances` | même format que `instances` du fichier principal ; les noms restent uniques sur toute la configuration |

Nommer le client ou l'un de ses alias dans une demande propose toutes ses instances (voir Activation d'une instance). `-t <client>` et `-x <client>` valent pour toutes ses instances activées ; une instance `enabled: false` d'un client ne se force que par son nom. Les instances du fichier principal n'ont pas de client et se comportent comme avant.

## Usage

```sh
clotr models
```

```sh
clotr tools
```

```sh
clotr templates
```

```sh
clotr plan "état de santé du cluster prod : pods en erreur, events warning récents"
```

```sh
clotr run "audit des limites de ressources des déploiements" -t prod,fs -o rapport.md
```

```sh
clotr run -m collector=ollama/qwen2.5-coder:7b --json "inventaire des ingress exposés" > result.json
```

```sh
clotr run --direct "taille de /var/log sur les hôtes de prod ?"
```

```sh
clotr run --chat --direct
```

| Option | Effet |
|---|---|
| `-c, --config` | fichier de configuration |
| `--refresh` | ignore le cache du catalogue |
| `-m, --model role=provider/model` | force le modèle d'un rôle |
| `--sovereign any\|prefer\|require` | politique souveraine pour l'exécution |
| `--confidential` | run confidentiel, équivalent de `--sovereign require` |
| `--lang auto\|fr\|en` | langue des réponses et rapports (prioritaire sur `language`) |
| `--ui-lang en\|fr` | langue de l'interface (prioritaire sur `ui_language`) |
| `-t, --tools` | restreint les groupes d'outils (`fs`, `mcp`, `mcp_<serveur>`, `<instance>`) ; sans `-t`, tous sont proposés au planner, et une instance n'est activée que si une tâche l'utilise. Un serveur ou une instance cité par son nom (`-t mcp_<serveur>`, `-t <instance>`) est activé même avec `enabled: false` ; `-t mcp` respecte `enabled`. Un nom qui ne correspond à aucun groupe est refusé. Une instance activée que `-t` écarte alors que la demande la cite (nom, mot-clé, cible, IP dans ses `networks`) fait l'objet d'un avertissement au démarrage, avec ce qui a été reconnu (audit `instance_filtered`) ; elle reste écartée. |
| `-x, --exclude` | exclut des groupes d'outils, mêmes préfixes que `-t` ; prioritaire sur `-t` et `enabled`. Exclure le serveur de `web_search.mcp` désactive la recherche web, ou la reporte sur `web_search.model` s'il est défini. |
| `-o, --output` | écrit le rapport dans un fichier |
| `--json` | sortie JSON : plan, résultats par tâche, rapport, `models_used` |
| `-q, --quiet` | n'affiche pas la progression sur stderr |
| `--plain` | progression ligne par ligne au lieu du tableau dynamique |
| `--max-agents N`, `--max-tasks N`, `--max-steps N` (`plan`, `run`) | remplacent `limits.max_agents`, `limits.max_tasks` et `limits.max_steps` pour ce run |
| `--direct[=<rôle>]` (`run`) | réponse directe, voir Réponse directe |
| `--chat` (`run`) | mode conversation, voir Conversation |
| `--raw` (`run`, `session`) | rapport en Markdown brut, sans mise en forme pour le terminal |
| `--with-evidence` (`run`, `session`) | annexe la sortie complète de chaque preuve citée, voir Preuves |
| `--incident` (`run`) | tri avant le plan, causes affichées dès qu'un agent les signale, premier Ctrl-C pour conclure tout de suite, voir Mode incident |
| `--all` (`models`) | affiche les chaînes de fallback complètes (par défaut : 3 premiers modèles) |

La demande `-` est lue sur stdin. Ctrl-C annule proprement les agents en cours.

### Progression

Si stderr est un terminal, `plan` et `run` affichent un tableau dynamique, rafraîchi sur place (Bubble Tea v2, mode inline) :
- **en-tête** : état, durée, tâches terminées sur le total (avec les échecs), nombre d'appels d'outils ;
- **une ligne par tâche**, `planner` et `synthesizer` compris :
  - statut : `·` en attente, spinner en cours, `✓` terminé, `✗` en échec ;
  - identifiant, rôle, modèle courant (mis à jour en cas de bascule) ;
  - barre d'avancement (étape LLM / `max_steps`, une borne haute et non un pourcentage) et durée ;
  - colonne steps : `step N` en cours, `N steps` une fois terminé, `max!` si la limite `max_steps` a forcé la conclusion ;
  - texte de l'étape en cours : objectif, `thinking…`, `tool <nom> <arguments>`, `fallback to …`, `waiting for …`, puis résumé (`N findings, M tool calls`) et coût une fois la tâche terminée.

Les libellés suivent la langue de l'interface (voir Langues). Tant que le tableau est affiché, tout ce qui est écrit sur stderr par une bibliothèque est capturé et réaffiché au-dessus du tableau, pour ne pas le décaler.

Le tableau final reste affiché au-dessus du bilan, et le rapport est écrit sur stdout. Hors terminal (redirection, CI) ou avec `--plain`, la progression est écrite ligne par ligne. `-q` la supprime.

### Rendu du rapport

Si stdout est un terminal, `run` et `session` affichent le rapport mis en forme (titres, gras, tableaux, listes, blocs de code colorés, retour à la ligne à la largeur du terminal, 120 colonnes au plus, sur les espaces seulement, suite d'une puce indentée sous son texte) avec [glamour](https://github.com/charmbracelet/glamour). Le thème clair ou sombre suit le fond du terminal ; `GLAMOUR_STYLE` (`dark`, `light`, `dracula`, `tokyo-night`, `ascii`, `notty` ou un fichier JSON de style) l'impose. Le rapport reste en Markdown brut avec `--raw`, `-o`, `--json` ou une redirection, ainsi que dans `report.md`.

### Mode incident

`run --incident` est fait pour l'investigation d'un dysfonctionnement :

- **Tri d'abord** : avant le plan, une tâche `t0` (rôle outillé le plus léger) localise le composant en échec et lit son message d'erreur exact et sa configuration. Le tri se termine dès qu'il signale une cause établie : il conclut à l'étape suivante (audit `goal_reached`), et l'explication des codes d'erreur et la recherche du correctif passent aux tâches planifiées. Le planner part de son résultat : il ne replanifie pas ce qu'elle a établi et, si la cause est prouvée, ne prévoit que sa vérification et la recherche du correctif. Chaque tâche reçoit le résultat de `t0` en entrée et n'a pas à relocaliser le composant.
- **Causes en direct** : les agents disposent de l'outil `cause_report` (résumé, preuves `[Exxx]` existantes obligatoires, statut `established` ou `probable`). Une cause signalée s'affiche aussitôt au-dessus du tableau de progression, est enregistrée en mémoire de session (`kind: lead`) et dans l'audit (`lead`), et est transmise aux autres tâches en cours à leur étape suivante (audit `inbox`), qui ne refont pas la collecte. Une cause issue d'un modèle souverain n'est pas transmise à une tâche non souveraine. Une cause déjà signalée n'est pas réaffichée. Chaque cause porte un numéro (`#N`, affiché et transmis) ; une cause qui en corrige ou en infirme une autre la désigne par `replaces` : l'ancienne est marquée remplacée (tag `superseded`, contenu préfixé « [remplacée par #M] »), la nouvelle s'affiche avec « corrige #N, retirée », et seule la correction est transmise aux autres tâches. Une cause négative (« ce n'est pas X ») n'est à signaler `established` que si sa preuve couvre toute la période, événements récents compris. Le synthesizer reçoit les causes signalées, à confirmer par les preuves ; la sortie `--json` les donne dans `leads`.
- **Ctrl-C pour conclure** : un premier Ctrl-C demande la conclusion : les tâches en cours concluent à leur étape suivante avec ce qu'elles ont (« conclusion demandée »), celles pas encore lancées sont abandonnées (« non lancée »), la vérification des constats est sautée, ou abandonnée si elle est en cours (y compris en attente de nouvel essai), et le rapport est produit. Un second Ctrl-C interrompt le run comme sans `--incident`.

`--incident` est incompatible avec `--direct` et `--chat`.

### Réponse directe

`run --direct` court-circuite le planner : un seul agent répond directement en Markdown, avec tous les outils, sans sous-agents, vérification des constats ni synthèse. L'agent identifie d'abord la source qui couvre la demande et n'utilise que ses outils ; si aucune source connectée ne la couvre, il le dit sans explorer. Comme en mode planifié, une instance que la demande ne mentionne pas ne lui est pas proposée (voir Activation d'une instance). Il garde le contrôle de progression (`stall_steps`, `max_steps`), les preuves citées `[Exxx]` avec leur annexe et le marquage des lignes appuyées sur une seule note de mémoire. Par défaut, il prend le rôle outillé de tier le plus léger (`collector` avec les rôles par défaut) ; `--direct=analyst` choisit un autre rôle. Le tour est enregistré dans la session comme un `run` : `run -s <session>` permet ensuite d'affiner, avec ou sans `--direct`.

### Conversation

`run --chat [demande]` ouvre un écran plein terminal (écran alternatif) sur une session, nouvelle ou reprise avec `-s`. Chaque échange est un tour de la session : mêmes outils, preuves, mémoire et enregistrement qu'un `run`. Les connecteurs (MCP, instances) sont préparés une fois pour toute la conversation, et les identifiants saisis restent en mémoire jusqu'à la fin.

Pendant un tour, le tableau de progression s'affiche sous la demande, puis la réponse s'écrit en direct (texte du synthesizer, ou de l'agent avec `--direct`), mise en forme comme ci-dessus. Les lignes écrites sur stderr (avertissements, activation d'une instance) s'affichent sous le tableau, et le bilan du tour (modèles, coût, preuves, chemin du `report.md`) sous la réponse. `max_run_cost` s'applique à chaque tour.

| Touche | Effet |
|---|---|
| `r` | répondre : ouvre la saisie pour le tour suivant |
| `entrée` / `alt+entrée` (ou `ctrl+j`) | envoyer / nouvelle ligne |
| `c` | copie la dernière réponse en Markdown dans le presse-papiers : `wl-copy` (Wayland), `xclip` ou `xsel` (X11), `pbcopy`, `clip.exe`, sinon séquence OSC 52 du terminal |
| `↑` `↓` `pgup` `pgdown` `home` `end` | défilement |
| `ctrl+c` | interrompt le tour en cours (deux fois : quitte) ; hors tour, quitte |
| `q`, `échap` | quitte |

`--chat` exige un terminal et n'accepte ni `--json` ni `-o`.

## Langues

Deux réglages indépendants :

- **Réponses et rapports** : `language` (config) ou `--lang`.

  | Valeur | Rapport, constats, objectifs (modèles) |
  |---|---|
  | `auto` | langue de la demande |
  | `fr` | français, consigne explicite aux modèles |
  | `en` | anglais, consigne explicite aux modèles |

  Une session mémorise cette langue : un tour d'affinage sans `--lang` reprend celle de la session. Les titres ajoutés par clotr au rapport (annexe des preuves) suivent ce réglage, en anglais pour `auto`.

- **Interface** : `ui_language` (config) ou `--ui-lang`, `en` (défaut) ou `fr`. Elle couvre tout ce que clotr affiche lui-même : aide des commandes, tableau de progression, bilan, `models`, `tools`, `plan`, `sessions`, `templates`, mode conversation, saisie des identifiants, erreurs et avertissements. Les messages sont regroupés dans `internal/i18n`.

Restent dans leur langue d'origine : les consignes envoyées aux modèles et ce qu'ils lisent (description et sortie des outils, environnement affiché par `clotr tools`), les textes de la configuration et des templates (contextes, hints, messages des scripts), et les erreurs des fournisseurs et des systèmes interrogés.

Une assertion de test de template qui porte sur un message du moteur (garde-fou http, chemin refusé…) dépend de la langue de l'interface : viser une partie commune aux deux langues (valeur citée, liste entre parenthèses).

## Streaming

Les appels LLM sont en streaming SSE (`stream: true` avec `stream_options.include_usage`) :
- **réponse** : contenu, `reasoning_content` et fragments d'appels d'outils sont réassemblés au fil du flux ;
- **progression** : le tableau affiche en direct `reasoning… ~N tok`, `writing… ~N tok` ou `preparing N tool call(s)…` ;
- **texte** : en mode conversation, le texte de la réponse finale est affiché au fil du flux, sans les blocs `<think>` ;
- **délais** : un appel est interrompu si le flux reste muet plus de `limits.idle_timeout`, ou s'il dépasse `limits.request_timeout` au total. Ces deux erreurs sont temporaires (nouvel essai, puis bascule) ;
- **désactivation** : `providers[].stream: false` repasse un provider en mode classique. Un serveur qui ignore `stream` et répond en JSON est aussi accepté.

## Budget

`providers[].budget` déclare le budget de chaque provider. Les valeurs possibles sont :
- **absent** : non déclaré ;
- **`unlimited`** : provider illimité, pas de contrôle ;
- **`{info_path, min_remaining, max_run_cost}`** : budget limité, suivi comme suit :
  - avant le run, `GET <base sans /v1><info_path>` (défaut `/key/info`, format LiteLLM : `info.spend`, `info.max_budget`). Le provider est écarté si son reste est inférieur à `min_remaining` ;
  - pendant le run, le coût de chaque appel est pris dans l'en-tête `x-litellm-response-cost` s'il est présent (mode non streaming). Sinon, il est estimé à partir de l'`usage` du flux et des prix par token de `/model/info` (`model_info: true`), et affiché avec `~`. Le provider est écarté si le coût cumulé du run atteint `max_run_cost` ;
  - après chaque tâche, `/key/info` est relu pour suivre le solde de la clé. Le provider est écarté si son reste passe sous `min_remaining`. LiteLLM écrit la dépense en base par lots : le solde lu peut retarder de quelques secondes.

`clotr models` affiche le statut et l'état du budget de chaque provider. À la fin du `run`, stderr affiche le coût par provider, ou « coût non communiqué » si le provider ne renvoie pas d'en-tête de coût.

## Identification des requêtes

Toutes les requêtes HTTP portent le User-Agent `clotr/<version>`. `providers[].session_header` envoie dans l'en-tête indiqué un identifiant stable par sous-agent. Exemple : `x-opencode-session`, exigé par OpenCode Go.

## Audit

Chaque `run` écrit `turns/NNN/audit.jsonl` dans sa session (et `plan` écrit `<audit.dir>/<AAAAMMJJ-HHMMSS>.jsonl`). Ce fichier contient :
- `run_start` et `run_end` ;
- `plan` ;
- `llm_call` : tâche, modèle, étape, durée, tokens, outils demandés ;
- `tool_call` : outil, arguments, durée, taille, erreur ;
- `http_call` : requête HTTP d'un template (instance, connecteur, méthode, URL, statut, durée, taille) ;
- `remote_exec` : commande SSH d'un template (instance, hôte, utilisateur, commande, durée, exit, taille) ;
- `task_end`.

À la fin du `run`, stderr affiche :
- les modèles utilisés ;
- ceux qui ne sont pas souverains ;
- le chemin du fichier d'audit.

`run_end` reprend la liste des modèles avec leur indicateur souverain.

## Structure

```
cmd/clotr/              CLI (cobra)
internal/config/        chargement et validation YAML
internal/catalog/       découverte des modèles, profils, cache
internal/router/        sélection et fallback par rôle
internal/llm/           client /chat/completions, pool par provider
internal/agent/         boucle tool-calling
internal/orchestrator/  planner, DAG concurrent, synthèse, réponse directe
internal/memory/        mémoire partagée
internal/session/       sessions et tours
internal/budget/        budget et coûts par provider
internal/tools/         registre et outils files, mcp
internal/template/      moteur de templates : chargement, paramètres, hôte Starlark, primitives, outils génériques, tests
internal/driver/ssh/    SSH en lecture seule : commandes fixes, chemins autorisés, known_hosts
internal/creds/         identifiants : variables d'environnement, Vault ou saisie
internal/vault/         lecture d'un secret Vault (KV v1/v2) avec la configuration du poste
internal/audit/         journal JSONL
internal/progress/      progression stderr, écran conversation
internal/markdown/      rendu Markdown pour le terminal
packaging/homebrew/     modèle de la formule Homebrew
.github/workflows/      CI (vet, tests, cross) et release sur tag
```

## Limites connues

- Aucune donnée n'est anonymisée avant envoi vers un modèle non souverain (`Boundary` = `Passthrough`). `--confidential` limite le run aux modèles souverains.
- La mémoire partagée suit la session : elle n'est pas partagée entre sessions.
- Les tâches du plan ne sont pas relancées après un échec ; seul le modèle bascule au sein d'une tâche.
- fs est intégré au binaire et n'est pas un template.
- SSH : clés avec passphrase et agent SSH non supportés.
