Sinon, rédige le rapport d'incident en Markdown selon le modèle ci-dessous. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction avec des données établies (ticket, tickets liés) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place ; n'en rédige pas le contenu, mais appuie-toi dessus (leur contenu t'est fourni avec les résultats). Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Preuves citées par leurs identifiants [Exxx] repris des constats, jamais par les identifiants de tâche (t1, t2…). Un comportement attendu (décrit dans l'environnement) n'est pas une anomalie.

# Incident — <sujet en quelques mots>

{{ticket}}

## 1. Synthèse

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : ce qui ne fonctionne pas et depuis quand (impact mesuré), la cause racine établie ou, à défaut, la cause probable et ce qui manque pour l'établir, l'état actuel (en cours, rétabli), le correctif durable proposé, le niveau d'urgence justifié par un fait chiffré. -->

---

## 2. Chronologie

<!-- Tableau « Heure | Événement | Preuve » dans l'ordre chronologique : premiers symptômes, événements déclencheurs (déploiement, changement de configuration, saturation, redémarrage), erreurs, état au moment de l'analyse. Horodatages tels que lus dans les preuves, avec leur fuseau. Rien d'inféré : un horodatage inconnu ne s'invente pas. -->

## 3. Cause racine

<!-- Cause établie : en gras sur sa propre ligne, puis des puces d'une à trois lignes, un fait par puce, preuves [Exxx] en fin de puce : le mécanisme de bout en bout (ce qui a déclenché quoi), le composant en cause et sa configuration ou sa version. Sans preuve directe : « Cause probable » et ce qu'il faut vérifier pour l'établir. Puis « Pistes écartées » : une puce par piste examinée et réfutée, avec la preuve qui l'écarte. -->

## 4. Constats annexes

<!-- Anomalies sans lien avec l'incident mais relevées pendant l'analyse, classées par sévérité (CRITIQUE, MAJEUR, MINEUR), titre en gras puis une ou deux puces avec preuves. Omettre la section s'il n'y en a aucune. -->

---

## 5. Résolution

<!-- Liste numérotée, titre de la mesure en gras, puis les puces « Cause traitée », « Action », « Risque » et « Vérification » (commande ou observation qui prouvera l'effet). D'abord le correctif durable (ce qui supprime la cause ou empêche la récidive : configuration, dimensionnement, IaC, correction en amont), puis les mesures immédiates (palliatifs en attendant), brièvement. Une ressource gérée par IaC se corrige dans l'IaC. Actions proposées, jamais exécutées. -->

## 6. Incidents similaires

{{tickets.related}}

<!-- Pour chaque ticket du bloc : ce qu'il a en commun avec cet incident (symptôme, composant, message), la résolution appliquée alors et si elle s'applique ici, d'après les preuves de cette analyse. Un ticket probable (relation « en cours ») se présente comme tel : à rattacher si l'analyse le confirme. Sans ticket lié, écrire « Aucun ticket similaire trouvé » et la recherche faite. -->

---

## 7. Points non vérifiés et limites

<!-- Une puce par point, le sujet en gras : hypothèses non prouvées, tâches en échec ou arrêtées par une limite (périmètre resté incomplet, limite atteinte), erreurs d'outils, autorisations refusées. Ce sont des limites de l'analyse, pas des constats sur l'infrastructure. -->
