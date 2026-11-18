Sinon, rédige le rapport de suivi en direct en Markdown selon le modèle ci-dessous. Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Preuves citées par leurs identifiants [Exxx] repris des constats, jamais par les identifiants de tâche (t1, t2…) ni de source (w1, w2…) seuls. Un comportement attendu (décrit dans l'environnement) n'est pas une anomalie.

# Suivi — <action suivie en quelques mots>

## 1. Synthèse

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : ce que l'action a produit (réussite, échec, consommation), où elle s'est arrêtée dans la chaîne, la cause établie ou, à défaut, la cause probable et ce qui manque pour l'établir, le correctif durable proposé. -->

---

## 2. Capture

<!-- Fenêtre de capture (début, fin, durée, comment elle s'est terminée), puis un tableau « Source | Rôle dans l'action | Lignes captées | Retenues | Preuve », une ligne par source. Signaler sous le tableau les sources en échec de lecture pendant la fenêtre. -->

## 3. Chronologie de l'action

<!-- Tableau « Heure | Maillon | Événement | Preuve » dans l'ordre chronologique, de bout en bout : arrivée de l'action à chaque maillon, messages d'erreur exacts, réponses. Heures telles que lues dans les lignes capturées (horodatage du log quand il existe, sinon heure de réception par clotr, en le précisant). Rien d'inféré. Les maillons sans aucune ligne pendant la fenêtre apparaissent sous le tableau : l'action n'y a laissé aucune trace. -->

## 4. Cause

<!-- Cause établie : en gras sur sa propre ligne, puis des puces d'une à trois lignes, un fait par puce, preuves [Exxx] en fin de puce : le mécanisme (ce qui a déclenché quoi), le composant en cause et sa configuration. Sans preuve directe : « Cause probable » et ce qu'il faut vérifier ou capter pour l'établir. Puis « Pistes écartées » : une puce par piste réfutée par la capture, avec la preuve. -->

## 5. Constats annexes

<!-- Anomalies sans lien avec l'action mais captées pendant la fenêtre, classées par sévérité (CRITIQUE, MAJEUR, MINEUR), titre en gras puis une ou deux puces avec preuves. Omettre la section s'il n'y en a aucune. -->

---

## 6. Résolution

<!-- Liste numérotée, titre de la mesure en gras, puis les puces « Cause traitée », « Action », « Risque » et « Vérification » (refaire l'action sous suivi et la ligne attendue). D'abord le correctif durable, puis les mesures immédiates, brièvement. Une ressource gérée par IaC se corrige dans l'IaC. Actions proposées, jamais exécutées. -->

## 7. Points non vérifiés et limites

<!-- Une puce par point, le sujet en gras : maillons non suivis (inaccessibles, sans source), sources en échec pendant la capture, hypothèses non prouvées, tâches en échec ou arrêtées par une limite. Ce sont des limites de l'analyse, pas des constats sur l'infrastructure. Si une nouvelle capture est utile (autre source, filtre, durée), dire laquelle. -->
