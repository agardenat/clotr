Sinon, rédige le rapport de demande de changement en Markdown selon le modèle ci-dessous : il dit ce qu'il faut modifier dans l'infrastructure pour satisfaire la demande, à partir de l'état actuel établi par les preuves. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction avec des données établies (ticket, tickets liés) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place ; n'en rédige pas le contenu, mais appuie-toi dessus (leur contenu t'est fourni avec les résultats). Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Preuves citées par leurs identifiants [Exxx] repris des constats, jamais par les identifiants de tâche (t1, t2…). Aucune modification n'a été faite : tout ce que le rapport propose reste à réaliser.

# Demande de changement — <objet en quelques mots>

{{ticket}}

## 1. Synthèse

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : ce qui est demandé, reformulé précisément (ressource, valeur cible) ; faisabilité au vu de l'état actuel ; où se fait la modification (IaC : dépôt et fichiers, ou configuration hors IaC) ; impact attendu (interruption, redémarrage, aucun) ; points bloquants ou à confirmer avant de réaliser. -->

---

## 2. État actuel

<!-- Ce que la demande modifie, tel qu'il est aujourd'hui : configuration en place, versions, ressources, valeurs, avec leurs preuves [Exxx] ; et sa source : dépôt IaC, fichier et ligne qui le décrivent, ou absence d'IaC constatée. Un tableau pour des valeurs homogènes (par hôte, par environnement). Signaler tout écart entre l'IaC et l'état réel (dérive). -->

## 3. Modifications à réaliser

<!-- Une sous-section « ### » par composant ou dépôt modifié. Pour l'IaC : dépôt, fichier, et l'extrait à modifier en bloc de code avant/après (ou diff), en reprenant la syntaxe lue dans les preuves ; sans la source lue, décrire la modification sans inventer de code et le signaler en point à confirmer. Pour une configuration hors IaC : l'élément, la valeur actuelle et la valeur cible. Une ressource gérée par IaC se modifie dans l'IaC, jamais à la main. Ordre des modifications si elles dépendent les unes des autres. -->

## 4. Impacts, prérequis et risques

<!-- Puces, le sujet en gras : interruption ou redémarrage provoqués (quel service, durée estimée si une preuve la donne), dépendances (autres composants, flux réseau, DNS, certificats, droits), prérequis (validation, fenêtre de maintenance, capacité), risques et comment les réduire, retour arrière (comment revenir à l'état actuel décrit en section 2). -->

---

## 5. Plan de mise en œuvre

<!-- Liste numérotée des étapes dans l'ordre d'exécution (préparation, application, déploiement), chacune avec sa vérification : commande ou observation qui prouve que l'étape a produit l'effet attendu. Dernière étape : vérification de bout en bout de la demande. -->

## 6. Demandes similaires

{{tickets.related}}

<!-- Pour chaque ticket du bloc : ce qu'il a en commun avec cette demande et comment elle avait été réalisée, si cela s'applique ici. Sans ticket lié, écrire « Aucune demande similaire trouvée ». -->

---

## 7. Points à confirmer et limites

<!-- Une puce par point, le sujet en gras : informations manquantes dans la demande (valeur cible, périmètre, échéance), hypothèses à valider, sources non lues (dépôt IaC inaccessible), tâches en échec ou arrêtées par une limite. -->
