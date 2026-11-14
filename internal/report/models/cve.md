Sinon, rédige le rapport en Markdown selon le modèle ci-dessous, reproduit une fois par sujet de la demande, dans l'ordre de la demande, en remplaçant <ID> par l'identifiant exact du sujet. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction avec des données établies (fiche issue des sources officielles, tableaux des actifs, tests déterminants, preuves) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place ; n'en rédige pas le contenu et ne le répète pas, mais appuie-toi dessus (leur contenu t'est fourni avec les résultats). Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Pas de section de constats par sévérité ni de cause racine : le rapport porte sur l'exposition de l'infrastructure à ce sujet.

# <ID> — <produit touché>

## 1. Verdict

{{cve.<ID>.verdict}}

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : l'infrastructure est-elle touchée, combien d'actifs positifs et lesquels sont réellement exposés ; niveau d'urgence justifié par le score, l'exploitation connue (CISA KEV, SSVC, EPSS) et l'exposition mesurée des positifs. Sans actif positif, le dire, et rappeler les actifs indéterminés s'il y en a. -->

## 2. La vulnérabilité

{{cve.<ID>.fiche}}

---

## 3. Actifs positifs

{{cve.<ID>.positives}}

<!-- Arbitrage, une puce par actif positif ou par groupe d'actifs identiques : l'actif en gras, puis ce qui aggrave ou atténue le risque d'après les conditions mesurées et les prérequis d'exploitation de la fiche (composant ou option activés ou non, exposition à internet ou au seul réseau interne, authentification requise), avec les preuves [Exxx], et la priorité qui en découle (immédiate, planifiée, faible). Une condition non mesurée se dit comme telle, sans supposer. Rien sous le tableau s'il n'y a aucun actif positif. -->

## 4. Actifs indéterminés

{{cve.<ID>.unknown}}

<!-- Pour chaque actif ou groupe d'actifs indéterminés : ce qu'il faut faire pour conclure (accès, commande, inspection de l'image). Rien s'il n'y en a aucun. -->

## 5. Actifs négatifs

{{cve.<ID>.negatives}}

<!-- Un paragraphe par type d'élément présent dans le bloc (hôtes, workloads, images, services) : ce qui a été testé (commandes, inventaires, versions relevées) et pourquoi c'est négatif (composant absent, version corrigée, release non touchée), avec les preuves [Exxx]. Pas de liste élément par élément. -->

---

## 6. Plan d'action

<!-- Liste numérotée dans l'ordre de priorité de la section 3, une entrée par actif positif ou par groupe d'actifs identiques (même composant, même version, même correctif). Titre en gras, puis les puces « Mitigation immédiate » (contournement de la fiche applicable à cet actif, ou « aucune »), « Correctif » (version ou paquet à déployer d'après la colonne « Corrigé dans », ou image à reconstruire) et « Vérification » (la commande de détection de la fiche qui prouvera la correction). Pour une compromission : retrait de la version malveillante, rotation des secrets que le composant a pu lire, recherche des traces sur la période d'exposition. Si des actifs sont indéterminés, une dernière entrée pour lever l'incertitude. Pas de recommandation générale sans lien avec un actif. -->

## 7. Limites de l'analyse

<!-- Une puce par limite, le sujet en gras : sources officielles indisponibles (voir la fiche), périmètres ou instances non couverts, tâches en échec ou arrêtées par une limite, autorisations refusées, actifs non inspectables. Ce sont des limites de l'analyse, pas des constats sur l'infrastructure. -->

