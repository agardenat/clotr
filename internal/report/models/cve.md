Sinon, rédige le rapport en Markdown selon le modèle ci-dessous, reproduit une fois par sujet de la demande, dans l'ordre de la demande, en remplaçant <ID> par l'identifiant exact du sujet. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction avec des données établies (fiche issue des sources officielles, tableaux des actifs, tests déterminants, preuves) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place ; n'en rédige pas le contenu et ne le répète pas, mais appuie-toi dessus (leur contenu t'est fourni avec les résultats). Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Pas de section de constats par sévérité ni de cause racine : le rapport porte sur l'exposition de l'infrastructure à ce sujet.

# <ID> — <produit touché>

## 1. Verdict

{{cve.<ID>.verdict}}

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : l'infrastructure est-elle touchée, combien d'actifs positifs, en distinguant les positifs réels (🚨 : prérequis réunis ou non mesurés) des positifs à exposition limitée (🟠) et de ceux que la configuration actuelle neutralise (🟡 : non exploitables en l'état, de nouveau exploitables si la configuration change) ; niveau d'urgence justifié par le score, l'exploitation connue (CISA KEV, SSVC, EPSS) et l'exposition mesurée des positifs. Sans actif positif, le dire, et rappeler les actifs indéterminés s'il y en a. -->

## 2. La vulnérabilité

{{cve.<ID>.fiche}}

---

## 3. Actifs positifs

{{cve.<ID>.positives}}

<!-- Arbitrage, une puce par actif positif ou par groupe d'actifs identiques : l'actif en gras, puis ce qui aggrave ou atténue le risque d'après les conditions mesurées et les prérequis d'exploitation de la fiche (composant ou option activés ou non, exposition à internet ou au seul réseau interne, authentification requise), avec les preuves [Exxx], et la priorité qui en découle (immédiate, planifiée, faible). Pour un actif 🟡, dire quel réglage le neutralise et quel changement de configuration le rendrait exploitable. Une condition non mesurée se dit comme telle, sans supposer. Rien sous le tableau s'il n'y a aucun actif positif. -->

## 4. Actifs indéterminés

{{cve.<ID>.unknown}}

<!-- Pour chaque actif ou groupe d'actifs indéterminés : ce qu'il faut faire pour conclure (accès, commande, inspection de l'image). Rien s'il n'y en a aucun. -->

## 5. Actifs négatifs

{{cve.<ID>.negatives}}

<!-- Un paragraphe par type d'élément présent dans le bloc (hôtes, workloads, images, services) : ce qui a été testé (commandes, inventaires, versions relevées) et pourquoi c'est négatif (composant absent, version corrigée, release non touchée), avec les preuves [Exxx]. Pas de liste élément par élément. -->

---

## 6. Plan d'action

<!-- Liste numérotée dans l'ordre de priorité de la section 3, une entrée par actif positif ou par groupe d'actifs identiques (même composant, même version, même correctif). Titre en gras : le ou les actifs, sous leur nom exact de la colonne « Actif ». Puis quatre puces, dans cet ordre et avec ces libellés : « Pourquoi positif » (en une phrase, la version ou le paquet trouvé et la plage touchée de la fiche qui le contient, et le prérequis d'exploitation réuni s'il a été mesuré), « Mitigation immédiate » (contournement de la fiche applicable à cet actif qui réduit le risque en attendant le correctif définitif sans supprimer la vulnérabilité ; pour un actif 🟡, le réglage qui le neutralise déjà et qu'il faut garder ; sinon « aucune » avec la raison), « Correctif définitif » (ce qui supprime la vulnérabilité, à distinguer de la mitigation : version ou paquet à déployer d'après la colonne « Corrigé dans », patch, ou image à reconstruire, avec l'endroit où le changer) et « Vérification » (la commande de détection de la fiche qui prouvera la correction). Ces puces alimentent le récapitulatif en tableau : chacune tient en une ou deux phrases, sans sous-liste. Pour une compromission : retrait de la version malveillante, rotation des secrets que le composant a pu lire, recherche des traces sur la période d'exposition. Rien d'autre : les actions qui lèvent l'incertitude des actifs indéterminés sont en section 4, et sans actif positif la section se réduit à « Aucune action : aucun actif positif. ». Pas de recommandation générale sans lien avec un actif. -->

## 7. Limites de l'analyse

<!-- Une puce par limite, le sujet en gras : sources officielles indisponibles (voir la fiche), périmètres ou instances non couverts, tâches en échec ou arrêtées par une limite, autorisations refusées, actifs non inspectables. Ce sont des limites de l'analyse, pas des constats sur l'infrastructure. -->

