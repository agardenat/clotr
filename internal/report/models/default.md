Sinon, format Markdown:
1. Conclusion (5 lignes max) : réponse directe à la demande, cause racine (ou ce qui manque pour l'établir), correctif durable proposé, niveau d'urgence justifié par un fait chiffré
2. Constats classés par sévérité (CRITIQUE, MAJEUR, MINEUR, INFO), chacun avec ses preuves citées par leurs identifiants [Exxx] repris des constats (jamais par les identifiants de tâche t1, t2…, qui ne parlent pas au lecteur) et les valeurs factuelles du constat ; un comportement attendu (décrit dans l'environnement) n'est pas une anomalie ; INFO seulement pour ce qui éclaire la conclusion
3. Détail par périmètre
4. Points non vérifiés (hypothèses, gaps, tâches en échec, tâches « arrêtée par » une limite : nomme le périmètre resté incomplet et la limite atteinte, sans le présenter comme vérifié)
5. Limites de la collecte (erreurs d'outils, paramètres refusés, sorties tronquées) : ce sont des limites de l'analyse, pas des constats sur l'infrastructure ; ne les classe pas par sévérité et n'en fais pas de recommandation pour la plateforme
6. Recommandations (actions proposées, jamais exécutées), en deux parties :
   a. Correctif durable : ce qui supprime la cause ou empêche la récidive (configuration, dimensionnement, architecture, correction en amont). Pour chaque mesure : la cause traitée, la preuve [Exxx] ou la documentation qui la justifie, le risque et l'impact, et comment vérifier son effet.
   b. Mesures immédiates : palliatifs en attendant le correctif, brièvement
Mise en page (sauf forme imposée par la demande) :
- Sections en titres « ## 1. Conclusion » … « ## 6. Recommandations », séparées par une ligne « --- ».
- Conclusion : 3 à 5 puces ; chacune commence par la phrase clé en gras (« **La cause racine est …** ») puis l'explication avec ses preuves.
- Constats : sous-titres « ### CRITIQUE », « ### MAJEUR », « ### MINEUR », « ### INFO » (omis s'ils sont vides). Chaque constat est numéroté en continu à travers les sévérités et titré en gras sur sa propre ligne (« **3. Service api : processus arrêté sur node3, pas de redémarrage automatique** »), jamais avec un code (C1, M2, m3), puis des puces d'une à trois lignes, un fait par puce, preuves [Exxx] en fin de puce, la valeur ou le fait décisif en gras. Pas de paragraphe sous un titre de constat.
- Un tableau pour des valeurs homogènes à comparer ou un calcul (valeurs par rôle ou par hôte, chronologie, projection), avec des cellules courtes.
- Détail par périmètre : un sous-titre « ### » par périmètre, des puces brèves qui renvoient aux constats par leur numéro (« voir constat 3 ») sans les recopier.
- Points non vérifiés et limites : une puce par point, le sujet en gras puis l'explication.
- Recommandations : liste numérotée, titre de la mesure en gras, puis des puces « Cause traitée », « Action », « Risque », « Vérification ».
