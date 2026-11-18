Sinon, rédige le mode opératoire de mise à jour en Markdown selon le modèle ci-dessous : il dit, étape par étape, comment faire passer les composants de la demande de leur version actuelle à la version cible, à partir de l'état actuel établi par les preuves et de la documentation officielle lue. Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Preuves citées par leurs identifiants [Exxx] repris des constats, jamais par les identifiants de tâche (t1, t2…). Aucune modification n'a été faite : tout ce que le document décrit reste à réaliser. Toute commande, option, opération d'API ou action d'interface vient d'une page de documentation lue ou d'une preuve : cite sa preuve [Exxx] ; sans source lue, décris l'action sans en écrire la syntaxe et ajoute-la aux points à confirmer. Les valeurs propres à l'environnement s'écrivent telles que les preuves les donnent (noms de clusters, d'environnement, versions) ; une valeur non établie s'écrit <entre chevrons>. Quand la documentation propose plusieurs variantes de procédure (progressive sans interruption, classique avec arrêt…), le document suit la variante retenue pour chaque composant : ses prérequis, ses arrêts, son interruption et ses étapes ; ceux d'une autre variante n'apparaissent que comme repli. Seuls les composants que la demande met à jour dans cette phase ont des étapes ; ceux qu'elle reporte à une phase ultérieure n'apparaissent que dans les sections de compatibilité, d'impacts et de phases suivantes.

# Mode opératoire — <composants> vers <version cible>

## 1. Synthèse

<!-- 3 à 5 puces, chacune commençant par la phrase clé en gras : périmètre de cette phase (composants mis à jour, composants reportés) ; version actuelle → version cible de chaque composant ; faisabilité et chemin de mise à jour (direct ou par une version intermédiaire) ; variante de procédure retenue et pourquoi ; interruption de service attendue avec cette variante ; points bloquants ou à confirmer avant de commencer. -->

---

## 2. Périmètre et état actuel

<!-- Tableau « Composant | Rôle | Version actuelle | Version cible | Phase | Preuve » couvrant les composants de la phase, ceux dont ils dépendent (identité, base de données, image, gestionnaire) et ceux reportés à une phase ultérieure. Versions de toutes les couches concernées (logiciel, gestionnaire, image ou système) telles que les preuves les donnent. Puis l'état de santé actuel de chaque composant de la phase, avec ses preuves. -->

## 3. Compatibilité, chemin de mise à jour et variante retenue

<!-- Variantes de procédure documentées pour chaque composant, dans un tableau « Variante | Conditions d'application | Mesuré | Remplie | Interruption | Preuve » ; la variante retenue et pourquoi (toutes ses conditions établies par les mesures, interruption la plus faible), la variante de repli. Chemins de mise à jour supportés depuis la version actuelle selon la documentation lue (direct, ou version intermédiaire obligatoire), ordre imposé entre composants, versions minimales requises des dépendances. Coexistence pendant la transition : ce que la documentation dit de composants restés à l'ancienne version face à ceux mis à jour (composants reportés), et ce qui leur reste possible ou interdit tant qu'ils ne sont pas mis à jour. Changements de la version cible qui touchent ce périmètre : fonctionnalités retirées ou modifiées, problèmes connus. -->

## 4. Prérequis et vérifications préalables

<!-- Tableau « Contrôle | Attendu (source) | Constaté | État | Preuve », État parmi OK, KO, À vérifier : un contrôle par prérequis de la variante retenue et par point relevé (santé des services, espace disque, versions des dépendances, sauvegardes existantes, personnalisations, opérations en cours, droits du compte qui réalisera la mise à jour). Un contrôle non mesuré par ce run est « À vérifier », avec la commande ou l'observation qui le mesure. Les KO sont repris en tête des points bloquants de la synthèse. -->

## 5. Sauvegardes

<!-- Ce qui doit être sauvegardé avant de commencer (données, métadonnées, bases, configurations), comment, où, et comment vérifier qu'une sauvegarde est exploitable ; sauvegardes existantes constatées (date, état) avec leurs preuves. -->

---

## 6. Mode opératoire

<!-- Étapes numérotées dans l'ordre d'exécution, regroupées sous des titres « ### » : préparation (J-n), jour J, par composant dans l'ordre imposé. Chaque étape : l'action ; la commande en bloc de code ou le chemin dans l'interface ; sa durée si une preuve la donne ; le résultat attendu et la commande ou l'observation qui le vérifie. Les étapes sont celles de la variante retenue, avec l'option ou le choix qui la sélectionne ; aucun arrêt qu'elle n'exige. Un point de décision « Go / No-go » avant chaque étape irréversible, avec ses critères. Dernière étape : vérification de bout en bout. -->

## 7. Vérifications après mise à jour

<!-- Liste de contrôles à faire après la mise à jour : versions effectives, santé de chaque service, fonctionnement de bout en bout (accès des utilisateurs, traitements, intégrations avec les composants reportés), chacun avec la commande ou l'observation et le résultat attendu. -->

## 8. Retour arrière

<!-- Ce que la documentation prévoit en cas d'échec, à chaque étape, et quand basculer sur la variante de repli : reprise, restauration de sauvegarde, réparation, ou absence de retour arrière possible (le dire clairement), avec la procédure et sa source. Point de non-retour de la procédure. -->

## 9. Impacts et communication

<!-- Puces, le sujet en gras : interruption de chaque service avec la variante retenue et durée estimée si une preuve la donne, puis ce qui changerait avec la variante de repli, utilisateurs et traitements touchés, fenêtre de maintenance conseillée, intervenants nécessaires (éditeur, équipes), informations à communiquer avant et après. -->

---

## 10. Phases suivantes

<!-- Pour chaque composant reporté : sa version actuelle, ce qui change pour lui une fois cette phase faite (compatibilité, restrictions jusqu'à sa mise à jour), les prérequis propres relevés, et les étapes de cette procédure qui s'appliqueront à nouveau. Sans composant reporté, écrire « Aucune phase ultérieure prévue par la demande ». -->

## 11. Points à confirmer et limites

<!-- Une puce par point, le sujet en gras : informations manquantes dans la demande (version cible exacte, fenêtre, composants), syntaxes et valeurs non établies par une source lue, prérequis non mesurés, pages de documentation non lues, tâches en échec ou arrêtées par une limite. -->
