Rédige le document d'architecture technique en Markdown selon le modèle ci-dessous, à partir des seuls constats des tâches de relevé. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction (schéma d'architecture) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place. Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte. Une section sans élément relevé contient une seule ligne : « Non décrit dans ce document. » Titres « ### » libres sous chaque section, un par objet (cluster, réseau, environnement) quand il y en a plusieurs. Tableaux pour toute série homogène (ressources, nœuds, règles, composants), cellules courtes ; jamais de liste de plus de cinq éléments homogènes hors tableau.

# Document d'architecture technique — <périmètre en quelques mots>

## 1. Introduction

<!-- Objet du document et périmètre couvert : plateforme, environnements, clouds ou hébergements, en un paragraphe. -->

## 2. Architecture globale

{{diagram}}

<!-- Description de l'architecture par couches, du point d'entrée aux données : accès des utilisateurs et des systèmes externes, exposition (DNS, répartiteurs, passerelles, ingress), calcul (machines, clusters), plateformes et applications, données et stockage, services transverses (identité, secrets, supervision, sauvegarde). Un paragraphe par couche, qui nomme les composants et leurs liens. -->

## 3. Accès et identités

<!-- Annuaire et fournisseur d'identité, groupes, rôles et leurs attributions, comptes de service et identités de charge de travail, accès d'administration (bastion, VPN, comptes nominatifs ou partagés). Tableau « Identité ou groupe | Portée | Rôle ou droit ». -->

## 4. Infrastructure as Code

<!-- Organisation du code : dépôts, outil (Terraform, GitOps…), répertoires par environnement ou par objet, version des outils et des fournisseurs, stockage de l'état, mode d'application (pipeline, réconciliation automatique, intervalle), gestion des secrets dans le code. Sans IaC dans le périmètre : le dire. -->

## 5. Réseau

<!-- Réseaux virtuels et sous-réseaux (nom, plage d'adresses, usage), interconnexions (peering, VPN, liaisons dédiées), DNS (zones publiques et privées, résolution), points d'entrée publics et privés (répartiteurs, passerelles, ingress, endpoints privés) avec leurs adresses et ports. Tableau par réseau. -->

## 6. Sécurité réseau

<!-- Groupes de sécurité, pare-feu et politiques réseau : à quoi chacun s'applique, puis ses règles dans un tableau « Sens | Source | Destination | Port/protocole | Action » ; regrouper les règles identiques d'un groupe à l'autre. -->

## 7. Calcul

<!-- Machines virtuelles (nom, rôle, taille, système, adresse) et clusters (version, pools ou groupes de nœuds, taille et nombre de nœuds, mise à l'échelle, profil réseau, identités). Un tableau par type de ressource. -->

## 8. Plateformes et composants déployés

<!-- Ce qui tourne sur le calcul : composants d'infrastructure (contrôleurs d'ingress, certificats, DNS, stockage, supervision) et applications, avec leur version et leur mode de déploiement. Pour plusieurs clusters ou environnements semblables, une matrice « Composant | <cluster 1> | <cluster 2>… » avec la version ou « absent ». -->

## 9. Données et stockage

<!-- Bases de données managées ou installées (moteur, version, taille, haute disponibilité, accès réseau), stockage objet et fichiers (nom, type, redondance, accès), volumes persistants et classes de stockage. -->

## 10. Secrets et chiffrement

<!-- Coffres de secrets (nom, accès, consommateurs), gestion des certificats (émetteur, renouvellement), chiffrement au repos et en transit (clés gérées par le fournisseur ou par le client). Sans nommer ni recopier aucun secret. -->

## 11. Exploitation

<!-- Sauvegardes (périmètre, fréquence, rétention, emplacement), reprise d'activité (réplication, zone ou région de secours), supervision et journalisation (outils, métriques et journaux collectés, alertes), mises à jour (politique, fenêtres). -->

## 12. Hors périmètre

<!-- variant: clean -->
<!-- Seulement les composants entiers du périmètre que ce document ne décrit pas (cluster, serveur, environnement), une puce chacun : son nom et « non décrit dans ce document », sans raison ni détail. Aucune mention de ce qui n'a été vu qu'en partie (versions, règles, paramètres, fichiers) : une valeur inconnue est simplement absente des tableaux. Sans composant entier non décrit : « Aucun. » -->

## 12. Périmètre non couvert et limites

<!-- variant: iac, drift -->
<!-- Une puce par point, le sujet en gras : sources annoncées mais illisibles, instances ou objets sans relevé, tâches en échec ou arrêtées par une limite, informations absentes des sources. Ce sont des limites du relevé, pas des constats sur l'infrastructure. -->

## 13. Écarts entre l'IaC et l'état réel

<!-- variant: drift -->
<!-- Les constats marqués [ÉCART], et eux seuls. Un tableau par objet « Ressource | Déclaré (IaC) | Observé | Preuves », une ligne par écart : valeur différente, ressource déclarée mais absente, ressource présente mais non déclarée. Puis une phrase par écart dont l'origine est établie par une preuve (modification manuelle, réconciliation en échec, code non appliqué). Sans écart relevé, le dire et rappeler ce qui a été comparé. -->
