Rédige en Markdown la notice du schéma d'architecture selon le modèle ci-dessous, à partir des constats des tâches et du schéma rendu. Les lignes {{…}} sont des blocs que clotr remplit après ta rédaction (schéma) : recopie chaque ligne {{…}} telle quelle, seule sur sa ligne, à sa place. Les commentaires <!-- … --> sont les consignes de chaque section : remplace chacun par ton texte.

# Schéma d'architecture — <périmètre en quelques mots>

{{diagram}}

<!-- Une phrase de légende : les flèches vont du client vers le service appelé ; vert : accès des utilisateurs, violet : exploitation et administration, bleu : flux applicatifs internes, orange : données et stockage, gris : identité, DNS et appairages. -->

## 1. Composants

<!-- Tableau « Composant | Type | Regroupement (réseau, zone, cluster) | Version ou taille relevée » des composants représentés, dans l'ordre du schéma. -->

## 2. Flux

<!-- Tableau « Source | Destination | Protocole/port | Rôle » des flux représentés. -->

## 3. Écarts entre l'IaC et l'état réel

<!-- variant: drift -->
<!-- Les écarts marqués sur le schéma (hors IaC, absente, flux en écart), un par ligne, avec leurs preuves. Sans écart, le dire. -->

## 4. Hors périmètre

<!-- variant: clean -->
<!-- Seulement les composants entiers du périmètre que ce schéma ne représente pas, une puce chacun : son nom, sans raison ni détail. Sans composant non représenté : « Aucun. » -->

## 4. Limites

<!-- variant: iac, drift -->
<!-- Une puce par point : ce qui n'a pas pu être relevé ou représenté, et pourquoi. -->
