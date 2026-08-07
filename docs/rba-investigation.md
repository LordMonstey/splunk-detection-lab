# RBA et investigation d'entité

Le pipeline Risk-Based Alerting matérialise les sorties positives des
détections sous une forme compatible avec les indexes `risk` et `notable` de
Splunk Enterprise Security. Il démontre la conception et l'exploitation du
modèle de risque sans présenter le package premium comme actif sur l'instance
de validation.

## Résultat matérialisé

| Indicateur | Valeur observée |
|---|---:|
| Risk modifiers | 19 |
| Risque cumulé de l'entité | 1 185 |
| Détections contributrices | 5 |
| Techniques ATT&CK distinctes | 5 |
| Finding courant | 1 |
| Versions du finding | 2 |

Chaque risk modifier conserve l'identifiant de la détection, la technique, la
sévérité, l'entité, le score, le message et l'identifiant de campagne. Cette
traçabilité permet de revenir du score agrégé à l'événement analytique qui l'a
produit.

## Agrégation et déduplication

Le finding est construit par entité et fenêtre de corrélation. La vue courante
est dédupliquée afin de garder une file opérateur lisible. Une nouvelle
évaluation ne détruit pas l'état antérieur : elle ajoute une version auditable
dans `notable`.

Le score ne suffit pas à lui seul. La priorité tient aussi compte de la
diversité des techniques, du nombre de détections contributrices, de la
fraîcheur et du contexte de l'entité. Cette séparation évite qu'une répétition
d'un même signal soit confondue avec une progression multi-technique.

## Parcours d'investigation

1. qualifier l'entité, la période et le finding courant ;
2. lire les contributions au risque par détection et technique ;
3. revenir à la télémétrie source au moyen de l'identifiant de campagne ;
4. vérifier le contexte processus, utilisateur, hôte et ligne de commande ;
5. comparer la version courante à l'historique ;
6. documenter la décision de clôture, tuning ou escalade.

## Contrôles de qualité

- aucun risk modifier sans entité ni score ;
- identifiant de détection stable entre catalogue, risque et finding ;
- déduplication de la file sans suppression de l'historique ;
- score explicable par la somme des contributions ;
- données publiques agrégées, sans événement brut.

La preuve assainie est publiée dans
[`artifacts/public/splunk-engineering-snapshot-20260806.json`](../artifacts/public/splunk-engineering-snapshot-20260806.json)
et la vue opérateur dans
[`site/assets/evidence/risk-correlation-assurance.png`](../site/assets/evidence/risk-correlation-assurance.png).
