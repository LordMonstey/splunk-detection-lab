# Modèle d’exploitation et passage à l’échelle

Ce document transforme les limites de capacité d’une instance standalone en
décisions d’architecture explicites. Il ne modifie pas les compétences
démontrées dans le dépôt : normalisation, contenu, validation, RBA,
administration et investigation restent les mêmes responsabilités.

## Invariants qui survivent au scale-out

- contenu versionné dans une application Splunk ;
- séparation des indexes par domaine et politique de rétention ;
- parsing et normalisation testés avant promotion ;
- tuning porté par lookups et macros, pas par copies de SPL ;
- validation avec dataset reproductible et métriques de runtime ;
- risk modifiers immuables, finding dédupliqué, historique auditable ;
- build déterministe, revue, manifeste et capacité de rollback.

## Topologie cible selon la charge

| Déclencheur mesuré | Évolution | Contrôle attendu |
|---|---|---|
| Concurrence de recherche et scheduler | Search Head Cluster | captain, bundle replication, search quotas, workload management |
| Débit/indexation et rétention | Indexer Cluster | RF/SF, bucket fix-up, capacité disque, IOPS, SmartStore si pertinent |
| Parc important de forwarders | Deployment Server | server classes, apps immuables, canary ring, phone-home monitoring |
| Parsing/routage complexe | Heavy Forwarder ou pipeline dédié | files d’attente, backpressure, masquage, routage déterministe |
| Multiples équipes | RBAC et espaces applicatifs | rôles analyst/admin/auteur, capabilities, permissions par index |

Le choix n’est jamais « cluster parce que cela sonne senior ». Il dépend de la
concurrence, du débit, des SLO et des domaines de panne observés.

## Data onboarding à l’échelle

1. définir propriétaire, finalité, volume/jour, rétention et criticité ;
2. choisir index, sourcetype et méthode de collecte ;
3. valider timestamp, line breaking, encoding et déduplication ;
4. mesurer les champs CIM requis et documenter les champs absents ;
5. créer les assets/identities et les contrôles de qualité ;
6. rejouer un échantillon connu avant ouverture du flux complet ;
7. surveiller fraîcheur, EPS, parsing failures et dérive de volume.

## Exploitation de la Detection Factory

- CI : syntaxe, cohérence IDs, macros/lookups référencés, ATT&CK, tests SPL ;
- canary : dispatch sur fenêtre contrôlée et comparaison au résultat attendu ;
- observation : bruit, coût de recherche, retard scheduler, faux positifs ;
- promotion : revue pair, preuve, seuils documentés et plan de rollback ;
- maintenance : ownership, date de dernière validation, dette de tuning et
  dépréciation des règles sans valeur.

## Passage au RBA natif Enterprise Security

Le pipeline actuel rend l’intention portable : objet risque, type d’objet,
score, message, technique, détection et contexte. Avec Splunk ES, ces champs
sont branchés aux actions de risque natives, aux règles de finding, à Mission
Control et aux workflows analystes. Les contrôles à conserver sont :

- stabilité de l’identité de l’entité ;
- bornes et normalisation du score ;
- déduplication déterministe ;
- seuil de diversité technique ;
- fenêtre de corrélation et late-arriving data ;
- permission sur les indexes et audit des modifications.

## SLO et reprise

| SLO | Mesure | Réponse |
|---|---|---|
| Fraîcheur des données | `_indextime - _time` par source | diagnostic UF/queue/indexing |
| Respect du scheduler | `dispatch_time`, skipped searches | tuning SPL, quotas ou capacité |
| Qualité CIM | complétude des champs requis | corriger parsing/alias avant contenu |
| Coût des recherches | scan count, runtime, cardinalité | filtrage initial, datamodel/summary si justifié |
| Disponibilité du contenu | build installé et objets activés | rollback applicatif versionné |
| Reprise plateforme | RTO/RPO testés | backup KV/config, restauration et validation |

La maturité ne consiste pas à masquer les contraintes : elle consiste à les
convertir en seuils, contrôles et décisions reproductibles.
