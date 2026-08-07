# Runbook - MCO cluster et resilience Splunk ES

## Objectif

Maintenir la disponibilite de la recherche et de l'indexation pendant une
operation planifiee ou une panne d'un noeud. Ce runbook couvre l'Indexer
Cluster et le Search Head Cluster qui porte Splunk ES.

## Pre-requis et roles

- changement approuve avec proprietaire, fenetre et plan de communication ;
- Cluster Manager, deployer et Monitoring Console accessibles ;
- sauvegarde recente des configurations, du search tier et du KV Store ;
- RF, SF, captain, peers et membres SHC identifies ;
- aucune operation de fix-up, de rebalance ou de rolling restart concurrente ;
- secrets transmis hors ticket et jamais ajoutes aux preuves.

## Etat initial obligatoire

1. Verifier la sante splunkd et les alertes Monitoring Console.
2. Confirmer que tous les peers sont `Up` et `Searchable`.
3. Confirmer RF et SF respectes pour chaque index clusterise.
4. Verifier le captain SHC, le quorum et la replication des artefacts.
5. Mesurer les recherches sautees, la latence d'ingestion et les queues.
6. Capturer la version, le bundle courant et l'heure de reference.

Si un de ces controles est rouge, le changement est `NO-GO` jusqu'a correction
ou acceptation formelle du risque.

## Maintenance des indexers

1. Valider le bundle sur le Cluster Manager.
2. Activer le maintenance mode uniquement pour la duree necessaire.
3. Appliquer le bundle en observant l'indication de restart requis.
4. Utiliser le rolling restart orchestre par le Cluster Manager.
5. Pour un peer isole, utiliser `splunk offline` puis `splunk start`, jamais un
   redemarrage brutal apres le debut de la replication.
6. Surveiller primaries, fix-up, RF/SF, recherche et ingestion pendant toute
   l'operation.

## Maintenance du Search Head Cluster

1. Confirmer le captain et la disponibilite du deployer.
2. Verifier le contenu de `etc/shcluster/apps` et le mode de push.
3. Valider le bundle avant application.
4. Appliquer le bundle avec preservation des lookups lorsque necessaire.
5. Utiliser le rolling restart ou rolling upgrade adapte a la version.
6. Controler captain, membres, replication des artefacts, scheduler et KV Store.

## Test de resilience

Pour chaque scenario, enregistrer heure de debut, impact attendu, signal
observe, heure de retablissement et resultat :

| Scenario | Service attendu | Controle de sortie |
|---|---|---|
| peer indexer indisponible | recherche et ingestion maintenues selon RF/SF | peer reintegre, fix-up termine |
| membre SHC indisponible | acces maintenu via les autres membres | quorum et captain stables |
| captain indisponible | election sans perte durable du service | nouveau captain et artefacts synchronises |
| deployer indisponible | recherches existantes maintenues | aucun push avant restauration |
| KV Store degrade | fonctions ES qualifiees ou changement bloque | backup valide et etat vert |

## Rollback

Le rollback est declenche si la recherche devient indisponible au-dela de la
fenetre acceptee, si RF/SF ne reviennent pas a la cible, si le SHC perd son
quorum ou si les smoke tests ES echouent.

1. Stopper toute nouvelle operation.
2. Restaurer le bundle precedent depuis le depot de changement.
3. Reappliquer via le role de distribution approprie.
4. Rejouer les controles initiaux.
5. Conserver logs, chronologie et cause racine.

## Preuves de cloture

- capture Monitoring Console avant/apres ;
- sortie cluster et SHC expurgee des secrets ;
- RF/SF, captain, membres et fix-up au vert ;
- tests recherche, ingestion, scheduler et application ES ;
- rapport de changement, decision et actions preventives.
