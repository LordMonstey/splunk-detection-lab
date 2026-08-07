# Runbook MCO - perte d'un peer d'indexation

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- peer `Down`, `GracefulShutdown` inattendu ou non joignable ;
- cluster invalide ou incomplet, RF/SF non respectes ;
- primaries manquants, fix-up durable ou recherches partielles ;
- ingestion redistribuee avec queues en hausse.

Cluster invalide ou resultats incomplets : SEV1. Cluster valide mais incomplet :
SEV2 jusqu'au retour RF/SF.

## Diagnostic

### SPL

Depuis le manager node :

```spl
| rest /services/cluster/manager/peers count=0
| eval up=if(status="Up",1,0), searchable=if(search_state="Searchable",1,0)
| stats count as peers sum(up) as peers_up sum(searchable) as searchable
        values(status) as statuses values(site) as sites
```

Verifier les erreurs de replication et les queues :

```spl
index=_internal earliest=-30m
  (component=CMRepJob OR component=BucketReplicator OR group=queue)
| stats count values(log_level) as levels by host component
```

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/cluster/manager/info?output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/cluster/manager/peers?count=0&output_mode=json"
```

### CLI

Sur le manager node, puis sur le peer si accessible :

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" show cluster-status --verbose
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" status
df -P "${SPLUNK_DB}"
```

Controler alimentation, OS, disque, temps, reseau, certificat, splunkd, port de
replication et dernier changement. Noter si le cluster est en maintenance mode :
le fix-up y est suspendu.

## Decision

| Etat cluster | Decision |
|---|---|
| valide et peer recuperable rapidement | restaurer le peer sans decommission |
| valide mais incomplet au-dela du RTO | laisser le fix-up progresser et preparer remplacement |
| invalide | proteger la recherche et l'ingestion, restaurer prioritairement les primaries |
| peer perdu definitivement | decommission approuve avec capacite RF+1 et controle des buckets standalone |
| plusieurs peers affectes | ne pas les redemarrer ensemble ; escalade architecture et stockage |

## Remediation

1. stopper rolling restart, bundle push et maintenance concurrente ;
2. si le peer repond, corriger la dependance racine puis lancer Splunk ;
3. confirmer son reenregistrement et la reallocation des primaries ;
4. surveiller fix-up, RF/SF, debit et recherche jusqu'a completude ;
5. pour une maintenance planifiee future, utiliser `splunk offline` puis
   `splunk start`, jamais un arret brutal ;
6. pour une perte permanente, suivre le decommissionnement officiel et verifier
   la capacite des peers restants avant l'operation.

Ne jamais supprimer manuellement les buckets du peer ni activer maintenance mode
pour masquer un fix-up durable.

## Rollback et retour arriere

- restaurer la configuration reseau, TLS ou `server.conf` precedente ;
- si un peer remplace ne rejoint pas, le retirer de la rotation sans supprimer
  l'enregistrement du peer historique ;
- arreter une operation de changement avant d'affecter un second peer ;
- revenir au dernier bundle valide via le manager node, puis recontroler RF/SF.

## Criteres de sortie

- tous les peers attendus `Up` et `Searchable` ;
- cluster valide et complet ; RF/SF respectes ;
- aucun fix-up restant et primaries equilibres ;
- ingestion continue, queues sous seuil et recherche de reference equivalente ;
- maintenance mode desactive et aucun changement concurrent orphelin ;
- cause racine et prevention attribuees.

## Preuves

- statut manager et peers avant/apres expurge des GUID, URI et noms ;
- chronologie de perte, detection, reenregistrement et completude ;
- RF/SF, nombre de fix-up et tests de recherche/ingestion ;
- diff du correctif, hash du bundle et approbation ;
- mesure de capacite et conclusion sur le RTO/RPO.

References : [Take a peer offline](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.1/manage-the-indexer-cluster/take-a-peer-offline) et [Restart an indexer cluster or peer](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.1/manage-the-indexer-cluster/restart-the-entire-indexer-cluster-or-a-single-peer-node).
