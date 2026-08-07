# Runbook MCO - pression disque, index ou retention

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- seuil `minFreeSpace` atteint, indexation suspendue ou recherche refusee ;
- volume hot/warm ou cold superieur au seuil preventif ;
- queue d'indexation durablement remplie ;
- `maxTotalDataSizeMB` susceptible de geler les buckets avant la retention cible ;
- projection de saturation inferieure a 30 jours.

Indexation arretee ou risque de perte imminente : SEV1.

## Diagnostic

### SPL

```spl
index=_internal source=*metrics.log group=queue earliest=-30m
| eval fill_pct=if(max_size_kb>0,100*current_size_kb/max_size_kb,0)
| stats latest(fill_pct) as current_pct max(fill_pct) as max_pct by host name
| where max_pct>=70
| sort - max_pct
```

```spl
| rest /services/data/indexes count=0
| eval fill_pct=round(100*currentDBSizeMB/maxTotalDataSizeMB,2)
| table title currentDBSizeMB maxTotalDataSizeMB frozenTimePeriodInSecs fill_pct
| sort - fill_pct
```

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/data/indexes?count=0&output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/server/health/splunkd?output_mode=json"
```

### CLI

```bash
df -P "${SPLUNK_DB}"
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool indexes list --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool server list diskUsage --debug
```

Separer : saturation du filesystem, limite par index, limite de volume, espace
dispatch, burst d'ingestion ou croissance structurelle. Pour un cluster, integrer
RF/SF et distribution reelle des buckets. Traiter SmartStore avec son modele de
cache, pas avec les seuils d'un index local.

## Decision

| Situation | Decision |
|---|---|
| espace sous `minFreeSpace` | contenir le flux non critique et restaurer de la marge sans supprimer de bucket |
| limite index avant retention | augmenter la capacite ou archiver avant de toucher a la retention |
| burst ponctuel | absorber, lisser et surveiller les queues |
| croissance structurelle | lancer extension et recalcul p50/p95/peak avec marge |
| filesystem sain mais dispatch plein | traiter la charge de recherche et les artefacts expires |

## Remediation

1. geler les changements concurrents et confirmer les donnees obligatoires ;
2. agrandir le filesystem ou le volume selon le processus infrastructure ;
3. corriger `maxTotalDataSizeMB`, les volumes et `frozenTimePeriodInSecs` dans un
   package teste, avec analyse du premier seuil atteint ;
4. configurer un archivage cold-to-frozen valide avant toute reduction de retention ;
5. filtrer ou echantillonner uniquement une source non critique approuvee ;
6. appliquer le bundle cluster et observer queues, fix-up, debit et latence.

Ne jamais effacer manuellement un repertoire de bucket. Une baisse de retention
peut supprimer des donnees sans confirmation et exige un changement distinct.

## Rollback et retour arriere

- restaurer `indexes.conf` et `server.conf` precedents si le changement degrade
  recherche, retention ou distribution ;
- retirer le filtre d'urgence apres retour de capacite et verifier le replay ;
- une extension de stockage n'est pas reduite pendant l'incident ; sa restitution
  est un changement ulterieur ;
- controler que le rollback ne fait pas franchir immediatement l'ancien seuil.

## Criteres de sortie

- espace libre au-dessus de `minFreeSpace` plus la marge d'exploitation ;
- queues sous le seuil pendant au moins deux pics de collecte ;
- indexation et recherche de reference sans erreur ;
- RF/SF et fix-up au vert pour un cluster ;
- retention effective compatible avec l'engagement ;
- projection p95 et peak avec au moins 30 jours de marge ou plan date.

## Preuves

- capacite filesystem, indexes et volumes avant/apres ;
- debit p50/p95/peak, ratio de compression et hypothese RF/SF ;
- configuration effective `btool` expurgee et hash du package ;
- evolution des queues et smoke tests recherche/ingestion ;
- estimation de date de saturation, decision et proprietaire du plan.

References : [Configure maximum index size](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.2/manage-index-storage/configure-maximum-index-size) et [Set limits on disk usage](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.1/manage-index-storage/set-limits-on-disk-usage).
