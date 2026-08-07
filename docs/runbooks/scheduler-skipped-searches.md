# Runbook MCO - recherches planifiees sautees

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- `status=skipped` dans `scheduler.log` ;
- correlation search ou rapport critique absent de sa fenetre attendue ;
- ratio de skip superieur au seuil MCO ;
- temps d'execution qui chevauche l'occurrence suivante.

Un skip sur une detection prioritaire est SEV2 meme si le ratio global est faible.

## Diagnostic

### SPL

```spl
index=_internal source=*scheduler.log earliest=-24h
| eval is_skip=if(status="skipped",1,0)
| stats count as executions sum(is_skip) as skipped
        p95(run_time) as runtime_p95 values(reason) as reasons
  by app savedsearch_name
| eval skip_pct=round(100*skipped/executions,2)
| sort - skip_pct
```

Verifier la pression de concurrence et de dispatch :

```spl
index=_internal source=*scheduler.log earliest=-2h
| timechart span=5m count by status limit=10 useother=f
```

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/servicesNS/-/-/saved/searches?count=0&output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/server/health/splunkd?output_mode=json"
```

### CLI

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool savedsearches list --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool limits list scheduler --debug
```

Classer chaque skip : limite de concurrence, occurrence precedente encore active,
fenetre nulle, permissions, search peer indisponible, espace dispatch ou erreur SPL.

## Decision

| Cause confirmee | Decision |
|---|---|
| chevauchement d'une recherche | optimiser puis elargir le cron ou utiliser une planification continue si le cas le permet |
| pics synchrones | decaler les cron et donner une fenetre aux recherches non critiques |
| recherche critique en concurrence | proteger sa priorite apres validation de l'impact global |
| limite systeme coherente avec la capacite | conserver la limite et reduire la charge |
| limite sous-dimensionnee avec marge CPU/RAM | augmenter par petit palier, puis mesurer |

Augmenter aveuglement la concurrence ne constitue pas une remediation.

## Remediation

1. executer la recherche manuellement sur la meme fenetre et valider ses resultats ;
2. optimiser filtres, index, data models ou commandes distributables ;
3. ecarter les cron concurrents et utiliser `schedule_window` pour le non critique ;
4. reserver la priorite elevee aux detections ayant un SLA ;
5. modifier `limits.conf` uniquement avec une mesure de capacite avant/apres ;
6. rejouer les occurrences manquees selon l'idempotence de l'action associee.

## Rollback et retour arriere

- restaurer la stanza `savedsearches.conf` ou `limits.conf` precedente ;
- arreter un backfill si sa charge recree les skips, sans supprimer ses resultats ;
- remettre le cron et la priorite d'origine ;
- confirmer que le retour arriere n'a pas cree un nouveau trou de detection.

## Criteres de sortie

- trois occurrences consecutives de chaque recherche critique sans skip ;
- ratio global sous le seuil MCO pendant une fenetre complete ;
- resultat fonctionnel equivalent avant/apres optimisation ;
- CPU, memoire, dispatch et peers sans nouvelle alerte ;
- backfill des fenetres manquees trace ou formellement juge inutile.

## Preuves

- agregat scheduler avant/apres par recherche, sans SPL sensible ;
- motif exact, runtime p95, cron et criticite ;
- hash du package, diff des stanzas et approbation ;
- controle d'equivalence des resultats et trois executions de sortie ;
- chronologie du backfill et impact mesure.

Reference : [Prioritize concurrently scheduled reports](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/reporting-manual/9.0/report-management/prioritize-concurrently-scheduled-reports-in-splunk-web).
