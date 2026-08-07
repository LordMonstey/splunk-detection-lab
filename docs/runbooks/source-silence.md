# Runbook MCO - silence d'une source de securite

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- dernier evenement plus ancien que le SLA de la source ;
- baisse brutale du nombre d'hotes ou du debit ;
- forwarder, HEC ou input absent de son inventaire attendu ;
- detection dependante inactive faute de donnees recentes.

Une source critique entierement silencieuse au-dela de son SLA est SEV2 ; passer
SEV1 si la couverture reglementaire ou une investigation en cours est compromise.

## Diagnostic

### SPL

```spl
| tstats latest(_time) as last_event count where index=<scoped_index>
  by index sourcetype host
| eval age_seconds=now()-last_event
| where age_seconds><source_sla_seconds>
| convert ctime(last_event)
```

Separer retard d'indexation et retard d'horodatage :

```spl
index=<scoped_index> sourcetype=<scoped_sourcetype> earliest=-24h
| eval ingest_lag=_indextime-_time
| stats count p50(ingest_lag) as lag_p50 p95(ingest_lag) as lag_p95
        max(_time) as last_event by host
```

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/admin/inputstatus/TailingProcessor:FileStatus?output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/deployment/server/clients?count=0&output_mode=json"
```

Interroger le premier endpoint sur le collecteur qui lit les fichiers et le second
sur le deployment server qui gere les clients concernes.

### CLI

Sur le collecteur concerne :

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" list forward-server
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool inputs list --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool outputs list --debug
```

Verifier maintenance declaree, service producteur, rotation de fichier, permissions,
checkpoint, queue, DNS, TLS, routage vers l'index et horloges.

## Decision

| Portee du silence | Decision |
|---|---|
| un hote | traiter agent, fichier, permission ou horloge localement |
| une source sur tous les hotes | inspecter producteur, input et parsing commun |
| plusieurs sources d'un collecteur | traiter sortie, reseau, TLS ou queue du collecteur |
| evenements indexes mais `_time` ancien | corriger temps/parsing sans relancer l'input |
| maintenance approuvee | prolonger l'inhibition uniquement avec nouvelle echeance |

## Remediation

1. retablir le producteur ou l'agent sans modifier son checkpoint ;
2. corriger chemin, permission, certificat ou route dans un package versionne ;
3. redemarrer le composant minimal, puis observer la reprise ;
4. rejouer la plage manquante depuis la source originale si l'operation est
   idempotente et approuvee ;
5. calculer la perte, les doublons et les detections a reevaluer ;
6. mettre a jour l'inventaire de fraicheur et l'alerte SLA.

Ne pas utiliser `oneshot` sur un fichier deja checkpointed sans strategie de
deduplication : la reprise d'un silence ne doit pas fabriquer des doublons.

## Rollback et retour arriere

- restaurer le package input/output precedent si la reprise route mal les donnees ;
- stopper un replay qui cree des doublons et conserver son perimetre exact ;
- remettre le certificat ou le chemin precedent si le nouveau endpoint echoue ;
- verifier la source initiale et les sources partageant le meme collecteur.

## Criteres de sortie

- fraicheur sous SLA pendant trois intervalles consecutifs ;
- debit dans la bande de reference ou ecart explique ;
- lag p95 conforme et horloges synchronisees ;
- aucun doublon ni evenement tronque cree par la reprise ;
- gap quantifie, replay termine ou risque accepte ;
- detections dependantes testees sur la fenetre restauree.

## Preuves

- inventaire attendu/recu et fraicheur agregee avant/apres ;
- chronologie du dernier evenement, de la reprise et du replay ;
- sorties forwarder/deployment expurgees des URI et noms d'hotes ;
- diff de configuration, hash du package et controle de doublons ;
- liste des detections reexecutees et decision sur le gap.

Reference : [I cannot find my data](https://help.splunk.com/en/splunk-enterprise/administer/troubleshoot/9.0/splunk-web-and-search-problems/i-cant-find-my-data).
