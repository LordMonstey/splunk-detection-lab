# Runbook MCO - KV Store indisponible

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- `status` different de `ready` au-dela du demarrage normal ;
- `replicationStatus` a `Down`, `Rollback`, `Recovering` ou `Unknown` ;
- `inputlookup`, `outputlookup`, collections ES ou workflows d'investigation en
  erreur ;
- health check KV Store rouge ou absence de quorum sur le search tier.

Une perte de quorum ou une indisponibilite ES etendue est SEV1.

## Diagnostic

### SPL

```spl
index=_internal earliest=-2h
  (source=*mongod.log OR source=*splunkd.log)
  (component=KVStore OR component=MongoModularInput OR "KV Store")
| rex field=_raw "(?i)(?<kv_signal>error|failed|rollback|recovering|initial sync)"
| stats count min(_time) as first_seen max(_time) as last_seen by host kv_signal
```

Tester une collection canari en lecture seule et comparer son nombre de lignes et
son hash logique a la reference approuvee.

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/kvstore/status?output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/server/health/splunkd?output_mode=json"
```

### CLI

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" show kvstore-status
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool server list kvstore --debug
```

Controler espace disque, permissions, horloge, chaine TLS, captain SHC, quorum,
version et erreurs de stockage avant tout nettoyage.

## Decision

| Etat | Decision |
|---|---|
| `starting` bref apres restart | observer avec delai borne |
| un membre SHC en `Initial sync` | surveiller progression et capacite reseau |
| moins de la moitie des membres stale | isoler et resynchroniser un membre a la fois selon la procedure de version |
| majorite stale, quorum perdu ou standalone corrompu | geler les ecritures et preparer une restauration approuvee |
| erreur disque, certificat ou permission | corriger d'abord la dependance racine |

Une restauration KV Store ecrase des donnees : elle n'est jamais lancee comme
premier reflexe et n'appartient pas aux drills de ce depot.

## Remediation

1. stopper les changements concurrents et les jobs `outputlookup` non essentiels ;
2. restaurer disque, permission, temps ou TLS si l'un de ces invariants est rompu ;
3. sur SHC, conserver quorum et captain dynamique sauf procedure de restauration ;
4. resynchroniser seulement le membre stale identifie, jamais plusieurs a la fois ;
5. si restauration necessaire, verifier archive, coherence point-in-time, RPO et
   presence des `collections.conf` avant la fenetre approuvee ;
6. reouvrir les ecritures apres validation des collections critiques.

## Rollback et retour arriere

- restaurer le bundle, le certificat ou les permissions precedents si la correction
  de dependance echoue ;
- si une resynchronisation ne progresse pas, remettre le membre hors rotation et
  revenir a l'etat de quorum stable ;
- apres restauration, le rollback est la sauvegarde anterieure approuvee et implique
  une nouvelle perte potentielle : decision du responsable RPO obligatoire.

## Criteres de sortie

- `status=ready` sur tous les membres attendus ;
- replication stable, quorum et captain conformes ;
- aucune operation backup/restore en echec ou en cours ;
- collection canari lisible, nombre de lignes et hash conformes ;
- dashboards, lookups et workflows ES de reference fonctionnels ;
- aucune erreur KV Store nouvelle pendant la fenetre d'observation.

## Preuves

- sorties `show kvstore-status` avant/apres expurgees ;
- etat SHC, captain et chronologie de replication ;
- hash et metadonnees de la sauvegarde sans contenu de collection ;
- resultats du canari et smoke tests applicatifs ;
- diff de configuration, decision RPO et action preventive.

References : [KV Store troubleshooting tools](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/administer-the-app-key-value-store/kv-store-troubleshooting-tools) et [Back up and restore KV Store](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/administer-the-app-key-value-store/back-up-and-restore-kv-store).
