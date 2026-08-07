# Runbook MCO - quota ou violation de licence

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- bannieres de licence, message `warning` ou `violation` ;
- usage du pool superieur a 80 % avant la fin de journee ;
- recherches utilisateur ou planifiees bloquees alors que l'indexation continue ;
- peer sans contact avec le license manager.

Ouvrir SEV1 si la recherche de securite est bloquee, SEV2 si le quota est depasse
sans blocage, SEV3 au seuil preventif. Ne jamais supposer qu'une suppression de
donnees deja indexees reduira le volume comptabilise.

## Diagnostic

### SPL

Mesurer la contribution par index et sourcetype, puis expurger `h` avant partage :

```spl
index=_internal source=*license_usage.log type=Usage earliest=@d
| eval GiB=round(b/1024/1024/1024,3)
| stats sum(GiB) as GiB by idx st h
| sort - GiB
```

Verifier aussi une rupture license manager/peer :

```spl
index=_internal source=*splunkd.log earliest=-24h
  component=LMTracker ("failed to send rows" OR "unable to connect")
| stats count min(_time) as first_seen max(_time) as last_seen by host
```

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/licenser/usage?output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/licenser/messages?count=0&output_mode=json"
```

### CLI

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" list licenses
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool server list license --debug
```

Comparer l'horloge du license manager, le quota du stack, les pools, le volume
depuis minuit local et la tendance des sept derniers jours.

## Decision

| Observation | Decision |
|---|---|
| peer sans contact, volume normal | restaurer la communication avant toute modification de pool |
| pic unique identifie | contenir la source non critique et surveiller jusqu'au reset journalier |
| croissance structurelle | reallouer une capacite disponible ou ouvrir l'extension de licence |
| recherche bloquee | maintenir l'indexation, utiliser `_internal` pour diagnostiquer et escalader le reset selon le contrat |

Tout filtrage est refuse si les evenements portent une exigence legale, d'audit
ou une dependance de detection non couverte par une analyse d'impact.

## Remediation

1. corriger l'horloge ou le lien vers le license manager si le volume n'est pas
   la cause ;
2. identifier le changement ayant cree le pic et son proprietaire ;
3. reduire le bruit a la source ou sur un heavy forwarder avec une regle testee,
   versionnee et approuvee ;
4. reallouer les pools uniquement apres controle des consommateurs voisins ;
5. installer une capacite additionnelle via le processus de licence officiel ;
6. confirmer que les sources de securite obligatoires continuent d'arriver.

Ne jamais purger des buckets, reindexer pour masquer le depassement ou desactiver
la comptabilisation.

## Rollback et retour arriere

- retirer le filtre ou restaurer le package d'inputs precedent si une couverture
  attendue disparait ;
- restaurer l'allocation de pool precedente si un autre peer est affame ;
- revalider la connectivite de chaque peer et les recherches critiques ;
- conserver le changement de licence acquis : son retrait est un changement
  distinct, pas un rollback automatique.

## Criteres de sortie

- license manager joignable par tous les peers ;
- aucun message critique nouveau pendant deux cycles de collecte ;
- ratio projete sous le seuil local avec marge documentee ;
- recherches interactives et planifiees de reference fonctionnelles ;
- aucune source obligatoire perdue et plan de capacite attribue.

## Preuves

- usage et quota avant/apres, horodates, sans identifiant de licence ;
- top contributeurs agreges et expurges ;
- messages licenser classes par severite ;
- diff du filtre ou de l'allocation, hash du package et approbation ;
- resultat de trois recherches critiques et decision de cloture.

Reference : [About license violations](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/manage-splunk-licenses/about-license-violations).
