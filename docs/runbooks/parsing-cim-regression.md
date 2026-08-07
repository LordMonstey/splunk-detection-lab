# Runbook MCO - regression parsing ou normalisation CIM

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document.

## Symptomes et declenchement

- champ pivot absent, type incorrect ou valeur anormalement `unknown` ;
- evenements fusionnes, tronques, dupliques ou mal horodates ;
- ecart entre volume brut et data model CIM ;
- correlation search ou dashboard vide apres un changement de TA ;
- `btool` montre une precedence inattendue.

Une regression qui aveugle une detection critique est SEV2.

## Diagnostic

### SPL

Mesurer la couverture sans exposer les valeurs :

```spl
index=<scoped_index> sourcetype=<scoped_sourcetype> earliest=-30m
| stats count as events
        count(eval(isnotnull(src))) as with_src
        count(eval(isnotnull(dest))) as with_dest
        count(eval(isnotnull(action))) as with_action
| foreach with_* [ eval <<FIELD>>_pct=round(100*<<FIELD>>/events,2) ]
```

Comparer donnees brutes et data model dans la meme fenetre :

```spl
| tstats summariesonly=f count from datamodel=Authentication.Authentication
  where earliest=-30m latest=now by Authentication.action
```

Verifier `_time`, `_indextime`, `linecount`, eventtype, tag et signatures de
doublons sur un jeu borne.

### REST

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/configs/conf-props?count=0&output_mode=json"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/configs/conf-transforms?count=0&output_mode=json"
```

### CLI

```bash
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool props list --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool transforms list --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool check
```

Determiner si le defaut est input-time, index-time ou search-time, puis localiser
le role d'execution : forwarder lourd, indexer ou search head. Une correction
search-time peut etre retroactive ; une correction index-time ne l'est pas.

## Decision

| Defaut | Decision |
|---|---|
| extraction search-time | corriger sur search tier et tester les dependances |
| breaking/time/line merge | corriger avant l'indexation et planifier le traitement historique separement |
| precedence d'app | retirer la collision ou deplacer la configuration vers l'app proprietaire |
| data model vide, champs presents | verifier eventtypes, tags, contraintes et acceleration |
| format source change | ouvrir le contrat de donnees et maintenir temporairement deux variantes |

## Remediation

1. figer un echantillon anonymise avec hash et resultats attendus ;
2. ecrire le correctif dans une app versionnee, jamais dans `system/local` ;
3. valider regex, time extraction, breaking et encodage hors production ;
4. deployer sur un canari et comparer couverture, debit, doublons et latence ;
5. appliquer au role exact puis revalider la configuration effective ;
6. reconstruire l'acceleration seulement si le changement CIM le requiert et si
   la capacite le permet.

## Rollback et retour arriere

- restaurer le package precedent et recharger ou redemarrer uniquement si requis ;
- conserver la source canari jusqu'a equivalence ;
- ne pas tenter d'effacer ou reindexer des donnees historiques pendant le rollback ;
- isoler le traitement historique dans un changement dedie avec deduplication.

## Criteres de sortie

- 100 % des fixtures passent les assertions parsing ;
- couverture des champs pivots au-dessus du contrat ;
- ecart brut/data model compris et sous le seuil ;
- zero doublon et zero troncation sur le canari ;
- `_time` et lag p95 conformes ;
- detections et dashboards dependants valides.

## Preuves

- hash des fixtures, assertions attendues et obtenues ;
- taux de couverture avant/apres sans valeurs sensibles ;
- extraits `btool --debug` limites aux stanzas concernees ;
- diff props/transforms/eventtypes/tags et hash du package ;
- comparaison data model et resultat des cas d'usage dependants.

Reference : [props.conf specification](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.3-configuration-file-reference/props.conf).
