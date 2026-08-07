# Reporting périodique MCO et CIM

## Finalité

Le dispositif conserve des mesures agrégées sur des périodes closes. Il ne
stocke ni événement brut, ni nom d'hôte, ni source, ni index, ni identifiant de
recherche. Le dashboard sépare explicitement la première baseline d'une
tendance exploitable.

## Architecture

- `report_mco_daily_aggregate` s'exécute chaque jour à 01:15 sur la journée
  précédente ;
- `report_cim_weekly_aggregate` s'exécute chaque lundi à 01:45 sur la semaine
  précédente ;
- les deux recherches écrivent dans le lookup KV Store
  `mco_cim_periodic_history` ;
- la clé SHA-256 dérivée de la famille, de la période et de la métrique rend une
  nouvelle exécution idempotente ;
- `schema_version=1` et `threshold_profile` figent le sens des valeurs ;
- le dashboard `periodic_mco_cim_reporting` lit uniquement l'agrégat.

Le schéma est long : une ligne représente une métrique pour une période. Cette
forme permet d'ajouter une métrique dans une future version du contrat sans
modifier les colonnes existantes. Les champs admis sont définis dans
`artifacts/templates/periodic-reporting-row.schema.json`.

## Seuils V1

| Domaine | Règle |
|---|---|
| Scheduler | `GREEN` à partir de 99 %, `WATCH` de 95 à 98,99 %, `ACTION` sous 95 % |
| Recherches sautées | `ACTION` dès qu'une exécution est sautée |
| Files d'attente | `WATCH` à partir de 75 %, `ACTION` à partir de 90 % |
| Sources en retard | `ACTION` dès qu'un dataset observé dépasse 15 minutes à la clôture |
| Complétude CIM | `GREEN` à partir de 99 %, `WATCH` de 95 à 98,99 %, `ACTION` sous 95 % |
| Absence d'échantillon | `NO_DATA`, jamais assimilé à `GREEN` |

Une modification de seuil exige un nouveau `threshold_profile`. La valeur
historique n'est donc jamais réinterprétée silencieusement.

`ingestion.active_datasets` et `ingestion.late_datasets` décrivent uniquement
les couples index/sourcetype observés pendant la période. La détection d'une
source attendue mais totalement silencieuse reste portée par le contrôle
d'inventaire et le runbook `source-silence.md` ; elle n'est pas extrapolée à
partir de cet agrégat.

## Mise en service contrôlée

1. Construire et déployer le package de l'application selon le runbook de
   changement.
2. Exécuter `btool check` et confirmer que KV Store est `ready`.
3. Lancer le harness de première exécution :

   ```powershell
   python scripts/qualify_periodic_reporting_live.py --uri https://splunk.example.invalid:8089 --username admin --ca-bundle C:\path\to\ca.cert.pem --output artifacts/public/periodic-reporting-live-evidence.json
   ```

   Le mot de passe est demandé sans écho et n'est jamais écrit dans la preuve.

4. Vérifier `2/2` recherches terminées, `invalid_rows=0` et une période par
   famille.
5. Contrôler visuellement les tableaux de la dernière période.

Le harness ne publie ni URI, ni identifiant de recherche, ni résultat brut, ni
identifiant technique. Sur une première exécution, sa preuve conserve
`trend_claimed=false`. Une courbe de tendance reste vide jusqu'à deux périodes
réelles pour sa famille.

## Retour arrière

La désactivation des deux recherches planifiées arrête toute nouvelle écriture.
Le dashboard peut être retiré sans modifier la collection. La collection ne
doit être purgée qu'après export, validation du périmètre et approbation du
propriétaire de service.

## Qualification hors ligne

```powershell
python scripts/validate_periodic_reporting.py --output artifacts/public/periodic-reporting-scaffold-20260807.json
python -m unittest tests.test_validate_periodic_reporting tests.test_qualify_periodic_reporting_live
```

La preuve hors ligne atteste le contrat, les horaires, l'idempotence et la
minimisation. Elle ne constitue pas une exécution live et ne revendique aucune
tendance historique.

## Qualification live du 2026-08-07

La qualification a été exécutée sur Splunk Enterprise 10.2.1 avec l'application
0.7.3. La connexion Web a validé la chaîne TLS et le nom du serveur. Splunkd est
resté vert et KV Store est resté `ready` avant et après les écritures.

Le premier cycle contrôlé est parti d'une collection vide et a produit 16
lignes : 7 métriques MCO et 9 métriques CIM. Le même cycle a ensuite été rejoué
sans changer la période. Le total est resté à 16 lignes, avec 16 clés uniques,
aucun doublon et aucune ligne hors schéma. Ce second passage qualifie l'upsert
idempotent ; il ne constitue pas une nouvelle période historique.

Les deux recherches sont actives, planifiées et possèdent une prochaine
exécution. Les cinq objets contrôlés, recherches, collection, lookup et
dashboard, sont lisibles par les rôles consommateurs et modifiables uniquement
par le rôle `admin`. Les dix recherches du dashboard lisent exclusivement le
lookup agrégé.

Une seule période quotidienne et une seule période hebdomadaire ont été
observées. `trend_eligible` et `trend_claimed` restent donc à `false`. La preuve
assainie est conservée dans
[`periodic-reporting-live-evidence-10.2.1-20260807.json`](../../artifacts/public/periodic-reporting-live-evidence-10.2.1-20260807.json).

## Références Splunk

- [outputlookup, keyed updates et KV Store](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/outputlookup)
- [collections.conf et types de champs](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.1-configuration-file-reference/collections.conf)
- [Configuration d'un lookup KV Store](https://help.splunk.com/en?resourceId=Splunk_Knowledge_ConfigureKVstorelookups&version=splunk-9_4)
