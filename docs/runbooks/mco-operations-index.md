# Runbooks MCO Splunk - cadre d'exploitation

## Portee

Ce dossier couvre huit incidents d'administration Splunk a fort impact : licence,
scheduler, KV Store, capacite, silence d'une source, parsing/CIM, certificats et
perte d'un peer d'indexation. Les procedures s'appliquent a Splunk Enterprise et,
lorsque le composant est present, a Splunk Enterprise Security.

> Statut de validation : procedures revues et drills synthetiques hors ligne.
> Aucun document de ce lot ne constitue, a lui seul, une preuve d'execution live.

## Contrat commun

Chaque incident suit le meme contrat :

1. dater le debut, nommer le pilote et ouvrir la chronologie UTC ;
2. confirmer le symptome par deux signaux independants ;
3. qualifier l'impact sur ingestion, recherche, detection et retention ;
4. choisir une decision explicite : observer, contenir, corriger ou restaurer ;
5. ne changer qu'une variable a la fois dans un package versionne ;
6. conserver le retour arriere disponible jusqu'aux criteres de sortie ;
7. clore avec une preuve expurgee et une action preventive attribuee.

Les commandes REST utilisent une URL HTTPS et une CA approuvee. `curl` recoit
seulement le nom de compte avec `--user` et demande le secret interactivement.
Les mots de passe, jetons, cookies, URI internes, noms d'hotes et evenements bruts
ne sont jamais copies dans un ticket ou un artefact public.

```bash
export SPLUNK_MGMT_URL="https://splunk-mgmt.example.invalid:8089"
export SPLUNK_USER="mco_operator"
export SPLUNK_CA="/path/to/approved-ca.pem"
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" \
  --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/server/health/splunkd?output_mode=json"
```

## Matrice de priorite

| Niveau | Condition type | Engagement initial | Escalade |
|---|---|---:|---|
| SEV1 | recherche de securite indisponible, indexation arretee ou perte de quorum | 15 min | responsable de service et equipes dependantes |
| SEV2 | couverture degradee, source critique silencieuse ou RF/SF non respectes | 30 min | plateforme, SOC et proprietaire de source |
| SEV3 | seuil preventif franchi sans impact fonctionnel | 4 h | backlog MCO avec echeance |

Les seuils locaux, le RTO, le RPO et les SLA de fraicheur priment sur les valeurs
indicatives de ces runbooks.

## Runbooks

| Scenario | Procedure | Signal directeur |
|---|---|---|
| quota ou violation de licence | [license-quota-incident.md](license-quota-incident.md) | usage journalier, messages licenser, recherche |
| recherches planifiees sautees | [scheduler-skipped-searches.md](scheduler-skipped-searches.md) | ratio de skip, motif, criticite |
| KV Store indisponible | [kv-store-unavailable.md](kv-store-unavailable.md) | status, replicationStatus, canari |
| pression disque ou index | [index-capacity-pressure.md](index-capacity-pressure.md) | espace libre, queues, projection |
| source silencieuse | [source-silence.md](source-silence.md) | fraicheur par source et SLA |
| regression parsing ou CIM | [parsing-cim-regression.md](parsing-cim-regression.md) | couverture de champs, doublons, data model |
| certificat proche de l'expiration | [certificate-expiry-incident.md](certificate-expiry-incident.md) | chaine, SAN, jours restants |
| peer indexer perdu | [indexer-peer-loss.md](indexer-peer-loss.md) | validite, completude, RF/SF, fix-up |

## Preuve recevable

Une preuve de cloture contient les horodatages UTC, la version Splunk, le role du
noeud, les mesures avant/apres, la decision, le changement, son approbation et les
criteres de sortie. Elle contient un hash SHA-256 du package et des resultats
expurges. Une capture seule, un statut `green` isole ou un drill synthetique ne
prouvent pas une remediation en production.

## Drills hors ligne

Le harness ne se connecte a aucune instance et n'execute aucune commande :

```bash
python scripts/run_mco_drills.py --validate-docs
python scripts/run_mco_drills.py --scenario scheduler_skipped_searches
```

Son rapport porte obligatoirement `live_execution=false` et
`claimable_as_live_proof=false`. Voir
[mco-drill-harness.md](mco-drill-harness.md).

## Qualification live en lecture seule

Le mode live observe cinq familles de controles via HTTPS avec CA et hostname
verifies. Il n'injecte aucun incident et ne lit aucun evenement brut. Apres
authentification, il utilise des endpoints REST GET et un unique export `tstats`
agrege sans SID ni commande mutante.

L'observation live prouve un etat ponctuel ; elle ne prouve ni remediation, ni
rollback, ni absence historique de skips. Cette frontiere et le gate de publication
sont detailles dans
[mco-live-read-only-qualification.md](mco-live-read-only-qualification.md).

La qualification du 7 aout 2026 a franchi les cinq controles et est publiee dans
[mco-live-read-only-qualification-20260807.json](../../artifacts/public/mco-live-read-only-qualification-20260807.json).

## References officielles

- [Monitoring Splunk Enterprise](https://help.splunk.com/splunk-enterprise/administer/monitor/10.0/introduction/monitoring-splunk-enterprise-overview)
- [About license violations](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/manage-splunk-licenses/about-license-violations)
- [KV Store troubleshooting tools](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/administer-the-app-key-value-store/kv-store-troubleshooting-tools)
- [Configure maximum index size](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.2/manage-index-storage/configure-maximum-index-size)
- [Take a peer offline](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.1/manage-the-indexer-cluster/take-a-peer-offline)
