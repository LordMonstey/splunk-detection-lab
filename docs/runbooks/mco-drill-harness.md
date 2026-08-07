# Harness de drills MCO hors ligne

## Finalite

`scripts/run_mco_drills.py` teste le contrat de decision des huit runbooks avec
des observations synthetiques. Il valide aussi leur structure et recherche des
motifs dangereux : secret en clair, adresse privee, desactivation TLS, suppression
REST, purge de buckets ou nettoyage Splunk.

Le harness :

- n'importe aucun client HTTP ;
- n'ouvre aucune socket et ne lance aucun sous-processus ;
- ne modifie ni Splunk, ni une VM, ni une configuration ;
- refuse une fixture qui autorise le reseau, un changement ou une action destructive ;
- qualifie chaque rapport de simulation non revendicable comme preuve live.

## Execution

Depuis la racine du depot :

```bash
python scripts/run_mco_drills.py --validate-docs
python scripts/run_mco_drills.py --list
python scripts/run_mco_drills.py --scenario kv_store_unavailable
python scripts/run_mco_drills.py --output tmp/mco-drill-report.json
```

Le fichier de sortie est optionnel. Il doit rester dans un espace de travail prive
tant qu'il n'a pas ete relu. Sa presence prouve seulement que le moteur de decision
a traite les fixtures ; elle ne prouve aucun incident ni changement reel.

## Scenarios et assertions

| Scenario | Etat incident | Signal synthetique | Sortie attendue |
|---|---|---|---|
| `license_quota` | critique | quota depasse et message critique | recherche disponible, quota sous seuil |
| `scheduler_skipped_searches` | critique | skip d'une recherche prioritaire | trois cycles representes sans skip |
| `kv_store_unavailable` | critique | statut failed | ready, replication stable, canari valide |
| `index_capacity_pressure` | critique | minFreeSpace et queue haute | marge disque et queues retablies |
| `source_silence` | critique | age superieur a trois SLA | fraicheur et doublons conformes |
| `parsing_cim_regression` | critique | couverture basse et troncations | parsing/CIM sous contrat de sortie |
| `certificate_expiry` | critique | moins de sept jours | chaine, nom et duree valides |
| `indexer_peer_loss` | critique | peer down, RF incomplet | cluster valide et complet |

## Ajout d'un cas

1. ajouter un objet dans `tests/fixtures/mco_drill_cases.json` ;
2. garder `provenance.kind=synthetic` et les trois permissions a `false` ;
3. fournir les observations `before`, `after` et les etats attendus ;
4. executer le scenario seul puis la suite complete ;
5. ne jamais copier une sortie live dans cette fixture.

## Limite de preuve

Un drill live futur doit utiliser un autre identifiant, une fenetre approuvee et un
artefact separe contenant les mesures reelles expurgees. Ce harness ne doit pas etre
renomme ni presente comme validation live.

Le mode d'observation live non intrusif est documente separement dans
[mco-live-read-only-qualification.md](mco-live-read-only-qualification.md). Il ne
remplace pas les fixtures : les fixtures testent les decisions, tandis que le mode
live constate uniquement un etat courant par REST GET et handshake TLS.
