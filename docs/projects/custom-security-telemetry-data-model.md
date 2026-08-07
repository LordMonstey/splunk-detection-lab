# Data model custom de qualification des télémétries de sécurité

## Résultat visé

Le projet ajoute `Security Telemetry Qualification`, un data model Splunk
custom destiné à qualifier une chaîne complète : connaissances de recherche,
permissions, accélération persistante, interrogation `tstats`, parité avec les
événements source et fraîcheur.

Ce modèle n'est pas un data model CIM natif. L'application
`Splunk_SA_CIM` et Splunk Enterprise Security ne sont pas installés dans
l'instance qualifiée. Cette limite est volontairement contrôlée dans le modèle,
le collecteur et la preuve publique. Le projet démontre l'administration d'un
data model Splunk sans revendiquer une validation native du CIM ou de Splunk ES.

## Définition

Le fichier
[`Security_Telemetry_Qualification.json`](../../conf/splunk/default/data/models/Security_Telemetry_Qualification.json)
déclare un dataset racine `Security_Telemetry` et six datasets enfants :

| Dataset | Sélection |
| --- | --- |
| `Authentication_Activity` | tag `authentication` |
| `Change_Activity` | tag `change` |
| `Process_Activity` | tag `process` |
| `Network_Activity` | tag `network` |
| `File_Registry_Activity` | tags `filesystem` ou `registry` |
| `Service_Activity` | tag `service` |

La contrainte racine commence par les trois index gérés par le laboratoire. Elle
référence ensuite les 20 eventtypes et les 7 tags déjà fournis par l'application.
Ce cadrage limite le coût de la synthèse et rend les dépendances auditables.

Le dataset racine expose 16 champs, dont `_time`, `host`, `source`,
`sourcetype`, `action`, `user`, `dest`, `src`, les attributs de processus, de
service, de fichier et de résolution DNS. Ces champs proviennent des alias et
évaluations de recherche de l'application; ils ne sont pas présentés comme un
contrat CIM natif.

## Accélération et permissions

[`datamodels.conf`](../../conf/splunk/default/datamodels.conf) active une
synthèse sur sept jours, planifiée toutes les cinq minutes. Les anciennes
synthèses sont refusées après une modification de définition. Le modèle est
partagé globalement en lecture, tandis que l'écriture reste limitée au rôle
`admin`.

Splunk impose qu'un data model soit partagé avant son accélération et indique
que les datasets événementiels racine peuvent être accélérés. Les synthèses
sont ensuite interrogées avec `tstats`; `summariesonly=t` interdit le repli sur
les données non résumées. Voir la documentation officielle :

- [Manage data models](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/build-a-data-model/manage-data-models)
- [Accelerate data models](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/use-data-summaries-to-accelerate-searches/accelerate-data-models)

## Déploiement contrôlé

La mise en service suit ce chemin :

1. sauvegarder l'application installée et calculer le SHA-256 de l'archive;
2. construire deux fois le package et vérifier que son SHA-256 reste identique;
3. contrôler les chemins de l'archive avant l'installation;
4. installer la version `0.7.3` et conserver le package `0.7.2` comme retour arrière;
5. traiter explicitement l'indication `Restart required by: server`;
6. vérifier Splunk Web en TLS, la santé `splunkd`, KV Store et `btool`;
7. attendre une synthèse complète avant toute conclusion sur l'accélération.

Le retour arrière consiste à restaurer l'archive pré-déploiement ou à réinstaller
le package `0.7.2`, puis à redémarrer Splunk et à exécuter les mêmes contrôles.
Aucun secret, certificat privé ou archive de sauvegarde n'est placé dans le
dépôt public.

## Qualification live

Le collecteur
[`qualify_custom_datamodel_live.py`](../../scripts/qualify_custom_datamodel_live.py)
échoue si un seul des contrôles suivants est absent :

- version Splunk et version d'application attendues;
- santé `splunkd` verte et KV Store prêt;
- définition chargée par la commande `datamodel`;
- hiérarchie, champs, eventtypes, tags et périmètre d'index exacts;
- mention explicite du caractère custom et non-CIM;
- partage global en lecture et écriture réservée à `admin`;
- accélération active sur sept jours sans anciennes synthèses;
- état complet, au moins un bucket et aucune erreur de synthèse;
- résultat non vide avec `tstats summariesonly=t`;
- compte et dernière date identiques entre recherche brute et synthèse;
- fraîcheur conforme au seuil de 900 secondes;
- absence de Splunk ES et de `Splunk_SA_CIM` dans l'instance qualifiée.

Le rapport public ne contient ni adresse, ni endpoint, ni source d'événement,
ni événement brut, ni SPL complet, ni identifiant de job. Les contraintes du
modèle sont représentées par leur empreinte SHA-256 et des comptes de
dépendances.

Preuve :
[`custom-datamodel-live-evidence-10.2.1-20260807.json`](../../artifacts/public/custom-datamodel-live-evidence-10.2.1-20260807.json).

## Résultat observé le 7 août 2026

| Contrôle | Résultat assaini |
| --- | --- |
| Plateforme | Splunk Enterprise `10.2.1`, topologie standalone |
| Application | `0.7.3`, package SHA-256 `6014053ee7183d0148c8dbb334ea635c0284bbc1428c582f7e07dca82638cfa4` |
| Santé | `splunkd` vert, KV Store prêt |
| Résumé | complet, 4 buckets, 8 192 octets, aucune erreur |
| Fenêtre de contrôle | 60 minutes |
| Recherche brute | 2 événements agrégés |
| `tstats summariesonly=t` | 2 événements agrégés |
| Parité | 100 %, écart de date 0 seconde |
| Fraîcheur | 613,046 secondes pour un SLA de 900 secondes |
| Acceptation | 13 contrôles sur 13 |

Le premier cycle d'accélération avait terminé avec un statut scheduler réussi,
mais sans résultat dans les fichiers TSIDX. L'analyse du journal de recherche a
montré que trois eventtypes Linux utilisaient `action` ou `status` dans leur
contrainte. Ces champs sont calculés à la recherche et leurs valeurs normalisées
n'existent pas comme termes dans l'événement indexé. Le plan d'exécution les
avait néanmoins poussés dans le filtre de lecture des buckets, ce qui produisait
zéro candidat.

Le correctif conserve les sélecteurs index, sourcetype et application, mais
retire ces seuls prédicats calculés des trois eventtypes. Le résumé vide a
ensuite été reconstruit par l'action native Splunk, puis alimenté par le texte de
synthèse généré par la plateforme. La preuve n'a été acceptée qu'après lecture
non vide en `summariesonly=t`, parité brute/résumé et contrôle de fraîcheur.

## Reproduire les contrôles

```powershell
python scripts/validate_conf.py
python scripts/build_splunk_app.py --output artifacts/build
python -m unittest tests.test_qualify_custom_datamodel_live
```

La qualification live exige un endpoint Splunk en TLS vérifié et un secret lu
depuis l'environnement ou une saisie masquée :

```powershell
python scripts/qualify_custom_datamodel_live.py `
  --uri https://splunk.example.test:8000 `
  --transport web `
  --ca-bundle C:\secure\ca.cert.pem `
  --app-package artifacts\build\splunk-detection-lab-0.7.3.tar.gz `
  --output artifacts\public\custom-datamodel-live-evidence-10.2.1-20260807.json
```

L'adresse de connexion peut être épinglée avec `--connect-ip`; elle sert au
transport mais n'est jamais écrite dans le rapport.
