# Platform et CIM Assurance

Cette surface rassemble les contrôles qui précèdent toute conclusion de
détection : santé de la plateforme, état des indexes, disponibilité des
sources, fraîcheur et complétude des champs normalisés.

## État runtime vérifié

| Contrôle | Résultat |
|---|---:|
| Splunk Enterprise | 10.2.1 |
| Application | 0.7.3 |
| Santé splunkd | verte |
| Licence | OK |
| Indexes applicatifs configurés | 5 |
| Qualification MCO live | 5 / 5 |

## Snapshot de détection historique

La campagne de détection du 2026-08-06 a été figée sous l'application 0.6.4.
Ses métriques restent immuables et ne sont pas utilisées comme inventaire du
runtime courant.

| Contrôle | Résultat |
|---|---:|
| Application de la campagne | 0.6.4 |
| Événements Windows contrôlés | 152 |
| Événements risk / notable | 19 / 2 |
| Complétude des champs processus | 100 % |
| Recherches dashboards | 49 / 49 |

Les 134 événements Sysmon Process Creation possèdent les champs attendus pour
`process`, `process_guid`, `process_name`, `user`, `dest`,
`process_cmdline` et `parent_process_path`. La mesure porte sur le jeu de
validation identifié, pas sur une promesse générale de qualité future.

## Gouvernance des indexes

| Index | Rétention | Taille maximale | Usage |
|---|---:|---:|---|
| `sysmon` | 90 jours | 12 000 MB | télémétrie Sysmon |
| `windows` | 90 jours | 8 000 MB | journaux Windows natifs |
| `risk` | 365 jours | 1 000 MB | risk modifiers compatibles ES |
| `notable` | 365 jours | 1 000 MB | findings versionnés |
| `os_linux` | 90 jours | 8 000 MB | télémétrie sécurité Linux |

La séparation facilite les politiques de rétention, les contrôles d'accès et
le suivi de capacité. Les valeurs sont bornées dans `indexes.conf` et vérifiées
dans la configuration effective.

## Contrôles d'administration

- validation complète de la configuration avec `splunk btool check --debug` ;
- inspection de la précédence `default/local` avant installation ;
- package déterministe et manifeste SHA-256 ;
- redémarrage contrôlé puis nouvelle validation des recherches ;
- gestion SSH par clé et management plane filtré par le pare-feu hôte ;
- HEC de replay révoqué et désactivé après la campagne ;
- artefacts publics sans secret, IP privée ni événement brut.

## Diagnostic rapide

Un écart de détection se traite dans cet ordre : disponibilité de la source,
horodatage, parsing, aliases, tags/eventtypes, macros, puis SPL. Cette séquence
évite de tuner une règle pour compenser un défaut de données.

Les rapports publics de contrôle sont :

- [`live-detection-validation-20260806.json`](../artifacts/public/live-detection-validation-20260806.json) ;
- [`dashboard-search-validation-20260806.json`](../artifacts/public/dashboard-search-validation-20260806.json) ;
- [`splunk-engineering-snapshot-20260806.json`](../artifacts/public/splunk-engineering-snapshot-20260806.json), snapshot historique ;
- [`mco-live-read-only-qualification-20260807.json`](../artifacts/public/mco-live-read-only-qualification-20260807.json) ;
- [`linux-onboarding-evidence-20260807.json`](../artifacts/public/linux-onboarding-evidence-20260807.json) ;
- [`tls-rotation-evidence-20260807.json`](../artifacts/public/tls-rotation-evidence-20260807.json) ;
- [`rbac-live-evidence-9.4.13-20260807.json`](../artifacts/public/rbac-live-evidence-9.4.13-20260807.json) ;
- [`custom-datamodel-live-evidence-10.2.1-20260807.json`](../artifacts/public/custom-datamodel-live-evidence-10.2.1-20260807.json) ;
- [`periodic-reporting-live-evidence-10.2.1-20260807.json`](../artifacts/public/periodic-reporting-live-evidence-10.2.1-20260807.json).
- [`parsing-canary-rollback-evidence-20260807.json`](../artifacts/public/parsing-canary-rollback-evidence-20260807.json).

L'inventaire REST détaillé reste un artefact interne et n'est pas publié.

Les anciennes captures contenant des éléments propres à l'environnement ont été
retirées. Le [registre de retrait](../artifacts/public/evidence-redaction-register-20260807.json)
conserve leurs chemins retirés et pointe vers les preuves agrégées qui les
remplacent, sans publier d’identifiant de blob ni réécrire les artefacts historiques.
