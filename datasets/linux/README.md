# Jeu de validation Linux

Ce répertoire contient exclusivement des événements synthétiques destinés à
tester le contrat de parsing et de normalisation avant un déploiement. Les
noms d'hôtes et de comptes sont fictifs. `198.51.100.24` appartient au bloc
TEST-NET-2 réservé à la documentation et `example.test` au domaine de test.
Aucun secret, jeton, identifiant client ou événement de production n'est
présent.

## Contenu

| Fichier | Sourcetype cible | Cas couverts |
|---|---|---|
| `auditd.log` | `linux:auditd` | exécution autorisée/bloquée, PAM, gestion de compte, changement de politique d'audit |
| `journald.ndjson` | `linux:journald` | état de services systemd avec métadonnées structurées |
| `rsyslog.log` | `linux:rsyslog` | SSH, élévation sudo, création de compte, état de service |

Le dataset vérifie les contrats CIM suivants : Authentication, Change,
Endpoint.Processes et Endpoint.Services. Il ne prouve pas à lui seul qu'une
plateforme Splunk live applique les configurations : cette preuve doit être
produite par les contrôles SPL décrits dans
[`docs/projects/linux-security-onboarding.md`](../../docs/projects/linux-security-onboarding.md).

## Validation hors ligne

Depuis la racine du dépôt :

```text
python scripts/validate_linux_onboarding.py
```

Le validateur contrôle la structure des exemples `.conf`, parse chaque ligne,
vérifie les champs CIM minimaux par scénario et bloque les secrets apparents,
les adresses privées et les adresses publiques non réservées à la
documentation.

## Replay contrôlé en laboratoire

Après installation des stanzas revues et création de l'index `os_linux` :

```text
$SPLUNK_HOME/bin/splunk add oneshot datasets/linux/auditd.log -index os_linux -sourcetype linux:auditd -host lab-linux-01
$SPLUNK_HOME/bin/splunk add oneshot datasets/linux/journald.ndjson -index os_linux -sourcetype linux:journald -host lab-linux-01
$SPLUNK_HOME/bin/splunk add oneshot datasets/linux/rsyslog.log -index os_linux -sourcetype linux:rsyslog -host lab-linux-01
```

Utiliser `earliest=0` pour cette donnée datée. Ne jamais rejouer ces fichiers
dans un index de production ni confondre le résultat synthétique avec une
mesure issue d'une source réelle.
