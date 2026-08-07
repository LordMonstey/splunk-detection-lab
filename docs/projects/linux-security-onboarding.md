# Onboarding sécurité Linux : auditd, journald et rsyslog

## Statut de la preuve

Ce dossier définit la configuration cible, un dataset synthétique et les
contrôles d'acceptation. Le contrat de parsing et de normalisation a été
qualifié sur Splunk Enterprise 10.2.1 par un replay live isolé. Cette campagne
ne vaut pas qualification d'une collecte Universal Forwarder sur hôte réel.

| Élément | État actuel |
|---|---|
| Contrat de collecte Universal Forwarder | configuration cible versionnée |
| Parsing et normalisation | configuration cible versionnée |
| Dataset auditd / journald / rsyslog | synthétique, non sensible |
| Tests statiques | exécutables avec `validate_linux_onboarding.py` |
| Validation Splunk live | 13/13 contrôles réussis sur replay synthétique isolé |
| Collecte hôte réelle | non exécutée |

La preuve publique assainie est
[`linux-onboarding-evidence-20260807.json`](../../artifacts/public/linux-onboarding-evidence-20260807.json).
Elle sépare explicitement le contrat de parsing démontré de la collecte hôte
qui reste à qualifier.

## Architecture cible

1. Le Universal Forwarder lit `audit.log` et le journal d'authentification
   rsyslog, puis utilise l'entrée journald native pour une liste bornée de
   services de sécurité.
2. Le parsing tier applique la segmentation, l'horodatage et la limite de
   taille depuis `props.conf`.
3. Le search tier applique les extractions de `transforms.conf`, les alias et
   champs calculés, puis les eventtypes et tags CIM.
4. L'index `os_linux` dispose d'une rétention et d'un RBAC propres aux données
   système, distincts des données Windows et des artefacts de détection.

Les fichiers `.example` ne sont pas chargés par Splunk. Ils doivent être
revus, fusionnés dans une application Splunk, puis validés avec `btool` avant
déploiement :

- [`linux-inputs.conf.example`](../../conf/uf/linux-inputs.conf.example) ;
- [`props-linux.conf.example`](../../conf/splunk/default/props-linux.conf.example) ;
- [`transforms-linux.conf.example`](../../conf/splunk/default/transforms-linux.conf.example).

## Stratégie de collecte et contrôle des doublons

Le profil Debian cible trois flux complémentaires :

| Flux | Entrée active | Portée |
|---|---|---|
| auditd | `/var/log/audit/audit.log` | syscall, PAM, gestion de compte, politique d'audit |
| rsyslog | `/var/log/auth.log` | SSH, sudo, useradd et événements d'authentification |
| journald | entrée native filtrée | état de `auditd`, `cron` et `systemd-logind` |

`/var/log/syslog`, `/var/log/messages` et `/var/log/secure` sont fournis comme
alternatives désactivées. Le principe de contrôle est simple : une famille
d'événements, un collecteur responsable. Un hôte RHEL active `/var/log/secure`
à la place de `/var/log/auth.log`; un hôte sans entrée journald native active
son journal texte à la place, jamais en parallèle sans test de non-recouvrement.

Contrôle SPL de doublons après mise en service :

```spl
index=os_linux earliest=-24h
| eval event_fingerprint=sha256(host."|".replace(_raw,"\s+"," "))
| stats count dc(source) AS source_count values(source) AS sources by event_fingerprint
| where count>1 OR source_count>1
| stats count AS duplicate_groups sum(count) AS duplicate_events
```

L'objectif est `duplicate_events / total_events < 0,5 %`, avec justification
de chaque exception connue.

## Parsing et horodatage

### auditd

Chaque record auditd reste un événement Splunk. Le couple
`audit_epoch:audit_serial` est extrait pour reconstruire un scénario multi-record
au moment de la recherche sans utiliser `transaction`. L'époque Unix portée par
`msg=audit(...)` devient `_time`; `LINE_BREAKER` maintient une ligne par record.

Pour corréler sans explosion mémoire :

```spl
index=os_linux sourcetype=linux:auditd earliest=-15m
| stats values(audit_type) AS record_types values(exe) AS exe values(comm) AS comm
        values(key) AS audit_key values(success) AS success
        min(_time) AS first_time max(_time) AS last_time
  by host audit_serial
```

### journald

L'entrée native s'appuie sur `journalctl`, conserve les champs utiles et écarte
les identifiants de boot ou d'invocation à très forte cardinalité. La liste de
services est explicitement bornée. Le dataset NDJSON sert uniquement à tester
la représentation structurée hors ligne; l'entrée native gère son curseur et
l'horodatage en exécution réelle.

### rsyslog

Le format cible est RFC3339 en UTC. L'en-tête produit `dest`, `dvc`, `app` et
`process_id`; des transforms spécialisés couvrent SSH, sudo, useradd et
systemd sans lancer une extraction générique incontrôlée sur toute la charge.

## Contrat CIM

Le mapping suit les champs et valeurs prescrits par les références Splunk CIM
pour [Authentication](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.3/data-models/authentication),
[Change](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.2/data-models/change)
et [Endpoint](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.1/data-models/endpoint).

| Dataset CIM | Événements | Champs de contrôle |
|---|---|---|
| Authentication | auditd `USER_AUTH`, SSH accepté/refusé | `action`, `app`, `dest`, `src`, `user`, `authentication_method` |
| Change.All_Changes | `USER_MGMT`, `CONFIG_CHANGE`, useradd, sudo borné | `action`, `change_type`, `command`, `dest`, `dvc`, `object_id`, `object_path`, `status`, `user` |
| Endpoint.Processes | auditd `SYSCALL` execve | `action`, `dest`, `process*`, `parent_process_id`, `user`, `vendor_product` |
| Endpoint.Services | unités systemd | `dest`, `service*`, `service_path`, `start_mode`, `status`, `user`, `vendor_product` |

Les tags sont générés par `tags.conf`, pas par une extraction nommée `tag`.
Après recette des champs, intégrer les contraintes suivantes dans les fichiers
standards de l'application :

```ini
# eventtypes.conf
[linux_authentication]
search = index=os_linux ((sourcetype=linux:auditd audit_type=USER_AUTH) OR (sourcetype=linux:rsyslog app=sshd action IN (success,failure)))

[linux_account_change]
search = index=os_linux ((sourcetype=linux:auditd audit_type="USER_MGMT") OR (sourcetype=linux:rsyslog app="useradd" status="success"))

[linux_audit_change]
search = index=os_linux sourcetype=linux:auditd audit_type="CONFIG_CHANGE"

[linux_privileged_endpoint_change]
search = index=os_linux sourcetype=linux:rsyslog app="sudo" status="success" (command="/usr/bin/systemctl *" OR command="/usr/sbin/useradd *" OR command="/usr/sbin/usermod *" OR command="/usr/bin/chmod *" OR command="/usr/bin/chown *" OR command="/usr/sbin/auditctl *")

[linux_process_start]
search = index=os_linux sourcetype=linux:auditd audit_type=SYSCALL syscall=59

[linux_service_state]
search = index=os_linux ((sourcetype=linux:journald service=*.service) OR (sourcetype=linux:rsyslog app=systemd service=*.service))
```

```ini
# tags.conf
[eventtype=linux_authentication]
authentication = enabled

[eventtype=linux_account_change]
change = enabled
account = enabled

[eventtype=linux_audit_change]
change = enabled
audit = enabled

[eventtype=linux_privileged_endpoint_change]
change = enabled
endpoint = enabled

[eventtype=linux_process_start]
process = enabled
report = enabled

[eventtype=linux_service_state]
service = enabled
report = enabled
```

Le filtre `sudo` doit rester borné aux commandes qui modifient réellement
l'état d'un endpoint. Une commande de lecture ne doit pas être classée Change.

## Déploiement contrôlé

### Pré-contrôles

```text
$SPLUNK_HOME/bin/splunk btool inputs list --debug
$SPLUNK_HOME/bin/splunk btool props list linux:auditd --debug
$SPLUNK_HOME/bin/splunk btool props list linux:journald --debug
$SPLUNK_HOME/bin/splunk btool props list linux:rsyslog --debug
$SPLUNK_HOME/bin/splunk btool transforms list linux_auditd_header --debug
$SPLUNK_HOME/bin/splunk btool check --debug
python scripts/validate_linux_onboarding.py
```

### Canary puis généralisation

1. Déployer l'application d'entrée sur un seul forwarder canary.
2. Vérifier les droits de lecture sans rendre les journaux world-readable.
   Pour auditd, préférer une ACL étroite persistée par la politique de rotation
   ou une méthode d'export dédiée; documenter explicitement le choix.
3. Vérifier `splunk list monitor`, `metrics.log`, les files d'attente et la
   fraîcheur par sourcetype.
4. Rejouer le dataset synthétique dans l'index de laboratoire.
5. Collecter au moins une fenêtre réelle de 24 heures sur le canary.
6. Promouvoir par anneaux après satisfaction des critères d'acceptation.
7. Rollback : désactiver l'application de déploiement, recharger le forwarder,
   confirmer l'arrêt des nouvelles écritures puis conserver les données déjà
   indexées selon la politique de rétention.

## Contrôles de qualité

Inventaire et fraîcheur :

```spl
index=os_linux earliest=-24h
| stats count latest(_time) AS latest_event dc(host) AS hosts by sourcetype
| eval freshness_seconds=now()-latest_event
| convert ctime(latest_event)
```

Décalage d'horloge et latence d'indexation :

```spl
index=os_linux earliest=-24h
| eval ingest_delay=_indextime-_time
| stats count median(ingest_delay) AS p50 perc95(ingest_delay) AS p95
        max(ingest_delay) AS max_delay by host sourcetype
```

Complétude CIM par dataset :

```spl
index=os_linux earliest=-24h
| eval cim_scope=case(
    audit_type="USER_AUTH" OR app="sshd", "Authentication",
    audit_type IN ("USER_MGMT","CONFIG_CHANGE") OR app IN ("useradd","sudo"), "Change",
    audit_type="SYSCALL", "Endpoint.Processes",
    isnotnull(service), "Endpoint.Services")
| eval required_ok=case(
    cim_scope="Authentication", isnotnull(action) AND action!="unknown" AND isnotnull(app) AND app!="unknown" AND isnotnull(dest) AND dest!="unknown" AND isnotnull(user) AND user!="unknown",
    cim_scope="Change", isnotnull(action) AND action!="unknown" AND isnotnull(change_type) AND change_type!="unknown" AND isnotnull(command) AND command!="unknown" AND isnotnull(dest) AND dest!="unknown" AND isnotnull(status) AND status!="unknown" AND isnotnull(user) AND user!="unknown",
    cim_scope="Endpoint.Processes", isnotnull(action) AND action!="unknown" AND isnotnull(dest) AND dest!="unknown" AND isnotnull(process_id) AND isnotnull(process_path) AND process_path!="unknown" AND isnotnull(user) AND user!="unknown",
    cim_scope="Endpoint.Services", isnotnull(dest) AND dest!="unknown" AND isnotnull(service) AND service!="unknown" AND isnotnull(service_path) AND service_path!="unknown" AND isnotnull(status) AND status!="unknown" AND isnotnull(user) AND user!="unknown",
    true(), false())
| stats count sum(required_ok) AS complete by cim_scope sourcetype
| eval completeness_pct=round(100*complete/count,2)
```

Contrôle via les data models après installation du Splunk Common Information
Model Add-on et des tags :

```spl
| tstats summariesonly=f count from datamodel=Authentication.Authentication
  where index=os_linux by Authentication.action Authentication.app Authentication.user

| tstats summariesonly=f count from datamodel=Change.All_Changes
  where index=os_linux by All_Changes.action All_Changes.change_type All_Changes.user

| tstats summariesonly=f count from datamodel=Endpoint.Processes
  where index=os_linux by Processes.process_name Processes.user Processes.dest

| tstats summariesonly=f count from datamodel=Endpoint.Services
  where index=os_linux by Services.service_name Services.status Services.dest
```

## Seuils d'acceptation

| Contrôle | Seuil cible |
|---|---:|
| sources attendues actives | 100 % |
| événements avec `host`/`dest` connu | 100 % |
| complétude des champs CIM requis | au moins 95 % par scope |
| délai d'indexation p95 en régime nominal | moins de 300 s |
| groupes de doublons non justifiés | moins de 0,5 % |
| événements tronqués | 0 |
| erreurs de parsing ou d'horodatage | 0 bloquante |

## Résultats live du replay de qualification

| Date UTC | Périmètre | Splunk | Événements | Scopes normalisés | Complétude | Doublons | p95 commit | Résultat |
|---|---|---|---:|---:|---:|---:|---:|---|
| 2026-08-07 | replay synthétique isolé | 10.2.1 | 13/13 | 4/4 | 100 % | 0 | 3 s | PASS |

Les trois sourcetypes `linux:auditd`, `linux:journald` et `linux:rsyslog` ont
produit les volumes attendus. Les quatre scopes de contrôle Authentication,
Change, Endpoint.Processes et Endpoint.Services atteignent 100 % sur les
champs requis de cette campagne. Aucun événement brut, secret, adresse privée,
nom d'hôte réel ou identifiant de personne n'est publié.

La collecte Universal Forwarder sur hôte réel reste un gate séparé. Sa preuve
devra joindre l'état du forwarder, les sorties `btool`, une fenêtre suffisante,
les métriques de files et de fraîcheur, puis confirmer l'absence de perte ou de
duplication lors de la reprise.
