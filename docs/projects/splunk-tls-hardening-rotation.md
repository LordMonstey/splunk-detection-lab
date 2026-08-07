# Sécurisation TLS Splunk : génération, rotation et rollback

## Portée et résultat attendu

Ce projet fournit une chaîne reproductible qualifiée en direct sur Splunk Enterprise 9.4.13. Les paramètres retenus existent aussi dans les références 10.2, mais une montée de version impose une nouvelle qualification complète :

- une autorité racine RSA-4096 dont la clé est chiffrée et conservée hors ligne ;
- un certificat de service RSA-4096 signé, avec SAN DNS explicites, sans SAN IP, et les EKU `serverAuth` et `clientAuth` ;
- des exemples `web.conf`, `server.conf`, `inputs.conf` et `outputs.conf` limités à TLS 1.2 ;
- la validation de la chaîne et du nom serveur côté client ;
- un contrôle hors ligne qui ne lit que les certificats publics et publie leurs empreintes SHA-256 ;
- une rotation par chemins versionnés, une bascule contrôlée et un rollback déterministe ;
- un gate de dépendance KV Store obligatoire avant la clôture du changement.

Le générateur ne produit rien dans le dépôt. Le répertoire de sortie est obligatoire, absolu, inexistant au démarrage et créé avec des permissions restrictives. Aucun certificat, aucune clé, aucun mot de passe et aucune adresse privée ne doivent être commités.

## Composants

| Fichier | Rôle |
|---|---|
| `scripts/generate_splunk_tls_material.sh` | Génère la CA et le certificat serveur dans un répertoire privé |
| `scripts/validate_splunk_tls.py` | Valide hors ligne chaîne, durée, SAN, usages, algorithmes et empreintes |
| `conf/tls-examples/web.conf` | Active HTTPS pour Splunk Web et HSTS sans sous-domaines ni preload |
| `conf/tls-examples/server.conf` | Sécurise le port de management et les connexions sortantes de `splunkd` |
| `conf/tls-examples/inputs.conf` | Active un receiver `splunktcp-ssl` TLS 1.2 |
| `conf/tls-examples/outputs.conf` | Force le forwarder à vérifier chaîne et nom des indexers |
| `conf/uf/server.conf` et `conf/uf/outputs.conf` | Modèle UF autonome : trust store global, TLS, validation de chaîne et de nom |

## Modèle de sécurité

La clé CA reste chiffrée par AES-256 et n'est jamais installée sur un noeud Splunk. La clé du service est volontairement non chiffrée pour permettre un redémarrage non interactif ; sa protection repose sur un propriétaire dédié, le mode `0600`, un répertoire `0700`, les sauvegardes chiffrées et un accès administrateur tracé. Le fichier `server.bundle.pem`, qui contient cette clé, est privé même si son extension est `.pem`.

Chaque noeud reçoit sa propre paire clé/certificat et ses propres SAN. Une même clé serveur ne doit jamais être réutilisée sur plusieurs search heads, indexers, managers ou forwarders. Seule la CA publique est commune.

Le profil de référence reste volontairement limité à TLS 1.2. C'est le protocole effectivement observé dans la preuve live 9.4.13. Aucune compatibilité TLS 1.3 n'est revendiquée par ce projet.

`sslVerifyServerCert = true` valide la chaîne. `sslVerifyServerName = true` impose la correspondance entre le nom utilisé pour joindre le service et le CN ou SAN présenté. Les deux contrôles sont nécessaires. Un chiffrement sans validation du pair ne constitue pas une authentification.

### Invariant KV Store

Un test HTTPS sur le port 8000 et un handshake valide sur le port 8089 ne suffisent pas à qualifier le certificat d'une instance Splunk. KV Store utilise le certificat inter-composants dans un contexte client et serveur. Le certificat utilisé par KV Store doit donc exposer les deux usages étendus X.509 :

- `TLS Web Server Authentication` (`serverAuth`) ;
- `TLS Web Client Authentication` (`clientAuth`).

La présence de `clientAuth` ne signifie pas que l'authentification mutuelle des forwarders est activée. Celle-ci dépend notamment de `requireClientCert = true` et d'un cycle de vie de certificats clients distinct, hors du périmètre exécuté ici.

La régression observée a précisément confirmé cet invariant : les rotations A et B, limitées à `serverAuth`, ont conservé Splunk Web et le port de management fonctionnels mais ont fait échouer KV Store avec `unsupported certificate purpose`. Elles ne constituent donc pas des rotations réussies de bout en bout. La rotation C a régénéré le certificat RSA-4096 avec `serverAuth,clientAuth`, puis a satisfait le gate KV Store.

## Préparation

1. Choisir un FQDN stable par service et vérifier sa résolution directe et inverse.
2. Recenser Splunk Web, port de management, receivers, deployment server, search peers et flux inter-noeuds.
3. Relever les empreintes, dates d'expiration et chemins actifs avant le changement.
4. Créer une fenêtre de changement et un critère de rollback : perte de connexion, arrêt d'ingestion, erreur de nom, erreur de chaîne, KV Store différent de `ready` après le délai borné ou santé cluster dégradée.
5. Préparer un chemin versionné, par exemple `$SPLUNK_HOME/etc/auth/tls/2026-rotation-a/`, sans remplacer les fichiers actifs.

## Génération hors ligne

Exécuter sur une machine d'administration Linux isolée disposant de Bash, OpenSSL et GNU coreutils. Le parent doit déjà exister, appartenir à l'opérateur et ne pas être accessible en écriture au groupe ou aux autres utilisateurs :

```bash
install -d -m 0700 /srv/pki-private
```

Générer ensuite un certificat distinct par noeud :

```bash
./scripts/generate_splunk_tls_material.sh \
  --output-dir /srv/pki-private/splunk-rotation-a \
  --organization "Example Security" \
  --ca-common-name "Example Splunk Root CA" \
  --server-common-name splunk-web.example.invalid \
  --dns splunk-web.example.invalid \
  --dns splunk-mgmt.example.invalid
```

Le script demande deux fois la phrase secrète de la CA. Elle ne transite ni dans les arguments de processus ni dans un fichier temporaire. La sortie contient :

- `private/ca.key.pem` : clé CA chiffrée, mode `0600`, à conserver hors ligne ;
- `private/server.key.pem` : clé du service, mode `0600` ;
- `private/server.bundle.pem` : clé, certificat serveur et chaîne, mode `0600` ;
- `public/ca.cert.pem` : ancre de confiance publique ;
- `public/server.cert.pem` : certificat serveur public seul ;
- `public/server.chain.pem` : certificat serveur suivi de la CA.

## Contrôle public hors ligne

Le validateur refuse un PEM contenant une clé privée, un lien symbolique, un SAN IP, un wildcard, SHA-1, MD5, une clé trop faible ou un ensemble de SAN inattendu :

```bash
python3 scripts/validate_splunk_tls.py \
  --ca-cert /srv/pki-private/splunk-rotation-a/public/ca.cert.pem \
  --server-cert /srv/pki-private/splunk-rotation-a/public/server.cert.pem \
  --expected-dns splunk-web.example.invalid \
  --expected-dns splunk-mgmt.example.invalid \
  --min-validity-days 30 \
  --json-output /srv/pki-private/splunk-rotation-a/public-validation.json
```

Le JSON est publiable après revue : il contient uniquement les métadonnées publiques, les SAN DNS et les empreintes SHA-256, jamais une clé ou un secret. Les chemins absolus ne sont pas inscrits dans le rapport.

Le validateur exécute les deux contrôles de finalité OpenSSL. Une rotation destinée au certificat inter-composants doit échouer dès le pré-déploiement si l'un des deux tests échoue :

```bash
openssl verify -purpose sslserver -CAfile public/ca.cert.pem public/server.cert.pem
openssl verify -purpose sslclient -CAfile public/ca.cert.pem public/server.cert.pem
openssl x509 -in public/server.cert.pem -noout -purpose -ext extendedKeyUsage
```

## Pré-déploiement Splunk

Installer les fichiers dans une application dédiée ou un chemin versionné. Ne jamais modifier `$SPLUNK_HOME/etc/system/default`.

Ne transférer sur le noeud que `ca.cert.pem`, le certificat ou la chaîne publique et la clé serveur qui lui appartient. `ca.key.pem` reste hors ligne. Appliquer les exemples par rôle : `web.conf` sur les interfaces Web, `inputs.conf` sur les receivers, `outputs.conf` sur les forwarders et `server.conf` sur chaque instance concernée. Ne pas pousser aveuglément les quatre fichiers sur toute la topologie.

```bash
$SPLUNK_HOME/bin/splunk btool web list settings --debug
$SPLUNK_HOME/bin/splunk btool server list sslConfig --debug
$SPLUNK_HOME/bin/splunk btool inputs list SSL --debug
$SPLUNK_HOME/bin/splunk btool outputs list tcpout:tls-indexers --debug
```

Vérifier que la configuration effective conserve :

- `sslVersions = tls1.2` ;
- `sslVerifyServerCert = true` ;
- `sslVerifyServerName = true` ;
- les EKU `serverAuth` et `clientAuth` sur le certificat utilisé par `server.conf` ;
- le trust store public attendu ;
- le bundle privé en `0600`, lisible seulement par le compte Splunk ;
- des FQDN de connexion présents dans les SAN.

Faire une sauvegarde de l'application active, de son checksum SHA-256 et des empreintes précédentes. Un mot de passe de clé éventuellement ajouté sur cible doit être géré par le mécanisme Splunk et ne doit jamais apparaître dans le dépôt ou un rapport.

## Bascule contrôlée

1. Déployer d'abord le nouveau trust store. Lors d'un changement de CA, distribuer temporairement un bundle contenant ancienne puis nouvelle CA.
2. Valider `btool` sur un canari et vérifier la lisibilité des fichiers par le compte Splunk.
3. Basculer le certificat serveur du canari vers le nouveau chemin versionné.
4. Effectuer le redémarrage contrôlé requis par le composant.
5. Rejouer les tests positifs et négatifs ci-dessous.
6. Attendre le résultat du gate KV Store. Ne pas clore ni étendre le changement tant que `status` n'est pas `ready` et `backupRestoreStatus` n'est pas `Ready`.
7. Observer au minimum la fraîcheur des événements, les connexions forwarders, les erreurs TLS et la santé des peers.
8. Étendre noeud par noeud. Retirer l'ancienne CA seulement après disparition de tous les clients utilisant l'ancienne chaîne.

## Tests positifs sans désactivation de validation

Les commandes conservent toujours la validation de chaîne et de nom ; aucune option de contournement TLS n'est admise.

```bash
export SPLUNK_WEB_FQDN=splunk-web.example.invalid
export SPLUNK_MGMT_FQDN=splunk-mgmt.example.invalid
export CA_FILE=/secure/public/ca.cert.pem

curl --fail --silent --show-error \
  --cacert "$CA_FILE" \
  "https://${SPLUNK_WEB_FQDN}:8000/en-US/account/login" >/dev/null

openssl s_client \
  -connect "${SPLUNK_MGMT_FQDN}:8089" \
  -servername "$SPLUNK_MGMT_FQDN" \
  -CAfile "$CA_FILE" \
  -verify_return_error \
  -verify_hostname "$SPLUNK_MGMT_FQDN" </dev/null
```

Dans Splunk, contrôler les connexions et erreurs sans publier de noms internes :

```spl
index=_internal source=*metrics.log group=tcpin_connections
| stats latest(_time) as last_seen latest(ssl) as tls by sourceHost
| eval freshness_seconds=now()-last_seen
| sort - freshness_seconds
```

```spl
index=_internal source=*splunkd.log (log_level=ERROR OR log_level=WARN)
  (component=SSLCommon OR component=TcpOutputProc OR component=TcpInputProc)
| stats count latest(_time) as last_seen by component log_level
```

## Gate de dépendance KV Store obligatoire

Le gate est exécuté avant le changement pour constituer la référence, puis après chaque redémarrage. La commande ne doit pas recevoir de mot de passe en argument ; utiliser l'authentification interactive ou le mécanisme d'identité administré par l'environnement :

```bash
"$SPLUNK_HOME/bin/splunk" show kvstore-status
```

Critères de passage sur une instance autonome :

- `status : ready` ;
- `backupRestoreStatus : Ready` ;
- aucun nouvel événement `unsupported certificate purpose` depuis la bascule ;
- une lecture authentifiée de `/services/kvstore/status` confirme le même état lorsque ce contrôle REST est automatisé.

Sur un search head cluster, le contrôle doit couvrir chaque membre et l'état de réplication. `starting` n'est qu'un état transitoire : il est sondé avec un délai maximal documenté. `failed`, un timeout, une erreur de finalité du certificat ou un membre non sain déclenchent le rollback. Un Web 200 ou un handshake 8089 réussi ne neutralise jamais cette décision.

## Tests négatifs obligatoires

Chaque test doit échouer avec un code non nul. L'échec attendu prouve que le contrôle n'a pas été neutralisé.

### Web en clair

```bash
if curl --fail --silent --show-error --max-time 5 \
  "http://${SPLUNK_WEB_FQDN}:8000/" >/dev/null; then
  echo "FAIL: cleartext Splunk Web was accepted" >&2
  exit 1
fi
```

### Nom serveur incorrect

```bash
if openssl s_client \
  -connect "${SPLUNK_MGMT_FQDN}:8089" \
  -servername "$SPLUNK_MGMT_FQDN" \
  -CAfile "$CA_FILE" \
  -verify_return_error \
  -verify_hostname wrong-name.example.invalid </dev/null; then
  echo "FAIL: hostname mismatch was accepted" >&2
  exit 1
fi
```

### Autorité non approuvée

```bash
export WRONG_CA_FILE=/secure/test-only/unrelated-ca.cert.pem
if openssl s_client \
  -connect "${SPLUNK_MGMT_FQDN}:8089" \
  -servername "$SPLUNK_MGMT_FQDN" \
  -CAfile "$WRONG_CA_FILE" \
  -verify_return_error \
  -verify_hostname "$SPLUNK_MGMT_FQDN" </dev/null; then
  echo "FAIL: untrusted chain was accepted" >&2
  exit 1
fi
```

### Protocole obsolète

```bash
if openssl s_client \
  -connect "${SPLUNK_MGMT_FQDN}:8089" \
  -servername "$SPLUNK_MGMT_FQDN" \
  -CAfile "$CA_FILE" \
  -verify_return_error \
  -tls1_1 </dev/null; then
  echo "FAIL: TLS 1.1 was accepted" >&2
  exit 1
fi
```

### Seuil d'expiration hors ligne

Utiliser un seuil supérieur à la durée restante doit faire échouer le validateur :

```bash
if python3 scripts/validate_splunk_tls.py \
  --ca-cert /secure/public/ca.cert.pem \
  --server-cert /secure/public/server.cert.pem \
  --expected-dns "$SPLUNK_WEB_FQDN" \
  --min-validity-days 398; then
  echo "FAIL: expiration threshold was not enforced" >&2
  exit 1
fi
```

## Rollback

Le rollback ne régénère rien et n'écrase aucun fichier.

1. Arrêter l'extension du changement dès le premier échec de chaîne, de nom, d'ingestion, de finalité EKU, de KV Store ou de santé.
2. Restaurer les chemins de configuration vers la version précédente dont le checksum et l'empreinte ont été enregistrés.
3. Conserver temporairement les deux CA dans le trust store si des clients ont déjà basculé.
4. Redéployer l'application précédente par le même mécanisme que la mise en service.
5. Redémarrer uniquement les composants concernés, dans l'ordre de la topologie.
6. Rejouer `btool`, les contrôles OpenSSL `sslserver` et `sslclient`, la validation de nom, le gate KV Store, la fraîcheur d'ingestion et la santé cluster.
7. Documenter la cause, les noeuds touchés, la durée, l'empreinte restaurée et la décision de clôture.

## Preuves de clôture

Le dossier de changement conserve uniquement des éléments non sensibles :

- version Splunk et rôle du composant, sans adresse privée ;
- empreinte SHA-256 avant et après ;
- dates de validité et SAN DNS anonymisés si nécessaire ;
- sortie du validateur public ;
- extraits `btool` nettoyés des chemins et noms internes ;
- résultats positifs, échecs attendus des quatre tests négatifs live et seuil d'expiration hors ligne ;
- état KV Store avant et après, y compris `backupRestoreStatus` ;
- métriques de fraîcheur et erreurs TLS agrégées ;
- décision de maintien ou de rollback.

## Preuve live publiée

La [preuve publique de rotation TLS](../../artifacts/public/tls-rotation-evidence-20260807.json) documente l'exécution du 7 août 2026 sur une instance autonome de laboratoire Splunk Enterprise 9.4.13 :

- rotations A et B : Web et management valides, mais gate de dépendance refusé car le certificat `serverAuth` seul était incompatible avec KV Store ;
- rotation C active : certificat RSA-4096 avec `serverAuth,clientAuth` ;
- Web HTTPS : statut 200, HSTS présent et Web en clair rejeté ;
- management 8089 : chaîne et nom validés, TLS 1.2 avec `ECDHE-RSA-AES256-GCM-SHA384` ;
- tests négatifs : mauvais nom, CA non approuvée et TLS 1.1 rejetés ;
- KV Store : `status=ready` et `backupRestoreStatus=Ready` après correction ;
- hygiène : clé de service en mode `0600` et aucune clé privée de CA sous l'arborescence Splunk.

Cette preuve qualifie une instance autonome de laboratoire. Elle ne prouve ni une topologie de production, ni l'authentification mTLS forwarder-indexer, ni l'installation native de Splunk Enterprise Security. Les rotations A et B sont conservées comme preuve de détection et de remédiation d'une régression, pas comme preuves de clôture réussie.

## Références officielles

- [Splunk Enterprise 9.4 - outputs.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.3-configuration-file-reference/outputs.conf)
- [Splunk Enterprise 9.4 - validation du nom entre composants](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificate-host-name-validation-for-secured-connections-between-splunk-software-components)
- [Splunk Enterprise 10.2 - préparation des certificats KV Store](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/administer-the-app-key-value-store/preparing-custom-certificates-for-use-with-kv-store)
- [Splunk Enterprise 10.2 - server.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/server.conf)
- [Splunk Enterprise 10.2 - outputs.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/outputs.conf)
- [Splunk Enterprise 10.2 - inputs.conf](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/configuration-file-reference/10.2.4-configuration-file-reference/inputs.conf)
- [Splunk Enterprise 10.2 - web.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.4-configuration-file-reference/web.conf)
- [Splunk - configuration TLS de l'indexation et du forwarding](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-splunk-indexing-and-forwarding-to-use-tls-certificates)
