# Gouvernance RBAC Splunk Enterprise 9.4.13 à 10.2.1

## Statut de la preuve

**CONFIGURATION CIBLE ET PERSISTANTE** : le modèle de rôles, les limites de
recherche et la matrice de décision sont versionnés. Les six rôles ont été
chargés durablement par une application Splunk dédiée sur l'instance de recette.

**PREUVE LIVE EXÉCUTÉE - RÉUSSIE** : la campagne du 7 août 2026 a validé le
contrat sur Splunk Enterprise 9.4.13, build `1d070b2427bf`. Les 38 contrôles ont
réussi : 14 positifs et 24 négatifs. Les six identités mono-rôle éphémères ont
été supprimées, aucun rôle inattendu n'a été trouvé et la validation TLS est
restée active. La preuve publique est disponible dans
[`rbac-live-evidence-9.4.13-20260807.json`](../../artifacts/public/rbac-live-evidence-9.4.13-20260807.json).

| Élément | État | Preuve disponible |
|---|---|---|
| Contrat `authorize.conf` | configuration cible | `conf/splunk/default/authorize.conf.example` |
| Matrice d'accès | configuration cible | `conf/splunk/lookups/rbac_access_matrix.csv` |
| Cohérence statique | exécutable hors ligne | `scripts/validate_rbac_contract.py` |
| Persistance des six rôles | chargés par l'application Splunk | six actions `unchanged` pendant la recette |
| Harnais de recette REST | exécuté, sans secret persistant | `scripts/apply_rbac_live.py` |
| Recette Splunk Enterprise 9.4.13 | réussie | 38/38 contrôles |
| Contextes et tests par rôle | réussis | 14/14 positifs, 24/24 négatifs |
| Nettoyage | réussi | 6/6 utilisateurs éphémères supprimés, 0 rôle inattendu |
| Transport | conforme | HTTPS avec certificat vérifié |

La preuve porte sur une instance standalone Splunk Enterprise 9.4.13 avec
l'authentification Enterprise active. Elle ne couvre ni un Search Head Cluster,
ni la propagation distribuée des rôles, ni les rôles et capacités natifs de
Splunk Enterprise Security : la cible était une instance non-ES. La
compatibilité 10.2.1 reste démontrée par le contrat statique commun, pas par cet
artefact live 9.4.13. Splunk Free ne fournit pas la fonction d'authentification
nécessaire à cette recette.

## Principes de gouvernance

Le modèle applique quatre invariants :

1. Aucun rôle custom n'importe `admin`. Les capacités sont attribuées
   explicitement et restent auditables.
2. L'administration de la plateforme est séparée de l'administration des
   identités. Aucun rôle custom ne possède `edit_user`, `edit_roles`,
   `change_authentication` ou l'accès aux secrets stockés.
3. Les index autorisés sont énumérés sans `*`. Les index internes, les données
   de sécurité et la piste d'audit restent des périmètres indépendants.
4. Les valeurs de quota sont strictement positives. Dans `authorize.conf`, une
   valeur `0` peut signifier une absence de limite; elle est donc exclue ici.

Le compte natif `admin` reste une identité break-glass, protégée, surveillée et
non utilisée pour les opérations quotidiennes. Les changements de rôle et les
affectations d'identité passent par ce circuit de gouvernance ou par un mapping
IdP approuvé.

La définition des rôles ne suffit pas à accorder l'accès à une application ou à
ses objets. Les ACL de `metadata/local.meta`, des saved searches, des macros,
des lookups et des data models doivent être testées séparément. Splunk
Enterprise Security peut également ajouter des rôles et capacités propres à la
version installée : ils doivent être inventoriés sur la cible, jamais devinés
dans le dépôt.

Références de conception :

- [Spécification `authorize.conf` Splunk Enterprise 9.4.13](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.13-configuration-file-reference/authorize.conf)
- [Spécification `authorize.conf` Splunk Enterprise 10.2.1](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.1-configuration-file-reference/authorize.conf)
- [Endpoints REST d'accès Splunk Enterprise 10.2](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/access-endpoints/access-endpoint-descriptions)
- [Définition des rôles et capacités](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/manage-splunk-platform-users-and-roles/define-roles-on-the-splunk-platform-with-capabilities)

### Compatibilité de l'upgrade

Les 71 capacités uniques du premier brouillon ont été comparées, nom par nom,
aux deux spécifications officielles. Les 71 existent en 10.2.1. Quatre ne sont
pas définies en 9.4.13 : `edit_certificates`, `list_certificates`,
`edit_saved_search` et `list_saved_searches`. Elles sont donc absentes du socle
commun. Les 67 capacités restantes existent dans les deux versions et sont de
nouveau comparées à `/services/authorization/capabilities` avant toute écriture
live.

Ce retrait ne bloque pas la création d'objets personnels :
`edit_own_objects` conserve ce droit pour `detection_engineer` et
`soc_analyst`. Il évite en revanche de leur accorder, après upgrade, une
visibilité ou une édition globale des saved searches contournant leurs ACL.
La gestion REST des certificats reste un changement 10.2 distinct, à qualifier
après l'upgrade plutôt qu'à simuler dans le rôle commun.

`queuedSearchQuota` est également absent de 9.4.13. Il s'agit d'un réglage de
rôle introduit en 10.2, pas d'une capacité. Le socle commun conserve les quotas
de jobs, de recherches cumulées, de temps et de disque; un overlay 10.2 pourra
ajouter le quota de file d'attente après une qualification séparée.

## Configuration cible

Le fichier `conf/splunk/default/authorize.conf.example` reste volontairement
inerte dans le dépôt public. Sur l'instance testée, son contrat a été persisté
sous le nom `authorize.conf` dans la couche `local` d'une application Splunk
dédiée. Cette application est la source durable des rôles; l'API REST du harness
sert au pré-contrôle, à la vérification effective et à la gestion des identités
de recette. Pendant la campagne publiée, les six rôles correspondaient déjà au
contrat et le harness a donc enregistré l'action `unchanged` pour chacun, sans
les créer ni les écraser. Le fichier
`$SPLUNK_HOME/etc/system/default/authorize.conf` ne doit jamais être modifié.

L'absence d'`importRoles` est intentionnelle. L'héritage cumule les capacités
et les index autorisés; importer le rôle `user` ou `power` rendrait le périmètre
d'index moins lisible et pourrait l'élargir. Chaque rôle reçoit donc son socle
de recherche explicitement.

Les quotas cumulatifs ne deviennent effectifs que si
`enable_cumulative_quota = true` est activé dans `limits.conf`. Ce paramètre
constitue un changement distinct : il doit être qualifié avec la charge du
search tier avant activation. Les quotas individuels restent applicables sans
ce réglage.

## Modèle de rôles

| Rôle | Responsabilité | Index par défaut | Écritures sensibles explicitement absentes |
|---|---|---|---|
| `platform_admin` | configuration et MCO de la plateforme | `_internal`, `_audit` | utilisateurs, rôles, secrets stockés, delete, scripted inputs |
| `platform_operator` | diagnostic et exploitation en lecture | `_internal`, `_introspection` | configuration, restart, données sécurité, audit |
| `detection_engineer` | contenu de détection, planification et data models | Windows, Sysmon, Linux, risk, notable | administration plateforme, identités, audit |
| `soc_analyst` | investigation et objets personnels | Windows, Sysmon, Linux, risk, notable | planification, accélération, administration, audit |
| `audit_reader` | piste d'audit et inventaire read-only des identités | `_audit` | toute modification et toute donnée opérationnelle |
| `api_health` | compte technique de supervision REST | `_internal` déclaré mais non recherchable | capacité `search`, modification, identité, certificat |

`api_health` possède un périmètre d'index déclaré pour rendre le contrat
explicite, mais ne possède pas la capacité `search`. Il interroge uniquement
les endpoints REST de santé autorisés. Ajouter `search` à ce rôle serait un
changement de périmètre nécessitant une nouvelle revue.

### Limites de recherche

| Rôle | Jobs historiques | Jobs RT | Disque par utilisateur | Fenêtre historique |
|---|---:|---:|---:|---:|
| `platform_admin` | 6 | 1 | 1 000 Mo | 90 jours |
| `platform_operator` | 4 | 1 | 500 Mo | 7 jours |
| `detection_engineer` | 6 | 1 | 1 000 Mo | 90 jours |
| `soc_analyst` | 4 | 1 | 500 Mo | 7 jours |
| `audit_reader` | 2 | 1 | 250 Mo | 31 jours |
| `api_health` | 1 | 1 | 100 Mo | 1 heure |

Aucun rôle ne reçoit `rtsearch`; le quota RT positif n'accorde pas cette
capacité, mais empêche une valeur illimitée si la politique évolue. Les recherches
temps réel restent interdites par la matrice.

### Séparation des tâches

La matrice `conf/splunk/lookups/rbac_access_matrix.csv` est la source lisible
par contrôle. Les points les plus structurants sont les suivants :

- `platform_admin` peut administrer les index, nœuds distribués, entrées et
  service, mais pas les utilisateurs, les rôles ou les certificats via les
  capacités réservées à 10.2;
- `platform_operator` peut lire la santé, les files d'attente, la topologie et
  l'état de licence, sans mutation;
- `detection_engineer` peut créer et planifier son contenu de détection,
  accélérer des data models et maintenir des lookups;
- `soc_analyst` peut chercher et sauvegarder ses investigations, sans planifier
  ni accélérer;
- `audit_reader` peut lire `_audit` et inventorier utilisateurs/rôles, sans
  modifier leur affectation;
- `api_health` ne peut ni lancer une recherche SPL, ni modifier la plateforme.

## Déploiement contrôlé

### 1. Pré-contrôles

Sur chaque membre du search tier, capturer l'état avant changement :

```text
$SPLUNK_HOME/bin/splunk version
$SPLUNK_HOME/bin/splunk btool authorize list --debug
$SPLUNK_HOME/bin/splunk btool check --debug
```

Exporter également l'inventaire des capacités réellement exposées par la
version et les applications installées :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  "$SPLUNK_MGMT/services/authorization/capabilities?count=0&output_mode=json"
```

`curl --user "$SPLUNK_USER"` demande le secret de façon interactive. Ne pas
placer de secret dans la ligne de commande, l'historique shell, le dépôt ou un
rapport. Le certificat de l'API doit être validé; `--insecure` n'est pas un
critère de recette acceptable.

Comparer les capacités du fichier cible à cet inventaire. Une capacité absente
de l'instance arrête le déploiement. Vérifier ensuite que les index référencés
existent et que leurs classifications de données sont approuvées.

### 2. Canary

1. Conserver le paquet RBAC actuellement effectif, sa somme SHA-256 et la sortie
   `btool --debug`.
2. Créer l'application de configuration RBAC sur la source de déploiement, avec
   un répertoire `local` et des permissions de fichier restrictives.
3. Copier le contenu revu de l'exemple vers `local/authorize.conf`.
4. Exécuter `python scripts/validate_rbac_contract.py` puis `btool check`.
5. Déployer sur un membre de recette ou une instance canary. En Search Head
   Cluster, passer par le deployer et la procédure de bundle validée; ne pas
   modifier un membre isolément.
6. Recharger l'authentification avec la méthode supportée par l'environnement ou
   redémarrer `splunkd` dans la fenêtre de changement.
7. Exécuter tous les tests positifs et négatifs avec une identité dédiée par
   rôle avant généralisation.

### 3. Contrôle de configuration effective

```text
$SPLUNK_HOME/bin/splunk btool authorize list platform_admin --debug
$SPLUNK_HOME/bin/splunk btool authorize list platform_operator --debug
$SPLUNK_HOME/bin/splunk btool authorize list detection_engineer --debug
$SPLUNK_HOME/bin/splunk btool authorize list soc_analyst --debug
$SPLUNK_HOME/bin/splunk btool authorize list audit_reader --debug
$SPLUNK_HOME/bin/splunk btool authorize list api_health --debug
```

La colonne de provenance `--debug` doit pointer vers le paquet attendu. Un rôle
créé par l'IdP ou Splunk Web portant le même nom ne doit pas masquer une autre
définition à plus forte précédence.

Pour chaque identité de recette, vérifier le contexte effectif :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  "$SPLUNK_MGMT/services/authentication/current-context?output_mode=json"
```

Le résultat doit contenir uniquement les rôles attendus. Une identité possédant
plusieurs rôles reçoit l'union des capacités et le périmètre le plus permissif;
elle invalide donc une recette mono-rôle.

## Tests positifs

Les exemples utilisent un endpoint générique tel que
`https://splunk.example.test:8089`. La preuve publique conserve le code HTTP,
le signal de décision normalisé, le rôle effectif, l'heure UTC et la somme du
paquet testé. Le nom aléatoire de l'identité reste uniquement en mémoire jusqu'à
sa suppression et n'entre jamais dans l'artefact.

### Recherche de sécurité

Avec `detection_engineer` puis `soc_analyst` :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  --data-urlencode 'search=search index=sysmon earliest=-15m | head 1' \
  --data-urlencode 'exec_mode=oneshot' \
  "$SPLUNK_MGMT/services/search/jobs?output_mode=json"
```

Le contrôle porte sur l'autorisation d'exécuter la recherche, pas sur la
présence d'événements dans la fenêtre.

### Diagnostic plateforme

Avec `platform_operator` :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  --data-urlencode 'search=search index=_internal earliest=-15m | stats count' \
  --data-urlencode 'exec_mode=oneshot' \
  "$SPLUNK_MGMT/services/search/jobs?output_mode=json"
```

Avec `platform_admin`, `platform_operator` puis `api_health` :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  "$SPLUNK_MGMT/services/server/health/splunkd?output_mode=json"
```

### Audit des identités

Avec `audit_reader`, exécuter une recherche `_audit`, puis lire les utilisateurs
et les rôles :

```bash
curl --fail --silent --show-error \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  "$SPLUNK_MGMT/services/authentication/users?count=0&output_mode=json"
```

Le rôle doit pouvoir inventorier sans disposer d'un endpoint d'écriture.

### Contenu de détection

Avec `detection_engineer`, créer dans l'espace utilisateur de l'application
Search une saved search de recette désactivée, confirmer sa lecture, tester sa
planification, puis supprimer l'objet de recette. Pour `output_file`, écrire
uniquement un lookup temporaire non sensible et le retirer après contrôle. Ces
tests sont exécutés sur le canary, jamais directement sur la production.

## Tests négatifs

Un test négatif valide un signal d'autorisation contrôlé : code HTTP `403`,
masquage d'un endpoint protégé, échec du job faute de capacité, ou exclusion
préalablement vérifiée de l'index dans le contexte effectif. Un résultat vide
pris isolément ne constitue pas une preuve. Pour les recherches sur index
interdites de la campagne publiée, la décision combine l'exclusion de l'index
dans le rôle effectif et l'absence de données retournées.

### Index interdits

Avec `soc_analyst` puis `detection_engineer`, tenter :

```bash
curl --silent --show-error \
  --output rbac-negative-response.json \
  --write-out '%{http_code}\n' \
  --user "$SPLUNK_USER" \
  --cacert "$SPLUNK_CA_FILE" \
  --data-urlencode 'search=search index=_audit earliest=-15m | head 1' \
  --data-urlencode 'exec_mode=oneshot' \
  "$SPLUNK_MGMT/services/search/jobs?output_mode=json"
```

Le contexte effectif doit d'abord confirmer que `_audit` est exclu du rôle. Le
test est ensuite accepté si Splunk renvoie une erreur d'autorisation ou si le
job ne retourne aucune donnée. La preuve publiée consigne le signal combiné
`effective_role_scope_excludes_index_and_search_returns_no_data`.

### Mutations de plateforme

- Avec `platform_operator`, un `POST` vers `/services/data/indexes` doit être
  refusé.
- Avec `detection_engineer`, un `POST` vers
  `/services/server/control/restart` doit être refusé.
- Avec `api_health`, un `POST` vers `/services/search/jobs` doit être refusé,
  même si `_internal` figure dans son périmètre déclaré.

### Administration des identités

Avec chacun des six rôles, tenter la création d'un utilisateur de recette via
`POST /services/authentication/users`, puis la création d'un rôle via
`POST /services/authorization/roles`. Les deux opérations doivent être
refusées. Aucun test ne doit employer un nom d'identité existant.

### Temps réel et élévation par cumul

La campagne 9.4.13 confirme le refus d'une recherche temps réel pour les six
rôles. Le test volontaire d'une identité cumulant deux rôles reste un contrôle
complémentaire, distinct des 38 contrôles publiés : il sert à démontrer l'effet
d'union avant toute autorisation d'affectations multiples.

## Rollback

Le rollback est préparé avant le canary et conserve une voie break-glass
indépendante des rôles custom.

1. Suspendre la promotion et conserver les réponses de test ayant déclenché le
   rollback.
2. Depuis la source de vérité, restaurer la version précédente du paquet RBAC,
   vérifiée par SHA-256. Ne jamais modifier `system/default`.
3. En Search Head Cluster, appliquer le bundle précédent par le deployer; sur
   une instance isolée, restaurer l'application puis recharger
   l'authentification ou redémarrer `splunkd` selon la procédure validée.
4. Vérifier `btool authorize list --debug`, la connexion break-glass, puis les
   tests d'accès de la version précédente.
5. Retirer les affectations vers un rôle supprimé uniquement après restauration
   de l'accès attendu; ne pas laisser une identité sans rôle de repli approuvé.
6. Documenter la cause, l'étendue, l'heure UTC, l'opérateur, le paquet restauré
   et le résultat des contrôles post-rollback.

Les déclencheurs sont : perte d'accès break-glass, capacité inattendue, accès à
un index interdit, échec d'un test négatif, conflit de précédence, ou erreur de
chargement Splunk.

## Registre de preuve live

| Contrôle | Résultat live 9.4.13 | Preuve publique |
|---|---|---|
| Inventaire des capacités | réussi | 67 capacités déclarées, 166 disponibles, 0 absente, 0 incompatible |
| Configuration des six rôles | réussie | six rôles déjà persistés par l'application, six actions `unchanged` |
| Contexte mono-rôle | 6/6 réussis | rôle et ensemble de capacités effectifs strictement conformes |
| Tests positifs | 14/14 réussis | six contextes et huit autorisations fonctionnelles |
| Tests négatifs | 24/24 réussis | index interdit, création d'utilisateur, création de rôle et temps réel pour chaque profil |
| Nettoyage des identités | réussi | 6 créées, 6 supprimées, aucune erreur |
| Dérive après recette | aucune | 0 rôle inattendu et 0 utilisateur inattendu à retirer |
| Transport | conforme | `tls_verified=true`, transport Splunk Web |

Les quotas sous charge et le déclenchement réel d'un rollback ne font pas partie
de cet artefact. Ils restent des scénarios de qualification dédiés avant un
déploiement distribué ou une mise en production.

L'artefact publié ne contient ni nom de compte, GUID, FQDN interne, adresse,
chemin d'infrastructure, secret, endpoint ou en-tête d'authentification.
L'absence de données sensibles est contrôlée statiquement et doit l'être à
nouveau avant chaque publication.

## Validation statique

Depuis la racine du dépôt :

```text
python scripts/validate_rbac_contract.py
python scripts/validate_rbac_contract.py --json
python scripts/apply_rbac_live.py --dry-run
python scripts/apply_rbac_live.py --self-test
```

Le validateur contrôle les six rôles, les capacités exactes, les index autorisés
et par défaut, l'absence d'héritage, les quotas bornés, les décisions de la
matrice, leur cohérence avec `authorize.conf`, la séparation entre cible et
preuve live, ainsi que les motifs sensibles impropres à une publication.

## Commandes de recette live

Le pré-contrôle REST est en lecture seule. Le secret administrateur est demandé
par une invite masquée; il n'est ni passé en argument ni écrit dans un fichier :

```text
python scripts/apply_rbac_live.py --preflight --url https://splunk.example.test:8089 --ca-bundle lab-ca.pem
```

Si le port de management n'est pas exposé mais que Splunk Web l'est, utiliser
le proxy REST authentifié :

```text
python scripts/apply_rbac_live.py --preflight --transport web --url https://splunk.example.test:8000 --ca-bundle lab-ca.pem
```

Après succès du pré-contrôle, la recette complète utilise la même origine et la
même autorité de certification :

```text
python scripts/apply_rbac_live.py --apply --transport web --url https://splunk.example.test:8000 --ca-bundle lab-ca.pem
```

`--apply` refuse HTTP et refuse la désactivation de la validation TLS. Le script
compare d'abord les 67 capacités au catalogue live, bloque tout rôle homonyme
en dérive, puis vérifie la configuration effective. Il sait créer par l'API de
configuration un rôle absent dans un environnement canary, mais ce mécanisme
REST n'est pas la source de persistance de la campagne publiée : les six rôles
étaient déjà fournis par l'application et sont tous restés `unchanged`. Le
harness a créé une identité aléatoire mono-rôle par profil, exécuté les
autorisations et refus attendus, puis supprimé les six identités dans son bloc
de nettoyage garanti.

Les tests live comprennent les recherches sur index autorisés et interdits, la
santé de plateforme, l'inventaire d'identités en lecture, la création d'une
détection planifiée appartenant à son auteur, le refus de créer un utilisateur,
le refus de créer un rôle et le refus d'une recherche temps réel. Pour un index
interdit, un résultat vide n'est probant qu'avec la vérification indépendante
que le contexte effectif exclut cet index.

En cas d'échec, les rôles créés par l'exécution sont retirés après suppression
des objets éphémères. Un rôle préexistant n'est jamais écrasé. En cas de succès,
une preuve JSON anonymisée est écrite sous
`artifacts/public/rbac-live-evidence-<version>-<date>.json`; elle ne contient ni
identité, secret, endpoint, adresse, résultat brut ou identifiant de job. La
campagne de référence est
[`rbac-live-evidence-9.4.13-20260807.json`](../../artifacts/public/rbac-live-evidence-9.4.13-20260807.json).
