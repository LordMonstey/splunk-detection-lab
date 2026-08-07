# Programme d'administration Splunk ES

Ce programme regroupe six projets autonomes. Chacun part d'un risque
d'exploitation, produit des livrables identifiables et se termine par des
criteres d'acceptation. La detection est traitee comme un service consommateur
de la plateforme, pas comme le centre du dispositif.

## Projet 1 - MCO et assurance de service Splunk ES

### Enjeu

Maintenir une plateforme exploitable par le SOC et rendre les degradations
visibles avant qu'elles n'affectent les recherches de securite.

### Architecture et realisation

- inventaire des roles, de la version, des applications et des indexes ;
- controles splunkd, KV Store, licences, scheduler, espace disque et retention ;
- analyse de `_internal`, `splunkd.log`, `scheduler.log` et `metrics.log` ;
- controle de la configuration effective avec `btool` et de la precedence
  `default/local` ;
- seuils de service et registre des anomalies avec proprietaire et echeance ;
- rapport MCO separant etat, risque, action, preuve et decision.

### Livrables

- dashboard Admin Operations Center ;
- catalogue des controles MCO ;
- rapport de sante et de capacite ;
- procedure de diagnostic par couche ;
- registre de changements et de rollback.

### Validation et resultat

La plateforme, les indexes, le scheduler, les sources et les objets de
connaissance sont controles depuis une surface unique. Une anomalie peut etre
reliee a sa cause, a son proprietaire et a sa preuve de retour au vert.

## Projet 2 - Onboarding industrialise Windows et Sysmon

### Enjeu

Integrer une source sans creer de dette de parsing, de perte silencieuse ou de
dependance a une recherche particuliere.

### Architecture et realisation

- cahier des charges source, volumetrie, criticite et politique de retention ;
- collecte Universal Forwarder et HEC, index et sourcetype explicites ;
- parsing XML, timestamps, `LINE_BREAKER`, `TRUNCATE`, routage et filtrage ;
- extractions, aliases, eventtypes, tags, macros et lookups ;
- controle `_time` / `_indextime`, fraicheur, repartition par host et trous de
  collecte ;
- recette brut-vers-normalise et rapport de qualite.

### Livrables

- cahier d'integration ;
- configurations `inputs.conf`, `props.conf` et `transforms.conf` ;
- matrice de tests et rapport de qualite ;
- runbook de diagnostic d'ingestion ;
- dashboard de fraicheur et de completude.

### Validation et resultat

Le jeu de validation comprend 152 evenements Windows, dont 134 creations de
processus. Les sept champs processus requis par le triage sont complets sur le
perimetre mesure.

## Projet 3 - Gouvernance CIM et contrat de donnees

### Enjeu

Garantir que les donnees restent consommables par Splunk ES apres une evolution
de source, de TA ou de nomenclature.

### Architecture et realisation

- mapping vers `Endpoint.Processes` avec dictionnaire source-vers-CIM ;
- contrat de champs requis, types, cardinalite et valeurs de reference ;
- separation des transformations index-time et search-time ;
- tests par EventCode, host, sourcetype et fenetre temporelle ;
- score de completude, fraicheur et conformite par champ ;
- gate de promotion avant activation d'un cas d'usage.

### Livrables

- specification de normalisation ;
- objets CIM versionnes ;
- rapport de couverture ;
- tableau de bord CIM Assurance ;
- tests de non-regression.

### Validation et resultat

La qualite est mesuree avant les recherches de securite. Un ecart de CIM est
identifie comme un defaut de donnees et n'est pas masque par du tuning SPL.

## Projet 4 - Qualification du socle distribue sous-jacent a Splunk ES

### Enjeu

Preparer le socle distribue supportant Splunk ES sans confondre haute
disponibilite, replication des donnees et reprise de service.

### Architecture et realisation

- plateforme Splunk Enterprise 10.2.1 realisee avec un Cluster Manager, deux
  peers indexers, un search head et un noeud Monitoring Console ;
- cinq GUID et cinq `serverName` uniques, RF=2, SF=2 et port de replication
  dedie ;
- separation Cluster Manager, indexers, search tier, Monitoring Console et
  controle de licence ;
- gates `service_ready`, `searchable`, RF/SF respectes et absence de fix-up ;
- procedure de bundle, maintenance mode et rolling restart des peers ;
- sequence SHC captain, bundle deployer et rolling upgrade ;
- matrice de panne : peer, search head, deployer, KV Store et certificat ;
- plan de continuite avec RTO, RPO, preuve de restauration et retour arriere.

### Livrables

- dossier d'architecture et matrice de roles ;
- runbook cluster, maintenance et reprise ;
- plan de tests de resilience ;
- criteres go/no-go et rapport de validation ;
- matrice RACI et plan d'escalade.

### Validation et resultat

Etat initial valide avec 2/2 peers `Up`, RF/SF atteints, toutes les donnees
recherchables, preflight valide et aucun fix-up. Pendant le redemarrage controle
d'un peer, 18 812 evenements ont ete servis par l'indexer restant et
`all_data_is_searchable` est reste vrai. Les deux peers, RF/SF, le preflight et
l'absence de fix-up sont revenus au vert en 222 secondes. La preuve assainie est
conservee dans `artifacts/public/cluster-resilience-evidence-20260806.json`.
La synthese de plateforme et Monitoring Console est conservee dans
`artifacts/public/splunk-admin-platform-evidence-20260806.json`.

## Projet 5 - Cycle de vie TLS et montee de version Splunk ES

### Enjeu

Eviter qu'un certificat expire ou qu'une montee de version non preparee ne
provoque une interruption du service SOC.

### Architecture et realisation

- inventaire des certificats Web, management, forwarding et inter-noeuds ;
- controle chaine, SAN, usages, permissions, date d'expiration et trust store ;
- alertes J-60, J-30, J-15 et J-7 avec proprietaire et plan de rotation ;
- matrice de compatibilite Splunk Enterprise, ES, TA et applications ;
- sauvegarde search tier, KV Store, configurations et contenus ES ;
- preflight, canary, smoke tests, rolling upgrade et criteres de rollback ;
- preuve post-changement : sante, recherche, ingestion, scheduler et contenus.

### Livrables

- registre TLS et procedure de rotation ;
- dossier de montee de version ;
- matrice de compatibilite ;
- plan de tests et rapport de changement ;
- procedure de retour arriere.

### Validation et resultat

Chaque changement possede un etat initial, un point de non-retour explicite,
des controles post-deploiement et une decision de maintien ou de rollback.

## Projet 6 - Admin Operations Center et reporting MCO

### Enjeu

Donner a l'administrateur, au responsable de service et au SOC une lecture
commune de la disponibilite, de la capacite et de la qualite de la plateforme.

### Architecture et realisation

- dashboard Simple XML admin-first avec filtres et drilldowns ;
- panneaux sante, licences, indexes, scheduler, queues et fraicheur ;
- registre des controles MCO, changements, certificats et sauvegardes ;
- statuts normalises `GREEN`, `WATCH`, `ACTION` et `BLOCKED` ;
- rapport periodique avec periode, risque, action et date cible ; la tendance
  n'est activee qu'apres un historique suffisant ;
- liens directs vers les runbooks de correction.

### Livrables

- dashboard Admin Operations Center ;
- catalogue de controles versionne ;
- modele de rapport MCO ;
- rapport de validation des recherches ;
- registre de preuves partageable sans secret.

### Validation et resultat

La Monitoring Console distribuee maintient quatre search peers `Up` et une
requete REST inventorie cinq roles distincts : licence/monitoring, Cluster
Manager, deux indexers et search head. Le tableau de bord transforme ces signaux
techniques en decisions d'exploitation et les preuves partageables excluent
adresses privees, secrets et evenements bruts. Le programme administrateur
passe 14/14 controles automatises et le dashboard expose 13 recherches
d'administration.

## References officielles

- [Deploy and upgrade Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/install)
- [Configure an indexer cluster](https://help.splunk.com/data-management/manage-splunk-enterprise-indexers/9.4/configure-the-indexer-cluster/configure-the-indexer-cluster-with-server.conf)
- [Perform a rolling restart](https://help.splunk.com/?resourceId=Splunk_Indexer_Userollingrestart)
- [Monitor a distributed deployment](https://help.splunk.com/en/splunk-enterprise/administer/distributed-deployment-manual/9.2/administer-your-deployment/monitor-your-distributed-deployment)
