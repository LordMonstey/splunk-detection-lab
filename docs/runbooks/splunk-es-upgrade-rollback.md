# Runbook - Montee de version Splunk ES et rollback

## Objectif

Faire evoluer Splunk Enterprise Security avec une fenetre maitrisee, des gates
go/no-go et un retour arriere exploitable.

## Dossier de changement

- versions source et cible de Splunk Enterprise et Splunk ES ;
- matrice de compatibilite OS, Python, TA, applications et navigateur ;
- notes de version, breaking changes et migrations irreversibles ;
- ordre des roles : gestion, indexation, search tier et contenu ES ;
- proprietaires, RACI, communication et fenetre ;
- RTO, RPO et seuils de rollback.

## Preflight

1. Confirmer la sante de la plateforme et l'absence d'incident ouvert.
2. Verifier licences, capacite, scheduler, queues et fraicheur des sources.
3. Sauvegarder configurations, applications, contenus ES et KV Store.
4. Verifier la restauration de la sauvegarde sur un chemin controle.
5. Executer `btool check`, l'inventaire des applications et les tests de
   recherches de reference.
6. Capturer les mesures de base et le bundle actif.
7. Bloquer le changement si un prerequis n'est pas conforme.

## Execution

### Search head autonome

1. Installer le package cible avec l'option d'upgrade.
2. Executer la configuration ES sans laisser une installation partielle.
3. Redemarrer uniquement lorsque le workflow le demande.
4. Rejouer les smoke tests avant remise aux utilisateurs.

### Search Head Cluster

1. Installer Splunk ES sur le deployer.
2. Executer l'installation avec le type `shc_deployer`.
3. Valider `ssl_enablement=strict` et la capacite du package.
4. Appliquer le bundle SHC avec la strategie de preservation des lookups.
5. Utiliser le rolling upgrade adapte a la version des membres.
6. Surveiller captain, quorum, artefacts, KV Store et scheduler.

## Smoke tests obligatoires

- authentification et navigation Splunk ES ;
- recherche interactive et recherche planifiee ;
- ingestion et fraicheur des sources critiques ;
- indexes, retention et droits d'acces ;
- KV Store et lookups ;
- tableaux de bord et drilldowns ;
- correlation searches, risk et findings de reference ;
- absence d'erreurs fatales dans les logs d'installation et `splunkd.log`.

## Rollback

Une montee vers Splunk ES 8 peut etre non reversible sans restauration. Le
rollback repose donc sur la sauvegarde validee, pas sur une desinstallation.

1. Stopper la remise en service et conserver les logs.
2. Restaurer la version, les configurations, applications et le KV Store depuis
   le point approuve.
3. Redistribuer les bundles precedents.
4. Rejouer les controles de sante et les smoke tests.
5. Documenter cause racine, impact et condition de nouvelle tentative.

## Rapport de cloture

Le rapport contient chronologie, versions, controles preflight, resultats des
smoke tests, incidents, decision, rollback eventuel et actions preventives.
