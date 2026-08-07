# Montée de version Splunk Enterprise 9.4.13 vers 10.2.1 avec rollback prouvé

## Statut et frontière de preuve

**PREUVE LIVE EXÉCUTÉE - RÉUSSIE** : le 7 août 2026, la procédure a été
exécutée de bout en bout sur une instance standalone isolée. La collecte
publique assainie passe le schéma et les 11 contrôles sémantiques du validateur :

- [preuve live 9.4.13 vers 10.2.1](../../artifacts/public/upgrade-evidence-9-4-13-to-10-2-1-live.json) ;
- [rapport de validation public](../../artifacts/public/upgrade-evidence-validation-9-4-13-to-10-2-1-live.json).

| Contrôle de clôture | Résultat observé |
|---|---:|
| Séquence de versions | `9.4.13 -> 10.2.1 -> 9.4.13 -> 10.2.1` |
| Smoke tests | **32 / 32 passés** |
| Santé des quatre phases | **4 / 4 vertes** |
| KV Store | **4 / 4 ready** |
| Licence | **4 / 4 OK, 0 violation** |
| Erreurs fatales / recherches sautées | **0 / 0** |
| Équivalence baseline / rollback | inventaires et 4 manifestes identiques |
| Équivalence post-upgrade / final | inventaires et 4 manifestes identiques |
| Restauration du snapshot | **vérifiée** |
| Validation schéma / sémantique | **0 erreur / 11 sur 11** |

La preuve porte exclusivement sur **Splunk Enterprise**. Splunk Enterprise
Security n'était pas installé : le champ publié
`enterprise_security_layer.status` vaut `not-installed`. Cette exécution ne
doit donc pas être présentée comme une montée de version de l'application ES.
Elle qualifie en revanche le processus d'administration de la plateforme qui
précède toute qualification ES : compatibilité, sauvegarde, changement,
contrôles de service, rollback et clôture.

## Séquence exécutée

Le scénario a couvert la chaîne complète suivante :

1. qualification de Splunk Enterprise 9.4.13 et décision GO ;
2. sauvegarde restaurable, snapshot cohérent et empreintes SHA-256 ;
3. montée vers 10.2.1 et contrôles post-upgrade ;
4. rollback volontaire par restauration vers 9.4.13 ;
5. preuve de retour à l'inventaire, aux configurations et au service initial ;
6. nouvelle montée vers 10.2.1 et validation finale.

La preuve relie la version, la santé, les contenus administrés, les recherches,
le KV Store, la licence, les smoke tests, la chronologie et les artefacts de
restauration. Elle ne repose pas sur une simple capture de l'écran « About ».

## Caveat OS du laboratoire

La VM de laboratoire rapporte **Debian GNU/Linux 13**. Ce résultat démontre la
méthode de changement dans le laboratoire ; il ne constitue ni une certification
de support éditeur de Debian 13, ni une recommandation de plateforme de
production. Avant tout GO en production, l'OS, l'architecture, la bibliothèque
C, le système de fichiers et la version Python doivent être comparés aux
[*System requirements* officiels](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises).
Un écart OS est traité comme un changement séparé de la montée Splunk.

Le saut direct de 9.4.13 à 10.2.1 a été vérifié dans la
[matrice de chemin de montée officielle](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/upgrade-or-migrate-splunk-enterprise/how-to-upgrade-splunk-enterprise)
avant l'exécution. Cette validation du chemin de version ne lève pas la frontière
de support liée à l'OS du laboratoire.

## Architecture et périmètre

Le scénario de preuve cible une instance standalone arrêtée et restaurable. Il
qualifie les mécanismes d'une montée de version : inventaire, compatibilité,
sauvegarde, intégrité, premier démarrage, migration de configuration, tests,
rollback et clôture.

Il ne remplace pas une procédure distribuée. En cluster, il faut ajouter l'ordre
des rôles, les facteurs RF/SF, le rolling upgrade, le captain SHC, la réplication
KV Store, la distribution des bundles et les conditions de retour arrière
propres à chaque tier.

## Dossier de changement

Le dossier est préparé avant la fenêtre avec les éléments suivants :

- versions et builds source/cible, type de package et SHA-256 éditeur ;
- notes de version, changements incompatibles et fonctions dépréciées ;
- matrice OS, applications, add-ons, Python, KV Store et ES le cas échéant ;
- inventaire des applications, recherches sauvegardées, recherches activées,
  collections KV et configurations administrées ;
- capacité disque avant extraction, sauvegarde, migration et journalisation ;
- fenêtre, responsable, RTO, RPO, critère d'arrêt et durée maximale de rollback ;
- sauvegardes, snapshot, emplacement hors VM et test de restauration ;
- liste des smoke tests, résultats de référence et décideurs GO/NO-GO.

Les secrets ne figurent ni dans les commandes, ni dans les journaux publiés, ni
dans le JSON de preuve. Les noms de machines et adresses privées sont remplacés
par des alias stables.

## Gates GO/NO-GO

| Gate | GO | NO-GO immédiat |
|---|---|---|
| Chemin de version | saut confirmé par la documentation éditeur | chemin direct absent, ambigu ou palier obligatoire non préparé |
| Compatibilité | OS et applications qualifiés, ES vérifié si présent | dépendance critique incompatible ou statut inconnu |
| Santé | splunkd vert, recherche possible, aucune erreur fatale | santé jaune/rouge, index non interrogeable, incident actif |
| Scheduler | aucune recherche sautée dans la fenêtre de référence | recherche critique sautée ou backlog non expliqué |
| Licence | état OK, aucune violation | état WARN/ERROR ou violation ouverte |
| KV Store | état ready et sauvegarde vérifiée | sauvegarde absente, état degraded/failed |
| Configuration | `btool check` propre et manifestes produits | erreur de syntaxe, conflit non qualifié, secret détecté |
| Capacité | marge suffisante pour package, sauvegarde et migration | espace libre sous le seuil du dossier de changement |
| Retour arrière | snapshot cohérent et restauration testée | restauration non testée ou RTO irréaliste |

Le GO est une décision enregistrée, pas une impression. Tout NO-GO conserve les
preuves, ouvre une action corrective et interdit le démarrage de l'installation.

## Préparation et baseline 9.4.13

1. Geler les changements applicatifs et noter le début de fenêtre en UTC.
2. Confirmer le build exact avec l'API `/services/server/info`.
3. Capturer santé splunkd, recherche de référence, scheduler, licence et KV Store.
4. Exporter l'inventaire des applications et des recherches sauvegardées.
5. Produire des manifestes déterministes pour les configurations administrées,
   applications privées, recherches et exports KV.
6. Exécuter `splunk btool check --debug` et conserver la sortie expurgée.
7. Exécuter les huit smoke tests de référence avant toute modification.
8. Enregistrer la décision `GO` seulement si tous les gates passent.

Les empreintes portent sur des exports canoniques et sur les configurations
administrées, pas sur des fichiers runtime volatils dont le contenu change à
chaque démarrage.

## Sauvegarde et snapshot cohérents

La stratégie associe une sauvegarde logique et un point de restauration complet.
Un snapshot seul n'est pas une politique de sauvegarde ; une archive jamais
restaurée n'est pas une preuve de rollback.

1. Créer une sauvegarde KV Store avec l'outil Splunk et vérifier sa présence.
2. Archiver `$SPLUNK_HOME/etc` et les applications privées vers un stockage hors VM.
3. Générer un manifeste SHA-256 des archives et métadonnées de snapshot.
4. Arrêter Splunk proprement et confirmer l'arrêt de splunkd.
5. Créer le snapshot VM sous un alias public sans nom d'hôte ni adresse IP.
6. Redémarrer 9.4.13 et vérifier que la baseline est intacte.
7. Tester la restauration pendant le drill, puis enregistrer son horodatage UTC.

La commande KV Store doit être adaptée à la version installée et exécutée avec
une identité locale autorisée. Aucun mot de passe n'est fourni en argument. Les
archives restent privées ; seules leurs empreintes et leurs statuts sont publiés.

## Exécution 9.4.13 vers 10.2.1

1. Vérifier l'empreinte du package cible avant extraction.
2. Rejouer les gates juste avant l'arrêt ; un changement de santé annule le GO.
3. Arrêter Splunk et confirmer qu'aucun processus ne garde les fichiers ouverts.
4. Installer 10.2.1 sur le chemin existant selon la procédure du type de package.
5. Lancer le premier démarrage sans placer de secret dans la ligne de commande.
6. Conserver les journaux de migration, `splunkd.log` et le code retour.
7. Rejouer `btool check`, l'inventaire, la santé, la licence et le KV Store.
8. Exécuter les huit smoke tests et capturer les métriques agrégées.
9. Enregistrer la version et le build 10.2.1 dans la phase `post_upgrade`.

La reprise du trafic n'est pas autorisée tant que la santé, le scheduler, les
sources critiques, les tableaux de bord et les recherches sauvegardées ne sont
pas vérifiés.

## Rollback par restauration

Le rollback d'une montée majeure ne consiste pas à installer un ancien binaire
par-dessus le nouveau. Ce mélange laisse des fichiers, migrations et formats de
données incompatibles. Le retour arrière repose sur la restauration du point
cohérent pris avant changement.

1. Stopper Splunk 10.2.1 et préserver les journaux d'incident hors du volume restauré.
2. Restaurer le snapshot et les sauvegardes approuvées, sans conserver de fichier 10.2.1.
3. Démarrer l'instance restaurée et confirmer version/build 9.4.13.
4. Vérifier santé, scheduler, licence, KV Store et recherche de référence.
5. Comparer les inventaires et manifestes avec la phase `pre_upgrade`.
6. Rejouer les huit smoke tests ; tout écart ouvre un NO-GO.
7. Mesurer le temps de restauration et le comparer au RTO du dossier de changement.
8. Enregistrer `GO-FINAL-UPGRADE` seulement après équivalence prouvée.

Pour que le rollback soit accepté, les comptes d'applications et de recherches,
les collections KV ainsi que les empreintes administrées doivent correspondre à
la baseline. Une version revenue à 9.4.13 avec des contenus perdus est un rollback
échoué.

## Montée finale et clôture

Après le rollback réussi, la montée est rejouée depuis la baseline restaurée.
La phase finale doit reproduire le post-upgrade : version 10.2.1, santé verte,
inventaires identiques, manifestes identiques et smoke tests passés. Une décision
`CLOSE` clôture le changement ; sinon la décision reste NO-GO et l'instance n'est
pas présentée comme qualifiée.

## Smoke tests obligatoires

Chaque phase contient exactement un résultat identifiable au minimum pour :

- `authentication` : authentification locale et accès au rôle attendu ;
- `interactive_search` : recherche de référence terminée sans erreur ;
- `scheduled_search` : déclenchement et résultat d'une recherche planifiée ;
- `ingestion_freshness` : fraîcheur d'une source contrôlée sous son SLA ;
- `kv_store` : lecture d'une collection de référence ;
- `license` : état OK et aucune violation ;
- `dashboard_load` : chargement d'un tableau de bord et de ses recherches ;
- `configuration_check` : contrôle `btool` sans erreur bloquante.

Chaque résultat enregistre un statut, une durée en millisecondes et le SHA-256
de sa sortie expurgée. Les événements bruts, SID, URI, noms d'hôte et identifiants
de session restent exclus de la preuve publique.

## Contrat de preuve et validation

Le contrat se trouve dans
`artifacts/templates/upgrade-evidence.schema.json`. Il impose les quatre phases,
leurs versions exactes et les surfaces opérationnelles attendues. Le schéma est
un gabarit de données ; il ne contient aucun résultat fictif.

Contrôle du schéma :

```powershell
python scripts/validate_upgrade_evidence.py --check-schema
```

Validation d'une collecte réelle expurgée :

```powershell
python scripts/validate_upgrade_evidence.py `
  artifacts/public/upgrade-evidence-9-4-13-to-10-2-1-live.json `
  --output artifacts/public/upgrade-evidence-validation-9-4-13-to-10-2-1-live.json
```

Le validateur contrôle en plus du schéma :

- l'ordre strict des horodatages UTC ;
- l'équivalence `pre_upgrade` / `rollback` ;
- l'équivalence `post_upgrade` / `final` ;
- la couverture et l'unicité des smoke tests ;
- les états santé, KV Store et licence ;
- la cohérence des décisions GO/NO-GO ;
- la frontière de revendication Enterprise Security ;
- l'absence d'adresse privée, de secret et de placeholder ;
- le rejet des empreintes SHA-256 factices évidentes.

Le rapport publié est `passed` : zéro erreur de schéma et 11 contrôles
sémantiques réussis sur 11. Il démontre la cohérence de la collecte, sans
remplacer la documentation éditeur, la revue de changement ni les sauvegardes
privées.

## Livrables de clôture

- dossier de changement et matrice de compatibilité datés ;
- manifestes SHA-256 des sauvegardes et exports administrés ;
- preuve JSON réelle et rapport de validation ;
- journaux expurgés des quatre phases ;
- chronologie, décisions GO/NO-GO et mesure du RTO ;
- écarts, cause racine, actions correctives et critères d'une nouvelle tentative.

Cette structure sépare la procédure, les preuves privées nécessaires à une
restauration et la preuve publique minimale. Elle rend le projet auditable sans
exposer l'infrastructure ni gonfler la réalisation au-delà de ce qui a réellement
été observé.
