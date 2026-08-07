# Restauration de Splunk Enterprise Security

Ce runbook couvre une remise en service on-premises lorsque le package officiel
Splunk Enterprise Security est disponible. Le dépôt ne redistribue aucun
composant premium et l'instance de validation actuelle ne prétend pas exécuter
Splunk ES.

## Conditions d'entrée

- package ES obtenu depuis le compte Splunk autorisé ;
- version de Splunk Enterprise compatible avec la version ES retenue ;
- licence, stockage, mémoire et espace temporaire vérifiés ;
- sauvegarde complète du search head, de `$SPLUNK_HOME/etc` et du KV Store ;
- inventaire des applications, add-ons, personnalisations et dépendances ;
- fenêtre de maintenance et point de rollback validés.

Splunk indique qu'ES 8.x est compatible avec Splunk Enterprise on-premises
9.2.0 et versions ultérieures, mais la matrice de la version exacte reste la
source de vérité. Une mise à niveau ES 8.x est une opération à sens unique : le
retour arrière repose sur la restauration de la sauvegarde, KV Store compris.

## Préflight

1. relever les versions, rôles, licence et état du KV Store ;
2. exécuter `splunk btool check --debug` et résoudre toute erreur ;
3. confirmer la topologie : search head unique ou Search Head Cluster ;
4. vérifier les add-ons inclus et ceux déployés sur indexers/forwarders ;
5. contrôler au moins 3 GB libres dans `/tmp` pour l'opération ;
6. calculer le SHA-256 du package et archiver le manifeste de changement.

Ne pas engager l'installation si le KV Store n'est pas sain, si la sauvegarde
n'est pas restaurable ou si la combinaison Splunk/ES n'apparaît pas dans la
matrice de compatibilité.

## Installation contrôlée

1. installer le package avec `splunk install app <package>` ou l'interface de
   gestion des applications ;
2. redémarrer Splunk si l'installateur le demande ;
3. exécuter d'abord `| essinstall --dry-run` ;
4. corriger les erreurs de préflight avant de lancer `| essinstall` ;
5. suivre `$SPLUNK_HOME/var/log/splunk/essinstaller2.log` jusqu'à la fin ;
6. redémarrer puis contrôler les messages Splunk, les applications et le KV
   Store.

L'installation en SHC suit le workflow spécifique au cluster. Elle ne doit pas
être remplacée par une copie manuelle d'applications sur chaque membre.

## Validation fonctionnelle

- ouverture de l'application ES sans erreur de ressource ;
- modèles de données présents et accélérations suivies ;
- indexes `risk` et `notable` accessibles avec les rôles attendus ;
- assets et identities chargés sans erreur ;
- détections exécutables et actions risk/finding opérationnelles ;
- création d'un finding contrôlé, investigation puis clôture ;
- vérification du scheduler, des erreurs `_internal` et de la capacité disque.

Les 18 détections, les mappings CIM et les dashboards de ce dépôt servent de
jeu de non-régression. Leur validation doit rester verte après l'installation.

## Rollback

1. arrêter les changements et conserver les logs d'installation ;
2. remettre le search head dans l'état précédant la maintenance ;
3. restaurer `$SPLUNK_HOME/etc` et le KV Store depuis la même sauvegarde ;
4. redémarrer puis vérifier licence, KV Store, scheduler et recherches ;
5. documenter la première erreur, la décision de rollback et les contrôles
   exécutés.

La suppression d'un seul dossier d'application ne constitue pas un rollback
ES fiable : ES est une suite d'applications et ses données KV Store doivent
rester cohérentes avec la version restaurée.

## Références Splunk

- [Deploy and upgrade Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/install)
- [Install Splunk Enterprise Security on an on-prem search head](https://help.splunk.com/en/splunk-enterprise-security-8/install/8.5/installation)
- [Compatibility and regional availability](https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.5/splunk-enterprise-security-release-notes/compatibility-and-regional-availability)
