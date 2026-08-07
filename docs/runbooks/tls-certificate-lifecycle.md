# Runbook - Cycle de vie des certificats Splunk

## Objectif

Renouveler un certificat sans interrompre Splunk Web, l'API de management, le
forwarding ou les communications inter-noeuds.

## Inventaire

Le registre TLS contient pour chaque certificat : service, noeud ou role, CN,
SAN, autorite, empreinte, date de debut, date d'expiration, proprietaire,
fichier de chaine, fichier de cle, permissions et trust store associe.

Les alertes sont ouvertes a J-60, J-30, J-15 et J-7. Une alerte sans
proprietaire est traitee comme une non-conformite.

## Preflight

1. Verifier la chaine complete et l'autorite de confiance.
2. Verifier que les SAN correspondent aux noms utilises par les clients.
3. Verifier l'usage de cle et le format PEM attendu.
4. Verifier que la cle privee correspond au certificat.
5. Verifier les permissions du compte de service Splunk.
6. Identifier les composants qui necessitent un restart ou un reload.
7. Sauvegarder la configuration active et noter l'empreinte precedente.

## Rotation

1. Installer le nouveau materiel dans un chemin versionne et protege.
2. Mettre a jour la configuration dans l'application ou le role approprie.
3. Valider la configuration effective avec `btool`.
4. Distribuer le changement selon la topologie : deployer, Cluster Manager ou
   deployment server.
5. Effectuer le restart controle seulement si requis.
6. Ne supprimer l'ancien certificat qu'apres validation de tous les clients.

## Validation

- Splunk Web presente la nouvelle chaine sans erreur ;
- l'API de management est joignable avec verification de nom active ;
- les forwarders restent connectes et les evenements restent frais ;
- les peers et membres SHC restent au vert ;
- aucune erreur TLS nouvelle n'apparait dans `splunkd.log` ;
- la nouvelle empreinte et la date d'expiration sont enregistrees.

## Rollback

Restaurer les chemins et empreintes precedents, redistribuer la configuration,
effectuer le restart controle requis puis rejouer tous les tests. Une rotation
n'est jamais consideree terminee sur la seule base d'une page Web accessible.

## Preuves de cloture

- registre TLS mis a jour ;
- resultat des controles chaine, SAN et correspondance cle/certificat ;
- validation Web, management, forwarding et inter-noeuds ;
- comparaison des erreurs TLS avant/apres ;
- decision de maintien ou de rollback.
