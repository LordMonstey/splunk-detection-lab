# Qualification MCO live en lecture seule

## Objectif

Observer une instance Splunk de laboratoire sans provoquer d'incident, modifier
une configuration, creer une recherche ou lire un evenement brut. La connexion
utilise exclusivement `https://splunk-probe.lab.test`, la CA publique approuvee et
la verification du nom DNS.

## Frontiere de preuve

Deux preuves differentes coexistent et ne doivent jamais etre confondues :

| Mode | Donnees | Ce qu'il prouve | Ce qu'il ne prouve pas |
|---|---|---|---|
| simulation fixture | observations inventees et determinees | logique du moteur de decision et protections du harness | etat d'une instance ou remediation reelle |
| observation live | reponses REST GET et handshake TLS verifies | etat observe a un instant, acces read-only et controles de publication | incident, diagnostic complet, changement ou rollback execute |

L'artefact live porte `evidence_class=live_read_only_observation` et
`proves_incident_remediation=false`. Le rapport synthetique porte
`live_execution=false` et `claimable_as_live_proof=false`.

## Controles autorises

Le script utilise une liste blanche fermee :

- sante splunkd et statut KV Store ;
- usage et messages de licence ;
- inventaire des recherches planifiees, sans historique de skips ;
- capacite et fraicheur agregees depuis les metadonnees d'indexes ;
- chaine, hostname, protocole, expiration et empreinte du certificat Web.

Apres l'authentification Web, seuls les appels REST GET de la liste blanche et un
POST vers `search/jobs/export` sont permis. Ce POST execute un `tstats` agrege sans
commande mutante, ne cree aucun SID et ne retourne ni evenement brut ni nom d'index.
Aucun endpoint de configuration n'est accessible. L'authentification cree une
session Web, mais ne change ni objet Splunk ni configuration.

## Execution locale securisee

Le secret provient du gestionnaire d'identifiants local ou d'une saisie masquee.
Il ne doit apparaitre ni dans les arguments, ni dans les variables affichees, ni
dans l'artefact.

```bash
python scripts/qualify_mco_live_readonly.py \
  --fqdn splunk-probe.lab.test \
  --connect-address <private-lab-route> \
  --ca-bundle <approved-public-ca.pem> \
  --output artifacts/public/mco-live-read-only-qualification.json
```

`--connect-address` sert uniquement au routage local ephemere. Le certificat reste
valide contre le FQDN, et l'adresse n'est jamais serialisee.

## Gate de publication

Le fichier public est ecrit uniquement si chaque controle vaut `PASS` ou
`NOT_APPLICABLE`. Dans ce second cas, le statut global est
`PASS_WITH_LIMITATIONS`. Un `UNKNOWN`, `INCOMPLETE` ou `FAIL` bloque l'ecriture.
Avant l'ecriture atomique, le validateur refuse :

- une adresse RFC1918 ;
- un hostname hors du domaine reserve `lab.test` ;
- une URI, un identifiant, un cookie ou une valeur assimilable a un secret ;
- un nom d'index, de recherche sauvegardee ou un evenement brut ;
- un resultat incomplet ou un statut global different de `PASS`.

En cas d'echec, aucun artefact de resultat n'est cree. Le diagnostic reste limite
au nom du controle en echec et ne contient pas la reponse serveur.

## Limite scheduler et fraicheur

Le scheduler est inventorie sans modifier ses objets. S'il n'existe aucune
recherche planifiee, son controle vaut `NOT_APPLICABLE` avec disposition
`OBSERVED`, jamais un faux `PASS` ou un `FAIL`. L'historique des skips n'est pas
mesure.

La fraicheur utilise un export `tstats` qui calcule une seule ligne agregee sur les
indexes non internes. Le resultat ne contient aucun nom. Une qualification des
skips ou d'une source precise exige un drill live separe avec SPL approuve.

## Validation

```bash
python -m py_compile scripts/qualify_mco_live_readonly.py
python -m unittest discover -s tests -p "test_qualify_mco_live_readonly.py" -v
python scripts/run_mco_drills.py --validate-docs
```

## Derniere observation publiee

L'artefact du 7 aout 2026 est disponible dans
[mco-live-read-only-qualification-20260807.json](../../artifacts/public/mco-live-read-only-qualification-20260807.json).
Il porte un statut global `PASS` : les cinq controles sont passes, aucun incident
n'a ete injecte et aucune configuration n'a ete modifiee. Les limites KV standalone
et historique scheduler restent inscrites dans l'artefact.
