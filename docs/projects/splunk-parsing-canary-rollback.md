# Qualification canari du parsing et rollback Splunk

## Statut de la preuve

Le dispositif hors ligne, les packages, les controles automatiques et la
sequence live ont ete qualifies le 7 aout 2026 sur une instance Splunk
Enterprise 10.2.1 isolee. Le resultat observe est celui attendu : baseline
`PASS`, candidat degrade `NO-GO`, rollback `PASS` et parite `RESTORED`.

La preuve publique agregee est disponible dans
[`artifacts/public/parsing-canary-rollback-evidence-20260807.json`](../../artifacts/public/parsing-canary-rollback-evidence-20260807.json).
Elle est conforme au contrat
[`artifacts/templates/parsing-canary-evidence.schema.json`](../../artifacts/templates/parsing-canary-evidence.schema.json).

## Enjeu d'administration

Une modification de `props.conf` ou `transforms.conf` peut etre syntaxiquement
valide tout en degradant l'horodatage, les champs pivots, les data models et les
cas d'usage qui en dependent. Ce projet qualifie donc le cycle complet d'un
changement de parsing :

1. mesurer une baseline conforme sur une source de recette ;
2. installer un candidat contenant une regression controlee ;
3. faire detecter la regression par un gate independant ;
4. prononcer `NO-GO` avant toute promotion ;
5. reinstaller l'artefact de baseline ;
6. prouver que la qualite et la configuration effective sont revenues a parite.

Ce n'est pas une demonstration de regex isolee. La preuve couvre le packaging,
la configuration effective, l'indexation, la recherche, la decision de
changement et le rollback.

## Perimetre canari

| Objet | Valeur de recette | Controle |
|---|---|---|
| App | `splunk_parsing_canary_qualification` | app masquee et versionnee |
| Index | `idx_recette_parsing` | 250 Mo, retention 7 jours |
| Sourcetype | `canary:auth` | aucun conflit avec une source metier |
| Fixture | 5 evenements synthetiques | adresses RFC 5737 uniquement |
| Champs de controle | `canary_run_id`, `canary_event_id`, `expected_event_time` | extraction inchangee entre les packages |
| Champs qualifies | `user`, `src`, `action` | couverture mesuree par phase |

L'index et le sourcetype ne sont references dans aucun input permanent. Les
cinq evenements sont injectes explicitement pour chaque phase. Les donnees
brutes, identifiants de recherche, adresses de la plateforme et informations
d'authentification restent dans `artifacts/private/`.

## Defaut injecte

Le package `baseline` 1.0.0 utilise `event_time=` pour l'horodatage et extrait
le triplet `user`, `src`, `action`.

Le package `candidate` 1.1.0-rc1 est volontairement non promouvable. Deux
ecarts bornes sont introduits :

- `TIME_PREFIX` recherche `occurred_at=` alors que la fixture fournit
  `event_time=` ;
- `DATETIME_CONFIG = CURRENT` force un horodatage d'indexation, ce qui rend le
  controle negatif deterministe ;
- l'extraction recherche `source_ip=` alors que la fixture fournit `src=`.

Les champs de controle restent identiques. Le gate peut donc retrouver le lot
candidat sans dependre des champs volontairement casses. Le candidat ne change
ni l'index, ni les permissions, ni le perimetre d'export. Le build refuse tout
autre diff. `KV_MODE = none` est fixe dans les deux variantes afin qu'une
auto-extraction des paires `cle=valeur` ne puisse pas masquer le defaut du
transform candidat.

## Gate de qualite

Une phase passe uniquement si tous les controles suivants sont vrais :

| Controle | Seuil |
|---|---|
| Volume | 5 attendus, 5 observes |
| Unicite | 5 identifiants distincts, zero doublon |
| Champs pivots | 100 % pour `user`, `src`, `action` |
| Horodatage | 100 % a plus ou moins 5 secondes de la valeur attendue |
| Integrite | zero evenement sans marqueur final |
| Latence | lag p95 inferieur ou egal a 900 secondes |

La sequence acceptable est strictement :

| Phase | Gate | Decision |
|---|---|---|
| Baseline | `PASS` | `GO-CANARY` |
| Candidat degrade | `NO-GO` | blocage de la promotion et rollback |
| Rollback | `PASS` | `CLOSE` apres parite |

Le builder de preuve refuse une execution dans laquelle le candidat passe. Il
refuse egalement un rollback dont l'archive, la configuration effective, la
couverture, l'horodatage ou l'integrite different de la baseline. Le lag p95
peut varier de 60 secondes au maximum entre baseline et rollback.

## Artefacts

| Fichier | Role |
|---|---|
| `conf/parsing-canary/baseline/` | configuration conforme 1.0.0 |
| `conf/parsing-canary/candidate/` | candidat degrade 1.1.0-rc1 |
| `scripts/build_parsing_canary_packages.py` | build deterministe et controle du diff |
| `scripts/render_parsing_canary_fixture.py` | rendu des cinq evenements par phase |
| `scripts/ingest_parsing_canary_fixture.py` | injection REST bornee avec TLS verifie |
| `scripts/collect_parsing_canary_phase.py` | recherche agregee en lecture seule |
| `scripts/capture_parsing_canary_effective_config.sh` | capture `btool --debug` des trois stanzas |
| `scripts/assemble_parsing_canary_run.py` | assemblage des preuves privees |
| `scripts/build_parsing_canary_evidence.py` | gate, parite, redaction et preuve publique |
| `tests/test_parsing_canary_drill.py` | tests de regression et controles de securite |
| `artifacts/public/parsing-canary-rollback-evidence-20260807.json` | preuve live agregee et assainie |

## Resultat live du 7 aout 2026

| Phase | Evenements | Couverture minimale | Horodatage conforme | Lag p95 | Decision |
|---|---:|---:|---:|---:|---|
| Baseline 1.0.0 | 5/5 | 100 % | 100 % | 302 s | `GO-CANARY` |
| Candidat 1.1.0-rc1 | 5/5 | 0 % | 0 % | 0 s | `NO-GO` |
| Rollback 1.0.0 | 5/5 | 100 % | 100 % | 301 s | `CLOSE` |

Le candidat a ete bloque sur les controles
`required_field_coverage` et `timestamp_conformance`. L'archive et la
configuration effective du rollback ont les memes empreintes SHA-256 que la
baseline. Les deltas baseline/rollback sont de 0 point pour les champs, 0
point pour l'horodatage et -1 seconde pour le lag p95. Aucun doublon ni
evenement tronque n'a ete observe dans les trois phases.

## Preparation hors ligne

Construire les deux archives dans l'espace prive :

```powershell
python scripts/build_parsing_canary_packages.py
python -m unittest tests.test_parsing_canary_drill -v
```

Le manifeste du candidat doit afficher :

```text
promotion_eligible: false
intended_outcome: controlled-no-go
```

Les archives sont deterministes : deux builds a sources identiques produisent
les memes octets et le meme SHA-256.

## Procedure live

### 1. Ouvrir le changement

Creer un identifiant sans nom d'hote ni information client :

```text
parsing-AAAAMMJJThhmmssZ-<suffixe-aleatoire>
```

Consigner l'heure UTC de debut. Verifier la disponibilite de Splunk, l'etat de
la licence et l'absence de changement concurrent sur le parsing tier.

### 2. Baseline

1. transferer l'archive baseline sur l'hote par le canal d'administration ;
2. verifier son SHA-256 contre le manifeste prive ;
3. installer ou mettre a jour l'app avec l'API `/services/apps/local` ;
4. effectuer le redemarrage controle requis par le parsing index-time ;
5. executer `splunk btool check` ;
6. capturer la configuration effective avec
   `capture_parsing_canary_effective_config.sh` ;
7. rendre, injecter puis collecter le lot baseline.

Rendu de la fixture :

```powershell
python scripts/render_parsing_canary_fixture.py `
  --run-id "${RUN_ID}-baseline" `
  --phase baseline `
  --output "artifacts/private/parsing-canary/${RUN_ID}/baseline.log"
```

Injection. Le mot de passe est demande de facon interactive et n'apparait ni
dans la ligne de commande ni dans le recu :

```powershell
python scripts/ingest_parsing_canary_fixture.py `
  --management-url "https://splunk.example.invalid:8089" `
  --ca-cert "<chemin-ca>" `
  --username "<compte-administration>" `
  --run-id "${RUN_ID}-baseline" `
  --fixture "artifacts/private/parsing-canary/${RUN_ID}/baseline.log" `
  --receipt "artifacts/private/parsing-canary/${RUN_ID}/baseline-ingest.json"
```

Collecte agregee :

```powershell
python scripts/collect_parsing_canary_phase.py `
  --management-url "https://splunk.example.invalid:8089" `
  --ca-cert "<chemin-ca>" `
  --username "<compte-administration>" `
  --run-id "${RUN_ID}" `
  --phase baseline `
  --output "artifacts/private/parsing-canary/${RUN_ID}/baseline-phase.json"
```

La phase doit etre `PASS` avant de poursuivre.

### 3. Candidat et decision NO-GO

Repeter le deploiement, le redemarrage controle, la capture effective, le rendu,
l'injection et la collecte avec le package candidat et le suffixe `candidate`.
Le gate doit signaler au moins `required_field_coverage` ou
`timestamp_conformance`. Le resultat attendu est `NO-GO`.

Un candidat qui passe ne prouve pas le fonctionnement du controle negatif : le
builder bloque donc la preuve. Aucun deploiement vers un autre index ou
sourcetype ne doit etre effectue.

### 4. Rollback

1. reinstaller exactement l'archive baseline deja hashee ;
2. effectuer le redemarrage controle ;
3. relancer `btool check` ;
4. capturer la configuration effective ;
5. rendre un nouveau lot avec le suffixe `rollback` ;
6. injecter et collecter les agregeats ;
7. consigner l'heure UTC de fin.

La capture effective du rollback doit etre identique a celle de la baseline
apres canonicalisation. Une reconstitution manuelle de la configuration n'est
pas acceptee comme rollback.

### 5. Assembler et publier la preuve

Les trois captures de phase, les manifestes et les sorties `btool` restent dans
`artifacts/private/`. L'assembleur produit le contrat prive, puis le builder ne
publie que les agregeats et les hashes :

```powershell
python scripts/assemble_parsing_canary_run.py `
  --run-id "${RUN_ID}" `
  --started-at "<UTC-debut>" `
  --completed-at "<UTC-fin>" `
  --baseline-manifest "<manifeste-baseline-prive>" `
  --candidate-manifest "<manifeste-candidat-prive>" `
  --baseline-phase "<phase-baseline-privee>" `
  --candidate-phase "<phase-candidat-privee>" `
  --rollback-phase "<phase-rollback-privee>" `
  --baseline-effective "<btool-baseline-prive>" `
  --candidate-effective "<btool-candidat-prive>" `
  --rollback-effective "<btool-rollback-prive>" `
  --output "artifacts/private/parsing-canary/${RUN_ID}/assembled.json"

python scripts/build_parsing_canary_evidence.py `
  --input "artifacts/private/parsing-canary/${RUN_ID}/assembled.json" `
  --output "artifacts/public/parsing-canary-rollback-evidence-${RUN_ID}.json"
```

## Securite et limites de revendication

- aucune option de desactivation TLS n'existe dans les collecteurs ;
- les mots de passe sont lus en invite masquee ou sur l'entree standard ;
- les URL avec identifiants integres sont refusees ;
- les sorties de collecte sont forcees sous `artifacts/private/` ;
- le candidat ne peut pas etre marque promouvable ;
- aucun evenement brut, SID de recherche, nom d'hote ou adresse privee n'entre
  dans la preuve publique ;
- le schema public accepte uniquement `live-isolated-lab` ;
- le projet qualifie Splunk Enterprise et la methode d'administration. Il ne
  revendique pas l'execution native de Splunk Enterprise Security.

## Valeur operationnelle

La preuve montre une pratique attendue d'un administrateur Splunk ES integre a
une equipe experte : contrat de donnees mesurable, package versionne, canari
borne, controle negatif, decision de changement explicite, rollback par
artefact immuable, verification de la configuration effective et publication
d'une preuve exploitable sans divulgation de donnees d'exploitation.
