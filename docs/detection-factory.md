# Detection Factory

Cette vue regroupe le cycle de vie des 18 détections livrées par l'application
`splunk-detection-lab`. Elle ne se limite pas à compter des fichiers : chaque
analytique est rapprochée de sa configuration Splunk effective, exécutée et
mesurée.

## Contrat d'une détection

Une détection versionnée contient au minimum :

- une hypothèse et une source de données attendue ;
- une recherche SPL, sa fenêtre temporelle et sa planification ;
- une technique MITRE ATT&CK et une sévérité ;
- un score de risque, une entité et un message exploitables ;
- des exclusions et pistes de tuning ;
- une procédure de triage et un état de promotion.

Les macros, eventtypes, tags et lookups isolent la logique de détection des
particularités de sourcetype. Les changements de parsing ou de normalisation ne
doivent donc pas être recopiés dans chaque recherche.

## Validation observée

La campagne `campaign-20260806-a` a été rejouée sur un jeu contrôlé de 152
événements Windows. Le validateur a dispatché les 18 saved searches avec une
fenêtre `earliest=0` et a enregistré uniquement les métadonnées d'exécution.

| Contrôle | Résultat |
|---|---:|
| Détections exécutées | 18 / 18 |
| Scénarios positifs | 5 |
| Erreurs de dispatch | 0 |
| Recherches des quatre dashboards | 49 / 49 |

Les scénarios positifs couvrent PowerShell encodé, accès suspect à LSASS,
usage de Certutil, création de compte local et modification d'une Run Key. Un
résultat nul sur les 13 autres recherches est attendu : la campagne n'injecte
pas artificiellement un événement pour chaque règle.

Le rapport machine est disponible dans
[`artifacts/public/live-detection-validation-20260806.json`](../artifacts/public/live-detection-validation-20260806.json).
Il ne contient ni événement brut, ni identifiant, ni adresse privée.

## Promotion

Le passage de `Testing` à `Production` exige quatre preuves :

1. la source et les champs requis sont présents ;
2. le SPL se termine sans erreur et son coût est mesuré ;
3. le scénario positif est reproductible ;
4. le bruit a été observé puis documenté avec ses exclusions.

Une promotion est donc une décision d'exploitation traçable. Le statut n'est
pas déduit de la présence du fichier dans le dépôt.

## Points de contrôle opérateur

- vérifier les erreurs de dispatch et le volume scanné ;
- comparer les résultats positifs à la matrice de campagne ;
- contrôler les changements de macros et lookups avant promotion ;
- conserver la version précédente lorsqu'une règle alimente une corrélation ;
- documenter tout tuning avec son motif, son propriétaire et sa date.

La capture associée est
[`site/assets/evidence/detection-factory-control-plane.png`](../site/assets/evidence/detection-factory-control-plane.png).
