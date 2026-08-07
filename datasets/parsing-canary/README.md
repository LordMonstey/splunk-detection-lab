# Fixture du canari parsing

`canary-auth.template.log` contient cinq evenements synthetiques. Les adresses
appartiennent au bloc documentaire RFC 5737 et ne representent aucun systeme
reel. Le rendu remplace uniquement `{run_id}` et `{event_time}`.

Le marqueur final permet de distinguer une troncation de la simple absence d'un
champ search-time. Aucun evenement brut ne doit etre copie dans la preuve
publique.
