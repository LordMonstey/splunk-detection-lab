# Runbook MCO - expiration ou rupture de certificat

> Validation : procedure et drill synthetique uniquement ; aucune execution live
> n'est revendiquee par ce document. Les cles privees ne font jamais partie des
> preuves.

## Symptomes et declenchement

- certificat a J-60, J-30, J-15 ou J-7 sans rotation achevee ;
- chaine non approuvee, SAN absent, cle et certificat non correspondants ;
- handshake en erreur sur Web, management, forwarding ou inter-noeuds ;
- client configure avec verification de certificat ou de nom desactivee.

Certificat expire sur un flux de collecte ou un composant de cluster : SEV1.

## Diagnostic

### SPL

```spl
index=_internal source=*splunkd.log earliest=-2h
  ("SSL" OR "TLS" OR "certificate")
  ("expired" OR "verify" OR "handshake" OR "unknown ca" OR "hostname")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(log_level) as levels by component host
```

### REST

Le premier appel doit reussir avec la CA et le nom DNS attendus ; un test avec
une CA non liee doit echouer.

```bash
curl --fail --silent --show-error --cacert "${SPLUNK_CA}" --user "${SPLUNK_USER}" \
  "${SPLUNK_MGMT_URL}/services/server/info?output_mode=json"
```

### CLI

```bash
openssl x509 -in "${SPLUNK_SERVER_CERT}" -noout -subject -issuer -dates -fingerprint -sha256
openssl x509 -in "${SPLUNK_SERVER_CERT}" -noout -checkend 2592000
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool web list settings --debug
sudo -u splunk "${SPLUNK_HOME}/bin/splunk" btool server list sslConfig --debug
```

Verifier chaine complete, SAN, usage de cle, correspondance cle/certificat,
permissions, trust stores clients, TLS 1.2 minimum et chaque service utilisant
l'empreinte. Ne jamais valider avec une option qui ignore la chaine ou le nom.

## Decision

| Etat | Decision |
|---|---|
| valide au-dela de J-60 | planifier dans le cycle normal |
| J-30 a J-7 | changement prioritaire avec certificat et trust deja prepositionnes |
| moins de J-7 | fenetre d'urgence, proprietaires clients mobilises |
| expire ou chaine rompue | contenir l'impact, restaurer l'ancien certificat valide ou tourner immediatement |
| SAN incorrect | reemettre ; ne pas desactiver la verification de nom |

## Remediation

1. generer ou recevoir un certificat contenant tous les SAN utilises ;
2. verifier hors ligne chaine, dates, usages et correspondance avec la cle ;
3. installer dans un chemin versionne, permissions minimales ;
4. distribuer d'abord la nouvelle CA si elle change ;
5. mettre a jour le composant proprietaire et effectuer le restart controle requis ;
6. valider successivement management, Web, forwarding, peers, SHC et integrations ;
7. conserver l'ancien materiel jusqu'a la fin de la fenetre d'observation.

## Rollback et retour arriere

- restaurer les chemins du certificat et de la cle precedents ;
- restaurer le trust store precedent si la nouvelle CA casse des clients ;
- effectuer le restart controle puis tester chaine et nom sans contournement ;
- ne retirer aucun ancien certificat tant que tous les consommateurs ne sont pas
  revenus au vert.

## Criteres de sortie

- certificat valide au-dela du seuil de renouvellement local ;
- chaine, SAN et hostname valides avec la CA approuvee ;
- TLS 1.2 ou plus sur tous les endpoints ;
- verification de certificat et de nom active ;
- forwarding, API, Web et communications cluster sans erreur nouvelle ;
- registre TLS, proprietaire et prochaine echeance mis a jour.

## Preuves

- empreintes SHA-256 ancienne/nouvelle, issuer, SAN et dates ;
- controles chaine, hostname et CA negative ;
- sorties `btool` expurgees des chemins sensibles si necessaire ;
- chronologie de rotation, restarts et tests de chaque consommateur ;
- aucune cle privee, passphrase, bundle PKCS#12 ou secret dans la preuve.

References : [Configure Splunk Web TLS](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-splunk-web-to-use-tls-certificates) et [TLS hostname validation](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificate-host-name-validation-for-secured-connections-between-splunk-software-components).
