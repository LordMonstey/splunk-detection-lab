#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

readonly PROGRAM_NAME="${0##*/}"

usage() {
  cat <<'EOF'
Usage:
  generate_splunk_tls_material.sh \
    --output-dir /absolute/private/path \
    --organization "Example Security" \
    --ca-common-name "Example Splunk Root CA" \
    --server-common-name splunk-web.example.invalid \
    --dns splunk-web.example.invalid \
    [--dns splunk-mgmt.example.invalid] \
    [--ca-days 3650] [--server-days 397]

The destination must not already exist. The script prompts twice for the CA
private-key passphrase and never places that passphrase on a command line.
Only DNS SANs are accepted; IP SANs and wildcard names are intentionally
excluded from this reference workflow.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_value() {
  local option="$1"
  local value="${2-}"
  [[ -n "$value" && "$value" != --* ]] || die "Missing value for ${option}"
}

validate_fqdn() {
  local value="$1"
  [[ ${#value} -le 253 ]] || return 1
  [[ "$value" != *..* ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

validate_subject_text() {
  local value="$1"
  [[ ${#value} -ge 2 && ${#value} -le 96 ]] || return 1
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*(\ [A-Za-z0-9][A-Za-z0-9._-]*)*$ ]]
}

validate_days() {
  local value="$1"
  local minimum="$2"
  local maximum="$3"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( 10#$value >= minimum && 10#$value <= maximum ))
}

prompt_ca_passphrase() {
  local first=""
  local second=""

  [[ -r /dev/tty ]] || die "A controlling terminal is required for the CA passphrase prompt"
  IFS= read -r -s -p 'CA private-key passphrase (16 characters minimum): ' first </dev/tty
  printf '\n' >&2
  IFS= read -r -s -p 'Confirm CA private-key passphrase: ' second </dev/tty
  printf '\n' >&2

  [[ ${#first} -ge 16 ]] || die "The CA passphrase must contain at least 16 characters"
  [[ "$first" == "$second" ]] || die "The CA passphrase confirmation does not match"
  CA_PASSPHRASE="$first"
  unset first second
}

output_dir=""
organization=""
ca_common_name=""
server_common_name=""
ca_days="3650"
server_days="397"
declare -a dns_names=()

while (( $# > 0 )); do
  case "$1" in
    --output-dir)
      require_value "$1" "${2-}"
      output_dir="$2"
      shift 2
      ;;
    --organization)
      require_value "$1" "${2-}"
      organization="$2"
      shift 2
      ;;
    --ca-common-name)
      require_value "$1" "${2-}"
      ca_common_name="$2"
      shift 2
      ;;
    --server-common-name)
      require_value "$1" "${2-}"
      server_common_name="$2"
      shift 2
      ;;
    --dns)
      require_value "$1" "${2-}"
      dns_names+=("$2")
      shift 2
      ;;
    --ca-days)
      require_value "$1" "${2-}"
      ca_days="$2"
      shift 2
      ;;
    --server-days)
      require_value "$1" "${2-}"
      server_days="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

require_command openssl
require_command mktemp
require_command install
require_command chmod
require_command id
require_command mv
require_command stat

(( BASH_VERSINFO[0] >= 4 )) || die "Bash 4 or newer is required"

[[ -n "$output_dir" ]] || die "--output-dir is required"
[[ "$output_dir" == /* ]] || die "--output-dir must be an absolute path"
[[ "$output_dir" != "/" ]] || die "--output-dir cannot be the filesystem root"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || die "The destination already exists"

validate_subject_text "$organization" || die "--organization contains unsupported characters or length"
validate_subject_text "$ca_common_name" || die "--ca-common-name contains unsupported characters or length"
validate_fqdn "$server_common_name" || die "--server-common-name must be a non-wildcard FQDN"
validate_days "$ca_days" 365 7300 || die "--ca-days must be between 365 and 7300"
validate_days "$server_days" 1 397 || die "--server-days must be between 1 and 397"
(( ${#dns_names[@]} > 0 )) || die "At least one --dns SAN is required"

declare -A seen_dns=()
server_cn_is_san="false"
for dns_name in "${dns_names[@]}"; do
  validate_fqdn "$dns_name" || die "Invalid non-wildcard DNS SAN: ${dns_name}"
  dns_key="${dns_name,,}"
  [[ -z "${seen_dns[$dns_key]+present}" ]] || die "Duplicate DNS SAN: ${dns_name}"
  seen_dns["$dns_key"]=1
  [[ "$dns_key" == "${server_common_name,,}" ]] && server_cn_is_san="true"
done
[[ "$server_cn_is_san" == "true" ]] || die "The server common name must also appear as a --dns SAN"

parent_dir="${output_dir%/*}"
destination_name="${output_dir##*/}"
[[ -n "$parent_dir" && -n "$destination_name" ]] || die "Unsafe destination path"
[[ "$destination_name" != "." && "$destination_name" != ".." ]] || die "Unsafe destination name"
[[ "$destination_name" != *$'\n'* && "$destination_name" != *$'\r'* ]] || die "Unsafe destination name"
[[ -d "$parent_dir" ]] || die "The destination parent directory does not exist"
[[ ! -L "$parent_dir" ]] || die "The destination parent directory must not be a symbolic link"
parent_dir="$(cd -P -- "$parent_dir" && pwd)"
output_dir="${parent_dir}/${destination_name}"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || die "The normalized destination already exists"
parent_owner="$(stat -c '%u' "$parent_dir")"
parent_mode="$(stat -c '%a' "$parent_dir")"
[[ "$parent_owner" == "$(id -u)" ]] || die "The destination parent must be owned by the current user"
(( (8#$parent_mode & 0022) == 0 )) || die "The destination parent must not be group- or world-writable"

CA_PASSPHRASE=""
work_dir=""
cleanup() {
  local status=$?
  unset CA_PASSPHRASE
  if (( status != 0 )) && [[ -n "$work_dir" && -d "$work_dir" ]]; then
    rm -rf -- "$work_dir"
  fi
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

prompt_ca_passphrase

work_dir="$(mktemp -d "${parent_dir}/.splunk-tls.XXXXXXXX")"
install -d -m 0700 "$work_dir/private"
install -d -m 0755 "$work_dir/public"

ca_config="$work_dir/private/ca.cnf"
server_request_config="$work_dir/private/server-request.cnf"
server_extension_config="$work_dir/private/server-extension.cnf"

cat >"$ca_config" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
O = ${organization}
CN = ${ca_common_name}

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

cat >"$server_request_config" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_server

[dn]
O = ${organization}
CN = ${server_common_name}

[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
EOF

san_index=1
for dns_name in "${dns_names[@]}"; do
  printf 'DNS.%d = %s\n' "$san_index" "$dns_name" >>"$server_request_config"
  (( san_index += 1 ))
done

cp -- "$server_request_config" "$server_extension_config"

printf '%s\n' "$CA_PASSPHRASE" |
openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -aes-256-cbc \
    -pass stdin \
    -out "$work_dir/private/ca.key.pem"

printf '%s\n' "$CA_PASSPHRASE" |
  openssl req \
    -new \
    -x509 \
    -sha384 \
    -days "$ca_days" \
    -key "$work_dir/private/ca.key.pem" \
    -passin stdin \
    -config "$ca_config" \
    -out "$work_dir/public/ca.cert.pem"

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 \
  -out "$work_dir/private/server.key.pem"

openssl req \
  -new \
  -sha384 \
  -key "$work_dir/private/server.key.pem" \
  -config "$server_request_config" \
  -out "$work_dir/private/server.csr.pem"

certificate_serial="$(openssl rand -hex 16)"
printf '%s\n' "$CA_PASSPHRASE" |
  openssl x509 \
    -req \
    -sha384 \
    -days "$server_days" \
    -in "$work_dir/private/server.csr.pem" \
    -CA "$work_dir/public/ca.cert.pem" \
    -CAkey "$work_dir/private/ca.key.pem" \
    -passin stdin \
    -set_serial "0x${certificate_serial}" \
    -extfile "$server_extension_config" \
    -extensions v3_server \
    -out "$work_dir/public/server.cert.pem"

cat \
  "$work_dir/public/server.cert.pem" \
  "$work_dir/public/ca.cert.pem" \
  >"$work_dir/public/server.chain.pem"

cat \
  "$work_dir/private/server.key.pem" \
  "$work_dir/public/server.cert.pem" \
  "$work_dir/public/ca.cert.pem" \
  >"$work_dir/private/server.bundle.pem"

rm -f -- \
  "$ca_config" \
  "$server_request_config" \
  "$server_extension_config" \
  "$work_dir/private/server.csr.pem"

chmod 0600 "$work_dir/private/ca.key.pem" "$work_dir/private/server.key.pem" "$work_dir/private/server.bundle.pem"
chmod 0644 "$work_dir/public/ca.cert.pem" "$work_dir/public/server.cert.pem" "$work_dir/public/server.chain.pem"

[[ "$(stat -c '%a' "$work_dir")" == "700" ]] || die "The output root is not mode 0700"
[[ "$(stat -c '%a' "$work_dir/private")" == "700" ]] || die "The private directory is not mode 0700"
for private_file in "$work_dir/private/"*.pem; do
  [[ "$(stat -c '%a' "$private_file")" == "600" ]] || die "Private material is not mode 0600"
done

openssl verify \
  -purpose sslserver \
  -CAfile "$work_dir/public/ca.cert.pem" \
  "$work_dir/public/server.cert.pem" >/dev/null
openssl verify \
  -purpose sslclient \
  -CAfile "$work_dir/public/ca.cert.pem" \
  "$work_dir/public/server.cert.pem" >/dev/null
openssl x509 \
  -in "$work_dir/public/server.cert.pem" \
  -noout \
  -checkhost "$server_common_name" >/dev/null

mv -T -- "$work_dir" "$output_dir"
work_dir=""
unset CA_PASSPHRASE

printf 'TLS material generated in %s\n' "$output_dir"
openssl x509 -in "$output_dir/public/ca.cert.pem" -noout -fingerprint -sha256
openssl x509 -in "$output_dir/public/server.cert.pem" -noout -fingerprint -sha256
printf 'Keep private/ offline or readable only by the Splunk service account.\n'
