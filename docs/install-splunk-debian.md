# Debian Splunk Installation

## Target Platform

- Debian 12 x64
- Splunk Enterprise 10.2.1
- Optional switch to Splunk Free after validation

## Install Prerequisites

```bash
sudo apt update
sudo apt install -y wget curl ca-certificates gnupg net-tools ufw
```

## Create Splunk Service Account

```bash
sudo groupadd --system splunk 2>/dev/null || true
sudo useradd --system --create-home --home-dir /home/splunk --gid splunk --shell /bin/bash splunk 2>/dev/null || true
```

## Download Splunk Enterprise

```bash
cd /tmp
wget -O splunk-10.2.1-c892b66d163d-linux-amd64.deb \
"https://download.splunk.com/products/splunk/releases/10.2.1/linux/splunk-10.2.1-c892b66d163d-linux-amd64.deb"

wget -O splunk-10.2.1-c892b66d163d-linux-amd64.deb.sha512 \
"https://download.splunk.com/products/splunk/releases/10.2.1/linux/splunk-10.2.1-c892b66d163d-linux-amd64.deb.sha512"

sha512sum -c /tmp/splunk-10.2.1-c892b66d163d-linux-amd64.deb.sha512
```

## Install Splunk

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
sudo dpkg -i /tmp/splunk-10.2.1-c892b66d163d-linux-amd64.deb
sudo chown -R splunk:splunk /opt/splunk
```

## Seed the Admin Account

```bash
read -rsp "Initial Splunk admin password: " SPLUNK_ADMIN_PASSWORD
printf '\n'
umask 077
sudo mkdir -p /opt/splunk/etc/system/local

{
  printf '[user_info]\n'
  printf 'USERNAME = admin\n'
  printf 'PASSWORD = %s\n' "$SPLUNK_ADMIN_PASSWORD"
} | sudo tee /opt/splunk/etc/system/local/user-seed.conf > /dev/null

sudo chown splunk:splunk /opt/splunk/etc/system/local/user-seed.conf
sudo chmod 600 /opt/splunk/etc/system/local/user-seed.conf
```

Use a unique password from a password manager. Never commit `user-seed.conf`,
paste the value into a screenshot, or place it literally in shell history.

## Enable Boot Start and Start Splunk

```bash
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk -group splunk --accept-license --answer-yes --no-prompt
sudo systemctl start Splunkd
sudo systemctl status Splunkd --no-pager
sudo test ! -e /opt/splunk/etc/system/local/user-seed.conf ||
  sudo shred -u /opt/splunk/etc/system/local/user-seed.conf
```

## Constrain Management and Firewall Access

This standalone lab has no distributed-search or remote REST consumer. Keep the
management API on loopback:

```bash
sudo tee /opt/splunk/etc/system/local/server.conf > /dev/null <<'EOF'
[httpServer]
acceptFrom = 127.0.0.1, ::1
EOF
sudo chown splunk:splunk /opt/splunk/etc/system/local/server.conf
sudo chmod 644 /opt/splunk/etc/system/local/server.conf
```

Replace `<LAB_CIDR>` with the private lab or VPN subnet. Do not publish the
management port `8089`.

```bash
LAB_CIDR="<LAB_CIDR>"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from "$LAB_CIDR" to any port 22 proto tcp
sudo ufw allow from "$LAB_CIDR" to any port 8000 proto tcp
sudo ufw allow from "$LAB_CIDR" to any port 9997 proto tcp
sudo ufw --force enable
sudo ufw status
```

Configure SSH keys and validate a second key-authenticated session before
setting `PasswordAuthentication no` and `PermitRootLogin no`.

## Create Custom Indexes

Copy `conf/splunk/local/indexes.conf` to:

```text
/opt/splunk/etc/system/local/indexes.conf
```

Or create it directly:

```bash
sudo tee /opt/splunk/etc/system/local/indexes.conf > /dev/null <<'EOF'
[windows]
homePath   = $SPLUNK_DB/windows/db
coldPath   = $SPLUNK_DB/windows/colddb
thawedPath = $SPLUNK_DB/windows/thaweddb

[sysmon]
homePath   = $SPLUNK_DB/sysmon/db
coldPath   = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb
EOF

sudo chown splunk:splunk /opt/splunk/etc/system/local/indexes.conf
sudo chmod 644 /opt/splunk/etc/system/local/indexes.conf
sudo systemctl restart Splunkd
```

## Enable Data Receiving on 9997

```bash
if [ -z "${SPLUNK_ADMIN_PASSWORD:-}" ]; then
  read -rsp "Splunk admin password: " SPLUNK_ADMIN_PASSWORD
  printf '\n'
fi
sudo -u splunk /opt/splunk/bin/splunk enable listen 9997 \
  -auth "admin:$SPLUNK_ADMIN_PASSWORD"
unset SPLUNK_ADMIN_PASSWORD
sudo systemctl restart Splunkd
```

## Validation

```bash
sudo /opt/splunk/bin/splunk status
ss -ltnp | egrep ':22|:8000|:8089|:9997'
sudo ufw status verbose
hostname -I
```

Confirm that `8089` is reachable only from loopback, while `22`, `8000`, and
`9997` are limited to the lab/VPN subnet.

## Optional: Switch to Splunk Free

After validation:

- open Splunk Web
- go to **Settings > Licensing**
- change the license group to **Free**

This is ideal for a permanent single-instance lab.
