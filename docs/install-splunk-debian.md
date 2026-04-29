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
sudo mkdir -p /opt/splunk/etc/system/local

sudo tee /opt/splunk/etc/system/local/user-seed.conf > /dev/null <<'EOF'
[user_info]
USERNAME = admin
PASSWORD = ChangeThisPasswordNow_123!
EOF

sudo chown splunk:splunk /opt/splunk/etc/system/local/user-seed.conf
sudo chmod 600 /opt/splunk/etc/system/local/user-seed.conf
```

## Enable Boot Start and Start Splunk

```bash
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk -group splunk --accept-license --answer-yes --no-prompt
sudo systemctl start Splunkd
sudo systemctl status Splunkd --no-pager
```

## Open Required Firewall Ports

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 8089/tcp
sudo ufw allow 9997/tcp
sudo ufw reload
sudo ufw status
```

## Create Custom Indexes

Copy `conf/splunk/indexes.conf` to:

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
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:ChangeThisPasswordNow_123!
sudo systemctl restart Splunkd
```

## Validation

```bash
sudo /opt/splunk/bin/splunk status
ss -ltnp | egrep ':8000|:8089|:9997'
hostname -I
```

## Optional: Switch to Splunk Free

After validation:

- open Splunk Web
- go to **Settings > Licensing**
- change the license group to **Free**

This is ideal for a permanent single-instance lab.