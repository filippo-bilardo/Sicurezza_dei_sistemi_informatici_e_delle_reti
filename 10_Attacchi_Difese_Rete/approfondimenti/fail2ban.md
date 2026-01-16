# Guida Completa a Fail2ban

## Indice
1. [Introduzione](#introduzione)
2. [Installazione](#installazione)
3. [Architettura e Componenti](#architettura)
4. [Configurazione Base](#configurazione-base)
5. [Jails (Prigioni)](#jails)
6. [Filtri e Regular Expression](#filtri)
7. [Azioni e Ban](#azioni)
8. [Configurazioni Avanzate](#configurazioni-avanzate)
9. [Monitoraggio e Log](#monitoraggio)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)
12. [Alternative a Fail2ban](#alternative)

---

## 1. Introduzione {#introduzione}

**Fail2ban** è un framework di prevenzione delle intrusioni scritto in Python che protegge server Linux da attacchi brute-force e DoS monitorando i log di sistema e bannando automaticamente gli IP sospetti.

### Come Funziona

```
┌─────────────────────────────────────────────────────────┐
│                    FAIL2BAN WORKFLOW                    │
└─────────────────────────────────────────────────────────┘

1. Monitor Logs
   ↓
   tail -f /var/log/auth.log
   
2. Match Patterns (Filters)
   ↓
   Failed password for root from 192.168.1.100
   
3. Count Failures
   ↓
   IP 192.168.1.100: 5 failures in 600 seconds
   
4. Trigger Action (Ban)
   ↓
   iptables -A INPUT -s 192.168.1.100 -j DROP
   
5. Unban After Time
   ↓
   iptables -D INPUT -s 192.168.1.100 -j DROP
```

### Caratteristiche Principali

- ✅ **Multi-service protection**: SSH, HTTP, FTP, MySQL, ecc.
- ✅ **Log monitoring**: parsing real-time dei log
- ✅ **Flexible actions**: iptables, firewalld, email, script custom
- ✅ **Regex-based filters**: pattern matching flessibile
- ✅ **Whitelisting**: protezione IP trusted
- ✅ **Notification system**: email, Slack, webhook
- ✅ **Lightweight**: basso consumo risorse

### Casi d'Uso

**Protezione SSH:**
```
Scenario: Attacco brute-force SSH
- Attaccante prova 100 password su account root
- Fail2ban rileva 5 tentativi falliti in 10 minuti
- IP attaccante bannato per 10 minuti (configurabile)
- Successive connessioni bloccate da firewall
```

**Protezione Web Server:**
```
Scenario: Directory traversal attack
- Attaccante richiede: /../../etc/passwd
- NGINX/Apache logga HTTP 404
- Fail2ban matcha pattern "404" ripetuti
- IP bannato dopo N tentativi
```

**Protezione Database:**
```
Scenario: MySQL authentication failures
- Bot tenta login MySQL con credenziali diverse
- MySQL logga authentication errors
- Fail2ban banna IP dopo soglia
```

---

## 2. Installazione {#installazione}

### Ubuntu/Debian

```bash
# Update repositories
sudo apt update

# Install fail2ban
sudo apt install fail2ban

# Start service
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
sudo service fail2ban start


# Verify status
sudo systemctl status fail2ban

# Check version
fail2ban-client version
```

### CentOS/RHEL/Rocky Linux

```bash
# Install EPEL repository (required)
sudo yum install epel-release

# Install fail2ban
sudo yum install fail2ban fail2ban-systemd

# Or with dnf (RHEL 8+)
sudo dnf install fail2ban fail2ban-systemd

# Start service
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

# SELinux configuration (if enabled)
sudo setsebool -P allow_httpd_mod_auth_pam on
```

### Arch Linux

```bash
# Install
sudo pacman -S fail2ban

# Enable and start
sudo systemctl enable --now fail2ban
```

### From Source

```bash
# Install dependencies
sudo apt install python3 python3-setuptools python3-pip

# Download latest release
wget https://github.com/fail2ban/fail2ban/archive/0.11.2.tar.gz
tar xvf 0.11.2.tar.gz
cd fail2ban-0.11.2

# Install
sudo python3 setup.py install

# Copy systemd service
sudo cp build/fail2ban.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fail2ban
```

### Verifica Installazione

```bash
# Check fail2ban is running
sudo fail2ban-client ping
# Output: Server replied: pong

# Show status
sudo fail2ban-client status

# List jails
sudo fail2ban-client status | grep "Jail list"

# Check configuration syntax
sudo fail2ban-client -x
```

---

## 3. Architettura e Componenti {#architettura}

### Struttura Directory

```
/etc/fail2ban/
├── action.d/              # Azioni di ban (iptables, mail, ecc.)
│   ├── iptables.conf
│   ├── iptables-multiport.conf
│   ├── sendmail.conf
│   └── ...
├── filter.d/              # Filtri regex per log parsing
│   ├── sshd.conf
│   ├── apache-auth.conf
│   ├── nginx-http-auth.conf
│   └── ...
├── jail.d/                # Configurazioni jail custom
│   └── defaults-debian.conf
├── fail2ban.conf          # Configurazione generale (NON editare)
├── fail2ban.local         # Override configurazione generale
├── jail.conf              # Configurazione jail (NON editare)
└── jail.local             # Override jail (QUI si configura)

/var/log/fail2ban.log      # Log fail2ban
/var/run/fail2ban/         # Socket e PID
```

### Componenti Principali

**1. Server:**
- Daemon principale
- Gestisce jails
- Coordina monitoring e actions

**2. Jails (Prigioni):**
- Configurazioni per servizi specifici
- Definiscono cosa monitorare e come reagire
- Esempio: sshd jail, apache-auth jail

**3. Filters (Filtri):**
- Regular expression per log parsing
- Identificano pattern di attacco
- File in `/etc/fail2ban/filter.d/`

**4. Actions (Azioni):**
- Cosa fare quando match pattern
- Ban IP (iptables, firewalld)
- Notifiche (email, Slack)
- File in `/etc/fail2ban/action.d/`

**5. Backends:**
- Metodo di monitoring log
- auto, pyinotify, gamin, polling, systemd

---

## 4. Configurazione Base {#configurazione-base}

### File Principale: jail.local

```bash
# Crea jail.local (mai modificare jail.conf direttamente)
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

### Configurazione Globale

```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# Ban time (secondi): 10 minuti
bantime = 600

# Find time (secondi): finestra temporale per contare failures
findtime = 600

# Max retry: numero massimo tentativi prima del ban
maxretry = 5

# Backend per log monitoring
backend = auto

# Destination email per notifiche
destemail = admin@example.com
sender = fail2ban@example.com

# Email action (sendmail, mail, etc.)
mta = sendmail

# Protocol (tcp, udp, icmp, all)
protocol = tcp

# Chain iptables
chain = INPUT

# Ban action
# %(action_)s = solo ban
# %(action_mw)s = ban + email con whois
# %(action_mwl)s = ban + email + log lines
banaction = iptables-multiport
action = %(action_mw)s

# Ignore IP (whitelist)
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
```

### Configurazione SSH (esempio completo)

```ini
# /etc/fail2ban/jail.local

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log          # Debian/Ubuntu
# logpath = /var/log/secure          # CentOS/RHEL
maxretry = 3
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 192.168.1.0/24

# Action personalizzata
action = iptables-multiport[name=SSH, port=ssh, protocol=tcp]
         sendmail-whois[name=SSH, dest=admin@example.com]
```

### Applicare Configurazione

```bash
# Test configurazione
sudo fail2ban-client -t

# Reload configurazione
sudo fail2ban-client reload

# Reload jail specifico
sudo fail2ban-client reload sshd

# Restart service
sudo systemctl restart fail2ban
```

---

## 5. Jails (Prigioni) {#jails}

### SSH Protection

```ini
# /etc/fail2ban/jail.local

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
findtime = 600
bantime = 3600

# Aggressive SSH protection
[sshd-aggressive]
enabled = true
port = ssh
filter = sshd[mode=aggressive]
logpath = %(sshd_log)s
maxretry = 2
findtime = 300
bantime = 7200
```

### Apache/NGINX Protection

```ini
# Apache authentication failures
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 5
findtime = 600
bantime = 3600

# NGINX authentication
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 5

# NGINX limit requests (DoS protection)
[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 600

# NGINX no-script (blocca .php, .asp, ecc. su siti statici)
[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
findtime = 60
bantime = 3600

# Nginx 404 errors (scanner/bot detection)
[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 86400
bantime = 86400
```

### MySQL/MariaDB Protection

```ini
[mysqld-auth]
enabled = true
filter = mysqld-auth
port = 3306
logpath = /var/log/mysql/error.log
# or logpath = /var/log/mysqld.log (CentOS/RHEL)
maxretry = 3
findtime = 600
bantime = 3600
```

### FTP Protection

```ini
# ProFTPD
[proftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = proftpd
logpath = /var/log/proftpd/proftpd.log
maxretry = 3

# vsftpd
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 3
```

### Email Services

```ini
# Postfix SMTP
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3

# Postfix SASL authentication
[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix[mode=auth]
logpath = /var/log/mail.log
maxretry = 3

# Dovecot IMAP/POP3
[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps,submission,465,sieve
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3
```

### WordPress Protection

```ini
[wordpress-hard]
enabled = true
filter = wordpress-hard
logpath = /var/log/nginx/access.log
# or /var/log/apache2/access.log
maxretry = 3
findtime = 600
bantime = 3600

[wordpress-auth]
enabled = true
filter = wordpress-auth
logpath = /var/log/nginx/error.log
maxretry = 5
port = http,https
```

---

## 6. Filtri e Regular Expression {#filtri}

### Anatomia di un Filtro

```ini
# /etc/fail2ban/filter.d/sshd.conf

[INCLUDES]
# Include common regex definitions
before = common.conf

[Definition]
# Failregex: pattern che identifica fallimento
failregex = ^%(__prefix_line)sFailed (?:password|publickey) for .* from <HOST>( port \d+)?(?: ssh\d*)?$
            ^%(__prefix_line)sConnection closed by <HOST> port \d+ \[preauth\]$
            ^%(__prefix_line)sDisconnected from (?:invalid user|authenticating user) .* <HOST> port \d+

# Ignoreregex: pattern da ignorare (optional)
ignoreregex = 

# Date pattern (per log parsing)
datepattern = {^LN-BEG}
```

### Creare Filtro Custom

**Esempio: Blocco Login Falliti Custom Application**

```bash
# 1. Analizza formato log
cat /var/log/myapp/auth.log
# 2023-01-13 14:30:45 [ERROR] Failed login attempt from 192.168.1.100 for user admin
# 2023-01-13 14:31:02 [ERROR] Failed login attempt from 192.168.1.100 for user root
```

```ini
# 2. Crea filtro: /etc/fail2ban/filter.d/myapp-auth.conf

[Definition]
# Failregex con cattura IP
failregex = ^\s*\[ERROR\] Failed login attempt from <HOST> for user

# Ignora tentativi da utenti specifici (optional)
ignoreregex = for user testuser$

# Date pattern
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S
```

```ini
# 3. Configura jail: /etc/fail2ban/jail.local

[myapp-auth]
enabled = true
filter = myapp-auth
logpath = /var/log/myapp/auth.log
maxretry = 3
findtime = 300
bantime = 3600
port = http,https
```

```bash
# 4. Test filtro con fail2ban-regex
sudo fail2ban-regex /var/log/myapp/auth.log /etc/fail2ban/filter.d/myapp-auth.conf

# Output mostra quante righe matchano
# Lines: X lines, Y ignored, Z matched

# 5. Reload fail2ban
sudo fail2ban-client reload
```

### Test Filtri Esistenti

```bash
# Test filtro SSH con log reale
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Test con verbose output
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf --print-all-matched

# Test singola regex
sudo fail2ban-regex "Failed password for root from 192.168.1.100" \
  "Failed password for .* from <HOST>"
```

### Pattern Comuni

```ini
# Capture IP address
<HOST>

# Prefix line (timestamp + hostname)
%(__prefix_line)s

# Match any username
(?:invalid user )?[^ ]+

# Match port number
port \d+

# Match multiple failure types
(?:password|publickey|keyboard-interactive)

# Match HTTP status codes
\s(?:404|403|401)\s

# Match email addresses
\S+@\S+\.\S+
```

---

## 7. Azioni e Ban {#azioni}

### Azioni Default

```ini
# /etc/fail2ban/action.d/iptables-multiport.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
```

### Azioni Multiple

```ini
# /etc/fail2ban/jail.local

[sshd]
enabled = true
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Multiple actions
action = iptables-multiport[name=SSH, port=ssh, protocol=tcp]
         sendmail-whois[name=SSH, dest=admin@example.com, sender=fail2ban@server]
         slack-notify[name=SSH]
```

### Email Notification

```ini
# /etc/fail2ban/jail.local

[DEFAULT]
destemail = admin@example.com
sender = fail2ban@server.com
mta = sendmail

# Action con email
action = %(action_mwl)s
# action_mwl = ban + mail with whois + log lines

[sshd]
enabled = true
filter = sshd
action = iptables-multiport[name=SSH, port=ssh]
         sendmail-whois[name=SSH, dest=%(destemail)s]
```

**Test Email:**
```bash
# Installa mailutils se non presente
sudo apt install mailutils

# Test email manuale
echo "Test fail2ban notification" | mail -s "Fail2ban Test" admin@example.com

# Trigger ban manuale per test notification
sudo fail2ban-client set sshd banip 1.2.3.4
```

### Custom Actions: Slack Notification

```ini
# /etc/fail2ban/action.d/slack-notify.conf

[Definition]
actionstart =
actionstop =
actioncheck =

actionban = curl -X POST <slack_webhook_url> \
            -H 'Content-Type: application/json' \
            -d '{"text":"[Fail2ban] <name>: Banned <ip> after <failures> attempts"}'

actionunban = curl -X POST <slack_webhook_url> \
              -H 'Content-Type: application/json' \
              -d '{"text":"[Fail2ban] <name>: Unbanned <ip>"}'

[Init]
slack_webhook_url = https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

```ini
# Uso in jail.local
[sshd]
enabled = true
action = iptables-multiport[name=SSH, port=ssh]
         slack-notify[name=SSH, slack_webhook_url=https://hooks.slack.com/...]
```

### Custom Action: Script Python

```python
#!/usr/bin/env python3
# /etc/fail2ban/scripts/ban-notify.py

import sys
import requests
import json
from datetime import datetime

def send_notification(ip, jail, failures):
    """Send ban notification to monitoring system"""
    
    webhook_url = "https://your-webhook.com/alert"
    
    payload = {
        "timestamp": datetime.now().isoformat(),
        "event": "ban",
        "ip": ip,
        "jail": jail,
        "failures": failures,
        "severity": "warning"
    }
    
    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        print(f"Notification sent for IP {ip}")
    except Exception as e:
        print(f"Error sending notification: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: ban-notify.py <ip> <jail> <failures>")
        sys.exit(1)
    
    ip = sys.argv[1]
    jail = sys.argv[2]
    failures = sys.argv[3]
    
    send_notification(ip, jail, failures)
```

```ini
# /etc/fail2ban/action.d/custom-notify.conf

[Definition]
actionban = /etc/fail2ban/scripts/ban-notify.py <ip> <name> <failures>
actionunban =

[Init]
name = default
```

```bash
# Rendi eseguibile
sudo chmod +x /etc/fail2ban/scripts/ban-notify.py

# Installa dipendenze
sudo pip3 install requests
```

---

## 8. Configurazioni Avanzate {#configurazioni-avanzate}

### Ban Incrementale (Recidive)

```ini
# /etc/fail2ban/jail.local

# Jail per recidivi: banna per più tempo chi è già stato bannato
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
         sendmail-whois-lines[name=recidive, logpath=/var/log/fail2ban.log]
bantime = 604800  ; 1 settimana
findtime = 86400  ; 1 giorno
maxretry = 3
```

### Ban Permanente

```ini
# Ban permanente (bantime negativo)
[sshd-permanent]
enabled = true
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = -1       ; Ban permanente
```

### Unban Programmato

```bash
# Script per unban programmato
#!/bin/bash
# /usr/local/bin/scheduled-unban.sh

JAIL="sshd"
IP="192.168.1.100"
UNBAN_TIME="3600"  # 1 ora

echo "Scheduling unban for $IP in $UNBAN_TIME seconds"
sleep $UNBAN_TIME

fail2ban-client set $JAIL unbanip $IP
echo "Unbanned $IP from $JAIL"
```

### Whitelist Dinamica

```python
#!/usr/bin/env python3
# /etc/fail2ban/scripts/dynamic-whitelist.py

import ipaddress
import subprocess

def is_whitelisted(ip):
    """Check if IP should be whitelisted"""
    
    ip_obj = ipaddress.ip_address(ip)
    
    # Whitelist private networks
    private_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]
    
    for network in private_networks:
        if ip_obj in network:
            return True
    
    # Check against external API (esempio: AbuseIPDB reputation)
    # if check_reputation(ip) > 90:  # High reputation
    #     return True
    
    return False

def main():
    import sys
    if len(sys.argv) < 2:
        sys.exit(1)
    
    ip = sys.argv[1]
    
    if is_whitelisted(ip):
        print(f"IP {ip} is whitelisted")
        subprocess.run(['fail2ban-client', 'set', 'sshd', 'unbanip', ip])
```

### GeoIP Blocking

```bash
# Installa GeoIP
sudo apt install geoip-bin geoip-database

# Verifica paese IP
geoiplookup 8.8.8.8
# GeoIP Country Edition: US, United States
```

```ini
# /etc/fail2ban/filter.d/geoip-block.conf

[Definition]
# Blocca IP da paesi specifici
failregex = 

# Custom script per check GeoIP
actionban = /etc/fail2ban/scripts/geoip-ban.sh <ip>
```

```bash
#!/bin/bash
# /etc/fail2ban/scripts/geoip-ban.sh

IP=$1
COUNTRY=$(geoiplookup $IP | awk -F: '{print $2}' | awk '{print $1}')

# Blocca paesi specifici
BLOCKED_COUNTRIES=("CN" "RU" "KP")

for blocked in "${BLOCKED_COUNTRIES[@]}"; do
    if [[ "$COUNTRY" == "$blocked" ]]; then
        echo "Banning $IP from country $COUNTRY"
        iptables -I INPUT -s $IP -j DROP
        exit 0
    fi
done
```

### Rate Limiting

```ini
# /etc/fail2ban/jail.local

# Ban veloce per rate limiting
[http-rate-limit]
enabled = true
filter = http-rate-limit
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60      ; 60 secondi
bantime = 300      ; 5 minuti
port = http,https
```

```ini
# /etc/fail2ban/filter.d/http-rate-limit.conf

[Definition]
# Match tutte le richieste (per rate limiting)
failregex = ^<HOST> -.*"(GET|POST|HEAD)
```

---

## 9. Monitoraggio e Log {#monitoraggio}

### Comandi Base Status

```bash
# Status generale
sudo fail2ban-client status

# Status jail specifico
sudo fail2ban-client status sshd

# Output:
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed: 2
# |  |- Total failed:     127
# |  `- File list:        /var/log/auth.log
# `- Actions
#    |- Currently banned: 3
#    |- Total banned:     45
#    `- Banned IP list:   192.168.1.100 10.0.0.50 172.16.0.10

# List banned IPs
sudo fail2ban-client get sshd banip

# List all jails
sudo fail2ban-client status | grep "Jail list"
```

### Manual Ban/Unban

```bash
# Ban IP manualmente
sudo fail2ban-client set sshd banip 192.168.1.100

# Unban IP
sudo fail2ban-client set sshd unbanip 192.168.1.100

# Unban tutti gli IP da un jail
sudo fail2ban-client unban --all

# Unban IP da tutti i jail
for jail in $(sudo fail2ban-client status | grep "Jail list" | sed 's/.*://'); do
    sudo fail2ban-client set $jail unbanip 192.168.1.100
done
```

### Log Analysis

```bash
# View fail2ban log
sudo tail -f /var/log/fail2ban.log

# Filter per jail specifico
sudo grep "sshd" /var/log/fail2ban.log

# Ban events
sudo grep "Ban" /var/log/fail2ban.log

# Unban events
sudo grep "Unban" /var/log/fail2ban.log

# Statistiche ban per IP
sudo grep "Ban" /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn

# Output:
#     15 192.168.1.100
#      8 10.0.0.50
#      3 172.16.0.10
```

### Script Monitoring

```python
#!/usr/bin/env python3
# /usr/local/bin/fail2ban-stats.py

import subprocess
import json
from datetime import datetime

def get_jail_status(jail):
    """Get status for specific jail"""
    try:
        result = subprocess.run(
            ['fail2ban-client', 'status', jail],
            capture_output=True,
            text=True,
            check=True
        )
        
        output = result.stdout
        
        # Parse output
        currently_failed = 0
        currently_banned = 0
        total_failed = 0
        total_banned = 0
        
        for line in output.split('\n'):
            if 'Currently failed' in line:
                currently_failed = int(line.split(':')[1].strip())
            elif 'Currently banned' in line:
                currently_banned = int(line.split(':')[1].strip())
            elif 'Total failed' in line:
                total_failed = int(line.split(':')[1].strip())
            elif 'Total banned' in line:
                total_banned = int(line.split(':')[1].strip())
        
        return {
            'jail': jail,
            'timestamp': datetime.now().isoformat(),
            'currently_failed': currently_failed,
            'currently_banned': currently_banned,
            'total_failed': total_failed,
            'total_banned': total_banned
        }
    
    except subprocess.CalledProcessError:
        return None

def get_all_jails():
    """Get list of active jails"""
    try:
        result = subprocess.run(
            ['fail2ban-client', 'status'],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.split('\n'):
            if 'Jail list' in line:
                jails_str = line.split(':')[1].strip()
                return [j.strip() for j in jails_str.split(',')]
        
        return []
    
    except subprocess.CalledProcessError:
        return []

def main():
    jails = get_all_jails()
    stats = []
    
    for jail in jails:
        status = get_jail_status(jail)
        if status:
            stats.append(status)
    
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
```

```bash
# Rendi eseguibile
sudo chmod +x /usr/local/bin/fail2ban-stats.py

# Esegui
sudo /usr/local/bin/fail2ban-stats.py

# Output JSON:
# [
#   {
#     "jail": "sshd",
#     "timestamp": "2026-01-13T15:30:00",
#     "currently_failed": 2,
#     "currently_banned": 3,
#     "total_failed": 127,
#     "total_banned": 45
#   }
# ]
```

### Dashboard Grafana

```bash
# Export metrics per Prometheus
# /usr/local/bin/fail2ban-exporter.py

import subprocess
from prometheus_client import start_http_server, Gauge
import time

# Define metrics
currently_banned = Gauge('fail2ban_currently_banned', 'Currently banned IPs', ['jail'])
total_banned = Gauge('fail2ban_total_banned', 'Total banned IPs', ['jail'])
currently_failed = Gauge('fail2ban_currently_failed', 'Currently failed attempts', ['jail'])
total_failed = Gauge('fail2ban_total_failed', 'Total failed attempts', ['jail'])

def collect_metrics():
    """Collect fail2ban metrics"""
    # Get jails
    result = subprocess.run(['fail2ban-client', 'status'], capture_output=True, text=True)
    
    for line in result.stdout.split('\n'):
        if 'Jail list' in line:
            jails = [j.strip() for j in line.split(':')[1].split(',')]
            
            for jail in jails:
                status = subprocess.run(
                    ['fail2ban-client', 'status', jail],
                    capture_output=True,
                    text=True
                )
                
                for stat_line in status.stdout.split('\n'):
                    if 'Currently banned' in stat_line:
                        value = int(stat_line.split(':')[1].strip())
                        currently_banned.labels(jail=jail).set(value)
                    elif 'Total banned' in stat_line:
                        value = int(stat_line.split(':')[1].strip())
                        total_banned.labels(jail=jail).set(value)
                    elif 'Currently failed' in stat_line:
                        value = int(stat_line.split(':')[1].strip())
                        currently_failed.labels(jail=jail).set(value)
                    elif 'Total failed' in stat_line:
                        value = int(stat_line.split(':')[1].strip())
                        total_failed.labels(jail=jail).set(value)

if __name__ == '__main__':
    # Start metrics server on port 9191
    start_http_server(9191)
    
    while True:
        collect_metrics()
        time.sleep(15)  # Update every 15 seconds
```

---

## 10. Best Practices {#best-practices}

### 1. Non Modificare File .conf Originali

```bash
# ❌ SBAGLIATO
sudo nano /etc/fail2ban/jail.conf

# ✅ CORRETTO
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

### 2. Whitelist Indirizzi Trusted

```ini
[DEFAULT]
# Whitelist
ignoreip = 127.0.0.1/8 ::1 
           192.168.1.0/24           # LAN
           10.0.0.0/8               # VPN
           203.0.113.50             # Office IP
           2001:db8::/32            # IPv6 range

# Whitelist from file
# ignoreip = 127.0.0.1/8 file:/etc/fail2ban/whitelist.txt
```

```bash
# /etc/fail2ban/whitelist.txt
192.168.1.0/24
10.0.0.0/8
203.0.113.50
```

### 3. Tuning Parametri

```ini
# Per servizi pubblici (SSH, web)
[sshd]
maxretry = 3        # Strict
findtime = 600      # 10 minuti
bantime = 3600      # 1 ora

# Per servizi interni (meno critici)
[mysql]
maxretry = 5        # More lenient
findtime = 3600     # 1 ora
bantime = 1800      # 30 minuti

# Per recidivi
[recidive]
maxretry = 2
findtime = 86400    # 24 ore
bantime = 604800    # 7 giorni
```

### 4. Log Rotation

```bash
# /etc/logrotate.d/fail2ban
/var/log/fail2ban.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        fail2ban-client flushlogs >/dev/null || true
    endscript
}
```

### 5. Monitoring Fail2ban Service

```bash
# Systemd service monitoring
sudo systemctl status fail2ban

# Auto-restart on failure
sudo systemctl edit fail2ban

# Aggiungi:
[Service]
Restart=always
RestartSec=10
```

```bash
# Cron check fail2ban running
# /etc/cron.hourly/check-fail2ban

#!/bin/bash
if ! systemctl is-active --quiet fail2ban; then
    echo "Fail2ban is down, restarting..."
    systemctl start fail2ban
    echo "Fail2ban restarted at $(date)" | mail -s "Fail2ban Alert" admin@example.com
fi
```

### 6. Backup Configurazione

```bash
#!/bin/bash
# /usr/local/bin/backup-fail2ban.sh

BACKUP_DIR="/backup/fail2ban"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
tar czf $BACKUP_DIR/fail2ban-config-$DATE.tar.gz \
    /etc/fail2ban/*.local \
    /etc/fail2ban/jail.d/ \
    /etc/fail2ban/filter.d/ \
    /etc/fail2ban/action.d/

# Keep only last 10 backups
ls -t $BACKUP_DIR/fail2ban-config-*.tar.gz | tail -n +11 | xargs rm -f

echo "Backup completed: fail2ban-config-$DATE.tar.gz"
```

### 7. Security Hardening

```ini
# Usa azioni least privilege
[DEFAULT]
# Solo DROP packets (non REJECT per evitare port scan info)
banaction = iptables-multiport
blocktype = DROP

# Chain separata per fail2ban
chain = INPUT

# Log ban/unban per audit
action = %(action_mwl)s
```

---

## 11. Troubleshooting {#troubleshooting}

### Common Issues

**Issue 1: Jail non si avvia**

```bash
# Check configurazione syntax
sudo fail2ban-client -t

# Output errori:
# ERROR: Failed during configuration: File '/etc/fail2ban/jail.local', line 42...

# Check logs
sudo tail -f /var/log/fail2ban.log

# Test filtro
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

**Issue 2: IP non viene bannato**

```bash
# 1. Verifica jail attivo
sudo fail2ban-client status sshd

# 2. Verifica log path corretto
ls -l /var/log/auth.log

# 3. Test filtro su log
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf --print-all-matched

# 4. Verifica che fail2ban possa leggere log
sudo -u fail2ban cat /var/log/auth.log

# 5. Check backend
sudo fail2ban-client get sshd backend
```

**Issue 3: IP whitelisted ancora bannato**

```bash
# Check ignoreip configuration
sudo fail2ban-client get sshd ignoreip

# Unban IP
sudo fail2ban-client set sshd unbanip 192.168.1.100

# Reload jail
sudo fail2ban-client reload sshd
```

**Issue 4: Iptables rules non create**

```bash
# Check iptables rules
sudo iptables -L -n | grep f2b

# Manual rule creation
sudo iptables -N f2b-sshd
sudo iptables -A f2b-sshd -j RETURN
sudo iptables -I INPUT -p tcp --dport 22 -j f2b-sshd

# Check fail2ban can execute iptables
sudo -u fail2ban iptables -L

# Se errore: add fail2ban user to sudoers
echo "fail2ban ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee /etc/sudoers.d/fail2ban
```

**Issue 5: High memory usage**

```bash
# Check memory usage
ps aux | grep fail2ban

# Reduce maxretry (meno tracking)
[DEFAULT]
maxretry = 3

# Disable unused jails
[apache-auth]
enabled = false

# Use polling backend (meno risorse)
[DEFAULT]
backend = polling
```

### Debug Mode

```bash
# Stop service
sudo systemctl stop fail2ban

# Start in foreground con debug
sudo fail2ban-client -x -v start

# Output verbose mostra:
# - Log file parsing
# - Regex matching
# - Ban/unban actions
# - Errors

# Ctrl+C to stop
```

### Verifica Ban Attivo

```bash
# Check iptables
sudo iptables -L f2b-sshd -n

# Check IP bannato
sudo iptables -L f2b-sshd -n | grep 192.168.1.100

# Test connessione da IP bannato (dovrebbe timeout)
ssh user@your-server  # Da 192.168.1.100

# Check fail2ban database
sudo fail2ban-client status sshd | grep "Banned IP"
```

---

## 12. Alternative a Fail2ban {#alternative}

### Confronto Alternative

| Tool | Linguaggio | Firewall | Complessità | Performance | Punti di Forza | Limitazioni |
|------|-----------|----------|-------------|-------------|----------------|-------------|
| **Fail2ban** | Python | iptables, firewalld | Media | Buona | Maturo, flessibile | Setup complesso |
| **SSHGuard** | C | pf, iptables, ipfw | Bassa | Ottima | Leggero, veloce | Meno flessibile |
| **DenyHosts** | Python | TCP Wrappers | Bassa | Buona | Semplice | Solo SSH |
| **OSSEC** | C | Integrato | Alta | Ottima | HIDS completo | Overhead alto |
| **CrowdSec** | Go | iptables, nftables | Media | Eccellente | Community-based, moderne | Giovane progetto |
| **CSF/LFD** | Perl | iptables | Bassa | Buona | All-in-one | cPanel focus |

---

### 1. SSHGuard

**Descrizione:**  
Lightweight daemon scritto in C per proteggere servizi da brute-force attacks.

**Caratteristiche:**
- ✅ Estremamente leggero (C)
- ✅ Multi-platform (Linux, BSD, macOS)
- ✅ Supporto pf, iptables, ipfw
- ✅ Attack pattern recognition
- ❌ Meno flessibile di fail2ban
- ❌ Configurazione limitata

**Installazione:**
```bash
# Ubuntu/Debian
sudo apt install sshguard

# CentOS/RHEL
sudo yum install sshguard

# Configuration: /etc/sshguard/sshguard.conf
BACKEND="/usr/libexec/sshguard/sshg-fw-iptables"
LOGREADER="LANG=C /usr/bin/journalctl -afb -p info -n1 -t sshd -o cat"
```

**Quando usare SSHGuard:**
- ✅ Performance critiche
- ✅ Setup minimalista
- ✅ Sistemi embedded
- ❌ Configurazione avanzata necessaria
- ❌ Multiple services monitoring

---

### 2. DenyHosts

**Descrizione:**  
SSH-specific intrusion prevention tool usando TCP Wrappers.

**Caratteristiche:**
- ✅ Specifico per SSH
- ✅ Semplice setup
- ✅ Sync tra server (host-sharing)
- ❌ Solo SSH
- ❌ Usa /etc/hosts.deny (obsoleto)
- ❌ Progetto poco attivo

**Installazione:**
```bash
# Ubuntu/Debian
sudo apt install denyhosts

# Configuration: /etc/denyhosts.conf
SECURE_LOG = /var/log/auth.log
HOSTS_DENY = /etc/hosts.deny
BLOCK_SERVICE = sshd
DENY_THRESHOLD_INVALID = 3
DENY_THRESHOLD_VALID = 5
DENY_THRESHOLD_ROOT = 1
```

**Quando usare DenyHosts:**
- ✅ Solo protezione SSH necessaria
- ✅ Setup veloce
- ✅ Legacy systems
- ❌ Multi-service protection
- ❌ Modern firewall integration

---

### 3. CrowdSec

**Descrizione:**  
Modern collaborative IPS con community-driven threat intelligence.

**Caratteristiche:**
- ✅ Scritto in Go (performance)
- ✅ Community IP reputation
- ✅ Modern architecture
- ✅ Bouncers per diversi firewall
- ✅ API-first design
- ✅ Machine learning detection
- ❌ Relativamente nuovo
- ❌ Setup più complesso

**Installazione:**
```bash
# Ubuntu/Debian
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install crowdsec

# Install firewall bouncer
sudo apt install crowdsec-firewall-bouncer-iptables

# Check status
sudo cscli metrics

# List scenarios (detection rules)
sudo cscli scenarios list

# List decisions (bans)
sudo cscli decisions list
```

**Configuration:**
```yaml
# /etc/crowdsec/config.yaml
common:
  daemonize: true
  log_media: file
  log_level: info
  log_dir: /var/log/
  working_dir: /var/lib/crowdsec/data/

crowdsec_service:
  acquisition_path: /etc/crowdsec/acquis.yaml
  parser_routines: 1

cscli:
  output: human
  hub_branch: master
```

```yaml
# /etc/crowdsec/acquis.yaml
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog

---
filenames:
  - /var/log/nginx/*.log
labels:
  type: nginx
```

**Quando usare CrowdSec:**
- ✅ Infrastruttura moderna
- ✅ Community threat intel necessario
- ✅ Multiple server sync
- ✅ API integration
- ❌ Legacy systems
- ❌ Setup semplice prioritario

---

### 4. OSSEC (Wazuh)

**Descrizione:**  
Full-featured Host-based Intrusion Detection System (HIDS).

**Caratteristiche:**
- ✅ HIDS completo
- ✅ Log analysis
- ✅ File integrity monitoring
- ✅ Rootkit detection
- ✅ Active response
- ✅ Centralized management
- ❌ Overhead significativo
- ❌ Complex setup

**Installazione:**
```bash
# Install Wazuh agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent

# Configure manager
sudo nano /var/ossec/etc/ossec.conf

# Start
sudo systemctl start wazuh-agent
```

**Active Response Configuration:**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

**Quando usare OSSEC/Wazuh:**
- ✅ Enterprise HIDS necessario
- ✅ Compliance requirements (PCI-DSS, HIPAA)
- ✅ Centralized monitoring
- ✅ File integrity monitoring
- ❌ Solo ban IP functionality
- ❌ Lightweight solution necessaria

---

### 5. CSF (ConfigServer Firewall) + LFD

**Descrizione:**  
All-in-one firewall con Login Failure Daemon, popolare su cPanel.

**Caratteristiche:**
- ✅ Firewall + IDS integrato
- ✅ Web UI (WHM/cPanel)
- ✅ Country blocking
- ✅ Port flooding detection
- ❌ Perl dependencies
- ❌ cPanel-focused

**Installazione:**
```bash
# Download
cd /usr/src
wget https://download.configserver.com/csf.tgz
tar xzf csf.tgz
cd csf

# Install
sudo sh install.sh

# Test
sudo perl /usr/local/csf/bin/csftest.pl

# Configuration
sudo nano /etc/csf/csf.conf
```

**Configuration:**
```bash
# /etc/csf/csf.conf

# Enable firewall
TESTING = "0"

# Login Failure Daemon
LF_DAEMON = "1"
LF_SSHD = "5"           # SSH failures before ban
LF_FTPD = "10"          # FTP failures
LF_APACHE = "5"         # Apache auth failures

# Ban time
LF_TRIGGER = "5"        # Failures in 60 seconds
LF_TRIGGER_PERM = "10"  # Permanent ban threshold

# Country blocking
CC_DENY = "CN,RU,KP"
CC_ALLOW_FILTER = "1"
```

**Quando usare CSF/LFD:**
- ✅ cPanel/WHM server
- ✅ All-in-one solution
- ✅ Web UI necessaria
- ❌ Non-cPanel environments
- ❌ Lightweight solution prioritaria

---

### 6. IPTables con Script Custom

**Descrizione:**  
Soluzione DIY usando iptables e bash scripting.

```bash
#!/bin/bash
# /usr/local/bin/simple-ban.sh

LOG_FILE="/var/log/auth.log"
MAX_ATTEMPTS=5
BAN_TIME=3600  # 1 hour

# Monitor log
tail -f $LOG_FILE | while read line; do
    # Extract failed login attempts
    if echo "$line" | grep -q "Failed password"; then
        IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
        
        if [ ! -z "$IP" ]; then
            # Count failures
            FAILURES=$(grep "Failed password.*$IP" $LOG_FILE | wc -l)
            
            if [ $FAILURES -ge $MAX_ATTEMPTS ]; then
                # Check not already banned
                if ! iptables -L INPUT -n | grep -q "$IP"; then
                    echo "$(date): Banning $IP after $FAILURES attempts"
                    iptables -I INPUT -s $IP -j DROP
                    
                    # Schedule unban
                    (sleep $BAN_TIME && iptables -D INPUT -s $IP -j DROP) &
                fi
            fi
        fi
    fi
done
```

**Quando usare Script Custom:**
- ✅ Requisiti molto specifici
- ✅ Learning purposes
- ✅ Minimal dependencies
- ❌ Production environments
- ❌ Complex scenarios

---

## Conclusioni

### Scelta Tool Appropriato

**Per Server Generici (SSH + Web + Services):**
1. **Fail2ban** - Best overall, mature, flexible
2. **CrowdSec** - Modern alternative, community intel
3. **OSSEC/Wazuh** - Se serve HIDS completo

**Per Solo SSH Protection:**
1. **SSHGuard** - Lightweight, performante
2. **DenyHosts** - Semplice setup
3. **Fail2ban** - Se serve espandere in futuro

**Per cPanel/WHM Servers:**
1. **CSF + LFD** - Integrazione nativa
2. **Fail2ban** - Alternative più flessibile

**Per Enterprise/Compliance:**
1. **OSSEC/Wazuh** - HIDS completo
2. **Fail2ban** - Log analysis focus
3. **CrowdSec** - Modern, scalable

**Per Performance-Critical:**
1. **SSHGuard** - C-based, minimal overhead
2. **CrowdSec** - Go-based, efficient
3. **Fail2ban** - Python overhead

### Approccio Layered Security

**Best Practice: Defense in Depth**

```yaml
Layer 1 - Network:
  - Cloud firewall (AWS Security Groups, Azure NSG)
  - Edge firewall (pfSense, OPNsense)

Layer 2 - Host Firewall:
  - iptables/nftables base rules
  - Fail2ban/CrowdSec dynamic blocking

Layer 3 - Application:
  - Rate limiting (NGINX limit_req)
  - WAF (ModSecurity, Cloudflare)

Layer 4 - Monitoring:
  - IDS/IPS (Suricata, Snort)
  - SIEM (ELK, Splunk, Wazuh)

Layer 5 - Hardening:
  - SSH key-only authentication
  - VPN for management access
  - Principle of least privilege
```

### Risorse Aggiuntive

**Documentazione:**
- [Fail2ban Official Docs](https://fail2ban.readthedocs.io/)
- [CrowdSec Documentation](https://doc.crowdsec.net/)
- [OSSEC/Wazuh Docs](https://documentation.wazuh.com/)

**Community:**
- [Fail2ban GitHub](https://github.com/fail2ban/fail2ban)
- [CrowdSec Hub](https://hub.crowdsec.net/)
- [r/sysadmin](https://reddit.com/r/sysadmin)

**Best Practices:**
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Server Security](https://owasp.org/)

---

**Data ultima revisione:** Gennaio 2026  
**Versione Fail2ban:** 1.0.2  
**Autore:** Corso Sicurezza dei Sistemi Informatici e delle Reti
