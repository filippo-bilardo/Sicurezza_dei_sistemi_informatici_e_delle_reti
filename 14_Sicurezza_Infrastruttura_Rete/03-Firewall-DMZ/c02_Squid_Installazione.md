# Squid: Installazione e Configurazione Base

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES03 — Proxy Server**

---

## Introduzione a Squid

**Squid** è il proxy server open source più diffuso al mondo, utilizzato da grandi organizzazioni (ISP, università, aziende) per:
- Cache web ad alte performance
- Filtraggio contenuti
- Reverse proxying
- Bandwidth management

**Caratteristiche:**
- Supporto HTTP, HTTPS, FTP
- Cache gerarchica (parent/sibling proxy)
- ACL granulari
- Autenticazione multi-metodo
- SSL/TLS inspection
- SNMP monitoring

---

## Installazione

### Ubuntu/Debian

```bash
# Update repository
sudo apt update

# Installa Squid
sudo apt install squid -y

# Verifica versione
squid -v
# Output: Squid Cache: Version 5.2 (Ubuntu)

# Verifica servizio
sudo systemctl status squid
```

### CentOS/RHEL

```bash
# Installa Squid
sudo yum install squid -y

# Avvia servizio
sudo systemctl start squid
sudo systemctl enable squid
```

---

## Struttura Directory

```
/etc/squid/
├── squid.conf              # Configurazione principale
├── squid.conf.original     # Backup default
├── errorpage.css           # Stile pagine errore
├── mime.conf               # MIME types
└── conf.d/                 # Configurazioni modulari

/var/log/squid/
├── access.log              # Log accessi
├── cache.log               # Log cache e startup
└── store.log               # Log oggetti cached

/var/spool/squid/           # Directory cache su disco
└── (file cache binari)

/usr/lib/squid/             # Helper e plugin
├── basic_ncsa_auth         # Auth Basic con htpasswd
├── basic_ldap_auth         # Auth LDAP
└── url_rewrite_helper      # URL rewriting
```

---

## Configurazione Minima

### squid.conf Base

```bash
# /etc/squid/squid.conf

# === NETWORK ===
http_port 3128

# === ACL BASE ===
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

acl SSL_ports port 443
acl Safe_ports port 80 443 21

acl CONNECT method CONNECT

# === ACCESS RULES ===
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

# === CACHE ===
cache_dir ufs /var/spool/squid 1024 16 256
maximum_object_size 50 MB
cache_mem 256 MB

# === LOGGING ===
access_log /var/log/squid/access.log squid
```

### Inizializzazione

```bash
# Verifica sintassi
sudo squid -k parse

# Inizializza directory cache
sudo squid -z

# Restart
sudo systemctl restart squid

# Verifica log
sudo tail -f /var/log/squid/cache.log
```

---

## Test Funzionamento

### Test da Client

```bash
# Configura variabile ambiente
export http_proxy=http://192.168.1.50:3128
export https_proxy=http://192.168.1.50:3128

# Test con curl
curl -v http://www.google.com

# Output atteso:
# * Uses proxy env variable http_proxy == 'http://192.168.1.50:3128'
# < HTTP/1.1 200 OK
```

### Test Browser

**Firefox:**
1. Impostazioni → Generale → Impostazioni di rete
2. Configurazione manuale proxy
3. Proxy HTTP: `192.168.1.50` Porta: `3128`
4. Visita `http://www.example.com`

---

## Riferimenti

- [Squid Configuration Manual](http://www.squid-cache.org/Doc/config/)

---

**Prossima Sezione**: [03 - Filtraggio ACL](./03_Filtraggio_ACL.md)
