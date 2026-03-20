# B — Progetto Autonomo: Proxy Aziendale con Autenticazione e Cache Avanzata

🏗️ **Tipo**: Progetto autonomo  
⭐ **Difficoltà**: ⭐⭐⭐⭐ (Avanzato)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumento**: Ubuntu Server + Squid + Apache Utils  
📁 **File da consegnare**: Progetto completo + documentazione

---

## 🏢 Scenario

L'azienda **SecureNet S.p.A.** (200 dipendenti) richiede un proxy server enterprise con le seguenti caratteristiche:

### Requisiti Funzionali

1. **Autenticazione utente**: ogni dipendente deve autenticarsi con username/password
2. **Policy differenziate**:
   - **Dirigenti**: accesso illimitato
   - **Reparto IT**: accesso completo per troubleshooting
   - **Uffici amministrativi**: blocco social network, streaming, gaming
   - **Ospiti**: solo whitelisting (siti pre-approvati)
3. **Cache aggressiva**: riduzione banda del 40% target
4. **Report giornalieri**: statistiche di utilizzo per reparto
5. **Banda limitata** per streaming video (YouTube max 1 Mbps)

### Requisiti Non Funzionali

- **Availability**: 99.5% uptime
- **Logging**: retention 90 giorni per compliance
- **Performance**: latenza < 50ms per richieste in cache
- **Sicurezza**: blocco malware tramite HTTPS inspection (opzionale)

---

## 🗺️ Topologia di Rete

```
                    INTERNET
                        │
                   [Router/FW]
                        │ 192.168.1.1
                        │
            ┌───────────┴──────────────┐
            │                          │
       [Squid Proxy]            [Active Directory]
       192.168.1.50:3128        192.168.1.10
       Ubuntu Server            Windows Server (opzionale)
            │
            │
      ┌─────┴─────┬──────────┬─────────┐
      │           │          │         │
   [Dirigenti] [IT Dept] [Uffici]  [Ospiti]
   10.10.1.x   10.10.2.x  10.10.3.x 10.10.99.x
```

---

## 📋 STEP 1 — Pianificazione Progetto

### 1.1 Matrice Policy per Reparto

| Reparto | Username | Categoria Bloccata | Bandwidth Limit | Orario Restrizioni |
|---------|----------|-------------------|-----------------|-------------------|
| Dirigenti | `dir_*` | Nessuna | Illimitata | No |
| IT | `it_*` | Nessuna | Illimitata | No |
| Amministrazione | `admin_*` | Social, Streaming, Gaming | 5 Mbps | 9:00-18:00 |
| Marketing | `mkt_*` | Gaming | 10 Mbps | 9:00-18:00 |
| Ospiti | `guest_*` | Tutto tranne whitelist | 1 Mbps | Sempre |

### 1.2 Piano di Indirizzamento

| Subnet | Range IP | Reparto | Gateway |
|--------|----------|---------|---------|
| 10.10.1.0/24 | .10-.50 | Dirigenti | 10.10.1.1 |
| 10.10.2.0/24 | .10-.50 | IT | 10.10.2.1 |
| 10.10.3.0/24 | .10-.100 | Uffici | 10.10.3.1 |
| 10.10.99.0/24 | .10-.20 | Ospiti | 10.10.99.1 |

---

## 📋 STEP 2 — Installazione Componenti

### 2.1 Installazione Squid + Tools

```bash
# Update sistema
sudo apt update && sudo apt upgrade -y

# Installa Squid e dipendenze
sudo apt install squid apache2-utils squidclient sarg -y

# SARG = Squid Analysis Report Generator

# Verifica versione
squid -v
```

### 2.2 Backup Configurazione

```bash
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
```

---

## 📋 STEP 3 — Configurazione Autenticazione

### 3.1 Creazione File Password (htpasswd)

```bash
# Crea file password
sudo htpasswd -c /etc/squid/passwords dir_mario
# Password: [inserisci password sicura]

# Aggiungi altri utenti (-c solo per il primo!)
sudo htpasswd /etc/squid/passwords dir_luigi
sudo htpasswd /etc/squid/passwords it_tech1
sudo htpasswd /etc/squid/passwords admin_contabilita
sudo htpasswd /etc/squid/passwords mkt_social
sudo htpasswd /etc/squid/passwords guest_temp1

# Verifica file
sudo cat /etc/squid/passwords
# Output:
# dir_mario:$apr1$xyz...
# dir_luigi:$apr1$abc...
```

### 3.2 Configurazione Autenticazione in squid.conf

```bash
sudo nano /etc/squid/squid.conf
```

Aggiungi:

```bash
# === AUTENTICAZIONE ===
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic children 5
auth_param basic realm Proxy SecureNet S.p.A. - Autenticazione Richiesta
auth_param basic credentialsttl 2 hours

# ACL per utenti autenticati
acl authenticated proxy_auth REQUIRED

# ACL per gruppi (basati su username pattern)
acl gruppo_dirigenti proxy_auth_regex ^dir_
acl gruppo_it proxy_auth_regex ^it_
acl gruppo_admin proxy_auth_regex ^admin_
acl gruppo_marketing proxy_auth_regex ^mkt_
acl gruppo_ospiti proxy_auth_regex ^guest_
```

---

## 📋 STEP 4 — Configurazione ACL e Policy Differenziate

### 4.1 Creazione Blacklist per Categorie

```bash
# Social Network
sudo nano /etc/squid/blacklist_social.txt
```

Contenuto:
```
.facebook.com
.instagram.com
.tiktok.com
.twitter.com
.linkedin.com
.snapchat.com
```

```bash
# Streaming
sudo nano /etc/squid/blacklist_streaming.txt
```

Contenuto:
```
.netflix.com
.youtube.com
.twitch.tv
.spotify.com
.primevideo.com
.disneyplus.com
```

```bash
# Gaming
sudo nano /etc/squid/blacklist_gaming.txt
```

Contenuto:
```
.steam.com
.epicgames.com
.ea.com
.origin.com
.battle.net
```

```bash
# Whitelist ospiti
sudo nano /etc/squid/whitelist_ospiti.txt
```

Contenuto:
```
.google.com
.wikipedia.org
.securenet.it
.gov.it
.linkedin.com
```

### 4.2 Configurazione ACL Categorie

```bash
sudo nano /etc/squid/squid.conf
```

Aggiungi:

```bash
# === ACL CATEGORIE ===
acl cat_social dstdomain "/etc/squid/blacklist_social.txt"
acl cat_streaming dstdomain "/etc/squid/blacklist_streaming.txt"
acl cat_gaming dstdomain "/etc/squid/blacklist_gaming.txt"
acl whitelist_ospiti dstdomain "/etc/squid/whitelist_ospiti.txt"

# ACL Orario Lavorativo (lun-ven 9:00-18:00)
acl orario_lavoro time MTWHF 09:00-18:00

# ACL Porte standard
acl SSL_ports port 443
acl Safe_ports port 80 443 21
acl CONNECT method CONNECT
```

---

## 📋 STEP 5 — Configurazione Regole di Accesso

```bash
# === REGOLE DI ACCESSO ===

# Sicurezza base
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Richiedi autenticazione
http_access deny !authenticated

# Policy DIRIGENTI: accesso completo
http_access allow gruppo_dirigenti

# Policy IT: accesso completo
http_access allow gruppo_it

# Policy AMMINISTRAZIONE: blocco social/streaming/gaming in orario lavoro
http_access deny gruppo_admin cat_social orario_lavoro
http_access deny gruppo_admin cat_streaming orario_lavoro
http_access deny gruppo_admin cat_gaming orario_lavoro
http_access allow gruppo_admin

# Policy MARKETING: blocco solo gaming
http_access deny gruppo_marketing cat_gaming orario_lavoro
http_access allow gruppo_marketing

# Policy OSPITI: solo whitelist
http_access allow gruppo_ospiti whitelist_ospiti
http_access deny gruppo_ospiti

# Blocca tutto il resto
http_access deny all
```

---

## 📋 STEP 6 — Configurazione Cache Avanzata

```bash
# === CONFIGURAZIONE CACHE ===

# Porta proxy
http_port 3128

# Cache directory: 10GB, 16 dir L1, 256 dir L2
cache_dir ufs /var/spool/squid 10240 16 256

# Memoria RAM per hot objects (512 MB)
cache_mem 512 MB

# Dimensione massima oggetto in RAM
maximum_object_size_in_memory 512 KB

# Dimensione massima oggetto su disco
maximum_object_size 100 MB

# Dimensione minima oggetto in cache
minimum_object_size 0 KB

# Cache refresh patterns (aggressivi)
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern -i \.(jpg|jpeg|png|gif|bmp|webp)$ 10080 90% 43200 override-expire
refresh_pattern -i \.(css|js)$  1440    50%     10080 override-expire
refresh_pattern -i \.(pdf|doc|docx|xls|xlsx)$ 10080 80% 43200
refresh_pattern .               0       20%     4320

# Rimuovi pragma no-cache da richieste client (cache aggressivo)
ignore_client_no_cache on

# Cache anche con query string (attenzione!)
cache_vary on
```

---

## 📋 STEP 7 — Bandwidth Limiting (Delay Pools)

```bash
# === DELAY POOLS (BANDWIDTH LIMITING) ===

# Abilita delay pools
delay_pools 3

# Pool 1: Amministrazione (max 5 Mbps totali, 1 Mbps per IP)
delay_class 1 2
delay_parameters 1 625000/625000 125000/125000
# 5 Mbps = 5000000 bits/s = 625000 bytes/s
# 1 Mbps = 125000 bytes/s
delay_access 1 allow gruppo_admin
delay_access 1 deny all

# Pool 2: Ospiti (max 1 Mbps totali, 256 Kbps per IP)
delay_class 2 2
delay_parameters 2 125000/125000 32000/32000
delay_access 2 allow gruppo_ospiti
delay_access 2 deny all

# Pool 3: Streaming per tutti (1 Mbps per connessione streaming)
delay_class 3 3
delay_parameters 3 -1/-1 -1/-1 125000/125000
acl streaming_sites dstdomain .youtube.com .netflix.com .twitch.tv
delay_access 3 allow streaming_sites
delay_access 3 deny all
```

---

## 📋 STEP 8 — Logging Avanzato

```bash
# === LOGGING ===

# Log formato esteso con username
logformat squid_extended %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt
access_log /var/log/squid/access.log squid_extended

# Log cache
cache_log /var/log/squid/cache.log

# Log cache store
cache_store_log /var/log/squid/store.log

# Rotazione log (90 giorni compliance)
logfile_rotate 90

# Visibilità
visible_hostname proxy.securenet.it
httpd_suppress_version_string on
```

---

## 📋 STEP 9 — Inizializzazione e Avvio

```bash
# Verifica sintassi
sudo squid -k parse

# Inizializza cache
sudo squid -z

# Restart servizio
sudo systemctl restart squid

# Verifica status
sudo systemctl status squid

# Abilita autostart
sudo systemctl enable squid

# Monitor log
sudo tail -f /var/log/squid/access.log
```

---

## 📋 STEP 10 — Configurazione Report Automatici con SARG

### 10.1 Installazione e Configurazione SARG

```bash
# SARG già installato nello STEP 2

# Configura SARG
sudo nano /etc/squid/sarg.conf
```

Modifica:

```bash
# Log di input
access_log /var/log/squid/access.log

# Output directory
output_dir /var/www/html/squid-reports

# Titolo report
title "Proxy SecureNet - Report Utilizzo"

# Formato data
date_format e

# Lingua
language Italian

# Mostra username
user_ip no

# Report per utente
topuser_sort_field BYTES reverse
```

### 10.2 Generazione Report

```bash
# Crea directory report
sudo mkdir -p /var/www/html/squid-reports

# Genera report
sudo sarg

# Installa web server per visualizzare report
sudo apt install apache2 -y
sudo systemctl start apache2

# Accedi a: http://192.168.1.50/squid-reports/
```

### 10.3 Automazione Report Giornalieri

```bash
# Crea script cron
sudo nano /etc/cron.daily/sarg-report
```

Contenuto:

```bash
#!/bin/bash
# Genera report SARG giornaliero

/usr/bin/sarg -d $(date -d yesterday +%d/%m/%Y)-$(date -d yesterday +%d/%m/%Y)
```

Rendi eseguibile:

```bash
sudo chmod +x /etc/cron.daily/sarg-report
```

---

## 📋 STEP 11 — Test Completo

### 11.1 Test Autenticazione

```bash
# Test con credenziali corrette
curl -x http://10.10.1.10:3128 --proxy-user admin_test:password123 http://www.google.com
# Output: HTML Google ✓

# Test con credenziali errate
curl -x http://10.10.1.10:3128 --proxy-user wrong:wrong http://www.google.com
# Output: 407 Proxy Authentication Required ✗
```

### 11.2 Test Policy Dirigenti

```bash
# Dirigente accede a social network (deve funzionare)
curl -x http://192.168.1.50:3128 --proxy-user dir_mario:password http://www.facebook.com
# Output: HTML Facebook ✓
```

### 11.3 Test Policy Amministrazione

```bash
# Admin accede a Facebook in orario lavoro (deve essere bloccato)
curl -x http://192.168.1.50:3128 --proxy-user admin_contabilita:password http://www.facebook.com
# Output: ERR_ACCESS_DENIED ✗

# Admin accede a Google (deve funzionare)
curl -x http://192.168.1.50:3128 --proxy-user admin_contabilita:password http://www.google.com
# Output: HTML Google ✓
```

### 11.4 Test Policy Ospiti

```bash
# Ospite accede a whitelist (deve funzionare)
curl -x http://192.168.1.50:3128 --proxy-user guest_temp1:password http://www.wikipedia.org
# Output: HTML Wikipedia ✓

# Ospite accede a sito non in whitelist (deve essere bloccato)
curl -x http://192.168.1.50:3128 --proxy-user guest_temp1:password http://www.google.com
# Output: ERR_ACCESS_DENIED ✗
```

### 11.5 Test Cache

```bash
# Accesso 1 (MISS)
time curl -x http://192.168.1.50:3128 --proxy-user it_tech1:password -s http://www.example.com > /dev/null
# Time: 0.850s

# Accesso 2 (HIT)
time curl -x http://192.168.1.50:3128 --proxy-user it_tech1:password -s http://www.example.com > /dev/null
# Time: 0.045s ✓ (molto più veloce)
```

---

## 📋 STEP 12 — Monitoring e Statistiche

### 12.1 Statistiche Cache Real-Time

```bash
squidclient -h localhost -p 3128 mgr:info | grep -A 20 "Cache information"
```

### 12.2 Top 10 Utenti per Banda

```bash
sudo awk '{print $8, $5}' /var/log/squid/access.log | \
  awk '{user[$1]+=$2} END {for(u in user) print u, user[u]}' | \
  sort -k2 -rn | head -10 | \
  awk '{printf "%-20s %10.2f MB\n", $1, $2/1024/1024}'
```

### 12.3 Siti Più Visitati

```bash
sudo awk '{print $7}' /var/log/squid/access.log | \
  sort | uniq -c | sort -rn | head -20
```

---

## 📋 STEP 13 — Documentazione Progetto

### 13.1 Struttura Documentazione Richiesta

**1. Executive Summary** (1 pagina)
- Obiettivi del progetto
- Architettura implementata
- Risultati chiave (cache hit ratio, banda risparmiata)

**2. Architettura Tecnica** (2-3 pagine)
- Topologia di rete con diagramma
- Piano di indirizzamento
- Matrice policy per reparto
- Componenti software utilizzati

**3. Configurazione** (3-4 pagine)
- File `squid.conf` completo commentato
- Spiegazione regole ACL
- Configurazione autenticazione
- Delay pools e bandwidth limiting

**4. Test e Validazione** (2-3 pagine)
- Test case eseguiti (almeno 10)
- Screenshot risultati
- Analisi log

**5. Statistiche e Performance** (1-2 pagine)
- Cache hit ratio
- Bandwidth risparmiata
- Top 10 utenti/siti
- Report SARG

**6. Conclusioni** (1 pagina)
- Obiettivi raggiunti
- Problemi riscontrati e soluzioni
- Miglioramenti futuri

---

## 📋 STEP 14 — Consegna

### 14.1 File da Consegnare

```
SecureNet_Proxy_Progetto/
│
├── docs/
│   ├── relazione_tecnica.pdf         (10-15 pagine)
│   └── presentazione.pptx            (10 slide)
│
├── config/
│   ├── squid.conf                    (configurazione completa)
│   ├── passwords                     (file htpasswd)
│   ├── blacklist_*.txt               (tutte le blacklist)
│   └── whitelist_ospiti.txt
│
├── scripts/
│   └── sarg-report.sh                (script automazione)
│
├── screenshots/
│   ├── 01_topology.png
│   ├── 02_auth_success.png
│   ├── 03_policy_test_dirigenti.png
│   ├── 04_policy_test_admin.png
│   ├── 05_policy_test_ospiti.png
│   ├── 06_cache_stats.png
│   ├── 07_bandwidth_stats.png
│   ├── 08_sarg_report.png
│   └── 09_log_analysis.png
│
└── README.md                         (istruzioni installazione)
```

### 14.2 Criteri di Valutazione

| Criterio | Peso | Descrizione |
|----------|------|-------------|
| Autenticazione | 20% | Funzionante per tutti i gruppi |
| Policy differenziate | 25% | Regole corrette per ogni reparto |
| Cache e performance | 15% | Hit ratio > 30%, latenza < 50ms |
| Bandwidth limiting | 15% | Delay pools configurati correttamente |
| Documentazione | 15% | Completa, chiara, professionale |
| Test e validazione | 10% | Almeno 10 test case documentati |

**Bonus (+10%)**:
- HTTPS inspection con SSL Bumping
- Integrazione con Active Directory (NTLM auth)
- Dashboard Grafana con metriche real-time

---

## 🔧 Troubleshooting Avanzato

### Problema: Autenticazione non funziona

```bash
# Test manuale basic_ncsa_auth
sudo /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
# Input: admin_test password123
# Output atteso: OK

# Verifica permessi file password
sudo chmod 640 /etc/squid/passwords
sudo chown proxy:proxy /etc/squid/passwords
```

### Problema: Delay pools non limita banda

```bash
# Verifica configurazione delay pools
sudo grep -A 5 "delay_pools" /etc/squid/squid.conf

# Controlla contatori
squidclient -h localhost mgr:delay
```

### Problema: Cache non aumenta hit ratio

```bash
# Verifica spazio disco
df -h /var/spool/squid

# Controlla oggetti in cache
sudo du -sh /var/spool/squid/*

# Analizza cosa viene cachato
sudo grep "TCP_HIT" /var/log/squid/access.log | wc -l
sudo grep "TCP_MISS" /var/log/squid/access.log | wc -l
```

---

## 📚 Risorse Aggiuntive

- [Squid Official Documentation](http://www.squid-cache.org/Doc/)
- [SARG Manual](https://sarg.sourceforge.io/)
- [Delay Pools Guide](https://wiki.squid-cache.org/Features/DelayPools)
- [SSL Bumping Tutorial](https://wiki.squid-cache.org/Features/SslPeekAndSplice)

---

*Esercizio B — ES03 Proxy Server | Sistemi e Reti 3*
