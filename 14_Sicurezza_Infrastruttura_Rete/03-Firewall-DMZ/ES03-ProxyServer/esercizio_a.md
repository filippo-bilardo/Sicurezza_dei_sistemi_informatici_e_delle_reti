# A — Laboratorio Guidato: Configurazione Squid Proxy Base con Filtraggio

🔬 **Tipo**: Laboratorio guidato  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumento**: Ubuntu Server 22.04 LTS + Squid 5.x  
📁 **File da consegnare**: `squid.conf`, screenshot, relazione tecnica

---

## 📸 Riepilogo Screenshot Richiesti

| # | Step | Cosa mostrare |
|---|------|---------------|
| 📸1 | STEP 2 | Output di `squid -v` che mostra la versione installata |
| 📸2 | STEP 3 | File `/etc/squid/squid.conf` con configurazione base |
| 📸3 | STEP 4 | Browser client configurato con proxy (Impostazioni → Rete) |
| 📸4 | STEP 5 | Accesso a sito permesso (es. wikipedia.org) |
| 📸5 | STEP 5 | Accesso bloccato a sito in blacklist (es. facebook.com) |
| 📸6 | STEP 6 | Output di `tail -f /var/log/squid/access.log` con richieste |
| 📸7 | STEP 7 | Statistiche cache con `squidclient mgr:info` |
| 📸8 | STEP 8 | Test di filtraggio per categoria (social network) |

---

## 🏢 Scenario

La scuola **ITI Fermi** ha incaricato il team IT di configurare un **proxy server** per la rete degli studenti. Il proxy deve:

1. **Filtrare contenuti** inappropriati (social network, streaming, gaming)
2. **Loggare** tutti gli accessi web per compliance
3. **Ottimizzare la banda** tramite caching
4. **Bloccare malware** noti tramite blacklist

L'infrastruttura utilizzerà **Squid** su Ubuntu Server, con configurazione trasparente per gli utenti.

---

## 🗺️ Topologia di Rete

```
┌────────────────────────────────────────────────┐
│              RETE SCOLASTICA                   │
│                                                │
│  ┌──────────────┐         ┌─────────────────┐  │
│  │  PC Studenti │────────→│  Squid Proxy    │──┼──→ Internet
│  │  10.1.1.10   │         │  10.1.1.100:3128│  │
│  │  .11, .12... │         │  Ubuntu Server  │  │
│  └──────────────┘         └─────────────────┘  │
│         ↑                          │           │
│         │                          ↓           │
│         └──────[Switch]─────[Router/Gateway]   │
│                10.1.1.0/24                     │
└────────────────────────────────────────────────┘
```

---

## 📋 STEP 1 — Preparazione Ambiente

### 1.1 Requisiti VM

| Componente | Specifica |
|------------|-----------|
| OS | Ubuntu Server 22.04 LTS |
| CPU | 2 core |
| RAM | 2 GB |
| Disco | 20 GB |
| Network | Bridge o NAT |

### 1.2 Piano di Indirizzamento

| Dispositivo | IP | Gateway | Ruolo |
|-------------|----|---------|-------|
| Squid Server | 10.1.1.100 | 10.1.1.1 | Proxy |
| PC Client 1 | 10.1.1.10 | 10.1.1.1 | Studente |
| PC Client 2 | 10.1.1.11 | 10.1.1.1 | Studente |
| Gateway/Router | 10.1.1.1 | — | Internet |

### 1.3 Verifica Connettività Base

Sul **Squid Server**:

```bash
# Verifica IP
ip addr show

# Verifica connessione Internet
ping -c 4 8.8.8.8
ping -c 4 google.com

# Aggiorna sistema
sudo apt update && sudo apt upgrade -y
```

---

## 📋 STEP 2 — Installazione Squid

### 2.1 Installazione Pacchetto

```bash
# Installa Squid
sudo apt install squid -y

# Verifica versione
squid -v

# Output atteso:
# Squid Cache: Version 5.2
# Service Name: squid
```

### 2.2 Backup Configurazione Originale

```bash
# Salva configurazione di default
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.original

# Verifica servizio
sudo systemctl status squid

# Abilita avvio automatico
sudo systemctl enable squid
```

📸 **SCREENSHOT 1**: Output di `squid -v`

---

## 📋 STEP 3 — Configurazione Base Squid

### 3.1 Creazione File di Configurazione

```bash
# Crea file pulito (opzionale: rimuovere commenti)
sudo bash -c 'grep -v "^#" /etc/squid/squid.conf.original | grep -v "^$" > /etc/squid/squid.conf.clean'

# Edita configurazione
sudo nano /etc/squid/squid.conf
```

### 3.2 Configurazione Minima

```bash
# /etc/squid/squid.conf

# === PORTE E ACCESSO ===
# Porta di ascolto del proxy
http_port 3128

# ACL: Definizione della rete locale
acl localnet src 10.1.1.0/24

# ACL: Porte sicure (HTTP/HTTPS)
acl SSL_ports port 443
acl Safe_ports port 80          # HTTP
acl Safe_ports port 443         # HTTPS
acl Safe_ports port 21          # FTP
acl CONNECT method CONNECT

# === REGOLE DI ACCESSO ===
# Blocca accesso a porte non sicure
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Permetti accesso dalla rete locale
http_access allow localnet
http_access allow localhost

# Blocca tutto il resto
http_access deny all

# === CACHE ===
# Directory cache: 1GB, 16 dir L1, 256 dir L2
cache_dir ufs /var/spool/squid 1024 16 256

# Dimensione massima oggetto in cache
maximum_object_size 50 MB

# Memoria RAM per cache (256 MB)
cache_mem 256 MB

# === LOGGING ===
# Log degli accessi
access_log /var/log/squid/access.log squid

# Log del cache
cache_log /var/log/squid/cache.log

# === IDENTIFICAZIONE ===
# Hostname visibile nei log
visible_hostname proxy.itifermi.local

# Non rivelare versione Squid
httpd_suppress_version_string on
```

### 3.3 Inizializzazione Cache e Riavvio

```bash
# Inizializza directory cache
sudo squid -z

# Verifica sintassi configurazione
sudo squid -k parse

# Se OK, riavvia Squid
sudo systemctl restart squid

# Verifica log per errori
sudo tail -f /var/log/squid/cache.log
```

📸 **SCREENSHOT 2**: File `squid.conf` con configurazione base

---

## 📋 STEP 4 — Configurazione Client

### 4.1 Configurazione Browser (Manuale)

**Firefox:**
1. Impostazioni → Rete → Impostazioni connessione
2. Seleziona "Configurazione manuale del proxy"
3. Proxy HTTP: `10.1.1.100` Porta: `3128`
4. ☑ Usa questo proxy per HTTPS e FTP
5. Nessun proxy per: `localhost, 127.0.0.1`

**Chrome/Edge:**
1. Impostazioni → Sistema → Apri impostazioni proxy del computer
2. (Windows) Impostazioni → Rete e Internet → Proxy
3. Proxy manuale: `10.1.1.100:3128`

### 4.2 Test Connettività

```bash
# Dal client, testa il proxy con curl
curl -x http://10.1.1.100:3128 http://www.google.com

# Output atteso: HTML di Google
```

📸 **SCREENSHOT 3**: Browser configurato con proxy

---

## 📋 STEP 5 — Configurazione Filtraggio Contenuti

### 5.1 Creazione Blacklist Siti

```bash
# Crea file blacklist
sudo nano /etc/squid/blacklist.txt
```

Inserisci i seguenti domini:

```
# /etc/squid/blacklist.txt
# Social Network
.facebook.com
.instagram.com
.tiktok.com
.twitter.com
.snapchat.com

# Streaming
.netflix.com
.youtube.com
.twitch.tv
.spotify.com

# Gaming
.steam.com
.epicgames.com
.ea.com

# Adult content (esempi)
.pornhub.com
.xvideos.com
```

### 5.2 Modifica squid.conf per Filtraggio

```bash
sudo nano /etc/squid/squid.conf
```

Aggiungi **prima delle regole http_access**:

```bash
# === FILTRAGGIO CONTENUTI ===

# ACL per blacklist domini
acl blacklist_domains dstdomain "/etc/squid/blacklist.txt"

# ACL per whitelist (siti sempre permessi)
acl whitelist_domains dstdomain .wikipedia.org .gov.it

# ACL orario scolastico (lun-ven 8:00-14:00)
acl orario_lezioni time MTWHF 08:00-14:00

# === REGOLE DI ACCESSO AGGIORNATE ===
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Permetti sempre whitelist
http_access allow whitelist_domains

# Blocca blacklist durante orario scolastico
http_access deny blacklist_domains orario_lezioni

# Permetti rete locale
http_access allow localnet
http_access allow localhost
http_access deny all
```

### 5.3 Applicazione Configurazione

```bash
# Verifica sintassi
sudo squid -k parse

# Ricarica configurazione
sudo squid -k reconfigure

# Verifica log
sudo tail -f /var/log/squid/access.log
```

### 5.4 Test Filtraggio

**Test 1: Sito Permesso**
```bash
curl -x http://10.1.1.100:3128 http://www.wikipedia.org
# Output: HTML di Wikipedia ✓
```

**Test 2: Sito Bloccato**
```bash
curl -x http://10.1.1.100:3128 http://www.facebook.com
# Output: ERR_ACCESS_DENIED ✗
```

📸 **SCREENSHOT 4**: Accesso permesso a Wikipedia  
📸 **SCREENSHOT 5**: Accesso bloccato a Facebook

---

## 📋 STEP 6 — Analisi Log

### 6.1 Formato Log Squid

```bash
# Visualizza log in tempo reale
sudo tail -f /var/log/squid/access.log

# Formato log:
# timestamp elapsed client_ip code/status bytes method URL - hierarchy/from content_type
```

**Esempio log:**
```
1678900000.123    156 10.1.1.10 TCP_MISS/200 5432 GET http://www.wikipedia.org/ - HIER_DIRECT/208.80.154.224 text/html
1678900010.456     12 10.1.1.11 TCP_DENIED/403 3456 GET http://www.facebook.com/ - HIER_NONE/- text/html
```

### 6.2 Analisi Log con Comandi

```bash
# Top 10 siti visitati
sudo cat /var/log/squid/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -10

# Conteggio richieste per client
sudo cat /var/log/squid/access.log | awk '{print $3}' | sort | uniq -c | sort -rn

# Richieste bloccate (TCP_DENIED)
sudo grep "TCP_DENIED" /var/log/squid/access.log | wc -l

# Bandwidth totale (MB)
sudo awk '{sum+=$5} END {print sum/1024/1024 " MB"}' /var/log/squid/access.log
```

📸 **SCREENSHOT 6**: Output di `tail -f /var/log/squid/access.log`

---

## 📋 STEP 7 — Configurazione e Test Cache

### 7.1 Verifica Cache Hit Ratio

```bash
# Installa squidclient
sudo apt install squidclient -y

# Statistiche cache
squidclient -h localhost -p 3128 mgr:info | grep -i "request hit ratios"

# Output esempio:
# Request Hit Ratios:    5min: 23.5%, 60min: 18.2%
# Byte Hit Ratios:       5min: 45.1%, 60min: 38.7%
```

### 7.2 Test Caching

```bash
# Primo accesso (MISS)
curl -x http://10.1.1.100:3128 -o /dev/null -s -w "Time: %{time_total}s\n" http://www.example.com

# Secondo accesso (HIT) - dovrebbe essere più veloce
curl -x http://10.1.1.100:3128 -o /dev/null -s -w "Time: %{time_total}s\n" http://www.example.com
```

📸 **SCREENSHOT 7**: Statistiche cache

---

## 📋 STEP 8 — Filtraggio Avanzato per Categoria

### 8.1 Uso di Liste Esterne (SquidGuard-style)

```bash
# Crea categoria social network
sudo mkdir -p /etc/squid/categories/social
sudo nano /etc/squid/categories/social/domains
```

Contenuto:
```
facebook.com
instagram.com
tiktok.com
twitter.com
linkedin.com
```

### 8.2 Configurazione squid.conf

```bash
# Aggiungi ACL
acl category_social dstdomain "/etc/squid/categories/social/domains"

# Regola
http_access deny category_social orario_lezioni
```

Ricarica:
```bash
sudo squid -k reconfigure
```

📸 **SCREENSHOT 8**: Test filtraggio categoria social

---

## 📋 STEP 9 — Consegna

### 9.1 File da Consegnare

1. **squid.conf** finale completo
2. **blacklist.txt** con almeno 20 domini
3. **8 screenshot** richiesti
4. **Relazione tecnica** (2-3 pagine) che include:
   - Topologia di rete utilizzata
   - Spiegazione delle ACL configurate
   - Analisi di 10 righe di log (interpretazione)
   - Statistiche cache (hit ratio)
   - Problemi incontrati e soluzioni

### 9.2 Criteri di Valutazione

| Criterio | Peso | Note |
|----------|------|------|
| Proxy funzionante | 30% | Client naviga tramite proxy |
| Filtraggio corretto | 25% | Blacklist blocca siti, whitelist permette |
| Cache configurata | 15% | Cache funzionante con hit > 10% |
| Log analisi | 15% | Interpretazione corretta log |
| Relazione tecnica | 15% | Chiarezza, completezza, professionalità |

---

## 🔧 Troubleshooting

### Problema: Proxy non risponde

```bash
# Verifica servizio attivo
sudo systemctl status squid

# Verifica porte in ascolto
sudo netstat -tuln | grep 3128

# Verifica firewall
sudo ufw status
sudo ufw allow 3128/tcp
```

### Problema: Siti non vengono bloccati

```bash
# Verifica sintassi ACL
sudo squid -k parse

# Verifica ordine regole (whitelist prima di blacklist)
sudo grep "http_access" /etc/squid/squid.conf

# Controlla log per debug
sudo tail -f /var/log/squid/cache.log
```

### Problema: Cache non funziona

```bash
# Verifica directory cache
ls -l /var/spool/squid

# Reinizializza cache
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid
```

---

## 📚 Domande di Verifica

1. **Qual è la differenza tra TCP_MISS e TCP_HIT nei log di Squid?**
2. **Spiega perché le regole `http_access` devono essere in un ordine specifico.**
3. **Come si può bloccare YouTube solo durante l'orario scolastico?**
4. **Cosa significa "cache hit ratio" e come si migliora?**
5. **Perché è importante il backup del file `squid.conf.original`?**

---

*Esercizio A — ES03 Proxy Server | Sistemi e Reti 3*
