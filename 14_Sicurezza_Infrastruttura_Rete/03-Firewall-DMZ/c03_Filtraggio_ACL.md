# Squid: Filtraggio e ACL

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES03 — Proxy Server**

---

## ACL (Access Control List)

Le ACL in Squid definiscono **gruppi di oggetti** (IP, domini, porte, orari) che poi vengono usati nelle regole `http_access`.

### Sintassi Base

```bash
acl <nome_acl> <tipo_acl> <valore>
```

---

## Tipi di ACL Principali

### 1. ACL per IP Sorgente

```bash
# Singolo IP
acl admin_ip src 10.0.0.10

# Subnet
acl rete_uffici src 10.0.0.0/24

# Range IP
acl rete_ospiti src 192.168.99.10-192.168.99.50

# File esterno
acl ip_bloccati src "/etc/squid/blocked_ips.txt"
```

### 2. ACL per Dominio Destinazione

```bash
# Singolo dominio (e tutti i sottodomini)
acl google dstdomain .google.com

# Lista domini
acl social dstdomain .facebook.com .instagram.com .tiktok.com

# File esterno
acl blacklist dstdomain "/etc/squid/blacklist.txt"
```

**Formato file blacklist.txt:**
```
.facebook.com
.twitter.com
.youtube.com
```

### 3. ACL per URL Pattern

```bash
# Parola chiave nell'URL
acl adult_content url_regex -i (porn|sex|xxx|adult)

# Estensione file
acl video url_regex -i \.(avi|mp4|mkv|mov)$

# File esterno con regex
acl malware_urls url_regex "/etc/squid/malware_patterns.txt"
```

### 4. ACL per Porta

```bash
# Porta singola
acl https port 443

# Porte multiple
acl safe_ports port 80 443 21

# Range
acl high_ports port 10000-65535
```

### 5. ACL per Orario

```bash
# Orario lavorativo (lun-ven 9:00-18:00)
acl orario_lavoro time MTWHF 09:00-18:00

# Weekend
acl weekend time AS

# Giorni:
# M = Monday, T = Tuesday, W = Wednesday, H = Thursday, F = Friday
# A = Saturday, S = Sunday
```

### 6. ACL per Metodo HTTP

```bash
acl GET method GET
acl POST method POST
acl CONNECT method CONNECT
```

---

## Regole http_access

### Ordine Valutazione

**Prima regola che matcha vince!** Ordine top-down.

```bash
# ERRATO: Tutto bloccato!
http_access deny all
http_access allow localnet    # Mai raggiunto

# CORRETTO:
http_access allow localnet
http_access deny all
```

### Operatori Logici

```bash
# AND implicito (tutte le ACL devono matchare)
http_access deny gruppo_admin cat_social orario_lavoro

# OR con multiple regole
http_access allow gruppo_dirigenti
http_access allow gruppo_it

# NOT con !
http_access deny !authenticated
```

---

## Esempi Pratici

### Esempio 1: Blocco Social Network

```bash
# ACL
acl social dstdomain .facebook.com .instagram.com .twitter.com
acl orario_lavoro time MTWHF 09:00-18:00

# Regola
http_access deny social orario_lavoro
```

### Esempio 2: Whitelist per Ospiti

```bash
# ACL
acl ospiti src 192.168.99.0/24
acl whitelist dstdomain .wikipedia.org .google.com

# Regole
http_access allow ospiti whitelist
http_access deny ospiti
```

### Esempio 3: Blocco Download Eseguibili

```bash
# ACL
acl executables url_regex -i \.(exe|msi|bat|sh)$

# Regola
http_access deny executables
```

---

## Blacklist Esterne

### Shallalist (Categorie Web)

```bash
# Download
wget http://www.shallalist.de/Downloads/shallalist.tar.gz
tar -xzf shallalist.tar.gz -C /etc/squid/

# Configurazione
acl adult dstdomain "/etc/squid/shallalist/adult/domains"
acl gambling dstdomain "/etc/squid/shallalist/gambling/domains"

http_access deny adult
http_access deny gambling
```

---

## Domande di Verifica

1. **Qual è la differenza tra `dstdomain .google.com` e `url_regex google`?**

2. **Scrivi una regola ACL per bloccare YouTube solo dalle 9:00 alle 17:00 nei giorni feriali.**

3. **Perché l'ordine delle regole `http_access` è importante? Fornisci un esempio.**

---

**Prossima Sezione**: [04 - Autenticazione](./04_Autenticazione.md)
