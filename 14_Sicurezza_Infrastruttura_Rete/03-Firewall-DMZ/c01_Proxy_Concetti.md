# Proxy Server: Concetti Fondamentali

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES03 — Proxy Server**

---

## Introduzione

Un **proxy server** è un intermediario tra client e server che intercetta, analizza e inoltra le richieste di rete. Il termine "proxy" deriva dal latino *procuratio* (gestire per conto di qualcun altro).

```
CONNESSIONE DIRETTA:
[Client] ────────────────> [Server Web]
   ↑ IP client esposto, nessun controllo

CONNESSIONE VIA PROXY:
[Client] ───> [Proxy] ───> [Server Web]
   10.0.0.5   192.168.1.50   93.184.216.34
              ↑ Filtra, logga, cachea
```

---

## Funzioni Principali

### 1. Filtraggio Contenuti (Content Filtering)

Blocco di siti in base a:
- **URL/Dominio**: blacklist/whitelist esplicite
- **Categoria**: social network, streaming, gambling, adult
- **Parole chiave**: nel contenuto della pagina
- **MIME type**: blocco file .exe, .zip, ecc.

**Esempio aziendale:**
```
Policy: Blocca social network durante orario lavorativo
Implementazione:
  IF (user=dipendente AND time=9:00-18:00 AND domain=*.facebook.com)
  THEN block
```

### 2. Caching

Memorizzazione locale di risposte HTTP per ridurre:
- **Latenza**: risposta immediata da cache locale
- **Banda Internet**: riutilizzo di contenuti già scaricati
- **Carico server**: meno richieste al server originale

**Esempio:**
```
Richiesta 1: www.example.com/logo.png
  Proxy → Internet → Server (200 OK, 150KB)
  [Cache: salva logo.png per 7 giorni]
  Latenza: 850ms

Richiesta 2 (dopo 5 minuti): www.example.com/logo.png
  Proxy → Cache locale (304 Not Modified)
  Latenza: 15ms ✓ (57x più veloce)
```

**Hit Ratio**: percentuale richieste servite da cache

```
Hit Ratio = (richieste cache HIT) / (richieste totali) × 100

Esempio:
1000 richieste totali
350 servite da cache (HIT)
650 da Internet (MISS)
Hit Ratio = 350/1000 = 35%
```

### 3. Anonimizzazione e Privacy

Il proxy maschera l'IP reale del client verso Internet.

```
Senza proxy:
[Client 10.0.0.5] → [Server web]
Server vede: IP 203.0.113.50 (IP pubblico client)

Con proxy:
[Client 10.0.0.5] → [Proxy 192.168.1.50] → [Server web]
Server vede: IP 203.0.113.100 (IP pubblico proxy)
Client reale nascosto ✓
```

**Header HTTP modificati:**
```
Senza proxy:
GET / HTTP/1.1
Host: www.example.com
X-Forwarded-For: 203.0.113.50

Con proxy anonimizzante:
GET / HTTP/1.1
Host: www.example.com
Via: 1.1 proxy.azienda.local (Squid/5.2)
X-Forwarded-For: (rimosso)
```

### 4. Logging e Auditing

Tracciamento completo dell'attività web:

```
Log Squid:
1678900000.123 156 10.0.0.5 TCP_MISS/200 5432 GET http://www.wikipedia.org/ mario.rossi DIRECT/208.80.154.224 text/html

Informazioni estratte:
• Timestamp: 2023-03-15 14:26:40
• Latency: 156ms
• Client IP: 10.0.0.5
• Username: mario.rossi
• URL: http://www.wikipedia.org/
• Bytes: 5432
• HTTP Status: 200 (OK)
```

**Utilizzo:**
- Compliance (GDPR, PCI-DSS)
- Incident response
- Bandwidth accounting
- Productivity monitoring

### 5. Protezione Malware

Scansione antivirus su file scaricati:

```
[Client] → richiesta download file.exe
           ↓
        [Proxy]
           ↓ scarica file.exe
        [Antivirus Scanner]
           ↓ scan ClamAV
           ✓ CLEAN: inoltra al client
           ✗ INFECTED: blocca + alert
```

---

## Tipologie di Proxy

### Forward Proxy

Proxy che opera **per conto dei client** interni per accedere a Internet.

```
┌──────────────────────────────────────┐
│         RETE INTERNA                 │
│                                      │
│  [Client 1] ───┐                     │
│  [Client 2] ───┼──> [Forward Proxy] ─┼─→ INTERNET
│  [Client 3] ───┘     192.168.1.50    │
│                                      │
└──────────────────────────────────────┘
```

**Casi d'uso:**
- Aziende: filtraggio web per dipendenti
- Scuole: controllo accesso studenti
- Provider: cache nazionale (es. Akamai, Cloudflare)

**Esempio configurazione client:**
```
Browser → Impostazioni → Proxy
HTTP Proxy: 192.168.1.50:3128
```

### Reverse Proxy

Proxy che opera **per conto dei server** interni, nascondendoli da Internet.

```
INTERNET ─→ [Reverse Proxy] ───┐
              80.241.210.50     │
                                ├──> [Web Server 1] 10.0.0.10
                                ├──> [Web Server 2] 10.0.0.11
                                └──> [Web Server 3] 10.0.0.12
```

**Funzionalità:**
- **Load balancing**: distribuzione traffico su più server
- **SSL offloading**: proxy gestisce HTTPS, server in HTTP (performance)
- **Caching**: CDN (Content Delivery Network)
- **WAF**: Web Application Firewall (protezione SQL injection, XSS)
- **Compressione**: gzip/brotli trasparente

**Esempi:**
- Nginx come reverse proxy
- HAProxy per load balancing
- Cloudflare CDN
- AWS CloudFront

**Configurazione Nginx:**
```nginx
server {
    listen 80;
    server_name www.azienda.com;

    location / {
        proxy_pass http://10.0.0.10:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Confronto Forward vs Reverse

| Aspetto | Forward Proxy | Reverse Proxy |
|---------|---------------|---------------|
| **Opera per** | Client | Server |
| **Posizione** | Rete interna | Rete perimetrale/DMZ |
| **Scopo** | Filtraggio, cache, privacy | Load balancing, sicurezza server |
| **Client sa del proxy?** | Sì (configurato) | No (trasparente) |
| **Esempio** | Squid aziendale | Nginx, HAProxy |

---

## Modalità di Deployment

### Explicit Proxy (Non-Transparent)

Il client **sa** del proxy e lo configura esplicitamente.

```
Browser:
☑ Usa proxy per tutte le connessioni
  HTTP Proxy: 192.168.1.50
  Porta: 3128
```

**Pro:**
- Nessuna manipolazione routing
- Supporto autenticazione facile
- Bypass semplice per troubleshooting

**Contro:**
- Richiede configurazione manuale ogni client
- Utenti possono disabilitarlo
- WPAD necessario per automazione

### Transparent Proxy (Intercepting)

Il proxy **intercetta** automaticamente il traffico, client ignaro.

```
Routing:
[Client] → gateway 10.0.0.1
           ↓ iptables REDIRECT
        [Proxy] 10.0.0.50:3128
           ↓
        INTERNET
```

**Implementazione Linux:**
```bash
# iptables redirect porta 80 → proxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128

# Squid intercept mode
http_port 3128 intercept
```

**Pro:**
- Nessuna configurazione client
- Utente non può bypassare
- Enforcement policy centralizzato

**Contro:**
- Problemi con HTTPS (richiede SSL bumping)
- Complesso routing
- Break protocolli che usano IP originale

### Comparison

| Caratteristica | Explicit | Transparent |
|----------------|----------|-------------|
| Config client | Richiesta | Non richiesta |
| Autenticazione | Facile | Complessa |
| HTTPS nativo | Sì | No (serve SSL bump) |
| Bypass utente | Possibile | Impossibile |
| Complexity | Bassa | Alta |

---

## Protocolli e Porte

### Porte Standard

| Protocollo | Porta | Descrizione |
|------------|-------|-------------|
| HTTP Proxy | 3128 | Squid default |
| HTTP Proxy | 8080 | Alternativa comune |
| SOCKS Proxy | 1080 | Generic proxy (TCP/UDP) |
| Transparent | 80/443 | Redirect automatico |

### SOCKS vs HTTP Proxy

**HTTP Proxy:**
- Solo protocollo HTTP/HTTPS
- Livello 7 (Applicazione)
- Ispeziona e modifica header HTTP
- Cache, filtraggio URL

**SOCKS Proxy:**
- Qualsiasi protocollo TCP/UDP
- Livello 4-5 (Trasporto/Sessione)
- Tunnel generico senza ispezione
- No cache, no filtraggio applicativo

**Esempio SOCKS:**
```bash
# SSH dynamic tunnel (SOCKS)
ssh -D 1080 user@server.com

# Configura browser
SOCKS Host: localhost:1080

# Ora tutto il traffico (HTTP, FTP, DNS) passa via SSH tunnel
```

---

## PAC File (Proxy Auto-Configuration)

Script JavaScript che decide dinamicamente quale proxy usare.

```javascript
// proxy.pac
function FindProxyForURL(url, host) {
    // Direct per subnet interna
    if (isInNet(host, "10.0.0.0", "255.0.0.0"))
        return "DIRECT";
    
    // Proxy per tutto il resto
    if (shExpMatch(url, "http:*"))
        return "PROXY proxy.azienda.local:3128";
    
    // HTTPS direct (no inspection)
    if (shExpMatch(url, "https:*"))
        return "DIRECT";
    
    return "DIRECT";
}
```

**Deployment:**
```
Browser → Configurazione automatica proxy
URL: http://proxy.azienda.local/proxy.pac
```

**WPAD (Web Proxy Auto-Discovery):**
```
Client cerca automaticamente PAC file via:
1. DHCP option 252
2. DNS: wpad.azienda.local
3. Download: http://wpad.azienda.local/wpad.dat
```

---

## Vantaggi e Svantaggi

### Vantaggi

```
✓ Controllo centralizzato accessi web
✓ Riduzione banda (cache hit ratio 30-50% tipico)
✓ Protezione malware (scansione download)
✓ Logging completo per compliance
✓ Anonimato IP verso Internet
✓ Bandwidth shaping per priorità
✓ Enforcement policy di sicurezza
```

### Svantaggi

```
✗ Single point of failure (se non ridondante)
✗ Latenza aggiuntiva (HTTPS inspection: +50-100ms)
✗ Complessità configurazione e manutenzione
✗ Privacy concerns (logging attività utenti)
✗ Problemi con app non proxy-aware
✗ HTTPS inspection = MITM controverso
✗ Costo licenze enterprise (BlueCoat, Zscaler)
```

---

## Proxy vs VPN vs Firewall

| Aspetto | Proxy | VPN | Firewall |
|---------|-------|-----|----------|
| **Layer OSI** | 7 (App) | 3 (Network) | 3-4 (Network/Transport) |
| **Granularità** | URL, contenuto | IP, porta | IP, porta, protocollo |
| **Cifratura** | Opzionale | Obbligatoria | No |
| **Uso tipico** | Filtraggio web | Accesso remoto | Perimetro rete |
| **Performance** | Cache velocizza | Overhead cifratura | Minimo |
| **Anonimato** | IP mascherato | IP mascherato | No |

---

## Domande di Verifica

1. **Spiega la differenza tra forward proxy e reverse proxy con esempi pratici.**

2. **Cos'è il cache hit ratio e come influenza le performance della rete?**

3. **Elenca 3 vantaggi e 3 svantaggi dell'uso di un transparent proxy rispetto a un explicit proxy.**

4. **Come funziona un file PAC? Fornisci un esempio di regola che usa proxy solo per domini `.com` e connessione diretta per il resto.**

5. **Perché l'HTTPS inspection è considerato controverso? Quali sono le implicazioni legali e di privacy?**

---

## Riferimenti

- [Squid Official Documentation](http://www.squid-cache.org/Doc/)
- [RFC 3143 - Known HTTP Proxy/Caching Problems](https://www.rfc-editor.org/rfc/rfc3143)
- [Proxy Auto-Configuration (PAC) Specification](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file)

---

**Prossima Sezione**: [02 - Installazione Squid](./02_Squid_Installazione.md)
