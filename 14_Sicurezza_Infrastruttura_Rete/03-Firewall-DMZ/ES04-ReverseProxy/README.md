# ES04 — Reverse Proxy: Load Balancing e Protezione Server

🛡️ **Livello**: Scuola Superiore — Classe 4ª/5ª | **Materia**: Sistemi e Reti  
🔥 **Argomento**: Reverse Proxy — High Availability e Sicurezza  
⏱️ **Durata stimata**: 4–6 ore (laboratorio + teoria)

---

## 📌 Introduzione

Un **Reverse Proxy** è un server che si posiziona davanti ai server web backend, intercettando le richieste dai client e distribuendole ai server appropriati. A differenza del forward proxy (che protegge i client), il reverse proxy **protegge e ottimizza i server**.

```
Senza Reverse Proxy:
[Client Internet] ────────> [Web Server] (IP pubblico esposto)
     ↑ Attacchi DDoS, exploit diretti al server

Con Reverse Proxy:
[Client Internet] ───> [Reverse Proxy] ───> [Web Server 1]
                       (IP pubblico)    ├──> [Web Server 2]
                                        └──> [Web Server 3]
     ↑ Server protetti, load balanced, cached
```

**Funzioni principali:**
- **Load Balancing**: distribuzione traffico su più server per alta disponibilità
- **SSL Termination**: gestione HTTPS centralizzata, server backend in HTTP
- **Caching**: riduzione carico server per contenuti statici
- **Protezione**: WAF, rate limiting, hiding server details
- **Compressione**: gzip/brotli trasparente
- **Alta disponibilità**: failover automatico se un server cade

**Perché è fondamentale**: 
- Siti web ad alto traffico (milioni di richieste/giorno)
- Applicazioni critiche che richiedono uptime 99.99%
- Protezione da attacchi DDoS e exploit web
- Microservizi e architetture distribuite (Kubernetes, Docker)

---

## 🎯 Competenze Coperte

Al termine di questa esercitazione lo studente sarà in grado di:

| # | Competenza |
|---|------------|
| 1 | Spiegare la differenza tra **forward proxy** e **reverse proxy** |
| 2 | Installare e configurare **Nginx** come reverse proxy |
| 3 | Implementare **load balancing** con algoritmi round-robin, least-conn, ip_hash |
| 4 | Configurare **SSL/TLS termination** con certificati Let's Encrypt |
| 5 | Implementare **health checks** automatici per failover |
| 6 | Configurare il **caching** di contenuti statici e dinamici |
| 7 | Proteggere server backend con **header security** (HSTS, CSP, X-Frame-Options) |
| 8 | Implementare **rate limiting** per protezione DDoS |
| 9 | Configurare **WebSocket** proxying per applicazioni real-time |
| 10 | Monitorare performance con log e metriche Nginx |

---

## 📚 Guide Teoriche

Le seguenti guide in `docs/` forniscono tutto il background teorico necessario. Si consiglia di leggerle **prima** di affrontare gli esercizi.

| # | File | Argomento | Prerequisito per |
|---|------|-----------|-----------------|
| 1 | [01_Reverse_Proxy_Concetti.md](docs/01_Reverse_Proxy_Concetti.md) | Cos'è un reverse proxy, use cases, architetture | Tutti gli esercizi |
| 2 | [02_Nginx_Installazione.md](docs/02_Nginx_Installazione.md) | Installazione Nginx, architettura, configurazione base | Esercizio A, B |
| 3 | [03_Load_Balancing.md](docs/03_Load_Balancing.md) | Algoritmi LB, health checks, session persistence | Esercizio A, B |
| 4 | [04_Nginx_Proxy_Manager.md](docs/04_Nginx_Proxy_Manager.md) | **🆕 NPM con Docker**: GUI web, SSL automatico, Access Lists | Progetto NPM |
| 5 | [05_Caching_Performance.md](docs/05_Caching_Performance.md) | Proxy caching, cache headers, CDN | Esercizio B |
| 6 | [06_Sicurezza_Hardening.md](docs/06_Sicurezza_Hardening.md) | WAF, rate limiting, security headers | Esercizio B |

---

## 🗂️ Esercizi

| Esercizio | Tipo | Titolo | Difficoltà | Durata |
|-----------|------|--------|------------|--------|
| [A](esercizio_a.md) | 🔬 Laboratorio guidato | Nginx reverse proxy base con load balancing | ⭐⭐⭐ | 2–3 ore |
| [B](esercizio_b.md) | 🏗️ Progetto autonomo | High-availability reverse proxy con SSL e cache | ⭐⭐⭐⭐ | 2–3 ore |
| [C](esercizio_c.md) | 📝 Verifica scritta | 20 domande di teoria su reverse proxy | ⭐⭐⭐ | 1 ora |

---

## 🗃️ Struttura Cartelle

```
ES04-ReverseProxy/
│
├── README.md                          ← Questa pagina
│
├── esercizio_a.md                     ← Lab guidato: Nginx + load balancing
├── esercizio_b.md                     ← Progetto: HA reverse proxy SSL
├── esercizio_c.md                     ← Verifica scritta (20 domande)
│
├── docs/
│   ├── 01_Reverse_Proxy_Concetti.md  ← Teoria: Reverse proxy, use cases
│   ├── 02_Nginx_Installazione.md     ← Teoria: Nginx setup e config base
│   ├── 03_Load_Balancing.md          ← Teoria: Algoritmi LB, health checks
│   ├── 04_SSL_Termination.md         ← Teoria: HTTPS, certificati
│   ├── 05_Caching_Performance.md     ← Teoria: Proxy cache, CDN
│   └── 06_Sicurezza_Hardening.md     ← Teoria: WAF, rate limiting
│
└── img/                               ← Screenshot lab
    └── (es04a_screenshot_01.png, ...)
```

---

## ⚠️ Prerequisiti

Prima di iniziare questa esercitazione è necessario avere:
- Conoscenza base di **Linux** (comandi bash, gestione servizi)
- Conoscenza base di **networking** (IP, DNS, routing)
- Conoscenza dei **protocolli HTTP/HTTPS**
- Comprensione dei **web server** (Apache, Nginx)
- Accesso a 3-4 macchine virtuali o container (reverse proxy + server backend)
- (Opzionale) Dominio per certificati SSL reali

---

## 💡 Suggerimento per l'Insegnante

L'esercizio A è pensato per essere svolto in coppia, con configurazione step-by-step di Nginx e 2-3 server backend (possono essere container Docker per semplicità). L'esercizio B può essere assegnato come progetto di gruppo (2-3 studenti) con requisiti enterprise (SSL, monitoring, failover). L'esercizio C è verifica scritta individuale.

**🆕 Opzione semplificata:** Per studenti che trovano complessa la configurazione manuale Nginx, è disponibile il progetto [**Nginx Proxy Manager**](nginx-proxy-manager-project/) con interfaccia web GUI. Ideale per chi non ha confidenza con Linux CLI o preferisce un approccio visuale.

Si consiglia di usare Docker Compose per velocizzare il deployment di server backend multipli.

---

## 🐳 Progetto Nginx Proxy Manager (Bonus)

Per chi preferisce un'**interfaccia web** invece della configurazione manuale:

📁 **Directory:** [`nginx-proxy-manager-project/`](nginx-proxy-manager-project/)

**Contenuti:**
- `docker-compose.yml` - Stack completo NPM
- `README.md` - Guida studente dettagliata  
- `npm-manage.sh` - Script gestione automatizzata
- `example-backend/` - 3 app backend di test

**Vantaggi NPM:**
- ✅ GUI web user-friendly (no comandi Linux)
- ✅ SSL certificati Let's Encrypt con 1 click
- ✅ Access Lists integrate (autenticazione)
- ✅ Log e monitoring visuali
- ✅ Ideale per principianti o lab rapidi

**Avvio rapido:**
```bash
cd nginx-proxy-manager-project
docker-compose up -d
# Accedi a http://localhost:81
```

Vedi [guida completa NPM](docs/04_Nginx_Proxy_Manager.md) per dettagli.

---

## 🔗 Confronto con Esercizi Precedenti

| Aspetto | ES03 Forward Proxy | ES04 Reverse Proxy |
|---------|-------------------|-------------------|
| **Protegge** | Client interni | Server backend |
| **Direzione** | LAN → Internet | Internet → LAN |
| **Use case** | Filtraggio web aziendale | Siti web pubblici ad alto traffico |
| **Software** | Squid | Nginx, HAProxy, Apache |
| **Features chiave** | ACL, autenticazione, cache | Load balancing, SSL, HA |

---

*ES04 — Sistemi e Reti 3 | Materiale didattico*
