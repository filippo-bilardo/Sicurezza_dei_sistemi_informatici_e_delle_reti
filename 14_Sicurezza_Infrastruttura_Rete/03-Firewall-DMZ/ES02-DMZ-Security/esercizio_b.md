# ES07-B — Progetto Autonomo: Hardening DMZ per FortressNet S.r.l.

> 🏗️ **Tipo**: Progetto autonomo (individuale o a coppie)
> ⏱️ **Durata**: 4–5 ore (o multi-sessione)
> 🎯 **Obiettivo**: Riprogettare da zero l'architettura di sicurezza di un'azienda colpita da un attacco pivot, implementando doppia DMZ, ACL avanzate, hardening e piano di risposta a incidenti
> 📋 **Prerequisiti**: Completamento ES07-A, lettura di tutti i docs/

---

## 🏢 Scenario Aziendale

**FortressNet S.r.l.** è una PMI italiana specializzata in servizi finanziari online con 85 dipendenti. Tre settimane fa ha subito un attacco informatico grave:

> *Un attaccante ha sfruttato una vulnerabilità SQL injection nel portale web (DMZ). Dalla web shell ottenuta, ha eseguito una ricognizione della rete interna e raggiunto il server database contenente i dati di 12.000 clienti, inclusi dati bancari. L'attacco è rimasto non rilevato per 11 giorni.*

**Il management ha commissionato una revisione completa dell'architettura di sicurezza.** Sei stato assunto come consulente di sicurezza junior e devi:

1. Riprogettare la rete con architettura **doppia DMZ**
2. Definire le **policy di sicurezza** complete
3. Scrivere le **regole ACL** per i due firewall
4. Creare un **piano di hardening** per ogni server
5. Progettare la **risposta a futuri incidenti**
6. Valutare il **rischio residuo**

---

## 🌐 Architettura Target: Doppia DMZ

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                    [FW-ESTERNO]
                  Firewall perimetrale
                           │
          ┌────────────────┼────────────────┐
          │                                 │
   ┌──────▼──────┐                  ┌───────▼───────┐
   │  DMZ PUBBLICA│                  │  (bloccata    │
   │  Web, DNS,   │                  │   dal FW-est) │
   │  Mail        │                  └───────────────┘
   └──────┬──────┘
          │
    [FW-INTERNO]
  Secondo firewall
          │
   ┌──────▼──────┐
   │  DMZ PRIVATA │
   │  App Server, │
   │  Rev. Proxy  │
   └──────┬──────┘
          │
    [FW-LAN o ACL]
          │
    ┌─────┴──────┐
    │            │
┌───▼───┐  ┌────▼────┐
│  LAN  │  │  LAN    │
│uffici │  │ server  │
│  /25  │  │  /26    │
└───────┘  └─────────┘
```

**Spazio IP assegnato**: `10.10.0.0/16`

---

## 📋 STEP 1 — Piano di Indirizzamento (5 Zone)

### ⚙️ Requisiti di Subnetting

Devi suddividere `10.10.0.0/16` nelle seguenti zone. Scegli liberamente i range specifici, rispettando le dimensioni richieste.

**Regola**: Le subnet devono essere **contigue e ordinate** per facilitare la creazione di ACL aggregate.

| # | Zona | CIDR richiesto | Uso | Host utili |
|---|------|---------------|-----|-----------|
| 1 | WAN verso ISP | /30 | Link punto-punto | 2 |
| 2 | DMZ Pubblica | /27 | Web server, DNS pubblico, Mail MX | 30 |
| 3 | DMZ Privata | /28 | App server, Reverse proxy, WAF interno | 14 |
| 4 | LAN Uffici | /25 | Postazioni lavoro dipendenti (85 host) | 126 |
| 5 | LAN Server Interni | /26 | DB server, Storage, Domain Controller | 62 |

### 📝 Tabella da Compilare — Piano di Indirizzamento

| Zona | Network Address | Broadcast | Range Host | Gateway FW | Dispositivi pianificati |
|------|----------------|-----------|-----------|-----------|------------------------|
| WAN | _______ /30 | _______ | _______ – _______ | — | FW-Esterno (lato ISP), Router ISP |
| DMZ Pubblica | _______ /27 | _______ | _______ – _______ | _______ | Web-Server, DNS-Pub, Mail-MX |
| DMZ Privata | _______ /28 | _______ | _______ – _______ | _______ | App-Server, Reverse-Proxy |
| LAN Uffici | _______ /25 | _______ | _______ – _______ | _______ | PC-*, PC-Mgmt |
| LAN Server | _______ /26 | _______ | _______ – _______ | _______ | DB-Primary, DB-Replica, Storage, DC |

> 💡 **Suggerimento**: Inizia da `10.10.1.0` e assegna le subnet in ordine di dimensione decrescente per evitare sprechi.

### 📝 Tabella da Compilare — Dispositivi e IP

| Dispositivo | Zona | IP Assegnato | Ruolo | Servizi attivi |
|-------------|------|-------------|-------|---------------|
| FW-Esterno (lato WAN) | WAN | _______ | Firewall perimetrale | Routing, ACL |
| FW-Esterno (lato DMZ-Pub) | DMZ-Pub | _______ | Gateway DMZ pubblica | Routing, ACL |
| Web-Server | DMZ-Pub | _______ | Portale web HTTPS | Apache/Nginx :443 |
| DNS-Pub | DMZ-Pub | _______ | DNS autoritative | BIND :53 (autoritative-only) |
| Mail-MX | DMZ-Pub | _______ | Mail gateway | Postfix :25 |
| FW-Interno (lato DMZ-Pub) | DMZ-Pub | _______ | Firewall interno | Routing, ACL |
| FW-Interno (lato DMZ-Priv) | DMZ-Priv | _______ | Gateway DMZ privata | Routing, ACL |
| Reverse-Proxy | DMZ-Priv | _______ | Proxy inverso HTTPS | Nginx :443 |
| App-Server | DMZ-Priv | _______ | Logica applicativa | Java/Node :8080 |
| FW-LAN (o ACL Router) | LAN-Uffici | _______ | Separazione LAN tiers | ACL inter-VLAN |
| DB-Primary | LAN-Server | _______ | Database principale | MySQL :3306 |
| DB-Replica | LAN-Server | _______ | Replica DB | MySQL :3306 |
| Storage-NAS | LAN-Server | _______ | File server | SMB :445, NFS :2049 |
| Domain-Controller | LAN-Server | _______ | Active Directory | LDAP :389, Kerberos :88 |
| PC-Admin | LAN-Uffici | _______ | Postazione amministratore | — |
| Bastion-Host | LAN-Server | _______ | Jump server per admin DMZ | SSH :22 |

---

## 🗺️ STEP 2 — Schema Topologico Architetturale

### 2.1 Disegna lo Schema

Crea un diagramma della rete (a mano su carta, con strumenti come draw.io, o come schema ASCII) che mostri:

- [ ] Tutti i dispositivi con IP assegnato
- [ ] I due firewall (FW-Esterno e FW-Interno) con le interfacce etichettate
- [ ] Le 5 zone chiaramente delimitate con il colore/etichetta
- [ ] I flussi principali di traffico (frecce direzionate)
- [ ] La collocazione del Bastion Host per l'accesso amministrativo

### 2.2 Schema Logico delle Zone (da completare)

```
INTERNET
    │
    │ [link WAN]  IP: _______ / _______
    │
[FW-ESTERNO]
    │ eth0: _______ (WAN)
    │ eth1: _______ (DMZ-Pub)
    │
    ├──── [Switch-DMZ-Pub]
    │         ├── Web-Server:     _______
    │         ├── DNS-Pub:        _______
    │         └── Mail-MX:        _______
    │
    │ [link DMZ-Pub → FW-Interno]
    │
[FW-INTERNO]
    │ eth0: _______ (DMZ-Pub side)
    │ eth1: _______ (DMZ-Priv)
    │ eth2: _______ (LAN-Uffici)
    │ eth3: _______ (LAN-Server)
    │
    ├──── [Switch-DMZ-Priv]
    │         ├── Reverse-Proxy:  _______
    │         └── App-Server:     _______
    │
    ├──── [Switch-LAN-Uffici]
    │         ├── PC-Admin:       _______
    │         └── ...altri PC...
    │
    └──── [Switch-LAN-Server]
              ├── DB-Primary:     _______
              ├── DB-Replica:     _______
              ├── Storage-NAS:    _______
              ├── Domain-Ctrl:    _______
              └── Bastion-Host:   _______
```

---

## 🔒 STEP 3 — Matrice delle Policy di Sicurezza

### 3.1 Legenda

| Simbolo | Significato |
|---------|------------|
| ✅ PERMIT | Traffico esplicitamente permesso |
| ❌ DENY | Traffico esplicitamente bloccato |
| ⚠️ RESTRICTED | Permesso solo per specifici IP/porte |
| 🔍 LOG | Permesso ma registrato per audit |

### 3.2 Matrice da Compilare (Zona Sorgente × Zona Destinazione)

> Compila ogni cella con: azione (PERMIT/DENY/RESTRICTED) + protocolli/porte + motivazione

| Sorgente ↓ \ Destinazione → | INTERNET | DMZ-Pub | DMZ-Priv | LAN-Uffici | LAN-Server |
|-----------------------------|----------|---------|----------|-----------|-----------|
| **INTERNET** | — | | | | |
| **DMZ-Pub** | | — | | | |
| **DMZ-Priv** | | | — | | |
| **LAN-Uffici** | | | | — | |
| **LAN-Server** | | | | | — |

### 3.3 Flussi Speciali da Definire

Oltre alla matrice, descrivi questi flussi specifici:

| Flusso | Mittente | Destinatario | Porta/Protocollo | Policy | Motivazione |
|--------|---------|-------------|-----------------|--------|-------------|
| Accesso admin DMZ | Bastion-Host | Web-Server (DMZ-Pub) | TCP :22 | | |
| Aggiornamento OS server DMZ | Web-Server | Repository (Internet) | TCP :80,:443 | | |
| App-Server consulta DB | App-Server (DMZ-Priv) | DB-Primary (LAN-Server) | TCP :3306 | | |
| Backup notturno | DB-Primary | Storage-NAS | TCP :445 | | |
| DNS interno | LAN-Uffici | Domain-Controller | UDP :53 | | |
| SIEM log collection | Tutti i server | SIEM (LAN-Server) | TCP :514 syslog | | |

---

## 📜 STEP 4 — Regole ACL

### 4.1 Requisiti

- **FW-Esterno**: almeno **12 regole** (con numerazione e commento)
- **FW-Interno**: almeno **10 regole** (con numerazione e commento)
- Ogni regola deve avere: numero, direzione, sorgente, destinazione, protocollo/porta, azione, commento motivazione

### 4.2 Template Regole FW-Esterno

Completa le regole lasciando gli IP reali della tua progettazione:

```
Regola | Dir | Sorgente         | Destinazione        | Proto:Porta | Azione  | Motivazione
-------|-----|------------------|---------------------|-------------|---------|------------------
  01   | IN  | any              | [Web-Server IP] :443 | TCP:443     | PERMIT  | HTTPS pubblico
  02   | IN  | any              | [Web-Server IP] :80  | TCP:80      | PERMIT  | HTTP (redirect a HTTPS)
  03   | IN  | any              | [DNS-Pub IP] :53     | UDP:53      | PERMIT  | DNS pubblico
  04   | IN  | any              | [DNS-Pub IP] :53     | TCP:53      | PERMIT  | DNS zone transfer esteso
  05   | IN  | any              | [Mail-MX IP] :25     | TCP:25      | PERMIT  | Ricezione email MX
  06   | IN  | any              | DMZ-Pub network      | any         | DENY    | Blocca accesso non autorizzato DMZ
  07   | IN  | any              | DMZ-Priv network     | any         | DENY    | DMZ privata non raggiungibile da Internet
  08   | IN  | any              | LAN-Uffici network   | any         | DENY    | LAN non esposta a Internet
  09   | IN  | any              | LAN-Server network   | any         | DENY    | Server LAN non esposti
  10   | OUT | DMZ-Pub network  | any                  | TCP:443     | PERMIT  | Server DMZ possono fare HTTPS (aggiornamenti)
  11   | OUT | DMZ-Pub network  | LAN-Priv network     | any         | ________| [da compilare]
  12   | OUT | DMZ-Pub network  | LAN-Server network   | any         | ________| [da compilare]
  [aggiungere almeno fino a regola 15...]
```

### 4.3 Template Regole FW-Interno

```
Regola | Dir | Sorgente           | Destinazione          | Proto:Porta    | Azione  | Motivazione
-------|-----|--------------------|-----------------------|----------------|---------|-------------------
  01   | IN  | [Reverse-Proxy IP] | [App-Server IP] :8080 | TCP:8080       | PERMIT  | Proxy → App tier
  02   | IN  | [App-Server IP]    | [DB-Primary IP] :3306 | TCP:3306       | PERMIT  | App → DB (solo query)
  03   | IN  | DMZ-Priv network   | LAN-Uffici network    | any            | _______ | [da compilare]
  04   | IN  | DMZ-Priv network   | LAN-Server network    | any except :3306 | _______| [da compilare]
  05   | IN  | LAN-Uffici network | DMZ-Pub network       | TCP:443,TCP:80 | PERMIT  | Browsing interno
  06   | IN  | LAN-Uffici network | DMZ-Priv network      | any            | _______ | [da compilare]
  07   | IN  | [Bastion-Host IP]  | DMZ-Pub network       | TCP:22         | PERMIT  | Admin SSH via jump server
  08   | IN  | [Bastion-Host IP]  | DMZ-Priv network      | TCP:22         | PERMIT  | Admin SSH DMZ privata
  09   | IN  | LAN-Server network | DMZ-Pub network       | any (established) | _____ | [da compilare]
  10   | IN  | any                | any                   | any            | DENY    | Default deny
  [aggiungere almeno 2 regole bonus...]
```

> 🎯 **Obiettivo**: Ogni regola che inserisci deve avere una motivazione chiara. Regole senza motivazione non vengono valutate.

---

## 🔐 STEP 5 — Piano di Hardening Server

Per **ogni server** in DMZ (Web-Server, DNS-Pub, Mail-MX, Reverse-Proxy, App-Server), elenca almeno **5 misure di hardening** specifiche per quel server.

### Template da Compilare per Ogni Server

```
SERVER: [nome server]
ZONA: [DMZ-Pubblica / DMZ-Privata]
OS PRESUNTO: [es. Ubuntu Server 22.04 LTS]
SERVIZIO: [es. Nginx + PHP-FPM]

MISURE DI HARDENING:
┌───┬─────────────────────────────┬──────────────┬────────────────────────────┬─────────────┐
│ # │ Misura                      │ Priorità     │ Come Implementarla         │ Verifica    │
├───┼─────────────────────────────┼──────────────┼────────────────────────────┼─────────────┤
│ 1 │ [descrivi misura]           │ CRITICA/ALTA │ [comando o procedura]      │ [come testi]│
│ 2 │                             │              │                            │             │
│ 3 │                             │              │                            │             │
│ 4 │                             │              │                            │             │
│ 5 │                             │              │                            │             │
│+  │ [misure bonus opzionali]    │              │                            │             │
└───┴─────────────────────────────┴──────────────┴────────────────────────────┴─────────────┘
```

### Spunti per le Misure (non esaustivi — aggiungi le tue!)

**Web-Server (Nginx/Apache)**:
- Nascondere versione server (header `Server:` e `X-Powered-By`)
- Disabilitare metodi HTTP: TRACE, PUT, DELETE
- Configurare Content Security Policy (CSP) e altri security header
- WAF (mod_security su Apache, configurazione rate limiting)
- Processo web server con utente dedicato senza privilegi (non root)
- Directory listing disabilitato
- Timeout connessioni e keep-alive configurati

**DNS-Pub**:
- Configurazione autoritative-only (no recursion)
- Response Rate Limiting (RRL) per prevenire amplification
- TSIG per zone transfer
- Separazione DNS interno/esterno (split-horizon)
- Versione BIND nascosta (`version "none"`)

**Mail-MX**:
- No open relay (configurazione `mynetworks` restrittiva)
- SPF, DKIM, DMARC obbligatori
- TLS obbligatorio (STARTTLS + TLS-only)
- Anti-spam (SpamAssassin o simili)
- Limitazione dimensione messaggi e allegati

---

## 🚨 STEP 6 — Scenario Incident Response

### Evento: Compromissione del Mail Server DMZ

È il 14 febbraio, ore 23:15. Il sistema di monitoraggio segnala:

```
[ALERT CRITICO] SIEM-01 | 14-Feb 23:14:58
Sorgente:   Mail-MX [IP: _______]  (la tua subnet)
Evento:     OUTBOUND_SCAN_DETECTED
Dettaglio:  Il server Mail-MX ha eseguito una port scan SYN verso
            172.168.x.x (LAN-Server) su 847 porte distinte
            negli ultimi 90 secondi.
Precedente: 3 tentativi di login SSH falliti alle 22:51 da IP esterno
            + 1 login riuscito alle 22:58
Score:      CRITICO (98/100)
```

### 6.1 Descrivi le Azioni di Incident Response in Ordine

Per **ogni fase NIST** (Preparation, Detection, Containment, Eradication, Recovery, Post-Incident), descrivi le azioni specifiche che esegui:

| Fase | Tempo | Azioni Concrete | Chi le esegue | Output atteso |
|------|-------|----------------|--------------|---------------|
| **Detection & Analysis** (già avvenuta) | T+0 | L'alert è arrivato. Cosa fai SUBITO? | | |
| **Containment** | T+5 min | Come isoli il Mail-MX senza spegnere gli altri server? | | |
| **Containment** | T+15 min | Cosa blocchi a livello firewall? Scrivi la regola ACL di emergenza | | |
| **Eradication** | T+2h | Dopo aver preservato le prove, come pulisci il sistema? | | |
| **Recovery** | T+4h | Come ripristini il servizio mail? Da dove ripristini? | | |
| **Post-Incident** | T+48h | Cosa scrivi nel report? Cosa cambi nell'architettura? | | |

### 6.2 Regola ACL di Emergenza (da scrivere)

Scrivi la regola ACL specifica per isolare il Mail-MX mantenendo attivi gli altri server DMZ:

```
! Regola di emergenza — compilare con i tuoi IP reali
ip access-list extended EMERGENCY-ISOLATE-MAILMX
 ! Blocca TUTTO il traffico IN USCITA dal Mail-MX
 deny ip host _______ any log
 ! Ma mantieni gli altri server DMZ raggiungibili da Internet
 permit tcp any host _______ eq 80    ! Web-Server
 permit tcp any host _______ eq 443   ! Web-Server
 permit udp any host _______ eq 53    ! DNS-Pub
 deny ip any any log
```

### 6.3 Domande di Analisi

Rispondi alle seguenti domande (3–5 righe ciascuna):

1. **Vettore di attacco**: Il log mostra 3 tentativi SSH falliti + 1 riuscito. Cosa significa? Quali ipotesi formuli?

2. **Scope**: Come verifichi se anche gli altri server DMZ (Web-Server, DNS-Pub) sono stati compromessi?

3. **Evidenza forense**: Prima di spegnere il Mail-MX, quali dati devi preservare?

4. **Root cause**: Quale debolezza architetturale ha permesso questo attacco? Come la correggi?

5. **GDPR**: FortressNet elabora dati di clienti. Entro quanto tempo devi notificare il Garante? A chi altro devi comunicare l'incidente?

---

## ⚖️ STEP 7 — Valutazione del Rischio Residuo

Anche dopo aver implementato tutte le contromisure, un rischio residuo esiste sempre. Identificalo onestamente.

### 7.1 Matrice Rischio Residuo

Compila la seguente tabella per la tua architettura:

| Asset | Minaccia Residua | Probabilità (1–5) | Impatto (1–5) | Rischio (P×I) | Motivazione | Accettabile? |
|-------|-----------------|------------------|--------------|--------------|-------------|-------------|
| Web-Server (DMZ-Pub) | Vulnerabilità 0-day applicativa | | | | | |
| DNS-Pub | DNS amplification se mal configurato | | | | | |
| Reverse-Proxy | SSL certificate compromise | | | | | |
| App-Server | Injection via input non sanificato | | | | | |
| DB-Primary | Credential theft da App-Server compromesso | | | | | |
| LAN-Uffici | Phishing → endpoint compromise | | | | | |
| FW-Esterno | Misconfiguration futura | | | | | |

> **Scala rischio**: 1–4 Basso | 5–9 Medio | 10–16 Alto | 17–25 Critico

### 7.2 Analisi — Domande di Riflessione

1. **Quale asset ha il rischio residuo più alto** nella tua valutazione? Come potresti ridurlo ulteriormente?

2. **Zero Trust**: Come cambierebbe l'architettura se adottassi il principio "Never trust, always verify" per ogni connessione, anche interna?

3. **Confronto con ISO 27001**: Quale dei controlli dell'Annex A di ISO 27001 è più rilevante per questa architettura? (Suggerimento: cerca i controlli della sezione A.13 - Communications Security)

---

## 📊 Rubrica di Valutazione — 100 Punti

| Step | Descrizione | Punti | Criteri |
|------|-------------|-------|---------|
| **STEP 1** | Piano di indirizzamento | 15 pt | Subnet corrette (5), IP logici e consistenti (5), tabella dispositivi completa (5) |
| **STEP 2** | Schema topologico | 10 pt | Schema chiaro e leggibile (4), tutte le zone delimitate (3), flussi rappresentati (3) |
| **STEP 3** | Matrice policy | 15 pt | Matrice completa (7), flussi speciali correttamente definiti (5), coerenza interna (3) |
| **STEP 4** | Regole ACL | 25 pt | FW-Esterno ≥12 regole complete (12), FW-Interno ≥10 regole complete (10), sintassi Cisco corretta (3) |
| **STEP 5** | Piano hardening | 15 pt | 5 server × ≥5 misure (10), misure specifiche non generiche (3), verifica indicata (2) |
| **STEP 6** | Incident Response | 15 pt | Fasi NIST complete (7), regola ACL emergenza corretta (4), domande analisi (4) |
| **STEP 7** | Rischio residuo | 5 pt | Matrice compilata (3), riflessioni motivate (2) |
| **TOTALE** | | **100 pt** | |

### 🌟 Bonus (fino a 15 punti aggiuntivi)

| Bonus | Descrizione | Punti |
|-------|-------------|-------|
| **Zero Trust** | Proposta dettagliata di implementazione Zero Trust per FortressNet (micro-segmentazione, identity-aware proxy, ZTNA) | +5 pt |
| **Documentazione Audit-Ready** | La documentazione è strutturata come un report professionale di security assessment (executive summary, findings, recommendations, appendici) | +5 pt |
| **Confronto ISO 27001** | Mappatura delle contromisure progettate sui controlli ISO 27001 Annex A rilevanti (almeno 8 controlli) | +5 pt |

---

## 📋 Checklist Consegna

Prima di consegnare, verifica di aver completato:

- [ ] Tutte le tabelle del STEP 1 compilate con IP reali coerenti
- [ ] Schema topologico presente e leggibile
- [ ] Matrice policy compilata (nessuna cella vuota)
- [ ] FW-Esterno: almeno 12 regole con motivazione
- [ ] FW-Interno: almeno 10 regole con motivazione
- [ ] Piano hardening per tutti e 5 i server in DMZ
- [ ] Incident Response: tutte le fasi NIST compilate
- [ ] Regola ACL di emergenza scritta con IP reali della tua progettazione
- [ ] Rischio residuo: matrice compilata e domande risposte
- [ ] Il documento è firmato (nome, classe, data)

---

*ES07-B | Progetto Autonomo: FortressNet S.r.l. | SISTEMI E RETI*
