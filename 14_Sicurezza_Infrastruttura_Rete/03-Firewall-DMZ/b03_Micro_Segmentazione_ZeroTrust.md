# 03 — Micro-Segmentazione e Zero Trust nella DMZ

> 📚 **Guida teorica** | Livello: 4ª–5ª superiore (concetti avanzati)
> 🔗 Prerequisiti: VLAN, ACL, concetti di architettura di rete
> ⏱️ Tempo di lettura: ~25 minuti

---

## 🏚️ I Limiti del Modello Perimetrale Classico

Il modello di sicurezza tradizionale si basa su un'unica assunzione fondamentale:

> **"Tutto ciò che è dentro il firewall è fidato. Tutto ciò che viene da fuori è nemico."**

Questa assunzione ha retto per decenni, quando:
- Le reti aziendali erano fisicamente isolate
- I dipendenti lavoravano tutti in ufficio
- Le applicazioni erano tutte on-premise

Oggi questa assunzione è **pericolosamente sbagliata**:

```
MODELLO CLASSICO (rotto):

INTERNET (untrusted)
    │
[Firewall perimetrale]
    │
┌───┴──────────────────────────────────────┐
│  "ZONA FIDATA"                           │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐│
│  │ DMZ  │──│ LAN  │──│ DB   │──│ DC   ││
│  │Server│  │ Uffici│  │Server│  │(AD)  ││
│  └──────┘  └──────┘  └──────┘  └──────┘│
│       "fidato" perché dentro il firewall │
└──────────────────────────────────────────┘

PROBLEMA: se un server DMZ viene compromesso,
ha accesso LIBERO a tutto il resto!
```

### I 3 Fallimenti del Modello Perimetrale

**1. Assunzione di fiducia implicita**
- Un server DMZ compromesso è "dentro" → considerato fidato
- Un laptop aziendale infetto che si connette alla VPN → "dentro" → fidato
- Un dipendente malintenzionato → "dentro" → fidato

**2. Lateral Movement difficile da rilevare**
- Una volta dentro, il traffico East-West (tra sistemi interni) raramente è ispezionato
- Un attaccante può muoversi liberamente tra i sistemi per ore/giorni senza alert

**3. Perimetro che si dissolve**
- Cloud, SaaS, smart working: non esiste più un perimetro fisico definito
- I dati sono ovunque, i dipendenti lavorano da casa, i server sono nel cloud

---

## 🔬 Micro-Segmentazione

### Definizione

La **micro-segmentazione** è un approccio di sicurezza che divide la rete in zone molto piccole (**micro-zone** o **micro-perimetri**), ognuna con le proprie policy di accesso, in modo che la compromissione di una zona non si propaghi automaticamente alle altre.

> 💡 **Analogia**: Invece di avere una nave con un'unica stiva enorme (se entra acqua, affonda tutta), costruiamo una nave con decine di compartimenti stagni (se uno si allaga, gli altri rimangono intatti).

### DMZ Classica vs DMZ Micro-Segmentata

```
DMZ CLASSICA:
┌─────────────────────────────────────────┐
│  DMZ (una zona unica)                   │
│                                         │
│  [Web] ←──→ [App] ←──→ [Mail] ←──→ [DNS]│
│    ↕           ↕         ↕         ↕    │
│  comunicazione libera tra tutti         │
└─────────────────────────────────────────┘
→ Se Web è compromesso, raggiunge App, Mail, DNS liberamente

DMZ MICRO-SEGMENTATA:
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Web Tier │  │ App Tier │  │Mail Tier │  │ DNS Tier │
│          │  │          │  │          │  │          │
│[Web Srv] │  │[App Srv] │  │[Mail MX] │  │[DNS Auth]│
│          │  │          │  │          │  │          │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │              │              │              │
  [ACL/FW]       [ACL/FW]      [ACL/FW]      [ACL/FW]
     │              │              │              │
     └──────────────┴──────────────┴──────────────┘
                         │
              Traffico inter-tier
              SOLO quello necessario:
              Web → App: solo TCP:8080
              App → DNS: solo UDP:53
              NO: Web → Mail, Mail → App, ecc.
```

### East-West Traffic Filtering

Il filtro **North-South** controlla il traffico che entra/esce dalla rete (dal firewall perimetrale):

```
INTERNET
   ↕ (North-South)
[Firewall perimetrale]
   ↕
DMZ / LAN
```

Il filtro **East-West** controlla il traffico che si muove *lateralmente* all'interno della stessa zona:

```
      Web Srv ←──East-West──→ App Srv
         ↕                       ↕
      Mail Srv ←──East-West──→ DNS Srv
```

Senza East-West filtering, un attaccante che compromette il Web Server può comunicare liberamente con Mail Server, DNS, App Server — anche se nessuno di questi servizi ha senso che sia raggiungibile dal Web Server.

### Implementazione con VLAN + ACL Inter-VLAN

```
Ogni micro-zona = una VLAN dedicata

VLAN 10: Web Tier    (172.16.10.0/27)
VLAN 20: App Tier    (172.16.20.0/28)
VLAN 30: Mail Tier   (172.16.30.0/29)
VLAN 40: DNS Tier    (172.16.40.0/29)

Il router/Layer3-switch che fa inter-VLAN routing applica ACL:
```

```cisco
! ACL per micro-segmentazione DMZ
! Solo Web Tier → App Tier (porta applicativa)
ip access-list extended ACL-WEB-TO-APP
 permit tcp 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.15 eq 8080
 deny ip 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.255 log
 permit ip any any

! Solo App Tier → DNS (query DNS)
ip access-list extended ACL-APP-TO-DNS
 permit udp 172.16.20.0 0.0.0.15 172.16.40.0 0.0.0.7 eq 53
 deny ip 172.16.20.0 0.0.0.15 172.16.40.0 0.0.0.255 log
 permit ip any any

! Blocco totale tra tier non correlati (Web → Mail: no motivo)
ip access-list extended ACL-WEB-TO-MAIL
 deny ip 172.16.10.0 0.0.0.31 172.16.30.0 0.0.0.7 log
 permit ip any any
```

### Software Defined Networking (SDN) — Cenni

In reti più grandi, la micro-segmentazione si implementa con **SDN**:

- **Control Plane**: un controller centralizzato (es. VMware NSX, Cisco ACI) definisce le policy
- **Data Plane**: i dispositivi fisici/virtuali applicano le policy ricevute dal controller
- Vantaggio: le policy seguono il **workload**, non la posizione fisica (utile nel cloud)

```
[Controller SDN]
      │ Policy "App Server può parlare solo con DB Server"
      │
   ┌──┴──────────────────────────────────────┐
   │ Ogni switch/hypervisor applica la policy │
   │ automaticamente quando il workload si    │
   │ sposta (anche nel cloud)                 │
   └─────────────────────────────────────────┘
```

---

## 🔐 Zero Trust Network Access (ZTNA)

### Il Principio Fondamentale

> **"Never Trust, Always Verify"** — non fidarsi mai di nessun utente, dispositivo o connessione, indipendentemente da dove si trova nella rete.

Zero Trust non è uno strumento o un prodotto: è un **modello architetturale** basato su tre assunzioni:

1. **La rete è già compromessa** (assume breach)
2. **La posizione nella rete non garantisce fiducia** (un PC nella LAN può essere infetto)
3. **Ogni accesso deve essere autenticato, autorizzato e cifrato**

### I 5 Pilastri Zero Trust

```
┌─────────────────────────────────────────────────┐
│                  ZERO TRUST                     │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ IDENTITÀ │  │DISPOSITIVO│  │  RETE    │      │
│  │          │  │          │  │          │      │
│  │Chi sei?  │  │È sicuro  │  │Traffico  │      │
│  │MFA, SSO  │  │il device?│  │cifrato?  │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│                                                 │
│         ┌──────────┐  ┌──────────┐             │
│         │APPLICAZIONE│  │  DATI   │             │
│         │          │  │          │             │
│         │Autorizzato│  │Classificati│           │
│         │per questa │  │e protetti│             │
│         │app?       │  │          │             │
│         └──────────┘  └──────────┘             │
└─────────────────────────────────────────────────┘
```

| Pilastro | Domanda | Tecnologia |
|---------|---------|-----------|
| **Identità** | Chi è l'utente? È chi dice di essere? | MFA, SSO, Identity Provider (IdP) |
| **Dispositivo** | Il dispositivo è sicuro e conforme alle policy? | EDR, MDM, Device Compliance |
| **Rete** | Il traffico è cifrato? La comunicazione è necessaria? | Micro-segmentazione, mTLS |
| **Applicazione** | L'utente ha il diritto di accedere a questa applicazione? | RBAC, least privilege |
| **Dati** | I dati sono classificati? Chi può leggerli/scriverli? | DLP, encryption at rest/in transit |

### Zero Trust vs VPN Tradizionale

```
VPN TRADIZIONALE:
┌──────────────────────────────────────────┐
│  Tunnel VPN = "passaporto" per la rete   │
│                                          │
│  Connesso alla VPN? → Accesso a TUTTO    │
│  la rete interna, come se fossi in ufficio│
└──────────────────────────────────────────┘
Problema: credenziali VPN rubate = accesso completo alla rete

ZERO TRUST (ZTNA):
┌──────────────────────────────────────────┐
│  Connessione richiesta → Verifica:       │
│  ✅ Identità (MFA)                       │
│  ✅ Dispositivo conforme                  │
│  ✅ Autorizzazione per QUESTA applicazione│
│                                          │
│  Accesso concesso SOLO a quella app,     │
│  non all'intera rete                     │
└──────────────────────────────────────────┘
Vantaggio: credenziali rubate danno accesso solo a una singola app
```

### Zero Trust Applicato alla DMZ

In un'architettura Zero Trust, anche i server **interni** non si fidano automaticamente di richieste provenienti dai server DMZ:

```
Scenario classico:
App Server (DMZ) → richiesta al DB (LAN) → DB risponde senza ulteriori verifiche

Scenario Zero Trust:
App Server (DMZ) → richiesta al DB (LAN):
  1. DB verifica: questa richiesta viene da un'identità nota? (mTLS certificate)
  2. DB verifica: l'identità ha il diritto di eseguire questa query? (RBAC)
  3. DB verifica: la sessione è valida? (token con scadenza breve)
  4. Solo dopo → risponde

Risultato: anche se l'App Server è compromesso, il DB non esegue
           query non autorizzate perché verifica ogni richiesta.
```

### Identity-Aware Proxy

Una componente chiave di Zero Trust per la DMZ è il **Identity-Aware Proxy (IAP)**:

```
UTENTE/APP
    │
    ▼
[Identity-Aware Proxy]
    │
    ├── Verifica identità (chi fa la richiesta?)
    ├── Verifica device (il dispositivo è sicuro?)
    ├── Verifica contesto (ora, posizione, comportamento)
    │
    ├── Se OK → inoltro alla risorsa target
    └── Se NON OK → blocco o step-up authentication

ESEMPIO: Google BeyondCorp, Cloudflare Access, Zscaler Private Access
```

---

## 🌑 Software-Defined Perimeter (SDP)

### La DMZ nel Modello "Dark Cloud"

L'SDP (Software-Defined Perimeter) è l'evoluzione estrema del Zero Trust: i server e le applicazioni sono **invisibili su Internet** finché non viene stabilita una connessione autorizzata.

```
DMZ CLASSICA:
server.azienda.it → IP pubblico → VISIBILE a tutti
                                  → scanner trovano porte aperte
                                  → attaccanti tentano exploit

SDP / DARK CLOUD:
server.azienda.it → IP pubblico → INVISIBILE (porte chiuse/filtrate)
                   ↑
                   Solo dopo autenticazione con SDP Controller
                   il firewall apre temporaneamente la connessione
```

### Architettura SDP

```
┌────────────────────────────────────────────────────────────┐
│                     INTERNET                               │
│                                                            │
│  Utente/Client                    Server Applicativo       │
│      │                                    │                │
│      │ 1. Richiesta connessione            │                │
│      ▼                                    │                │
│  [SDP Controller]                         │                │
│      │ 2. Verifica identità               │                │
│      │    e autorizzazione                │                │
│      │ 3. Autorizza connessione           │                │
│      ▼                                    │                │
│  [SDP Gateway] ────────────────────────▶ [Server]          │
│  4. Connessione diretta e cifrata         │                │
│     (il client ora "vede" il server)      │                │
└────────────────────────────────────────────────────────────┘

Senza l'autorizzazione del Controller:
- Il server è completamente invisibile
- Un port scan non trova nulla
- Nessun exploit diretto è possibile
```

---

## 🍯 Deception Technology

### Honeypot in DMZ

Un **honeypot** è un sistema (server, servizio, credenziale) progettato per **sembrare reale ma essere una trappola**. Il suo scopo non è bloccare l'attaccante, ma **rilevarlo e seguire le sue mosse**.

```
RETE DMZ con Honeypot:

   Web Server (reale)    Mail Server (reale)    DNS (reale)
   172.16.10.10          172.16.10.12           172.16.10.11
                  
                  [HONEYPOT]
                  172.16.10.99
                  
                  Appare come un server legacy vulnerabile
                  Nessun utente legittimo lo sa raggiungere
                  
                  Se qualcuno ci si connette → è un attaccante!
                  Alert immediato al SIEM
```

**Vantaggio**: Qualsiasi traffico verso l'honeypot è **per definizione** sospetto. Non ci sono falsi positivi: nessun utente legittimo dovrebbe connettersi a un sistema che non conoscono.

### Honeynet

Una **honeynet** è una rete intera di sistemi trappola (più honeypot connessi):

```
HONEYNET nella DMZ:

Internet → [Firewall] → [Honeynet]
                           │
                    ┌──────┼──────────┐
                    │      │          │
               [Honey    [Honey    [Honey
               Web]       DB]       Mail]
               172.16.10.80  .81       .82
               
               Tutti i 3 comunicano tra loro
               → l'attaccante può fare il pivot all'interno
               → SIEM registra ogni mossa
               → Security team impara le TTP dell'attaccante
               
TTP = Tactics, Techniques, Procedures (terminologia MITRE ATT&CK)
```

### Canary Token

I **canary token** sono credenziali, file o URL "fake" che avvisano il team di sicurezza se vengono utilizzati. Esistono nel mezzo dell'ambiente reale ma non hanno uso legittimo.

**Esempi pratici**:

| Tipo | Posizionamento | Come funziona |
|------|---------------|---------------|
| **Canary file** | Un file `credentials_backup.txt` nella cartella di config del web server | Se qualcuno lo legge, il server canary.tools riceve una richiesta e manda una notifica |
| **Canary URL** | Un link `http://admin-internal.azienda.it/debug` nei commenti del codice sorgente | Se un attaccante trova il codice e segue il link, scatta l'alert |
| **Canary password** | Una password `P@ssw0rd!` nel file `.env` del server web, ma non valida da nessuna parte | Se viene tentata l'autenticazione con questa password, scatta l'alert |
| **Canary DNS** | Un hostname `legacy-server.azienda.it` che non risolve a nulla di reale | Se viene risolto, indica che qualcuno sta esplorando la rete |

```python
# Esempio concettuale di canary token in un file di config
# config.php (file reale del web server)

# ... configurazione vera ...
$db_host = "172.16.20.20";
$db_user = "webapp";
$db_pass = "r3al_p@ssword_here";

# CANARY TOKEN — il file includerà questa stringa innocua
# che in realtà è una URL di tracking canarytokens.org
# Se qualcuno la copia e la usa, il canary server riceve la richiesta
$legacy_backup_url = "http://canarytokens.com/stuff/abc123/contact.php";
```

### Early Warning System: Rilevare il Movimento Laterale

La deception technology diventa particolarmente potente come **early warning** per il lateral movement:

```
Timeline di un attacco con Deception Technology:

T+0h    Attaccante compromette Web Server DMZ
T+0.5h  Ricognizione interna: scansiona la rete
        → Scopre l'honeypot (172.16.10.99)
        → Si connette all'honeypot
T+0.5h  ⚠️ ALERT SIEM: "Connessione a honeypot da 172.16.10.10"
        → Security team è allertato
T+0.5h  Security team inizia monitoring del Web Server compromesso
        → Vede che sta tentando connessioni verso LAN
T+1h    Web Server viene isolato prima che raggiunga la LAN

SENZA deception technology:
T+0h    Attaccante compromette Web Server DMZ
T+0.5h  Ricognizione interna
T+1h    Accesso al Server-DB
T+2h    Esfiltrazione dati
T+48h   SIEM rileva anomalia (troppo tardi)
```

---

## 📊 DMZ Classica vs DMZ con Zero Trust + Micro-Segmentazione

| Caratteristica | DMZ Classica | DMZ Zero Trust + Micro-Seg |
|----------------|-------------|---------------------------|
| **Fiducia nella rete** | "Dentro = fidato" | "Mai fidarsi, sempre verificare" |
| **Traffico East-West** | Non filtrato | Filtrato per ogni coppia source-dest |
| **Lateral movement** | Facile | Molto difficile (ogni micro-zona è isolata) |
| **Rilevamento intrusioni** | Solo alert perimetrali | Alert anche su movimento laterale interno |
| **Accesso admin** | SSH diretto ai server | Solo via bastion host + MFA |
| **Autenticazione** | Solo al perimetro | Continua, per ogni risorsa |
| **Visibilità** | Limitata al perimetro | Totale su ogni flusso |
| **Complessità gestione** | Media | Alta (richiede strumenti adeguati) |
| **Costo** | Basso | Medio-Alto |
| **"Blast radius"** | Intera rete | Limitato alla micro-zona compromessa |

---

## 🧪 Punti di Riflessione

> 💬 **Domanda 1**: Un'azienda ha configurato una DMZ con micro-segmentazione perfetta, ma non ha implementato East-West filtering nella LAN interna. Qual è il rischio residuo?

> 💬 **Domanda 2**: La deception technology (honeypot) richiede manutenzione e può essere bypassata da attaccanti esperti. Perché vale comunque la pena implementarla?

> 💬 **Domanda 3**: Zero Trust richiede autenticazione e autorizzazione continue. Come si bilancia questa necessità con la **user experience** dei dipendenti che devono accedere frequentemente alle risorse?

---

*03 — Micro-Segmentazione e Zero Trust | Guida Teorica ES07 | SISTEMI E RETI*
