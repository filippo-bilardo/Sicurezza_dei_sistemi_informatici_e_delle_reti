# B - Progetto Autonomo: DMZ a Doppio Firewall per CorpSecure S.p.A.

🏗️ **Tipo**: Progetto autonomo  
⭐ **Difficoltà**: ⭐⭐⭐⭐ (Avanzato)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumenti**: Cisco Packet Tracer 8.x + Relazione scritta  
📁 **File da consegnare**: `es06b_corpsecure.pkt` + `es06b_relazione.pdf`

---

## 📋 Modalità di Consegna

Prepara un documento Google Doc strutturato come segue:

1. **Copertina** — Nome, cognome, classe, data, titolo del progetto
2. **Indice** — con riferimenti ai STEP
3. **STEP 1** — Tabelle di indirizzamento compilate
4. **STEP 2** — Screenshot della topologia Packet Tracer annotato con i nomi dei dispositivi
5. **STEP 3** — Tabelle ACL complete con motivazioni
6. **STEP 4** — Screenshot output CLI (`show ip route`, `show ip interface brief`, `show access-lists`) per entrambi i firewall
7. **STEP 5** — Tabella test compilata + screenshot ping/simulazione
8. **STEP 6** — Motivazioni regole ACL
9. **STEP 7** — Risposte analisi critica
10. **Conclusioni** (C1–C3)

> **Risposte alle Domande di Riflessione** (R1.1–R6.3) indicated with ❓ at the end of each section.

**Formato file PT**: salvare come `es06b_corpsecure.pkt`  

---

## 🏢 Contesto Aziendale

**CorpSecure S.p.A.** è una banca online italiana in rapida crescita. Offre servizi finanziari tramite web (internet banking, trading), posta elettronica istituzionale e API per partner commerciali.

A seguito di un **audit di sicurezza**, il CTO ha richiesto un upgrade dell'infrastruttura di rete, passando da una DMZ a singolo firewall a una **architettura a doppio firewall**, considerata lo standard per istituzioni finanziarie regolamentate (PCI-DSS, DORA).

Il team IT ha incaricato te di progettare e configurare la nuova infrastruttura.

---

## 🗺️ Architettura Richiesta

L'architettura deve seguire questo schema generale:

```
        INTERNET
           │
           │  (IP pubblici assegnati dall'ISP)
    ┌──────┴──────┐
    │  FIREWALL   │   ← Firewall Esterno (FW-EXT)
    │  ESTERNO    │     Filtra traffico Internet → DMZ
    └──────┬──────┘
           │
    ╔══════╪══════════════════════════════════╗
    ║      │         ZONA DMZ                 ║
    ║  ┌───┴────┐  ┌──────────┐  ┌─────────┐  ║
    ║  │Web Srv │  │Mail Srv  │  │DNS Srv  │  ║
    ║  │Reverse │  │(SMTP/    │  │(Pubblico│  ║
    ║  │Proxy   │  │ IMAP)    │  │ esterno)│  ║
    ║  └────────┘  └──────────┘  └─────────┘  ║
    ╚══════╪══════════════════════════════════╝
           │
    ┌──────┴──────┐
    │  FIREWALL   │   ← Firewall Interno (FW-INT)
    │  INTERNO    │     Filtra traffico DMZ → LAN / Server Farm
    └──────┬──────┘
           │
    ┌──────┴──────────────────────────────────┐
    │                                         │
    ▼                                         ▼
┌──────────┐                          ┌──────────────┐
│   LAN    │                          │  SERVER FARM │
│  UFFICI  │                          │  INTERNA     │
│ PC, VoIP │                          │ DB, AppSrv   │
│ Stampanti│                          │ Auth Server  │
└──────────┘                          └──────────────┘
```

---

## 📐 Specifiche Tecniche

### Spazio di Indirizzamento

Tutte le reti interne devono essere progettate **all'interno di `172.16.0.0/16`**. Sei libero di scegliere le subnet specifiche, purché rispettino i vincoli dimensionali indicati.

| Zona | Maschera Richiesta | Host Utili | Dispositivi Previsti |
|------|-------------------|------------|----------------------|
| WAN verso ISP | /30 | 2 | Link punto-punto FW-EXT — Router ISP |
| DMZ | /27 | 30 max | Web server, mail, DNS, reverse proxy (4 server) |
| LAN Uffici | /24 | 254 max | PC, stampanti, VoIP (50–80 dispositivi) |
| Server Farm Interna | /26 | 62 max | DB server, app server, auth server (5–10 server) |

> ⚠️ La WAN usa IP pubblici reali (`203.0.113.0/30` assegnati dall'ISP — **non** modificare).

---

## 📋 STEP 1 — Piano di Indirizzamento (20 punti)

### 1.1 Tabella Subnet da Completare

Compila la seguente tabella con le subnet che hai scelto:

| # | Zona | Rete | Maschera | CIDR | Primo host | Ultimo host | Broadcast | Gateway |
|---|------|------|----------|------|-----------|-------------|-----------|---------|
| 1 | WAN | 203.0.113.0 | 255.255.255.252 | /30 | 203.0.113.1 | 203.0.113.2 | 203.0.113.3 | — |
| 2 | DMZ | ____________ | ____________ | /27 | ____________ | ____________ | ____________ | ____________ |
| 3 | LAN Uffici | ____________ | ____________ | /24 | ____________ | ____________ | ____________ | ____________ |
| 4 | Server Farm | ____________ | ____________ | /26 | ____________ | ____________ | ____________ | ____________ |

### 1.2 Tabella IP Dispositivi

Completa la tabella degli indirizzi IP di tutti i dispositivi:

| Dispositivo | Interfaccia | IP | Maschera | Gateway | Zona |
|-------------|-------------|-----|----------|---------|------|
| Router-ISP | Gi0/0 | 203.0.113.1 | 255.255.255.252 | — | WAN |
| FW-EXT | Gi0/0 (WAN) | 203.0.113.2 | 255.255.255.252 | 203.0.113.1 | WAN |
| FW-EXT | Gi0/1 (DMZ) | ____________ | ____________ | — | DMZ |
| FW-INT | Gi0/0 (DMZ) | ____________ | ____________ | — | DMZ |
| FW-INT | Gi0/1 (LAN) | ____________ | ____________ | — | LAN |
| FW-INT | Gi0/2 (SrvFarm) | ____________ | ____________ | — | Server Farm |
| Web Server | NIC | ____________ | ____________ | ____________ | DMZ |
| Mail Server | NIC | ____________ | ____________ | ____________ | DMZ |
| DNS Server | NIC | ____________ | ____________ | ____________ | DMZ |
| Reverse Proxy | NIC | ____________ | ____________ | ____________ | DMZ |
| PC1 (LAN) | NIC | ____________ | ____________ | ____________ | LAN |
| PC2 (LAN) | NIC | ____________ | ____________ | ____________ | LAN |
| DB Server | NIC | ____________ | ____________ | ____________ | Server Farm |
| App Server | NIC | ____________ | ____________ | ____________ | Server Farm |
| Auth Server | NIC | ____________ | ____________ | ____________ | Server Farm |

#### ❓ Domande di Riflessione — Piano di Indirizzamento

**R1.1** Che criterio hai seguito per scegliere le subnet specifiche all'interno di `172.16.0.0/16`? Hai scelto subnet contigue o sparse? Perché una pianificazione contigua può semplificare le ACL con wildcard mask?

**R1.2** La WAN usa una `/30` (2 host utili). Esiste un tipo di indirizzo IPv4 progettato proprio per link punto-punto che elimina lo "spreco" dei due indirizzi non assegnabili? Indica il tipo e spiega perché non viene usato qui.

**R1.3** Hai separato LAN Uffici e Server Farm in due subnet distinte. Quali benefici concreti di sicurezza porta questa separazione rispetto a una singola grande subnet interna? Nomina almeno due minacce che questa segmentazione mitiga.

---

## 🏗️ STEP 2 — Schema Topologia (10 punti)

### 2.1 Disegno in Cisco Packet Tracer

Realizza la topologia in **Cisco Packet Tracer** rispettando:
- 2 router Cisco 2901 (FW-EXT e FW-INT)
- 1 router Cisco 2901 (Router-ISP)
- 3 switch Cisco 2960 (uno per DMZ, uno per LAN, uno per Server Farm)
- 4 server generici in DMZ
- Almeno 2 PC in LAN Uffici
- Almeno 2 server in Server Farm
- Cablaggio corretto (cavi straight-through e cross-over dove necessario)

### 2.2 Documentazione della Topologia

Disegna uno schema testuale (o descrivi accuratamente) la tua topologia:

```
[Schema da completare dallo studente]

Esempio di struttura (da adattare con i tuoi IP):

     Router-ISP
    203.0.113.1
          │
    ┌─────┴─────┐
    │  FW-EXT   │
    │ WAN: .2   │
    │ DMZ: ...  │
    └─────┬─────┘
          │
    ┌─────┴─────┐
    │ Switch-DMZ│
    └─┬──┬──┬───┘
      │  │  │
     Web Mail DNS
          │
    ┌─────┴─────┐
    │  FW-INT   │
    └──┬─────┬──┘
       │     │
    LAN    Server Farm
```

#### ❓ Domande di Riflessione — Topologia e Design

**R2.1** Perché si usano switch dedicati per ogni zona (DMZ, LAN, Server Farm) invece di connettere direttamente i server alle interfacce dei firewall? Cosa cambierebbe in termini di scalabilità e sicurezza?

**R2.2** Il Router-ISP è un dispositivo gestito dall'ISP, non da CorpSecure. Spiega come l'architettura scelta isola la rete interna da un eventuale compromissione del Router-ISP. Quale sarebbe il rischio se FW-EXT non esistesse?

**R2.3** In ambienti reali ad alta sicurezza, FW-EXT e FW-INT sono spesso di **vendor diversi** (es. Cisco + Fortinet). Qual è il vantaggio di sicurezza di questa scelta rispetto a due firewall dello stesso vendor?

---

## 🔒 STEP 3 — Tabella Regole ACL (25 punti)

Progetta le regole ACL per entrambi i firewall. Usa il formato tabella e poi implementale in Cisco IOS.

### 3.1 Regole ACL per FW-EXT (minimo 8 regole)

**ACL_EXT_WAN_IN** — Applicata su interfaccia WAN, direzione IN (traffico da Internet verso DMZ):

| # | Azione | Protocollo | IP Sorgente | IP Destinazione | Porta Dst | Motivazione |
|---|--------|-----------|------------|----------------|-----------|-------------|
| 1 | PERMIT | TCP | any | Web Server (DMZ) | 80 | Accesso HTTP sito web bancario |
| 2 | PERMIT | TCP | any | Web Server (DMZ) | 443 | Accesso HTTPS (obbligatorio per banca) |
| 3 | PERMIT | UDP | any | DNS Server (DMZ) | 53 | Query DNS pubblico |
| 4 | PERMIT | TCP | any | Mail Server (DMZ) | 25 | Ricezione mail da Internet |
| 5 | _______ | _______ | _______ | _______ | _______ | _______ |
| 6 | _______ | _______ | _______ | _______ | _______ | _______ |
| 7 | _______ | _______ | _______ | _______ | _______ | _______ |
| 8 | _______ | _______ | _______ | _______ | _______ | _______ |
| 9 | DENY | IP | any | any | any | Blocca tutto il resto |

**ACL_EXT_DMZ_IN** — Applicata su interfaccia DMZ, direzione IN (traffico da DMZ verso Internet):

| # | Azione | Protocollo | IP Sorgente | IP Destinazione | Porta Dst | Motivazione |
|---|--------|-----------|------------|----------------|-----------|-------------|
| 1 | _______ | _______ | _______ | _______ | _______ | _______ |
| 2 | _______ | _______ | _______ | _______ | _______ | _______ |
| 3 | _______ | _______ | _______ | _______ | _______ | _______ |
| 4 | _______ | _______ | _______ | _______ | _______ | _______ |
| 5 | DENY | IP | any | any | any | Default deny |

### 3.2 Regole ACL per FW-INT (minimo 8 regole)

**ACL_INT_DMZ_IN** — Applicata su interfaccia DMZ di FW-INT, direzione IN:

| # | Azione | Protocollo | IP Sorgente | IP Destinazione | Porta Dst | Motivazione |
|---|--------|-----------|------------|----------------|-----------|-------------|
| 1 | DENY | IP | DMZ | LAN | any | Server DMZ non contattano LAN |
| 2 | _______ | _______ | _______ | _______ | _______ | _______ |
| 3 | _______ | _______ | _______ | _______ | _______ | _______ |
| 4 | _______ | _______ | _______ | _______ | _______ | _______ |
| 5 | DENY | IP | any | any | any | Default deny |

**ACL_INT_LAN_IN** — Applicata su interfaccia LAN di FW-INT, direzione IN:

| # | Azione | Protocollo | IP Sorgente | IP Destinazione | Porta Dst | Motivazione |
|---|--------|-----------|------------|----------------|-----------|-------------|
| 1 | _______ | _______ | _______ | _______ | _______ | _______ |
| 2 | _______ | _______ | _______ | _______ | _______ | _______ |
| 3 | _______ | _______ | _______ | _______ | _______ | _______ |
| 4 | DENY | IP | any | any | any | Default deny |

#### ❓ Domande di Riflessione — Progettazione ACL

**R3.1** Confronta le ACL di FW-EXT e quelle di FW-INT: quale dei due firewall ha regole più restrittive verso la LAN interna? Perché il firewall interno deve essere il "custode finale" anche se il traffico è già passato da FW-EXT?

**R3.2** La tua ACL `ACL_INT_DMZ_IN` inizia con `DENY IP DMZ → LAN`. Eppure il Web Server potrebbe dover autenticarsi tramite l'Auth Server in Server Farm. Come risolvi questa contraddizione? Scrivi la regola ACL specifica che permette solo questa comunicazione.

**R3.3** Inserire `DENY IP any any` esplicito a fine ACL ha un vantaggio rispetto all'implicit deny di Cisco IOS. Quale? (Suggerimento: considera il comando `show access-lists` e i log di sicurezza)

**R3.4** Un auditor PCI-DSS chiede di dimostrare che "nessun host non autorizzato può contattare i server di database". Come le tue ACL dimostrano questa conformità? Indica il nome dell'ACL e il numero di regola specifico.

---

## 💻 STEP 4 — Configurazione Cisco Packet Tracer (20 punti)

### 4.1 Configurazione FW-EXT

Configura il Firewall Esterno con:
- [ ] Hostname: `FW-EXT`
- [ ] IP su interfaccia WAN (Gi0/0): _________
- [ ] IP su interfaccia DMZ (Gi0/1): _________
- [ ] `no shutdown` su entrambe le interfacce
- [ ] Route di default verso Router-ISP
- [ ] ACL_EXT_WAN_IN configurata e applicata
- [ ] ACL_EXT_DMZ_IN configurata e applicata

```cisco
! === TEMPLATE - da adattare con i tuoi IP ===
FW-EXT(config)# hostname FW-EXT
FW-EXT(config)# interface GigabitEthernet0/0
FW-EXT(config-if)# description "WAN - Verso ISP"
FW-EXT(config-if)# ip address [TUO_IP_WAN] 255.255.255.252
FW-EXT(config-if)# no shutdown
FW-EXT(config-if)# exit

FW-EXT(config)# interface GigabitEthernet0/1
FW-EXT(config-if)# description "DMZ - Zona Perimetrale"
FW-EXT(config-if)# ip address [TUO_GATEWAY_DMZ] [TUA_MASK_DMZ]
FW-EXT(config-if)# no shutdown
FW-EXT(config-if)# exit

FW-EXT(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1

! === ACL - COMPLETA DA SOLO ===
FW-EXT(config)# ip access-list extended ACL_EXT_WAN_IN
! [inserisci le tue regole]
FW-EXT(config-ext-nacl)# exit

FW-EXT(config)# interface GigabitEthernet0/0
FW-EXT(config-if)# ip access-group ACL_EXT_WAN_IN in
```

### 4.2 Configurazione FW-INT

Configura il Firewall Interno con:
- [ ] Hostname: `FW-INT`
- [ ] IP su 3 interfacce: DMZ, LAN, Server Farm
- [ ] Routing verso tutte le zone
- [ ] ACL per ogni zona

### 4.3 Verifica Routing

Dopo la configurazione, esegui su entrambi i firewall:
```cisco
show ip route
show ip interface brief
show access-lists
```

Documenta l'output e allega gli screenshot.

#### ❓ Domande di Riflessione — Configurazione Firewall

**R4.1** Dopo `show access-lists`, i contatori di match mostrano quante volte ogni regola è stata colpita. Se la regola `DENY IP any any` ha contatore 0 dopo tutti i test, cosa significa? Se invece ha contatore molto alto, cosa potrebbe indicare?

**R4.2** La route di default su FW-EXT punta a `203.0.113.1` (Router-ISP). Come fa FW-INT a instradare il traffico verso Internet? Descrivere il percorso completo di un pacchetto da `PC1` verso `8.8.8.8` (hop per hop, con interfacce).

**R4.3** Hai configurato FW-INT con tre interfacce (DMZ, LAN, Server Farm). Se aggiungi una quarta interfaccia per una rete "Management" dedicata all'amministrazione remota dei firewall, quali regole ACL aggiungeresti per permettere solo SSH dalla rete Management verso i firewall, bloccando tutto il resto?

---

## 🧪 STEP 5 — Test di Connettività (15 punti)

Compila la seguente tabella eseguendo i test in Cisco PT. Per ogni test indica l'esito reale ottenuto.

| # | Sorgente | Destinazione | Servizio | Esito Atteso | Esito Reale | Pass/Fail |
|---|---------|-------------|---------|-------------|-------------|----------|
| T01 | PC1 (LAN) | Web Server (DMZ) | ping | ✅ OK | | |
| T02 | PC1 (LAN) | DB Server (SrvFarm) | ping | ✅ OK | | |
| T03 | PC1 (LAN) | Router-ISP (Internet) | ping | ✅ OK | | |
| T04 | Web Server (DMZ) | PC1 (LAN) | ping | ❌ BLOCCA | | |
| T05 | Web Server (DMZ) | DB Server (SrvFarm) | ping | ❌ BLOCCA | | |
| T06 | Router-ISP | Web Server (DMZ) | TCP 80 | ✅ OK* | | |
| T07 | Router-ISP | PC1 (LAN) | ping | ❌ BLOCCA | | |
| T08 | Router-ISP | DB Server (SrvFarm) | ping | ❌ BLOCCA | | |
| T09 | PC1 (LAN) | Auth Server (SrvFarm) | ping | ✅ OK | | |
| T10 | Web Server (DMZ) | Auth Server (SrvFarm) | TCP 389** | ❓ A TUA SCELTA | | |

> *TCP 80 non è facilmente testabile con semplice ping in PT. Usa il browser del PC simulato o la modalità simulazione.  
> **TCP 389 è la porta LDAP. Decidi tu se il Web Server in DMZ deve autenticarsi contro LDAP — giustifica la scelta.

#### ❓ Domande di Riflessione — Test di Connettività

**R5.1** Analizza i risultati della colonna "Esito Reale". Se ci sono discrepanze rispetto all'esito atteso, indica per ciascuna il probabile punto di fallimento: ACL errata, route mancante, IP sbagliato, o `no shutdown` dimenticato. Come lo hai diagnosticato?

**R5.2** Il test T10 (Web Server → Auth Server LDAP) era a tua discrezione. Quale decisione hai preso e perché? Se hai scelto di **permettere** questa comunicazione, quali misure aggiuntive (es. autenticazione mutua TLS, network segmentation) adotteresti per ridurre il rischio?

**R5.3** Usando la modalità **Simulazione** di Packet Tracer, descrivi step-by-step come traceresti il percorso di un pacchetto dal test T07 (Router-ISP → PC1) per identificare esattamente su quale interfaccia e in quale ACL viene bloccato.

---

## 📄 STEP 6 — Documentazione (5 punti)

### 6.1 Motivazione delle Regole ACL

Per ciascuna regola ACL che hai inserito, scrivi una motivazione (2–3 righe):

**Esempio**:
> *Regola 3 — ACL_EXT_WAN_IN — PERMIT UDP any → DNS Server port 53*  
> Il server DNS di CorpSecure è autoritativo per il dominio `corpsecure.it`. I client di tutto il mondo devono poter risolvere `www.corpsecure.it` → IP pubblico del reverse proxy. Senza questa regola il sito sarebbe irraggiungibile per hostname.

Scrivi le motivazioni per le regole che hai aggiunto (righe 5–8 in ogni tabella):

| ACL | Regola # | Motivazione |
|-----|----------|-------------|
| ACL_EXT_WAN_IN | 5 | ______________________________________________ |
| ACL_EXT_WAN_IN | 6 | ______________________________________________ |
| ACL_EXT_WAN_IN | 7 | ______________________________________________ |
| ACL_EXT_WAN_IN | 8 | ______________________________________________ |
| ACL_INT_DMZ_IN | 2 | ______________________________________________ |
| ACL_INT_DMZ_IN | 3 | ______________________________________________ |
| ACL_INT_LAN_IN | 1 | ______________________________________________ |
| ACL_INT_LAN_IN | 2 | ______________________________________________ |
| ACL_INT_LAN_IN | 3 | ______________________________________________ |

#### ❓ Domande di Riflessione — Documentazione e Motivazioni

**R6.1** Guardando le motivazioni che hai scritto per le regole ACL: quale regola è stata più difficile da giustificare? C'è qualche regola che, rileggendola, ti sembra troppo permissiva? Proponi una versione più restrittiva.

**R6.2** La relazione potrebbe essere letta da un auditor PCI-DSS. Quali elementi mancanti aggiungeresti per renderla conforme? (Consulta brevemente la sezione "Requirement 1" di PCI-DSS che riguarda firewall e network segmentation)

**R6.3** Immagina di dover ripristinare questa configurazione tra 6 mesi da zero. Quali informazioni, se non documentate ora nella relazione, saresti costretto a ricostruire per tentativi? Questo esercizio ti ha convinto dell'importanza della documentazione tecnica?

---

## 🧠 STEP 7 — Analisi Critica (5 punti)

Rispondi alle seguenti domande nella relazione scritta (max 10 righe per domanda):

### Domanda 7.1 — Singolo vs Doppio Firewall

Compila la tabella comparativa:

| Caratteristica | DMZ Singolo Firewall | DMZ Doppio Firewall |
|----------------|---------------------|---------------------|
| Numero di dispositivi | 1 router/firewall | 2 router/firewall |
| Complessità configurazione | Minore | ____________ |
| Costo infrastruttura | ____________ | ____________ |
| Livello di sicurezza | ____________ | ____________ |
| Scenario di compromissione FW esterno | Accesso a tutto | ____________ |
| Adatto per... | PMI, scuole, associazioni | ____________ |

### Domanda 7.2 — Perché una Banca Sceglie il Doppio Firewall?

Elenca almeno **3 motivazioni concrete** per cui CorpSecure S.p.A., in quanto istituzione finanziaria, deve adottare l'architettura a doppio firewall:

1. _______________________________________________________________
2. _______________________________________________________________
3. _______________________________________________________________

### Domanda 7.3 — Possibili Vulnerabilità della Tua Configurazione

Identifica almeno **2 possibili debolezze** nella tua implementazione e proponi come mitigarle:

| Vulnerabilità | Mitigazione Proposta |
|---------------|---------------------|
| _____________ | _____________________ |
| _____________ | _____________________ |

---

## 🧠 Domande di Riepilogo Finali

Rispondi a queste domande nelle **Conclusioni** della relazione:

**C1 — Confronto Architetturale**  
Completa la tabella comparativa con le tue parole, basandoti sull'esperienza diretta di aver configurato entrambe le architetture (singolo firewall in ES06-A, doppio firewall in ES06-B):

| Caratteristica | Singolo Firewall (ES06-A) | Doppio Firewall (ES06-B) |
|----------------|--------------------------|-------------------------|
| Complessità configurazione | | |
| Numero ACL totali | | |
| Rischio se FW è compromesso | | |
| Tempo di configurazione | | |
| Adatto per... | | |

**C2 — Scenario di Attacco**  
Un attaccante sfrutta una vulnerabilità nel Web Server DMZ e ottiene una shell remota sul server. Descrivi, passo per passo, cosa può fare **con** la configurazione attuale del doppio firewall, e cosa potrebbe fare se esistesse solo un singolo firewall. Quale zona è più difficile da raggiungere e perché?

**C3 — Riflessione Personale**  
Descrivi in almeno 150 parole: qual è stato il passaggio più complesso di questo progetto, cosa hai imparato che non sapevi prima, e se dovessi ridisegnare questa rete per una vera banca cosa cambieresti (tecnologie, strumenti, approcci diversi da Cisco IOS)?

---

## 📊 Rubrica di Valutazione (100 punti)

| Criterio | Punti max | Punti ottenuti |
|----------|-----------|----------------|
| **STEP 1** — Piano di indirizzamento corretto e completo | 20 | |
| **STEP 2** — Topologia PT funzionante con tutti i dispositivi | 10 | |
| **STEP 3** — Regole ACL corrette per entrambi i firewall | 25 | |
| **STEP 4** — Configurazione Cisco IOS funzionante | 20 | |
| **STEP 5** — Test di connettività eseguiti e documentati | 15 | |
| **STEP 6** — Documentazione e motivazione regole | 5 | |
| **STEP 7** — Analisi critica e risposta alle domande | 5 | |
| **TOTALE** | **100** | |

### 🏆 Bonus (fino a +15 punti)

| Bonus | Punti aggiuntivi |
|-------|-----------------|
| Documentazione professionale (relazione impaginata con indice, header/footer) | +5 |
| Aggiunta di servizi extra in DMZ (reverse proxy funzionante, FTP server) | +5 |
| Analisi critica approfondita con riferimento a standard (PCI-DSS, ISO 27001) | +3 |
| Configurazione NAT statico per i server DMZ (IP pubblico → IP privato) | +2 |

---

## 📁 Consegna

Consegna i seguenti file compressi in un archivio `.zip` nominato `ES06B_[COGNOME]_[NOME].zip`:

1. `es06b_corpsecure.pkt` — File Cisco Packet Tracer completo
2. `es06b_relazione.pdf` — Relazione con tutti i passi documentati (screenshot inclusi)
3. `es06b_acl.txt` — File di testo con TUTTI i comandi CLI usati per le ACL (copy-paste dalla CLI)

---

*ES06-B — Sistemi e Reti 3 | Progetto DMZ doppio firewall*
