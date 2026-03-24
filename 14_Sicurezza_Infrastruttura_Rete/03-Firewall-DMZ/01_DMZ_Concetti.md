# 01 — DMZ: Concetti Fondamentali e Architetture

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: Cos'è la DMZ, perché si usa, architetture, defense in depth

---

## 1. Origine del Termine

Il termine **DMZ** nasce nel contesto militare e geopolitico: una *Demilitarized Zone* è una fascia di territorio cuscinetto tra due paesi o fazioni in conflitto, dove nessuna delle due parti può schierare truppe o armamenti. L'esempio più noto è la zona smilitarizzata tra Corea del Nord e Corea del Sud.

In informatica, il termine è stato mutuato con lo stesso spirito: la **DMZ di rete** è una zona cuscinetto tra Internet (la "zona ostile") e la rete interna aziendale (la "zona protetta"), dove si posizionano i server che devono essere accessibili pubblicamente ma che non devono avere accesso diretto alla LAN privata.

---

## 2. Perché Serve la DMZ

### 2.1 Scenario SENZA DMZ — Il Rischio Diretto

Immagina un'azienda senza DMZ che espone un web server direttamente su Internet:

```
INTERNET ─────────── Router ─────────── LAN INTERNA
8.8.8.8              │                  192.168.1.0/24
                     │
                Web Server
                192.168.1.100
                (nella stessa LAN!)
```

**Problema**: Se un attaccante riesce a compromettere il web server (es. tramite una vulnerabilità SQL injection o RCE), si trova già **all'interno della LAN aziendale**. Da lì può:
- Attaccare il server del database
- Accedere al file server con dati riservati
- Compromettere il server Active Directory
- Muoversi lateralmente su tutti i PC della rete (**lateral movement**)

Questo scenario è chiamato **"flat network"** ed è considerato una grave lacuna di sicurezza.

### 2.2 Scenario CON DMZ — L'Isolamento

Con la DMZ, il web server viene spostato in una rete separata:

```
INTERNET ──── Firewall ──── DMZ ──── Firewall ──── LAN INTERNA
8.8.8.8        │            │         │             192.168.1.0/24
               │       Web Server     │
               │       192.168.100.x  │
               │                      │
               └── regole ACL ────────┘
```

**Vantaggio**: Anche se il web server viene compromesso, l'attaccante si trova nella DMZ — una zona isolata con regole di firewall che **bloccano esplicitamente** qualsiasi connessione verso la LAN interna. Il danno è limitato alla sola DMZ.

---

## 3. I Tre Tipi di Traffico in una DMZ

In un'architettura DMZ, il traffico può essere classificato in tre categorie:

### 3.1 Traffico Inbound (Internet → DMZ)

```
INTERNET ──[PERMIT selettivo]──► DMZ
```
- Permesso: HTTP (80), HTTPS (443) verso web server
- Permesso: SMTP (25) verso mail server
- Permesso: DNS UDP/TCP (53) verso DNS server
- **Bloccato**: qualsiasi traffico verso la LAN interna

### 3.2 Traffico Outbound (LAN → Internet)

```
LAN ──[PERMIT]──► INTERNET
```
- I dipendenti navigano liberamente su Internet
- Spesso mediato da un **proxy HTTP** in DMZ per controllo e cache
- Può essere filtrato per categoria (filtro contenuti)

### 3.3 Traffico Interno (LAN ↔ DMZ)

```
LAN ──[PERMIT]──► DMZ     (i dipendenti accedono ai server)
DMZ ──[DENY]───► LAN      (i server DMZ non contattano la LAN)
```

Questa distinzione è cruciale: i dipendenti devono poter accedere ai server in DMZ (intranet, applicazioni), ma i server DMZ **non devono mai** poter iniziare connessioni verso la LAN interna.

---

## 4. Il Principio del "Least Privilege" nelle Zone di Rete

Il **principio del minimo privilegio** (least privilege) applicato alla segmentazione di rete dice che ogni zona deve avere accesso solo a ciò che è strettamente necessario per la sua funzione:

| Zona | Può accedere a | Non può accedere a |
|------|---------------|---------------------|
| Internet | DMZ (servizi esposti) | LAN interna, Server Farm |
| DMZ | Internet (risposte) | LAN interna, Server Farm |
| LAN | DMZ, Internet, Server Farm | (accesso ampio ma controllato) |
| Server Farm | LAN, DMZ (selettivo) | Internet direttamente |

---

## 5. Quali Servizi Appartengono alla DMZ

La DMZ ospita **tutti i servizi che devono essere raggiungibili da Internet** ma che non necessitano di accesso diretto alla rete interna:

| Servizio | Porta/Protocollo | Motivo per stare in DMZ |
|----------|-----------------|-------------------------|
| **Web Server** (Apache, Nginx, IIS) | TCP 80, 443 | Deve rispondere a richieste HTTP/HTTPS pubbliche |
| **DNS Server pubblico** | UDP/TCP 53 | Risponde a query DNS per il dominio aziendale |
| **Mail Server (SMTP)** | TCP 25, 587 | Riceve/invia mail da/verso Internet |
| **FTP Server (pubblico)** | TCP 21 | Download file per partner o clienti |
| **VPN Gateway** | UDP 500, 4500 (IPSec) | Punto di accesso VPN per utenti remoti |
| **Reverse Proxy** | TCP 80, 443 | Smista le richieste verso server applicativi interni senza esporli |
| **Bastion Host / Jump Server** | TCP 22 (SSH) | Accesso amministrativo sicuro alla rete interna |
| **API Gateway** | TCP 443 | Esposizione API verso clienti e partner |

### 5.1 Reverse Proxy — Caso Speciale

Il **reverse proxy** merita un approfondimento: invece di esporre direttamente i server applicativi su Internet, si espone solo il reverse proxy (es. Nginx, HAProxy) che:
1. Riceve le richieste HTTPS dall'esterno
2. Termina il TLS (decifra la comunicazione)
3. Invia la richiesta (in chiaro o ricifrando) al server applicativo interno
4. Restituisce la risposta al client

```
Internet ──HTTPS──► Reverse Proxy (DMZ) ──HTTP──► App Server (LAN)
```

Questo schema limita ulteriormente la superficie di attacco.

---

## 6. Cosa NON Deve Stare in DMZ

È altrettanto importante sapere quali servizi **non devono mai** essere posizionati in DMZ:

| Servizio | Perché NON in DMZ |
|----------|-------------------|
| **Database** (MySQL, PostgreSQL, Oracle) | Contiene dati sensibili; deve essere raggiungibile solo dalla LAN/applicazioni interne |
| **Server applicativi interni** (ERP, CRM) | Processano dati aziendali riservati |
| **Active Directory / LDAP** | Server di autenticazione; se compromesso, tutti gli account sono a rischio |
| **File Server** (cartelle condivise) | Contiene documenti interni riservati |
| **Backup Server** | Se compromesso, backups inutilizzabili (ransomware) |
| **Server di sviluppo/test** | Spesso meno sicuri; non devono essere esposti |

---

## 7. Defense in Depth — La DMZ come Strato Difensivo

La **defense in depth** (difesa in profondità) è una strategia di sicurezza militare adattata all'informatica: invece di affidarsi a un'unica barriera di difesa, si costruiscono **molteplici strati** di protezione. Se un attaccante supera uno strato, trova immediatamente un altro ostacolo.

```
    INTERNET
       │
  ┌────▼──────┐
  │ Firewall  │  ← Strato 1: filtraggio pacchetti
  │Perimetrale│
  └────┬──────┘
       │
  ┌────▼──────┐
  │   IDS/    │  ← Strato 2: rilevamento intrusioni
  │   IPS     │
  └────┬──────┘
       │
  ┌────▼──────┐
  │   DMZ     │  ← Strato 3: zona isolata per server pubblici
  │           │
  └────┬──────┘
       │
  ┌────▼──────┐
  │ Firewall  │  ← Strato 4: secondo firewall (doppia DMZ)
  │ Interno   │
  └────┬──────┘
       │
  ┌────▼──────┐
  │   LAN     │  ← Strato 5: segmentazione interna
  │ Interna   │    (VLAN per HR, IT, Direzione...)
  └────┬──────┘
       │
  ┌────▼──────┐
  │  Endpoint │  ← Strato 6: antivirus, EDR, patch management
  │ Security  │
  └───────────┘
```

**La DMZ è uno strato**: non è la soluzione completa, ma fa parte di una strategia più ampia. Un'azienda che ha solo la DMZ ma non ha IDS, segmentazione interna, endpoint protection, ecc. ha ancora numerose vulnerabilità.

---

## 8. Architetture DMZ — Schemi Visivi

### 8.1 Architettura a Singolo Firewall (Single-Homed DMZ)

```
                     Internet
                        │
                   ┌────┴────┐
                   │  Router │ (ISP)
                   └────┬────┘
                        │
              ┌─────────┴─────────┐
              │    FIREWALL       │ ← Un solo dispositivo
              │  (Router Cisco o  │   con 3 interfacce
              │   ASA)            │
              └──┬──────────┬─────┘
                 │          │
          ┌──────┴──┐  ┌────┴────┐
          │   DMZ   │  │   LAN   │
          │ Server  │  │ Uffici  │
          └─────────┘  └─────────┘
```

- **Pro**: Economico, semplice da configurare
- **Contro**: Il firewall è un **single point of failure**; se viene compromesso, sia DMZ che LAN sono esposte
- **Usato per**: PMI, scuole, associazioni con budget limitato

### 8.2 Architettura a Doppio Firewall (Dual-Homed DMZ)

```
                     Internet
                        │
                   ┌────┴────┐
                   │ FW Est. │ ← Firewall Esterno
                   └────┬────┘     (filtra Internet → DMZ)
                        │
               ╔════════╪════════╗
               ║        │  DMZ   ║
               ║   ┌────┴───┐    ║
               ║   │Server  │    ║
               ║   │Pubblici│    ║
               ║   └────┬───┘    ║
               ╚════════╪════════╝
                        │
                   ┌────┴────┐
                   │ FW Int. │ ← Firewall Interno
                   └────┬────┘     (filtra DMZ → LAN)
                        │
                  ┌─────┴─────┐
                  │    LAN    │
                  │  Interna  │
                  └───────────┘
```

- **Pro**: Massima sicurezza; un attaccante deve compromettere **due** firewall separati
- **Contro**: Costo maggiore, configurazione complessa
- **Usato per**: Banche, ospedali, PA, aziende con dati molto sensibili

### 8.3 Screened Subnet

La **screened subnet** è una variante in cui la DMZ è isolata da due router/firewall separati che formano una "subnet schermata":

```
Internet ──[Router-Ext]── DMZ Subnet ──[Router-Int]── LAN
```

Simile al doppio firewall, ma con router tradizionali invece di firewall dedicati. Meno sicuro del doppio firewall (i router non hanno ispezione stateful), ma più economico.

---

## 9. Tabella Comparativa Architetture

| Caratteristica | Singolo Firewall | Doppio Firewall | Screened Subnet |
|----------------|-----------------|-----------------|-----------------|
| N° dispositivi | 1 FW | 2 FW | 2 router |
| Complessità config | Bassa | Alta | Media |
| Costo | Basso | Alto | Medio |
| Livello sicurezza | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Single point of failure | Sì | No | Parziale |
| Adatto per | PMI, scuole | Banche, PA, healthcare | Aziende medie |
| Standard di riferimento | — | PCI-DSS, ISO 27001 | — |

---

## 10. Riepilogo Concetti Chiave

| Termine | Definizione |
|---------|-------------|
| **DMZ** | Rete perimetrale isolata che ospita server pubblici, separata da LAN e Internet |
| **Defense in Depth** | Strategia di sicurezza multi-strato: più barriere, più sicurezza |
| **Least Privilege** | Ogni entità ha accesso solo a ciò che è strettamente necessario |
| **Lateral Movement** | Tecnica attaccante: dopo aver compromesso un sistema, si espande ad altri nella stessa rete |
| **Flat Network** | Rete senza segmentazione — tutti i dispositivi nella stessa rete IP |
| **Bastion Host** | Server rafforzato esposto in DMZ, punto di accesso controllato |
| **Reverse Proxy** | Server DMZ che riceve richieste esterne e le inoltra a server interni |
| **Single Point of Failure** | Componente la cui rottura causa il fallimento dell'intero sistema |

---

*Guida 01/04 — ES06 — Sistemi e Reti 3*
