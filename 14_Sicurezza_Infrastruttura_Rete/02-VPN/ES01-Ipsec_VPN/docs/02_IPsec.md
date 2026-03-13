# 02 — Architettura IPsec

> **Guida teorica** — ES08 VPN  
> Leggi questa guida prima di configurare i router nell'Esercizio A.

---

## 🏛️ Cos'è IPsec?

**IPsec (Internet Protocol Security)** è una suite di protocolli che fornisce servizi
di sicurezza (autenticazione, integrità, cifratura) a livello di rete (Layer 3 OSI).

A differenza di SSL/TLS che protegge le singole applicazioni (HTTPS, SMTPS, ecc.),
IPsec opera trasparentemente sotto le applicazioni: qualsiasi applicazione ne beneficia
senza modifiche al codice.

IPsec è definito da numerosi RFC, tra cui:
- RFC 4301 — Security Architecture for the Internet Protocol
- RFC 4302 — IP Authentication Header (AH)
- RFC 4303 — IP Encapsulating Security Payload (ESP)
- RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)

---

## 🔑 I due protocolli principali di IPsec

### AH — Authentication Header (Protocollo IP 51)

**AH** fornisce:
- ✅ **Autenticazione** dell'origine dei dati
- ✅ **Integrità** dei dati (i pacchetti non possono essere modificati)
- ✅ **Anti-replay protection** (protezione da attacchi di replay)
- ❌ **NO cifratura** — i dati rimangono in chiaro, solo autenticati

AH protegge anche l'intestazione IP esterna, il che lo rende **incompatibile con NAT**
(il NAT modifica l'IP sorgente, rompendo l'autenticazione AH).

**Quando usare AH**: reti interne dove la confidenzialità non è richiesta ma è
necessario garantire che i pacchetti non vengano alterati. Oggi è raramente usato.

```
Pacchetto AH (Transport Mode):
┌──────────┬────────────────────┬──────────────┐
│ IP header│  AH header         │   Payload    │
│ (orig.)  │ (next: 51)         │ (in chiaro!) │
└──────────┴────────────────────┴──────────────┘
           └────────── autenticato ─────────────┘
           (incluso IP header → incompatibile NAT)
```

### ESP — Encapsulating Security Payload (Protocollo IP 50)

**ESP** fornisce:
- ✅ **Cifratura** dei dati (confidenzialità)
- ✅ **Autenticazione** dell'origine
- ✅ **Integrità** dei dati
- ✅ **Anti-replay protection**
- ✅ **Compatibile con NAT** (con NAT-T, porta UDP 4500)

ESP è il protocollo usato praticamente in tutte le VPN IPsec moderne.

```
Pacchetto ESP (Tunnel Mode):
┌──────────────┬──────────┬─────────────────────────────────┬──────────┐
│ Outer IP hdr │ ESP hdr  │  CIFRATO                        │ ESP auth │
│ (pub: 203.x) │          │  [Inner IP | TCP/UDP | payload] │ trailer  │
└──────────────┴──────────┴─────────────────────────────────┴──────────┘
                          └────────── cifrato ──────────────┘
               └───────────────────── autenticato ──────────────────────┘
```

---

## 🔀 Modalità operative: Transport vs Tunnel Mode

### Transport Mode

Protegge solo il **payload** del pacchetto IP. L'intestazione IP originale è mantenuta
e visibile. Usato tra due **host** che comunicano direttamente.

```
Pacchetto originale:
┌──────────────────────────────┬────────────────────┐
│ IP header (10.1.1.1→10.2.2.2)│ TCP | dati         │
└──────────────────────────────┴────────────────────┘

Con ESP Transport Mode:
┌──────────────────────────────┬──────────┬────────────────────────┐
│ IP header (10.1.1.1→10.2.2.2)│ ESP hdr  │ TCP | dati (CIFRATO)   │
└──────────────────────────────┴──────────┴────────────────────────┘
               ↑
       IP originale visibile
```

**Uso tipico**: comunicazione sicura tra due server nella stessa organizzazione,
IPsec end-to-end tra host (non tra gateway).

### Tunnel Mode

Incapsula l'**intero pacchetto IP originale** (header + payload) in un nuovo pacchetto
con nuovi header IP. È la modalità standard per le VPN gateway-to-gateway.

```
Pacchetto originale (LAN Milano → LAN Roma):
┌────────────────────────────────────────────┬──────────┐
│ IP header (192.168.1.10 → 192.168.2.10)    │ TCP|dati │
└────────────────────────────────────────────┴──────────┘
                          ↓  Router-Milano lo incapsula
Pacchetto trasmesso su Internet:
┌──────────────────────────┬──────────┬──────────────────────────────────────┐
│ Outer IP hdr             │ ESP hdr  │ CIFRATO:                             │
│ (203.0.113.2→203.0.113.6)│          │ [192.168.1.10→192.168.2.10│TCP│dati] │
└──────────────────────────┴──────────┴──────────────────────────────────────┘
             ↑                                    ↑
     IP pubblici visibili              IP privati NASCOSTI nella cifratura
```

**Uso tipico**: VPN Site-to-Site tra router/firewall (come nell'Esercizio A),
VPN Remote Access tra client e concentratore VPN.

### Confronto Transport vs Tunnel Mode

| Caratteristica | Transport Mode | Tunnel Mode |
|---------------|---------------|-------------|
| Cosa viene cifrato | Solo payload | Intero pacchetto IP originale |
| Header IP originale | Visibile | Nascosto (cifrato) |
| Overhead | Minore | Maggiore (due header IP) |
| Uso tipico | Host-to-Host | Gateway-to-Gateway |
| IP privati visibili? | Sì | No |
| Usato in VPN Site-to-Site | ❌ No | ✅ Sì |

---

## 🤝 SA — Security Association

Una **SA (Security Association)** è un accordo unidirezionale tra due peer IPsec
che definisce come proteggere una comunicazione specifica.

**Caratteristiche della SA**:
- **Unidirezionale**: per comunicare nei due sensi servono 2 SA (una per direzione)
- **Identificata univocamente** dal triplice: SPI (Security Parameter Index) + protocollo (AH/ESP) + IP destinazione
- **Temporanea**: ha una scadenza (lifetime) in secondi o byte trasmessi

**Tipi di SA**:
- **ISAKMP SA** (o IKE SA): creata nella Phase 1, protegge la negoziazione IKE
- **IPsec SA**: creata nella Phase 2, protegge il traffico dati reale

**SAD (Security Association Database)**: il database dove il router memorizza tutte le SA attive.
**SPD (Security Policy Database)**: il database che definisce quali pacchetti devono essere protetti da IPsec (in Cisco: le ACL VPN-TRAFFIC).

---

## 🔐 IKE — Internet Key Exchange

**IKE** è il protocollo che negozia automaticamente i parametri e le chiavi per IPsec.
Senza IKE, i parametri dovrebbero essere configurati manualmente su ogni router (SA manuale).

IKE usa la porta **UDP 500** (e UDP 4500 per NAT-T).

### IKE Phase 1 — Stabilisce il canale di gestione sicuro

L'obiettivo della Phase 1 è creare un canale sicuro e autenticato tra i due peer,
che verrà poi usato per negoziare i parametri di Phase 2.

**Cosa viene negoziato**:
1. Algoritmo di cifratura (AES, 3DES)
2. Algoritmo di hash (SHA, MD5)
3. Metodo di autenticazione (PSK, certificati)
4. Gruppo Diffie-Hellman (per lo scambio di chiavi)
5. Lifetime della SA

**Cosa viene creato**: una **ISAKMP SA** (bidirezionale, protegge la Phase 2)

#### Main Mode (6 messaggi) — raccomandato
```
Initiator                              Responder
    │─── Messaggio 1: SA proposals ────→│  "Ecco le mie policy supportate"
    │←── Messaggio 2: SA selected ──────│  "Accetto questa policy"
    │─── Messaggio 3: DH public key ───→│  Scambio chiavi Diffie-Hellman
    │←── Messaggio 4: DH public key ────│  (senza trasmettere la chiave privata)
    │─── Messaggio 5: ID + Hash ───────→│  Autenticazione (cifrata con DH key)
    │←── Messaggio 6: ID + Hash ────────│  Conferma autenticazione
```
✅ **Più sicuro**: l'identità dei peer è scambiata in modo cifrato (messaggi 5-6)
⚠️ **Più lento**: 6 messaggi

#### Aggressive Mode (3 messaggi) — sconsigliato
```
Initiator                              Responder
    │─── Msg 1: SA + DH key + ID ──────→│  Tutto in un messaggio
    │←── Msg 2: SA + DH key + ID + hash─│  
    │─── Msg 3: hash ──────────────────→│  
```
⚡ **Più veloce**: solo 3 messaggi
❌ **Meno sicuro**: l'identità viene scambiata in chiaro prima che la cifratura sia attiva

### IKE Phase 2 — Negozia il tunnel dati (IPsec SA)

L'obiettivo della Phase 2 è negoziare i parametri per il traffico dati reale,
usando il canale sicuro creato in Phase 1.

**Cosa viene negoziato**:
1. Algoritmo di cifratura ESP (AES, 3DES)
2. Algoritmo di autenticazione ESP (SHA-HMAC, MD5-HMAC)
3. Durata (lifetime) delle SA IPsec
4. PFS (Perfect Forward Secrecy) — opzionale

**Cosa viene creato**: due **IPsec SA** unidirezionali (una per direzione)

**Quick Mode** (3 messaggi, tutto cifrato con la ISAKMP SA):
```
Initiator                              Responder
    │─── Msg 1: SA proposals + nonce ──→│  
    │←── Msg 2: SA selected + nonce ────│  
    │─── Msg 3: hash confirm ──────────→│  
```

### Riepilogo IKE Phase 1 vs Phase 2

| Aspetto | Phase 1 | Phase 2 |
|---------|---------|---------|
| Scopo | Canale di gestione sicuro | Tunnel per traffico dati |
| Cosa crea | ISAKMP SA (bidirezionale) | 2x IPsec SA (unidirezionali) |
| SA result. | 1 SA IKE | 2 SA IPsec (in/out) |
| Porta | UDP 500 | Incapsulato in Phase 1 |
| Rinnovo | Ogni `lifetime` (es. 86400s) | Ogni `lifetime` (es. 3600s) |
| Cisco config | `crypto isakmp policy` | `crypto ipsec transform-set` |

---

## ⚙️ Parametri ISAKMP Policy su Cisco IOS

```cisco
crypto isakmp policy 10
 encryption aes          ! Cifratura: des | 3des | aes (128/192/256)
 hash sha                ! Hash: md5 | sha | sha256
 authentication pre-share! Autenticazione: pre-share | rsa-sig | rsa-encr
 group 2                 ! DH Group: 1 | 2 | 5 | 14 | 19 | 20
 lifetime 86400          ! Durata SA Phase 1 in secondi (default: 86400 = 24h)
```

### Parametro `encryption` — algoritmo di cifratura

| Valore | Algoritmo | Lunghezza chiave | Sicurezza |
|--------|-----------|-----------------|-----------|
| `des` | DES | 56-bit | ❌ Insicuro (rotto facilmente) |
| `3des` | Triple-DES | 168-bit effettivi | ⚠️ Obsoleto, lento |
| `aes` | AES-128 | 128-bit | ✅ Sicuro, veloce |
| `aes 192` | AES-192 | 192-bit | ✅ Molto sicuro |
| `aes 256` | AES-256 | 256-bit | ✅ Massima sicurezza |

### Parametro `hash` — algoritmo di integrità

| Valore | Algoritmo | Output | Sicurezza |
|--------|-----------|--------|-----------|
| `md5` | MD5 | 128-bit | ⚠️ Vulnerabile a collision |
| `sha` | SHA-1 | 160-bit | ⚠️ Deprecato (2017) |
| `sha256` | SHA-256 | 256-bit | ✅ Raccomandato |

### Parametro `group` — Diffie-Hellman

Il **DH Group** determina la dimensione dei parametri usati per generare chiavi condivise.
Un gruppo più alto = chiavi più lunghe = più sicuro ma più lento.

| Valore | Dimensione chiave DH | Sicurezza | Note |
|--------|---------------------|-----------|------|
| `group 1` | 768-bit | ❌ Rotto | Non usare |
| `group 2` | 1024-bit | ⚠️ Debole | Usato in PT per compatibilità |
| `group 5` | 1536-bit | ⚠️ Accettabile | Legacy |
| `group 14` | 2048-bit | ✅ Raccomandato | Buon compromesso |
| `group 19` | 256-bit ECC | ✅ Eccellente | Curve ellittiche, moderno |
| `group 20` | 384-bit ECC | ✅ Eccellente | Curve ellittiche, molto sicuro |

> 💡 In Packet Tracer usiamo `group 2` per massima compatibilità.
> In produzione usa almeno `group 14`.

---

## 🔄 Perfect Forward Secrecy (PFS)

**Il problema**: se un attaccante registra tutto il traffico cifrato di una VPN per anni,
e in futuro riesce a ottenere la chiave principale (PSK o chiave privata RSA),
potrebbe decifrare retroattivamente tutto il traffico passato.

**La soluzione — PFS**: ogni negoziazione Phase 2 genera una chiave completamente nuova
e indipendente. Anche se la chiave di una sessione viene compromessa, le altre sessioni
rimangono protette.

```
SENZA PFS:
Chiave master ─→ Session Key 1 ─→ Session Key 2 ─→ Session Key 3
   Se compromessa: TUTTE le sessioni passate e future sono vulnerabili!

CON PFS (nuova DH exchange ogni Phase 2):
Chiave master
      ↓
DH 1 ─→ Session Key 1   (indipendente)
DH 2 ─→ Session Key 2   (indipendente)
DH 3 ─→ Session Key 3   (indipendente)
   Se una chiave di sessione viene compromessa: solo quella sessione è vulnerabile
```

**Configurazione PFS in Cisco IOS**:

```cisco
crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.6
 set transform-set VPN-TRANSFORM
 set pfs group14                ! Abilita PFS con DH Group 14
 match address VPN-TRAFFIC
```

---

## 🛡️ Anti-Replay Protection

IPsec numera sequenzialmente ogni pacchetto con un **sequence number**.
Il ricevitore mantiene una finestra degli ultimi pacchetti ricevuti e scarta
qualsiasi pacchetto con un sequence number già ricevuto.

Questo previene gli **attacchi di replay** in cui un attaccante cattura pacchetti
legittimi e li ritrasmette in seguito.

---

## 📊 Riepilogo configurazione Cisco IOS — Foglio di riferimento rapido

```cisco
! ─── FASE 1: ISAKMP Policy ─────────────────────────────────────────────────
crypto isakmp policy [numero_priorità]
 encryption aes [128|192|256]
 hash sha [256]
 authentication pre-share
 group [2|5|14]
 lifetime [secondi]

! Pre-Shared Key
crypto isakmp key [PASSWORD] address [IP_peer]

! ─── FASE 2: Transform-Set ──────────────────────────────────────────────────
crypto ipsec transform-set [NOME] [cifratura] [autenticazione]
! Esempi:
! esp-aes esp-sha-hmac         (AES + SHA — raccomandato in lab)
! esp-3des esp-md5-hmac        (3DES + MD5 — legacy)
! esp-aes 256 esp-sha256-hmac  (AES-256 + SHA256 — produzione)

! ─── ACL traffico interessante ───────────────────────────────────────────────
ip access-list extended [NOME_ACL]
 permit ip [rete_locale] [wildcard] [rete_remota] [wildcard]

! ─── Crypto Map ─────────────────────────────────────────────────────────────
crypto map [NOME_MAP] [sequenza] ipsec-isakmp
 set peer [IP_peer]
 set transform-set [NOME_TRANSFORM]
 set pfs [group]             ! Opzionale: abilita PFS
 match address [NOME_ACL]

! ─── Applicazione all'interfaccia ────────────────────────────────────────────
interface [INTERFACCIA_WAN]
 crypto map [NOME_MAP]

! ─── Comandi di verifica ─────────────────────────────────────────────────────
show crypto isakmp sa
show crypto ipsec sa
show crypto map
show crypto isakmp policy
show crypto session
```

---

## 🧮 Schema IKE: messaggi scambiati (Phase 1 + Phase 2)

```
Router-Milano (Initiator)              Router-Roma (Responder)
        │                                       │
        │ ──── IKE Phase 1 Main Mode ────────▶ │
        │  Msg 1: SA proposals                  │
        │◀──── Msg 2: SA selected ─────────────│
        │  Msg 3: DH public key                 │
        │◀──── Msg 4: DH public key ───────────│
        │  [chiave DH generata da entrambi]     │
        │  Msg 5: ID + Auth (CIFRATO)           │
        │◀──── Msg 6: ID + Auth (CIFRATO) ──── │
        │                                       │
        │  ══ ISAKMP SA stabilita (Phase 1) ══  │
        │                                       │
        │ ──── IKE Phase 2 Quick Mode ───────▶ │
        │  Msg 1: SA + nonce (cifrato)          │
        │◀──── Msg 2: SA + nonce (cifrato) ─── │
        │  Msg 3: conferma (cifrato)            │
        │                                       │
        │ ══ IPsec SA stabilita (Phase 2) ══    │
        │                                       │
        │ ════ TRAFFICO DATI CIFRATO CON ESP ══ │
        │  [192.168.1.10 → 192.168.2.10: PING]  │
        │◀═════════════════════════════════════│
```
