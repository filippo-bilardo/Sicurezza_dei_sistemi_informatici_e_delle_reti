# 02 — Firewall e ACL Cisco: Guida Completa

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: Firewall, ACL standard ed estese, wildcard mask, applicazione e verifica

---

## 1. Cos'è un Firewall

Un **firewall** è un sistema (hardware, software o entrambi) che controlla il flusso di traffico di rete in base a un insieme di regole predefinite. Opera come un **guardiano** tra due zone di rete con diversi livelli di fiducia.

### 1.1 Tipi di Firewall

| Tipo | Funzionamento | Livello OSI | Esempio |
|------|--------------|-------------|---------|
| **Packet Filter** | Esamina ogni pacchetto singolarmente (IP src/dst, porta, protocollo) | L3/L4 | ACL su router Cisco |
| **Stateful Firewall** | Traccia lo stato delle connessioni (sessioni TCP/UDP attive) | L3/L4 | Cisco ASA, pfSense |
| **Application Proxy** | Intercetta tutto il traffico e lo reinoltra (full inspection) | L7 | Squid Proxy, Zscaler |
| **NGFW** (Next-Gen) | Ispezione applicativa profonda (DPI), IPS integrato, filtro URL | L7 | Palo Alto, Cisco Firepower |
| **Host-based Firewall** | Software di protezione installato su singoli host | L3/L4/L7 | Windows Defender Firewall, ZoneAlarm, Little Snitch |

### 1.2 Firewall Hardware vs Software

**Firewall Hardware (di rete)**:
- Proteggono **l'intera rete** filtrando il traffico al perimetro
- Posizionati tra la rete interna e Internet
- Controllano il traffico tra zone diverse (es. LAN, DMZ, Internet)
- Esempi: Cisco ASA, pfSense, Fortinet FortiGate, Palo Alto Networks

**Firewall Software (host-based)**:
- Installati **su singoli host** (workstation, server)
- Proteggono il dispositivo individuale
- Monitorano le applicazioni e i processi che accedono alla rete
- Controllano connessioni in ingresso e uscita per quel computer
- Esempi: Windows Defender Firewall, macOS Firewall, iptables/firewalld su Linux, ZoneAlarm, Comodo Firewall
- **Vantaggio**: protezione granulare per applicazione; **Svantaggio**: complessità gestionale su molti host

### 1.3 Modello di Zona Fidata/Non Fidata

Un firewall protegge dividendo la rete in **zone di fiducia**:

```
Internet (Non Fidata)
  │
  ▼
┌─────────────┐
│  FIREWALL   │ ← applica regole
└─────────────┘
  ││
  │└─► DMZ (Semifidata)    [server pubblici]
  │
  └──► LAN Interna (Fidata) [workstation, file server]
```

**Principio**: il traffico dalla zona meno fidata verso quella più fidata è **negato per default**, solo eccezioni esplicite sono permesse (whitelist).

### 1.4 Regole di Filtraggio Fondamentali

Le regole di un firewall seguono un ordine **top-down**: la **prima regola che corrisponde** viene applicata, il resto viene ignorato.

```cisco
Regola 1: permit TCP 8.8.8.8 any port 80  [MATCH → PERMIT, fine]
Regola 2: deny ip any any                 [non viene mai raggiunta]
```

**Struttura tipica di una regola**:
```
[AZIONE] [PROTOCOLLO] [IP SORGENTE] [IP DESTINAZIONE] [PORTA] [STATO]
 permit    tcp         192.168.1.0    192.168.100.0     443    established
```

---

## 2. Firewall Stateless vs Stateful

Questa è una delle distinzioni più importanti da comprendere.

### 2.1 Firewall Stateless (Packet Filter)

Un firewall **stateless** esamina ogni pacchetto **in modo indipendente**, senza alcuna memoria delle connessioni precedenti. Decide solo in base agli header del pacchetto corrente.

```
Pacchetto in arrivo:
  IP src: 8.8.8.8   IP dst: 192.168.1.10   TCP dst: 80   flag: SYN

Controllo regola per regola → PERMIT o DENY
(Non sa se questo è parte di una connessione esistente)
```

**Problema concreto**: per permettere le risposte a una richiesta HTTP, devi creare una regola che permette **tutto il traffico** sulle porte alte (1024–65535) in ingresso. Questo è un rischio di sicurezza.

**Soluzione parziale in Cisco IOS**: la keyword `established` controlla i flag TCP (ACK, RST), permettendo solo le risposte TCP. **Non funziona per UDP e ICMP**.

```cisco
! Permetti solo risposte HTTP (tcp con ACK flag)
access-list 100 permit tcp any 10.0.0.0 0.0.0.255 established
```

### 2.2 Firewall Stateful

Un firewall **stateful** mantiene una **tabella delle connessioni attive** (state table). Quando un pacchetto arriva, il firewall controlla se fa parte di una connessione già stabilita.

```
Client LAN (10.0.0.5) inizia connessione HTTP:
  → SYN verso 8.8.8.8:80   [PERMIT - nuova connessione, tracciata]
  ← SYN-ACK da 8.8.8.8:80  [PERMIT - risposta a connessione stabilita]
  → ACK                      [PERMIT - parte della sessione]
  ← Dati HTTP                [PERMIT - parte della sessione]

Tentativo di intrusione:
  ← Pacchetto non richiesto da 8.8.8.8  [DENY - non in state table!]
```

**Vantaggio**: Non serve una regola esplicita per le risposte. Il firewall sa automaticamente che una risposta è legittima se la connessione è stata iniziata dall'interno.

| Caratteristica | Stateless | Stateful |
|----------------|-----------|----------|
| Memoria connessioni | ❌ No | ✅ Sì |
| Gestione risposte TCP | Manuale (established) | Automatica |
| Gestione risposte UDP | ❌ Impossibile | ✅ Sì (timeout) |
| Performance | Alta | Leggermente inferiore |
| Sicurezza | Media | Alta |
| Cisco IOS base | ✅ ACL stateless | ❌ (serve ZPF/CBAC) |

> ⚠️ **Nota per Packet Tracer**: Le ACL standard in Cisco IOS (quelle che usiamo in PT) sono **stateless**. Per un firewall stateful in IOS occorre configurare CBAC o Zone-Based Policy Firewall — argomenti avanzati al di là di questo corso.

---


## 3. ACL Cisco: Introduzione

Le **ACL (Access Control List)** sono liste di regole che definiscono quali pacchetti possono passare attraverso le interfacce di un router Cisco. Sono lo strumento principale per implementare policy di sicurezza su router IOS.

### 3.1 ACL Standard (numerata 1–99, 1300–1999)

Filtrano il traffico basandosi **solo sull'indirizzo IP sorgente**. Sono semplici ma limitate.

**Sintassi**:
```cisco
access-list [numero] {permit|deny} [source-address] [wildcard-mask]
```

**Esempi**:
```cisco
! Permetti tutto il traffico dalla rete 10.0.0.0/24
access-list 10 permit 10.0.0.0 0.0.0.255

! Nega il traffico dall'host specifico 192.168.1.5
access-list 10 deny host 192.168.1.5

! Permetti tutto (usato come ultima regola per non bloccare tutto)
access-list 10 permit any
```

> 💡 **Quando usare le ACL standard**: Solo per controllo di accesso semplice basato su IP sorgente (es. permettere solo certi host ad accedere al router via Telnet). Per sicurezza di rete seria, usa sempre le ACL estese.

### 3.2 ACL Estese (numerata 100–199, 2000–2699)

Filtrano il traffico basandosi su:
- Indirizzo IP **sorgente**
- Indirizzo IP **destinazione**
- **Protocollo** (IP, TCP, UDP, ICMP, OSPF...)
- **Porta sorgente e/o destinazione**
- Flag TCP (established)

**Sintassi**:
```cisco
access-list [numero] {permit|deny} [protocollo] [src] [wildcard] [dst] [wildcard] [operatore porta]
```

**Operatori di porta**:
| Operatore | Significato | Esempio |
|-----------|-------------|---------|
| `eq` | uguale a | `eq 80` (porta 80) |
| `neq` | diverso da | `neq 23` (non Telnet) |
| `lt` | minore di | `lt 1024` (porte privilegiate) |
| `gt` | maggiore di | `gt 1023` (porte non privilegiate) |
| `range` | intervallo | `range 20 21` (FTP) |

**Esempi completi**:
```cisco
! Permetti HTTP (TCP porta 80) da qualsiasi sorgente verso 192.168.100.10
access-list 110 permit tcp any host 192.168.100.10 eq 80

! Permetti HTTPS da qualsiasi verso la rete DMZ intera
access-list 110 permit tcp any 192.168.100.0 0.0.0.31 eq 443

! Permetti DNS UDP verso il server DNS specifico
access-list 110 permit udp any host 192.168.100.11 eq 53

! Permetti ping (ICMP echo)
access-list 110 permit icmp any any echo

! Nega tutto il resto (esplicito, ma c'è già l'implicit deny)
access-list 110 deny ip any any
```

---

## 4. Named ACL (ACL Nominata)

Le **Named ACL** sono identiche alle numeriche ma usano un nome descrittivo invece di un numero. Sono fortemente raccomandate per la leggibilità e la manutenibilità.

**Vantaggi delle Named ACL**:
- Nome descrittivo (es. `ACL_DMZ_IN` invece di `110`)
- Possibilità di **modificare singole righe** senza riscrivere tutta l'ACL
- Possibilità di **numerare le righe** (sequence numbers) per inserire regole in mezzo

**Sintassi**:
```cisco
! Creazione ACL estesa nominata
ip access-list extended [NOME_ACL]
  [sequence] {permit|deny} [protocollo] [src] [dst] [porta]

! Applicazione all'interfaccia
interface [INTERFACCIA]
  ip access-group [NOME_ACL] {in|out}
```

**Esempio completo**:
```cisco
ip access-list extended ACL_WAN_IN
 10 permit tcp any 192.168.100.0 0.0.0.31 eq 80
 20 permit tcp any 192.168.100.0 0.0.0.31 eq 443
 30 permit udp any host 192.168.100.11 eq 53
 40 deny ip any any

interface GigabitEthernet0/2
 ip access-group ACL_WAN_IN in
```

**Modifica singola regola**:
```cisco
! Aggiunta di una regola in posizione 25 (tra riga 20 e 30)
ip access-list extended ACL_WAN_IN
 25 permit tcp any host 192.168.100.12 eq 25

! Rimozione di una regola specifica
ip access-list extended ACL_WAN_IN
 no 25
```

---

## 5. Wildcard Mask

La **wildcard mask** è l'opposto della subnet mask: indica quali bit dell'indirizzo IP devono essere **ignorati** (bit a 1 = ignora) e quali devono corrispondere esattamente (bit a 0 = deve corrispondere).

### 5.1 Calcolo della Wildcard

**Formula**: Wildcard = 255.255.255.255 − Subnet Mask

| Subnet Mask | Wildcard | Significato |
|-------------|----------|-------------|
| 255.255.255.255 | 0.0.0.0 | Host singolo (usa `host` come shortcut) |
| 255.255.255.0 | 0.0.0.255 | Rete /24 |
| 255.255.255.224 | 0.0.0.31 | Rete /27 |
| 255.255.255.192 | 0.0.0.63 | Rete /26 |
| 255.255.0.0 | 0.0.255.255 | Rete /16 |
| 0.0.0.0 | 255.255.255.255 | Qualsiasi IP (usa `any` come shortcut) |

### 5.2 Esempi con Wildcard

```cisco
! Rete 10.0.0.0/24 → wildcard 0.0.0.255
permit ip 10.0.0.0 0.0.0.255 any

! Rete 192.168.100.0/27 → wildcard 0.0.0.31
permit tcp any 192.168.100.0 0.0.0.31 eq 443

! Host singolo 10.0.0.5 → wildcard 0.0.0.0 (o usa "host")
permit ip host 10.0.0.5 any
! equivalente a:
permit ip 10.0.0.5 0.0.0.0 any

! Qualsiasi IP → (usa "any")
deny ip any any
! equivalente a:
deny ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
```

> ⚠️ **Errore comune**: confondere wildcard con subnet mask! `255.255.255.224` è la subnet mask per /27, ma nella ACL devi scrivere `0.0.0.31` (la wildcard).

---

## 6. Regola Implicita DENY ALL

Ogni ACL Cisco termina con una **regola implicita** non visibile:

```
deny ip any any
```

Questo significa che qualsiasi traffico che **non corrisponde** a nessuna regola precedente viene **automaticamente bloccato**. Non devi scriverla (è già lì), ma è buona pratica aggiungerla esplicitamente per:
1. **Chiarezza**: rende esplicito il comportamento
2. **Logging**: con la variante `deny ip any any log` registra i pacchetti bloccati

```cisco
ip access-list extended ACL_WAN_IN
 10 permit tcp any host 192.168.100.10 eq 80
 20 permit tcp any host 192.168.100.10 eq 443
 99 deny ip any any log    ← esplicita, con logging
```

---

## 7. Applicazione ACL alle Interfacce

Le ACL vengono applicate alle interfacce del router con il comando:
```cisco
interface [NOME_INTERFACCIA]
ip access-group [NOME_ACL] {in|out}
```

### 7.1 IN vs OUT — Quale Usare?

La scelta tra `in` e `out` dipende dal punto di vista del router:

```
                       ┌─────────────┐
Traffico               │             │   Traffico
da Internet  ──IN──►   │   ROUTER    │   ──OUT──► verso LAN
             (Gi0/2)   │             │   (Gi0/0)
                       └─────────────┘
                               │
                           ◄──IN── (Gi0/1)
                        traffico dalla DMZ
```

- **`in`**: filtra il traffico **quando entra** nell'interfaccia (dal punto di vista del router)
- **`out`**: filtra il traffico **quando esce** dall'interfaccia

**Regola pratica**: È quasi sempre meglio applicare le ACL **in ingresso** (`in`) perché:
- Il traffico viene bloccato prima di essere processato dal router
- Risparmia risorse CPU (il router non fa routing prima di scartare)
- Più facile ragionare ("filtro cosa entra da questa interfaccia")

### 7.2 Limite: Una sola ACL per interfaccia per direzione

Su ogni interfaccia puoi applicare **una sola ACL** per direzione:
- Una ACL in ingresso: `ip access-group ACL_IN in`
- Una ACL in uscita: `ip access-group ACL_OUT out`

Se hai più regole, devono essere tutte nella stessa ACL.

---

## 8. Verifica e Debug delle ACL

### 8.1 Comandi di Verifica

```cisco
! Mostra tutte le ACL configurate con i contatori di match
show access-lists

! Mostra le ACL applicate a ogni interfaccia
show ip interface [nome-interfaccia]

! Mostra la configurazione completa del router (include ACL)
show running-config

! Mostra solo le ACL nella running config
show running-config | section access-list
show running-config | section ip access-list
```

**Esempio output di `show access-lists`**:
```
Extended IP access list ACL_WAN_IN
    10 permit tcp any 192.168.100.0 0.0.0.31 eq 80 (47 matches)
    20 permit tcp any 192.168.100.0 0.0.0.31 eq 443 (123 matches)
    30 permit udp any host 192.168.100.11 eq 53 (8 matches)
    99 deny ip any any (12 matches)
```

I **contatori** (es. `47 matches`) indicano quante volte quella regola è stata applicata — utile per verificare che le regole stiano funzionando.

### 8.2 Debug (da usare con cautela in produzione!)

```cisco
! Mostra tutti i pacchetti IP elaborati dal router (MOLTO verboso!)
debug ip packet

! Mostra solo i pacchetti bloccati dalle ACL
debug ip packet detail

! Disabilita il debug (importante!)
no debug all
! oppure
undebug all
```

> ⚠️ **Attenzione**: Il debug genera molto output e può rallentare il router in produzione. Usalo solo in ambiente di test o con filtri.

---

## 9. Esempi Completi di ACL per DMZ

### Scenario: Router con 3 interfacce (WAN, DMZ, LAN)

```cisco
! ============================================================
! CONFIGURAZIONE COMPLETA ACL PER SCENARIO DMZ
! Router con:
!   Gi0/0 = LAN    10.0.0.0/24       (rete interna)
!   Gi0/1 = DMZ    192.168.100.0/27  (zona server)
!   Gi0/2 = WAN    203.0.113.0/30    (Internet)
! ============================================================

! --- ACL per traffico IN da Internet (Gi0/2) ---
ip access-list extended ACL_WAN_IN
 ! HTTP verso qualsiasi server DMZ
 10 permit tcp any 192.168.100.0 0.0.0.31 eq 80
 ! HTTPS verso qualsiasi server DMZ
 20 permit tcp any 192.168.100.0 0.0.0.31 eq 443
 ! DNS UDP verso il DNS server
 30 permit udp any host 192.168.100.11 eq 53
 ! DNS TCP (zone transfer)
 40 permit tcp any host 192.168.100.11 eq 53
 ! SMTP verso il mail server
 50 permit tcp any host 192.168.100.12 eq 25
 ! Risposte a connessioni stabilite dalla LAN
 60 permit tcp any 10.0.0.0 0.0.0.255 established
 ! Blocca tutto il resto
 99 deny ip any any log

! --- ACL per traffico IN dalla DMZ (Gi0/1) ---
ip access-list extended ACL_DMZ_IN
 ! BLOCCA DMZ → LAN (regola critica!)
 10 deny ip 192.168.100.0 0.0.0.31 10.0.0.0 0.0.0.255
 ! Permetti risposte TCP stabilite da DMZ verso Internet
 20 permit tcp 192.168.100.0 0.0.0.31 any established
 ! Permetti ICMP (ping) da DMZ per diagnostica
 30 permit icmp 192.168.100.0 0.0.0.31 any
 ! Permetti DNS queries dal DNS server verso Internet
 40 permit udp host 192.168.100.11 any eq 53
 ! Blocca tutto il resto
 99 deny ip any any log

! --- ACL per traffico IN dalla LAN (Gi0/0) ---
ip access-list extended ACL_LAN_IN
 ! Permetti tutto dalla LAN verso DMZ
 10 permit ip 10.0.0.0 0.0.0.255 192.168.100.0 0.0.0.31
 ! Permetti tutto dalla LAN verso Internet
 20 permit ip 10.0.0.0 0.0.0.255 any
 ! Blocca tutto il resto (non dovrebbe mai scattare)
 99 deny ip any any log

! --- Applicazione ACL alle interfacce ---
interface GigabitEthernet0/2
 ip access-group ACL_WAN_IN in

interface GigabitEthernet0/1
 ip access-group ACL_DMZ_IN in

interface GigabitEthernet0/0
 ip access-group ACL_LAN_IN in
```

---

## 10. Tabella Riassuntiva ACL Cisco

| Tipo | Numero | Filtra | Quando usare |
|------|--------|--------|-------------|
| Standard | 1–99 | Solo IP sorgente | Controllo accesso semplice (es. Telnet/SSH) |
| Estesa | 100–199 | IP src+dst, protocollo, porta | Sicurezza di rete, DMZ, firewall |
| Standard Named | ip access-list standard | Solo IP sorgente | Come standard, ma con nome |
| Estesa Named | ip access-list extended | IP src+dst, protocollo, porta | **Raccomandata per tutto** |

---

*Guida 02/04 — ES06 — Sistemi e Reti 3*

