# ES07-A — Laboratorio Guidato: Simulazione Attacco Pivot DMZ → LAN

> 🔬 **Tipo**: Laboratorio guidato con Cisco Packet Tracer
> ⏱️ **Durata**: 3–4 ore
> 🎯 **Obiettivo**: Simulare un attacco pivot da un server DMZ compromesso verso la LAN interna, poi configurare le contromisure ACL per bloccarlo
> 📋 **Prerequisiti**: ES04 (ACL base), ES06 (architettura DMZ), concetti di routing

---

## 📸 Riepilogo Screenshot Richiesti

| # | Contenuto | Step |
|---|-----------|------|
| 📸1 | Topologia completa in Packet Tracer con tutti i dispositivi posizionati | Step 2 |
| 📸2 | Dettaglio cablaggio: porte fisiche collegate su Firewall/Router0 | Step 2 |
| 📸3 | Output `show ip interface brief` su Router0 (tutte le interfacce UP) | Step 3 |
| 📸4 | ACL permissiva applicata — output `show access-lists` | Step 4 |
| 📸5 | Ping PC-Attaccante → PC-Admin e Server-DB: **successo** (ACL permissiva) | Step 5 |
| 📸6 | Ping PC-Attaccante → PC-Admin: **fallisce** dopo ACL restrittiva | Step 6 |
| 📸7 | Output `show access-lists` con contatori dopo ACL ESTABLISHED | Step 7 |
| 📸8 | Topologia aggiornata con subnet `172.16.30.0/27` per Server-DB | Step 8 |
| 📸9 | Ping PC-Dev → Server-DB: **bloccato** dalla nuova ACL inter-LAN | Step 8 |
| 📸10 | File `es07a_dmz_security.pkt` salvato e aperto | Step 9 |

---

## 🌐 Scenario

**Data**: Martedì mattina, ore 02:47.

Il SIEM aziendale segnala traffico insolito: il **Web Server in DMZ** (172.16.10.10) sta inviando pacchetti verso la subnet LAN interna (172.16.20.0/24) su porte che non dovrebbe mai raggiungere. L'analisi rivela che un attaccante ha sfruttato una vulnerabilità nel CMS del web server per caricare una **web shell**, ottenendo una shell remota. Ora sta usando il web server come **pivot** per attaccare la LAN interna.

**Il tuo compito**: Ricreare l'ambiente in Packet Tracer, dimostrare l'attacco e configurare le contromisure per bloccarlo.

---

## 📐 STEP 1 — Piano di Indirizzamento e Analisi Flussi

### 1.1 Tabella IP Completa

| Zona | Dispositivo | Interfaccia | Indirizzo IP | Subnet Mask | Gateway | Note Sicurezza |
|------|-------------|-------------|--------------|-------------|---------|----------------|
| WAN | Router-ISP | Gi0/0 | 203.0.113.1 | /30 (255.255.255.252) | — | Simulazione Internet |
| WAN | Firewall (Router0) | Gi0/2 | 203.0.113.2 | /30 | 203.0.113.1 | Interfaccia esterna |
| DMZ | Firewall (Router0) | Gi0/1 | 172.16.10.1 | /27 (255.255.255.224) | — | Gateway DMZ |
| DMZ | Web Server ⚠️ | NIC | 172.16.10.10 | /27 | 172.16.10.1 | **COMPROMESSO** |
| DMZ | DNS Server | NIC | 172.16.10.11 | /27 | 172.16.10.1 | Autoritative-only |
| DMZ | Mail Server | NIC | 172.16.10.12 | /27 | 172.16.10.1 | Solo SMTP/IMAP |
| DMZ | PC-Attaccante 🔴 | NIC | 172.16.10.50 | /27 | 172.16.10.1 | Simula controllo remoto |
| LAN | Firewall (Router0) | Gi0/0 | 172.16.20.1 | /24 (255.255.255.0) | — | Gateway LAN |
| LAN | PC-Admin | NIC | 172.16.20.10 | /24 | 172.16.20.1 | 🎯 Bersaglio |
| LAN | PC-HR | NIC | 172.16.20.11 | /24 | 172.16.20.1 | Dati sensibili |
| LAN | Server-DB | NIC | 172.16.20.20 | /24 | 172.16.20.1 | 🎯 Bersaglio primario |
| LAN | PC-Dev | NIC | 172.16.20.12 | /24 | 172.16.20.1 | Postazione sviluppo |

> 💡 **Subnet DMZ** `172.16.10.0/27`: range 172.16.10.1–172.16.10.30 (30 host utili)
> 💡 **Subnet LAN** `172.16.20.0/24`: range 172.16.20.1–172.16.20.254 (254 host utili)

### 1.2 Schema Topologico ASCII

```
 INTERNET (simulata)
 203.0.113.0/30
        |
   [Router-ISP]
   203.0.113.1
        |
        | WAN link /30
        |
   [Router0 = FIREWALL]
   Gi0/2: 203.0.113.2 ← WAN
   Gi0/1: 172.16.10.1 ← DMZ
   Gi0/0: 172.16.20.1 ← LAN
        |
   ┌────┴────────────────────┐
   │                         │
   ↓ Gi0/1                   ↓ Gi0/0
[Switch-DMZ]            [Switch-LAN]
   |    |    |    |         |    |    |    |
  WEB  DNS  MAIL ATTACC  PC-ADM PC-HR SRV-DB PC-DEV
.10  .11  .12   .50      .10   .11   .20    .12

172.16.10.0/27              172.16.20.0/24
       DMZ                       LAN
```

### 1.3 Matrice Flussi — Stato INIZIALE (Vulnerabile)

| Sorgente | Destinazione | Protocollo/Porta | Permesso? | Motivazione |
|----------|-------------|-----------------|-----------|-------------|
| Internet | DMZ Web Server :80/:443 | TCP | ✅ Sì | Servizio pubblico |
| Internet | DMZ DNS Server :53 | UDP/TCP | ✅ Sì | DNS pubblico |
| Internet | DMZ Mail Server :25 | TCP | ✅ Sì | Ricezione email |
| DMZ | LAN (qualsiasi) | Qualsiasi | ⚠️ **SÌ** | **VULNERABILITÀ! Regola troppo permissiva** |
| LAN | DMZ (qualsiasi) | Qualsiasi | ✅ Sì | Amministrazione |
| LAN | Internet | Qualsiasi | ✅ Sì | Navigazione |
| Internet | LAN (diretta) | Qualsiasi | ❌ No | Bloccata dal firewall |

> 🔴 **PROBLEMA**: La regola che permette `DMZ → LAN qualsiasi` è l'errore di configurazione che permette l'attacco pivot!

### 1.4 Matrice Flussi — Stato CORRETTO (Dopo Contromisure)

| Sorgente | Destinazione | Protocollo/Porta | Permesso? | Motivazione |
|----------|-------------|-----------------|-----------|-------------|
| Internet | DMZ Web Server :80/:443 | TCP | ✅ Sì | Servizio pubblico |
| Internet | DMZ DNS Server :53 | UDP/TCP | ✅ Sì | DNS pubblico |
| Internet | DMZ Mail Server :25 | TCP | ✅ Sì | Ricezione email |
| DMZ | LAN (iniziata dalla DMZ) | Qualsiasi | ❌ **NO** | **Blocco pivot attack** |
| LAN | DMZ | TCP ESTABLISHED | ✅ Sì | Risposte a connessioni iniziate dalla LAN |
| LAN-uffici | LAN-server (DB) | Solo :3306,:5432 | ✅ Sì | Solo query DB autorizzate |
| LAN-uffici | LAN-server (DB) | Altro | ❌ No | Micro-segmentazione |

---

## 🖥️ STEP 2 — Creazione Topologia in Packet Tracer

### 2.1 Dispositivi da Inserire

Apri Packet Tracer e inserisci i seguenti dispositivi:

| Dispositivo PT | Nome da Assegnare | Categoria PT |
|----------------|------------------|-------------|
| Router 4331 (o 2911) | Router0 (Firewall) | Routers |
| Router 4331 (o 2911) | Router-ISP | Routers |
| Switch 2960 | Switch-DMZ | Switches |
| Switch 2960 | Switch-LAN | Switches |
| Server-PT | Web-Server | End Devices → Servers |
| Server-PT | DNS-Server | End Devices → Servers |
| Server-PT | Mail-Server | End Devices → Servers |
| PC-PT | PC-Attaccante | End Devices |
| PC-PT | PC-Admin | End Devices |
| PC-PT | PC-HR | End Devices |
| PC-PT | PC-Dev | End Devices |
| Server-PT | Server-DB | End Devices → Servers |

### 2.2 Schema Cablaggio

```
Router-ISP  Gi0/0 ──────── Gi0/2  Router0 (Firewall)
                                   Gi0/1 ──── Fa0/1  Switch-DMZ
                                   Gi0/0 ──── Fa0/1  Switch-LAN

Switch-DMZ  Fa0/2 ──── Web-Server
            Fa0/3 ──── DNS-Server
            Fa0/4 ──── Mail-Server
            Fa0/5 ──── PC-Attaccante

Switch-LAN  Fa0/2 ──── PC-Admin
            Fa0/3 ──── PC-HR
            Fa0/4 ──── PC-Dev
            Fa0/5 ──── Server-DB
```

> 📸 **Screenshot 1**: Topologia completa con tutti i dispositivi posizionati e cablati
> 📸 **Screenshot 2**: Zoom su Router0 — mostrare le 3 porte (Gi0/0, Gi0/1, Gi0/2) collegate

---

## ⚙️ STEP 3 — Configurazione IP e Routing Base

### 3.1 Configurazione Router-ISP

```cisco
! ============================================================
! ROUTER-ISP — Simulazione Internet
! ============================================================
enable
configure terminal
hostname Router-ISP

! Interfaccia verso il Firewall aziendale (WAN link)
interface GigabitEthernet0/0
 description WAN-link-verso-FW-aziendale
 ip address 203.0.113.1 255.255.255.252
 no shutdown

! Rotta verso le reti aziendali (per simulare risposte)
ip route 172.16.0.0 255.255.0.0 203.0.113.2

end
write memory
```

### 3.2 Configurazione Router0 (Firewall) — IP e Routing

```cisco
! ============================================================
! ROUTER0 — FIREWALL AZIENDALE
! Tre interfacce: WAN, DMZ, LAN
! ============================================================
enable
configure terminal
hostname Firewall

! --- Interfaccia WAN (verso Internet) ---
interface GigabitEthernet0/2
 description WAN-Internet
 ip address 203.0.113.2 255.255.255.252
 no shutdown

! --- Interfaccia DMZ ---
interface GigabitEthernet0/1
 description DMZ-172.16.10.0/27
 ip address 172.16.10.1 255.255.255.224
 no shutdown

! --- Interfaccia LAN ---
interface GigabitEthernet0/0
 description LAN-Interna-172.16.20.0/24
 ip address 172.16.20.1 255.255.255.0
 no shutdown

! --- Default route verso Internet ---
ip route 0.0.0.0 0.0.0.0 203.0.113.1

end
write memory
```

### 3.3 Configurazione Host DMZ

Per ogni dispositivo in DMZ, configurare tramite la tab **Desktop → IP Configuration**:

```
Web-Server:     IP 172.16.10.10  Mask 255.255.255.224  GW 172.16.10.1
DNS-Server:     IP 172.16.10.11  Mask 255.255.255.224  GW 172.16.10.1
Mail-Server:    IP 172.16.10.12  Mask 255.255.255.224  GW 172.16.10.1
PC-Attaccante:  IP 172.16.10.50  Mask 255.255.255.224  GW 172.16.10.1
```

### 3.4 Configurazione Host LAN

```
PC-Admin:   IP 172.16.20.10  Mask 255.255.255.0  GW 172.16.20.1
PC-HR:      IP 172.16.20.11  Mask 255.255.255.0  GW 172.16.20.1
PC-Dev:     IP 172.16.20.12  Mask 255.255.255.0  GW 172.16.20.1
Server-DB:  IP 172.16.20.20  Mask 255.255.255.0  GW 172.16.20.1
```

### 3.5 Verifica Connettività Base

Dal CLI di Firewall (Router0):
```cisco
show ip interface brief
```

Output atteso:
```
Interface              IP-Address      OK? Method Status   Protocol
GigabitEthernet0/0     172.16.20.1     YES manual up       up
GigabitEthernet0/1     172.16.10.1     YES manual up       up
GigabitEthernet0/2     203.0.113.2     YES manual up       up
```

> 📸 **Screenshot 3**: Output del comando `show ip interface brief` con tutte le interfacce UP/UP

---

## ⚠️ STEP 4 — Configurazione ACL Permissiva (Stato Vulnerabile)

> 🎯 **Obiettivo**: Simulare la configurazione errata che molte aziende hanno: la DMZ può comunicare liberamente con la LAN interna.

```cisco
! ============================================================
! ACL PERMISSIVA — STATO VULNERABILE (configurazione sbagliata)
! ATTENZIONE: questa ACL simula un errore di configurazione
!             NON usare in produzione!
! ============================================================
enable
configure terminal

! ACL 100: traffico WAN → DMZ (accesso ai servizi pubblici)
ip access-list extended ACL-WAN-IN
 ! Permetti HTTP/HTTPS verso web server DMZ
 permit tcp any host 172.16.10.10 eq 80
 permit tcp any host 172.16.10.10 eq 443
 ! Permetti DNS verso DNS server DMZ
 permit udp any host 172.16.10.11 eq 53
 permit tcp any host 172.16.10.11 eq 53
 ! Permetti SMTP verso mail server DMZ
 permit tcp any host 172.16.10.12 eq 25
 ! Blocca tutto il resto da Internet
 deny ip any any log

! ACL 101: traffico DMZ → LAN (VULNERABILE: troppo permissiva!)
ip access-list extended ACL-DMZ-IN-VULNERABILE
 ! ERRORE: permette TUTTO dalla DMZ verso la LAN!
 permit ip 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.255
 ! Permetti DMZ verso Internet (aggiornamenti, NTP, ecc.)
 permit ip 172.16.10.0 0.0.0.31 any
 deny ip any any log

! --- Applicazione ACL alle interfacce ---
interface GigabitEthernet0/2
 ip access-group ACL-WAN-IN in

interface GigabitEthernet0/1
 ip access-group ACL-DMZ-IN-VULNERABILE in

end
write memory
```

Verifica l'applicazione:
```cisco
show access-lists
show ip interface GigabitEthernet0/1
```

> 📸 **Screenshot 4**: Output di `show access-lists` con le ACL permissive applicate

---

## 🔴 STEP 5 — Simulazione Attacco Pivot

> 🎭 **Scenario**: L'attaccante ha compromesso il Web Server (172.16.10.10) e ora usa **PC-Attaccante** (172.16.10.50) per simulare i comandi che lancerebbe dalla web shell ottenuta.

### 5.1 Ricognizione dalla DMZ

Dal **PC-Attaccante** (Desktop → Command Prompt):

```bash
! Fase 1: L'attaccante verifica la connettività verso la LAN
ping 172.16.20.1
! Risposta attesa: Reply from 172.16.20.1 — il gateway LAN è raggiungibile!

! Fase 2: Scansione degli host LAN (in PT simula con ping)
ping 172.16.20.10
! Risposta attesa: Reply — PC-Admin raggiungibile!

ping 172.16.20.20
! Risposta attesa: Reply — Server-DB raggiungibile!
```

### 5.2 "Attacco" verso i bersagli

```bash
! Il server DB è raggiungibile dalla DMZ → grave vulnerabilità!
ping 172.16.20.20

! In un attacco reale qui si tenterebbero:
! - Port scan sulla porta 3306 (MySQL)
! - Credential stuffing con credenziali trovate nel web server
! - Exploit di vulnerabilità del DB
```

> 📸 **Screenshot 5**: Tutti i ping da PC-Attaccante verso la LAN hanno **successo** (questo dimostra la vulnerabilità)

> ⚠️ **Commento didattico**: Con la configurazione attuale, un attaccante che compromette QUALSIASI server DMZ ha accesso diretto a TUTTI i sistemi interni, incluso il database aziendale. Questo è il "pivot attack".

---

## 🛡️ STEP 6 — Contromisura 1: ACL Restrittiva (Blocco DMZ→LAN)

> 🎯 **Principio**: Una regola fondamentale della sicurezza DMZ — la DMZ **non deve mai** poter iniziare connessioni verso la LAN interna.

```cisco
! ============================================================
! CONTROMISURA 1: BLOCCO TOTALE DMZ → LAN
! Regola d'oro: la DMZ non può iniziare traffico verso la LAN
! ============================================================
enable
configure terminal

! Rimuovi l'ACL vulnerabile dall'interfaccia
interface GigabitEthernet0/1
 no ip access-group ACL-DMZ-IN-VULNERABILE in

! Elimina l'ACL vulnerabile
no ip access-list extended ACL-DMZ-IN-VULNERABILE

! Crea nuova ACL restrittiva
ip access-list extended ACL-DMZ-RESTRITTIVA
 ! BLOCCA qualsiasi traffico dalla DMZ verso la LAN interna
 deny ip 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.255 log
 ! Permetti traffico DMZ verso Internet (aggiornamenti, NTP, DNS)
 permit ip 172.16.10.0 0.0.0.31 any
 ! Nega tutto il resto
 deny ip any any log

! Applica la nuova ACL
interface GigabitEthernet0/1
 ip access-group ACL-DMZ-RESTRITTIVA in

end
write memory
```

### 6.1 Verifica Blocco Attacco

Dal **PC-Attaccante**, ripeti il ping:
```bash
ping 172.16.20.10
! Risultato atteso: Request timeout — BLOCCATO! ✅

ping 172.16.20.20
! Risultato atteso: Request timeout — BLOCCATO! ✅
```

Controlla i contatori ACL:
```cisco
show access-lists ACL-DMZ-RESTRITTIVA
! Il contatore "matches" sulla deny aumenta → prove che il blocco funziona
```

> 📸 **Screenshot 6**: Ping da PC-Attaccante **fallisce** — il pivot attack è bloccato

---

## 🔬 STEP 7 — Contromisura 2: ACL Granulare con ESTABLISHED

> 🎯 **Concetto avanzato**: Bloccare tutto DMZ→LAN è corretto, ma dobbiamo permettere le **risposte** a connessioni legittime iniziate dalla LAN verso la DMZ (es. un PC LAN che visita il sito web in DMZ).

> ⚠️ **Nota Packet Tracer**: PT ha supporto limitato per `established`. La configurazione sotto mostra la sintassi corretta da usare su router Cisco reali. In PT potresti dover usare `ip inspect` (CBAC) o accettare questa limitazione didattica.

```cisco
! ============================================================
! CONTROMISURA 2: ACL GRANULARE CON ESTABLISHED
! Permette risposte a sessioni TCP iniziate dalla LAN,
! blocca qualsiasi connessione iniziata dalla DMZ
! ============================================================
enable
configure terminal

! Prima, ACL sull'interfaccia LAN IN
! (per permettere alla LAN di iniziare connessioni verso DMZ)
ip access-list extended ACL-LAN-IN
 ! LAN può accedere ai servizi DMZ
 permit tcp 172.16.20.0 0.0.0.255 172.16.10.0 0.0.0.31 eq 80
 permit tcp 172.16.20.0 0.0.0.255 172.16.10.0 0.0.0.31 eq 443
 permit udp 172.16.20.0 0.0.0.255 host 172.16.10.11 eq 53
 ! LAN può navigare su Internet
 permit ip 172.16.20.0 0.0.0.255 any
 deny ip any any log

! ACL sull'interfaccia DMZ IN — con ESTABLISHED
no ip access-list extended ACL-DMZ-RESTRITTIVA

ip access-list extended ACL-DMZ-AVANZATA
 ! Permetti SOLO risposte TCP a sessioni stabilite dalla LAN
 ! (il flag 'established' verifica ACK o RST)
 permit tcp 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.255 established
 ! Permetti risposte UDP DNS verso LAN (stateless, serve porta sorgente 53)
 permit udp host 172.16.10.11 eq 53 172.16.20.0 0.0.0.255
 ! BLOCCA qualsiasi connessione NUOVA dalla DMZ verso LAN
 deny ip 172.16.10.0 0.0.0.31 172.16.20.0 0.0.0.255 log
 ! Permetti DMZ verso Internet
 permit ip 172.16.10.0 0.0.0.31 any
 deny ip any any log

! Applica le ACL
interface GigabitEthernet0/1
 no ip access-group ACL-DMZ-RESTRITTIVA in
 ip access-group ACL-DMZ-AVANZATA in

interface GigabitEthernet0/0
 ip access-group ACL-LAN-IN in

end
write memory
```

Verifica:
```cisco
show access-lists
! Osserva i contatori: le deny di ACL-DMZ-AVANZATA devono colpire
! i tentativi dell'attaccante, NON il traffico legittimo di risposta
```

> 📸 **Screenshot 7**: Output di `show access-lists` con contatori — le deny colpiscono solo il traffico di attacco

---

## 🏗️ STEP 8 — Contromisura 3: Micro-Segmentazione LAN

> 🎯 **Concetto**: Anche se un attaccante superasse il firewall, la LAN interna deve essere segmentata. Il Server-DB (asset critico) deve essere in una subnet separata con accesso ulteriormente limitato.

### 8.1 Nuova Subnet per il Tier Database

Aggiungiamo la subnet `172.16.30.0/27` per il Server-DB:

**Modifica topologia PT**:
1. Aggiungi un nuovo **Switch-DB** 
2. Sposta Server-DB su questo switch
3. Collega Switch-DB a Router0 su una nuova interfaccia (Gi0/3 o usa una sotto-interfaccia)

Per semplicità in PT, aggiungi un **secondo router** come "firewall interno" oppure usa sotto-interfacce:

```cisco
! ============================================================
! MICRO-SEGMENTAZIONE: nuova subnet LAN-SERVER 172.16.30.0/27
! ============================================================
enable
configure terminal

! Aggiunta interfaccia per la nuova subnet DB
! (Usa Gi0/3 se disponibile, altrimenti sotto-interfaccia)
interface GigabitEthernet0/3
 description LAN-SERVER-DB-172.16.30.0/27
 ip address 172.16.30.1 255.255.255.224
 no shutdown

! Riconfigura Server-DB con nuovo IP:
! Server-DB: IP 172.16.30.10  Mask 255.255.255.224  GW 172.16.30.1

! ACL tra LAN-uffici e LAN-server: solo traffico DB autorizzato
ip access-list extended ACL-LAN-UFFICI-TO-DB
 ! PC-Admin può accedere al DB (MySQL e PostgreSQL)
 permit tcp host 172.16.20.10 host 172.16.30.10 eq 3306
 permit tcp host 172.16.20.10 host 172.16.30.10 eq 5432
 ! PC-Dev può accedere al DB in modalità lettura (solo 3306)
 permit tcp host 172.16.20.12 host 172.16.30.10 eq 3306
 ! PC-HR NON può accedere al DB direttamente
 deny tcp host 172.16.20.11 host 172.16.30.10 log
 ! Blocca tutto il resto verso la subnet DB
 deny ip any 172.16.30.0 0.0.0.31 log
 permit ip any any

! Applica sull'interfaccia LAN-uffici uscente verso DB
interface GigabitEthernet0/0
 ip access-group ACL-LAN-UFFICI-TO-DB out

end
write memory
```

### 8.2 Verifica Segmentazione

```cisco
! Da PC-HR (172.16.20.11):
ping 172.16.30.10
! Atteso: BLOCCATO ✅ (HR non può accedere al DB)

! Da PC-Admin (172.16.20.10):
! Testa porta 3306 — in PT usa PDU personalizzata o verifica con ping
ping 172.16.30.10
! Atteso: OK (PC-Admin può raggiungere la subnet DB)
```

> 📸 **Screenshot 8**: Topologia aggiornata con subnet 172.16.30.0/27 e Switch-DB
> 📸 **Screenshot 9**: Ping da PC-HR verso Server-DB — **bloccato** (micro-segmentazione attiva)

---

## 💾 STEP 9 — Salvataggio File

1. Clicca **File → Save** in Packet Tracer
2. Salva il file come: `es07a_dmz_security.pkt`
3. Fai uno screenshot della finestra di Packet Tracer con il file aperto e il titolo visibile nella barra del titolo

> 📸 **Screenshot 10**: Finestra PT con il file `es07a_dmz_security.pkt` aperto e salvato

---

## 📋 Riepilogo Comandi di Verifica

```cisco
! ============================================================
! COMANDI DI VERIFICA — da eseguire dopo ogni step
! ============================================================

! Verifica interfacce e IP
show ip interface brief

! Verifica tutte le ACL configurate con contatori
show access-lists

! Verifica ACL applicate alle interfacce
show ip interface GigabitEthernet0/0
show ip interface GigabitEthernet0/1
show ip interface GigabitEthernet0/2

! Verifica tabella di routing
show ip route

! Verifica configurazione running
show running-config | section access-list
show running-config | section interface
```

---

## 🔧 Troubleshooting — Problemi Comuni

| Problema | Causa Probabile | Soluzione |
|----------|----------------|-----------|
| Ping non funziona neanche prima delle ACL | IP configurato male | Verifica subnet mask: DMZ è /27, non /24 |
| ACL applicata ma il traffico passa ancora | ACL applicata nella direzione sbagliata | Verifica `in` vs `out` — il traffico dal PC-Attaccante entra su Gi0/1 (`in`) |
| `show access-lists` non mostra contatori | Nessun traffico corrispondente | Genera traffico (ping) e ricontrolla |
| Errore "wildcard bits inconsistent" | Wildcard mask sbagliata | /27 → wildcard 0.0.0.31; /24 → wildcard 0.0.0.255 |
| ACL ESTABLISHED non funziona in PT | Limitazione PT | Normale — PT non implementa pienamente ESTABLISHED; usa CBAC o segnala al docente |
| Server-DB non raggiungibile dopo migrazione subnet | Gateway non aggiornato | Aggiorna il gateway del Server-DB a 172.16.30.1 |
| Interfaccia Gi0/3 non disponibile sul router | Router con solo 3 interfacce | Aggiungi modulo NIM-2T o usa sotto-interfacce su Gi0/0 |

### Calcolo Wildcard Masks — Riferimento Rapido

| CIDR | Subnet Mask | Wildcard Mask | Host utili |
|------|-------------|---------------|-----------|
| /24 | 255.255.255.0 | 0.0.0.255 | 254 |
| /27 | 255.255.255.224 | 0.0.0.31 | 30 |
| /28 | 255.255.255.240 | 0.0.0.15 | 14 |
| /30 | 255.255.255.252 | 0.0.0.3 | 2 |

---

## 📝 Note Tecniche — Limitazioni Packet Tracer

| Funzionalità | Disponibile in PT? | Alternativa in PT |
|-------------|-------------------|-------------------|
| ACL `established` | ⚠️ Parziale | Usa `ip inspect` (CBAC) su router IOS |
| IPS/IDS simulato | ❌ No | Solo studio teorico |
| Port scanning (nmap) | ❌ No | Ping come sostituto didattico |
| Web shell / exploit | ❌ No | Usare PC-Attaccante come proxy concettuale |
| Firewall stateful completo | ⚠️ Base | `ip inspect` per CBAC base |
| Honeypot | ❌ No | Solo studio teorico |
| Log dettagliati | ⚠️ Base | `show access-lists` per contatori |

> 💡 **Per la produzione reale**: Cisco ASA, pfSense o Fortinet offrono tutte queste funzionalità. Packet Tracer è uno strumento didattico; i concetti appresi qui si applicano 1:1 ai dispositivi reali.

---

## ✅ Checklist Completamento Esercizio

- [ ] STEP 1: Piano di indirizzamento compilato e matrice flussi completata
- [ ] STEP 2: Topologia PT creata con tutti i dispositivi (📸1, 📸2)
- [ ] STEP 3: Tutti gli IP configurati, `show ip interface brief` verde (📸3)
- [ ] STEP 4: ACL permissiva applicata (📸4)
- [ ] STEP 5: Dimostrato che l'attacco pivot **funziona** con ACL permissiva (📸5)
- [ ] STEP 6: ACL restrittiva applicata, attacco **bloccato** (📸6)
- [ ] STEP 7: ACL con ESTABLISHED configurata, contatori verificati (📸7)
- [ ] STEP 8: Subnet 172.16.30.0/27 creata, Server-DB migrato (📸8, 📸9)
- [ ] STEP 9: File salvato come `es07a_dmz_security.pkt` (📸10)

---

*ES07-A | Laboratorio Guidato: Pivot Attack DMZ | SISTEMI E RETI*
