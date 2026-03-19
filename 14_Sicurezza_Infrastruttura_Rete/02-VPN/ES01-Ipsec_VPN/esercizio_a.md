# ES01a — Laboratorio guidato: Configurazione VPN IPsec Site-to-Site in Cisco Packet Tracer

> **Tipo**: 🔬 Laboratorio guidato  
> **Durata stimata**: 3–4 ore  
> **Punteggio**: 40 punti  
> **File da consegnare**: `es01a_vpn.pkt` + 10 screenshot nella cartella `img/`

---

## 📸 Riepilogo Screenshot richiesti

| # | Screenshot | Step | Descrizione |
|---|-----------|------|-------------|
| 📸1 | `es01a_01_layout.png` | STEP 2 | Topologia PT senza cavi |
| 📸2 | `es01a_02_cavi.png` | STEP 2 | Topologia PT con tutti i cavi |
| 📸3 | `es01a_03_ping_base.png` | STEP 3 | Ping Milano→Roma PRIMA della VPN |
| 📸4 | `es01a_04_simulation.png` | STEP 4 | Simulation Mode — traffico in chiaro |
| 📸5 | `es01a_05_isakmp.png` | STEP 5 | Configurazione ISAKMP Phase 1 su Router-Milano |
| 📸6 | `es01a_06_ipsec.png` | STEP 6 | Configurazione IPsec Phase 2 e crypto map |
| 📸7 | `es01a_07_tunnel_up.png` | STEP 7 | Output `show crypto isakmp sa` con tunnel UP |
| 📸8 | `es01a_08_ipsec_sa.png` | STEP 8 | Output `show crypto ipsec sa` con contatori |
| 📸9 | `es01a_09_simulation_vpn.png` | STEP 8 | Simulation Mode — traffico cifrato con VPN |
| 📸10 | `es01a_10_salvataggio.png` | STEP 9 | Salvataggio file `.pkt` |

---

## 🌐 Scenario

L'azienda **TechItalia S.r.l.** ha la sede centrale a **Milano** e una filiale a **Roma**.
Le due sedi devono comunicare in modo sicuro attraverso Internet per condividere file,
accedere ai server aziendali e gestire applicazioni gestionali.

Senza VPN, tutto il traffico tra Milano e Roma passerebbe attraverso l'ISP —
chiunque con uno sniffer potrebbe leggere il traffico in chiaro, inclusi email, documenti e credenziali.

La soluzione: configurare una **VPN IPsec Site-to-Site** tra i due router perimetrali,
in modo che tutto il traffico tra le LAN venga automaticamente cifrato prima di uscire
su Internet e decifrato all'arrivo.

---

## 🗺️ Topologia di rete

```
SEDE CENTRALE (Milano)         INTERNET (simulata)          FILIALE (Roma)
192.168.1.0/24                 203.0.113.0/30               192.168.2.0/24
                               203.0.113.4/30

┌─────────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   Router-Milano     │    │   Router-ISP     │    │    Router-Roma      │
│  (Cisco 2901)       │    │ (Cisco 2901)     │    │  (Cisco 2901)       │
│                     │    │                  │    │                     │
│ Gi0/0: 192.168.1.1  │    │ Fa0/0:203.0.113.1│    │ Gi0/0: 192.168.2.1  │
│ Gi0/1: 203.0.113.2  ├────┤                  ├────┤ Gi0/1: 203.0.113.6  │
└─────────────────────┘    │ Fa0/1:203.0.113.5│    └─────────────────────┘
         │                 └──────────────────┘              │
  ┌──────┴──────┐                                     ┌──────┴──────┐
  │ Switch-Milan│                                     │ Switch-Roma │
  └──────┬──────┘                                     └──────┬──────┘
    ┌────┴──────────────┐                          ┌─────────┴─────────┐
    │         │         │                          │         │         │
 PC-MI1    PC-MI2   Server-MI                   PC-RO1   PC-RO2   Server-RO
.1.10      .1.11     .1.20                      .2.10    .2.11     .2.20
```

> **Nota**: Router-ISP simula la rete Internet pubblica. Non ha ruolo nella VPN,
> si limita a instradare pacchetti tra i due router perimetrali.

---

## STEP 1 — Piano di indirizzamento IP

### 📋 Tabella di indirizzamento completa

| Dispositivo | Interfaccia | Indirizzo IP | Subnet Mask | Gateway | Ruolo |
|-------------|-------------|--------------|-------------|---------|-------|
| Router-Milano | Gi0/0 | 192.168.1.1 | 255.255.255.0 | — | Gateway LAN Milano |
| Router-Milano | Gi0/1 | 203.0.113.2 | 255.255.255.252 | — | Interfaccia WAN (verso ISP) |
| Router-ISP | Fa0/0 | 203.0.113.1 | 255.255.255.252 | — | Collegamento verso Milano |
| Router-ISP | Fa0/1 | 203.0.113.5 | 255.255.255.252 | — | Collegamento verso Roma |
| Router-Roma | Gi0/0 | 192.168.2.1 | 255.255.255.0 | — | Gateway LAN Roma |
| Router-Roma | Gi0/1 | 203.0.113.6 | 255.255.255.252 | — | Interfaccia WAN (verso ISP) |
| Switch-Milano | — | — | — | — | Switch LAN Milano |
| Switch-Roma | — | — | — | — | Switch LAN Roma |
| PC-MI1 | Fa0 | 192.168.1.10 | 255.255.255.0 | 192.168.1.1 | Client sede Milano |
| PC-MI2 | Fa0 | 192.168.1.11 | 255.255.255.0 | 192.168.1.1 | Client sede Milano |
| Server-MI | Fa0 | 192.168.1.20 | 255.255.255.0 | 192.168.1.1 | Server sede Milano |
| PC-RO1 | Fa0 | 192.168.2.10 | 255.255.255.0 | 192.168.2.1 | Client filiale Roma |
| PC-RO2 | Fa0 | 192.168.2.11 | 255.255.255.0 | 192.168.2.1 | Client filiale Roma |
| Server-RO | Fa0 | 192.168.2.20 | 255.255.255.0 | 192.168.2.1 | Server filiale Roma |

### 💡 Cos'è una VPN — concetti chiave

Prima di iniziare la configurazione, è fondamentale capire **cosa succede con e senza VPN**:

**SENZA VPN:**
```
PC-MI1 → Router-Milano → (INTERNET: pacchetto in chiaro!) → Router-Roma → PC-RO1
         Chiunque intercetta il traffico tra i router può leggere i dati!
```

**CON VPN IPsec:**
```
PC-MI1 → Router-Milano → [ESP: header IP + payload CIFRATO] → Router-Roma → PC-RO1
         Il pacchetto originale viene INCAPSULATO e CIFRATO dal router di Milano,
         DECIFRATO dal router di Roma. L'ISP vede solo pacchetti cifrati.
```

**Cosa viene cifrato?**
- ✅ Tutto il payload del pacchetto IP originale (dati applicativi, intestazioni TCP/UDP)
- ✅ L'indirizzo IP sorgente e destinazione interni (192.168.1.x ↔ 192.168.2.x)
- ❌ L'intestazione IP esterna (203.0.113.2 → 203.0.113.6) — necessaria per il routing

---

## STEP 2 — Creazione topologia in Packet Tracer

### Dispositivi da inserire

| Dispositivo | Modello PT | Quantità |
|-------------|------------|----------|
| Router perimetrali | Cisco 2901 | 2 (Router-Milano, Router-Roma) |
| Router ISP | Cisco 2901 | 1 (Router-ISP) |
| Switch | Cisco 2960 (o generic) | 2 (Switch-Milano, Switch-Roma) |
| PC | PC generico | 4 (PC-MI1, PC-MI2, PC-RO1, PC-RO2) |
| Server | Server generico | 2 (Server-MI, Server-RO) |

### Cablaggio

| Cavo | Da | Porta | A | Porta |
|------|-----|-------|---|-------|
| Copper Straight | Router-Milano | Gi0/0 | Switch-Milano | Fa0/1 |
| Copper Straight | Router-Milano | Gi0/1 | Router-ISP | Fa0/0 |
| Copper Straight | Router-ISP | Fa0/1 | Router-Roma | Gi0/1 |
| Copper Straight | Router-Roma | Gi0/0 | Switch-Roma | Fa0/1 |
| Copper Straight | Switch-Milano | Fa0/2 | PC-MI1 | Fa0 |
| Copper Straight | Switch-Milano | Fa0/3 | PC-MI2 | Fa0 |
| Copper Straight | Switch-Milano | Fa0/4 | Server-MI | Fa0 |
| Copper Straight | Switch-Roma | Fa0/2 | PC-RO1 | Fa0 |
| Copper Straight | Switch-Roma | Fa0/3 | PC-RO2 | Fa0 |
| Copper Straight | Switch-Roma | Fa0/4 | Server-RO | Fa0 |

> 📸 **Screenshot 1** — Topologia PT con tutti i dispositivi inseriti (senza cavi)  
> 📸 **Screenshot 2** — Topologia PT con tutti i cavi collegati e luci verdi

---

## STEP 3 — Configurazione IP base e routing

### Router-Milano — configurazione completa

```
Router> enable
Router# configure terminal
Router(config)# hostname Router-Milano

! ── Interfaccia LAN ──────────────────────────────────────────────────────────
Router-Milano(config)# interface GigabitEthernet0/0
Router-Milano(config-if)# description LAN Milano 192.168.1.0/24
Router-Milano(config-if)# ip address 192.168.1.1 255.255.255.0
Router-Milano(config-if)# no shutdown

! ── Interfaccia WAN (verso Internet/ISP) ────────────────────────────────────
Router-Milano(config)# interface GigabitEthernet0/1
Router-Milano(config-if)# description WAN verso Router-ISP
Router-Milano(config-if)# ip address 203.0.113.2 255.255.255.252
Router-Milano(config-if)# no shutdown

! ── Route statica verso rete Roma (via ISP) ─────────────────────────────────
Router-Milano(config)# ip route 192.168.2.0 255.255.255.0 203.0.113.1
! Significato: "Per raggiungere 192.168.2.0/24, manda i pacchetti a 203.0.113.1 (ISP)"
! ── nel caso di collegamento con ISP reale, questa sarebbe la default route 
! verso Internet ─────────────────────────────────────────────────────────────
! Router-Milano(config)# ip route 0.0.0.0 255.255.255.0 203.0.113.1
! Significato: "Per raggiungere qualsiasi rete non conosciuta, manda i 
!pacchetti a 203.0.113.1 (ISP)" ──────────────────────────────────────────────

! ── Salvataggio configurazione ───────────────────────────────────────────────
Router-Milano(config)# end
Router-Milano# copy running-config startup-config
```

### Router-ISP — configurazione completa

```
Router> enable
Router# configure terminal
Router(config)# hostname Router-ISP

! ── Interfaccia verso Milano ─────────────────────────────────────────────────
Router-ISP(config)# interface FastEthernet0/0
Router-ISP(config-if)# description Collegamento verso Router-Milano
Router-ISP(config-if)# ip address 203.0.113.1 255.255.255.252
Router-ISP(config-if)# no shutdown

! ── Interfaccia verso Roma ───────────────────────────────────────────────────
Router-ISP(config)# interface FastEthernet0/1
Router-ISP(config-if)# description Collegamento verso Router-Roma
Router-ISP(config-if)# ip address 203.0.113.5 255.255.255.252
Router-ISP(config-if)# no shutdown

! ── Route statiche verso le LAN private ─────────────────────────────────────
Router-ISP(config)# ip route 192.168.1.0 255.255.255.0 203.0.113.2
Router-ISP(config)# ip route 192.168.2.0 255.255.255.0 203.0.113.6

Router-ISP(config)# end
Router-ISP# write memory
```

### Router-Roma — configurazione completa

```
Router> enable
Router# configure terminal
Router(config)# hostname Router-Roma

! ── Interfaccia LAN ──────────────────────────────────────────────────────────
Router-Roma(config)# interface GigabitEthernet0/0
Router-Roma(config-if)# description LAN Roma 192.168.2.0/24
Router-Roma(config-if)# ip address 192.168.2.1 255.255.255.0
Router-Roma(config-if)# no shutdown

! ── Interfaccia WAN (verso Internet/ISP) ────────────────────────────────────
Router-Roma(config)# interface GigabitEthernet0/1
Router-Roma(config-if)# description WAN verso Router-ISP
Router-Roma(config-if)# ip address 203.0.113.6 255.255.255.252
Router-Roma(config-if)# no shutdown

! ── Route statica verso rete Milano (via ISP) ───────────────────────────────
Router-Roma(config)# ip route 192.168.1.0 255.255.255.0 203.0.113.5
! Significato: "Per raggiungere 192.168.1.0/24, manda i pacchetti a 203.0.113.5 (ISP)"

Router-Roma(config)# end
Router-Roma# write memory
```

### Configurazione IP degli end-device

Configura manualmente gli IP su PC e Server tramite la scheda Desktop → IP Configuration:

| Device | IP | Subnet | Gateway |
|--------|----|--------|---------|
| PC-MI1 | 192.168.1.10 | 255.255.255.0 | 192.168.1.1 |
| PC-MI2 | 192.168.1.11 | 255.255.255.0 | 192.168.1.1 |
| Server-MI | 192.168.1.20 | 255.255.255.0 | 192.168.1.1 |
| PC-RO1 | 192.168.2.10 | 255.255.255.0 | 192.168.2.1 |
| PC-RO2 | 192.168.2.11 | 255.255.255.0 | 192.168.2.1 |
| Server-RO | 192.168.2.20 | 255.255.255.0 | 192.168.2.1 |

### Verifica connettività base (senza VPN)

Da PC-MI1, apri il Command Prompt e testa:

```
C:\> ping 192.168.1.1       (gateway Milano — deve funzionare)
C:\> ping 203.0.113.1       (Router-ISP — deve funzionare)
C:\> ping 192.168.2.10      (PC-RO1 — deve funzionare SENZA VPN)
```

> ⚠️ Prima di aggiungere la VPN, la connettività deve funzionare. Se il ping fallisce,
> controlla IP, subnet mask, gateway e routing prima di procedere.

> 📸 **Screenshot 3** — Ping riuscito da PC-MI1 verso PC-RO1 (traffico ancora in chiaro)

---

## STEP 4 — Verifica traffico PRIMA della VPN (Simulation Mode)

Prima di configurare la VPN, osserva come i pacchetti viaggiano in chiaro:

1. Clicca su **Simulation** (in basso a destra in PT)
2. Clicca su **Edit Filters** → lascia solo ICMP spuntato
3. Da PC-MI1, invia un ping verso PC-RO1 (`ping 192.168.2.10`)
4. Premi **Play** nel pannello Simulation
5. Clicca sui pacchetti che passano per Router-ISP e apri il dettaglio PDU
6. Osserva che puoi vedere chiaramente: IP sorgente (192.168.1.10), IP destinazione (192.168.2.10)

💡 **Questo dimostra che senza VPN il traffico è completamente visibile** all'ISP e a
chiunque intercetti il traffico su Internet!

> 📸 **Screenshot 4** — Simulation Mode con pacchetti ICMP visibili in chiaro tra i router

---

## STEP 5 — Configurazione ISAKMP Phase 1 (IKE)

La **Phase 1** crea un canale sicuro tra i due router per negoziare i parametri IPsec.
È come una "handshake" in cui i due router concordano come comunicare in modo sicuro.

### 📖 Spiegazione parametri ISAKMP policy

| Parametro | Valore usato | Significato |
|-----------|-------------|-------------|
| `policy 10` | numero 10 | Priorità della policy (più basso = priorità maggiore) |
| `encryption aes` | AES | Algoritmo di cifratura simmetrica per IKE Phase 1 |
| `hash sha` | SHA-1 | Algoritmo di hash per l'integrità dei messaggi |
| `authentication pre-share` | PSK | Autenticazione con chiave pre-condivisa (password) |
| `group 2` | DH Group 2 | Diffie-Hellman group 2 (1024-bit) per scambio chiavi |
| `lifetime 86400` | 86400 secondi | Durata della SA Phase 1 (24 ore) |

### Router-Milano — ISAKMP Phase 1

```
Router-Milano# configure terminal

! ── ISAKMP Policy: parametri per negoziare il tunnel sicuro (Phase 1) ────────
!   AES = Advanced Encryption Standard, algoritmo simmetrico sicuro e veloce
!   SHA = Secure Hash Algorithm, garantisce l'integrità dei messaggi
!   pre-share = si usa una "parola chiave" segreta condivisa (PSK)
!   DH Group 2 = Diffie-Hellman 1024-bit, per generare chiavi senza trasmetterle
!   86400 sec = 24 ore, dopo le quali la SA Phase 1 viene rinnovata
Router-Milano(config)# crypto isakmp policy 10
Router-Milano(config-isakmp)# encryption aes
Router-Milano(config-isakmp)# hash sha
Router-Milano(config-isakmp)# authentication pre-share
Router-Milano(config-isakmp)# group 2
Router-Milano(config-isakmp)# lifetime 86400
Router-Milano(config-isakmp)# exit

! ── Chiave pre-condivisa (PSK): DEVE essere identica su entrambi i router ────
!   VPN_KEY_SECRET = la password segreta condivisa tra i due router
!   203.0.113.6   = indirizzo IP del peer (Router-Roma, interfaccia WAN)
    Router-Milano(config)# crypto isakmp key VPN_KEY_SECRET address 203.0.113.6
```

### Router-Roma — ISAKMP Phase 1 (speculare)

```
Router-Roma# configure terminal

! ── ISAKMP Policy: IDENTICA a quella di Router-Milano ────────────────────────
Router-Roma(config)# crypto isakmp policy 10
Router-Roma(config-isakmp)# encryption aes
Router-Roma(config-isakmp)# hash sha
Router-Roma(config-isakmp)# authentication pre-share
Router-Roma(config-isakmp)# group 2
Router-Roma(config-isakmp)# lifetime 86400
Router-Roma(config-isakmp)# exit

! ── PSK: stessa password, ma con l'IP del PEER = Router-Milano ───────────────
!   203.0.113.2 = indirizzo IP del peer (Router-Milano, interfaccia WAN)
Router-Roma(config)# crypto isakmp key VPN_KEY_SECRET address 203.0.113.2
```

> ⚠️ **ATTENZIONE**: La chiave PSK (`VPN_KEY_SECRET`) deve essere **esattamente identica**
> su entrambi i router, altrimenti la Phase 1 non si completa. È case-sensitive!

> 📸 **Screenshot 5** — Configurazione ISAKMP Phase 1 su Router-Milano (mostra il terminale CLI)

---

## STEP 6 — Configurazione IPsec Phase 2 (Transform-Set e Crypto Map)

La **Phase 2** configura come cifrare il traffico dati reale tra le due LAN.

### 📖 Spiegazione dei componenti Phase 2

| Componente | Scopo |
|-----------|-------|
| **Transform-Set** | Definisce gli algoritmi di cifratura e autenticazione per i dati |
| **ACL VPN-TRAFFIC** | Definisce *quale* traffico deve essere cifrato (da LAN Milano a LAN Roma) |
| **Crypto Map** | Collega il peer, il transform-set e l'ACL in un'unica policy VPN |

### Router-Milano — IPsec Phase 2 completa

```
! ── Configurazione IPsec Phase 2 su Router-Milano ─────────────────────────────
Router-Milano# configure terminal

! ── Transform-Set: come cifrare i dati del tunnel ───────────────────────────
!   VPN-TRANSFORM = nome del transform-set (a scelta)
!   esp-aes       = usa ESP con cifratura AES per la riservatezza dei dati
!   esp-sha-hmac  = usa SHA per l'autenticazione/integrità dei dati
Router-Milano(config)# crypto ipsec transform-set VPN-TRANSFORM esp-aes esp-sha-hmac

! ── ACL: definisce il traffico da cifrare (traffico "interessante") ───────────
!   Cifra TUTTO il traffico dalla LAN Milano (192.168.1.0/24) verso LAN Roma (192.168.2.0/24)
!   Nota: si usa la wildcard mask (inverso della subnet mask)
Router-Milano(config)# ip access-list extended VPN-TRAFFIC
Router-Milano(config-ext-nacl)# permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
Router-Milano(config-ext-nacl)# exit

! ── Crypto Map: collega tutto insieme ────────────────────────────────────────
!   VPN-MAP = nome della crypto map
!   10      = numero sequenza entry
!   ipsec-isakmp = usa IKE per negoziare automaticamente le SA
!   Indirizzo IP del router remoto (Router-Roma)
!   Usa il transform-set definito sopra
!   Applica la crypto map solo al traffico definito nell'ACL VPN-TRAFFIC
Router-Milano(config)# crypto map VPN-MAP 10 ipsec-isakmp
Router-Milano(config-crypto-map)# set peer 203.0.113.6
Router-Milano(config-crypto-map)# set transform-set VPN-TRANSFORM
Router-Milano(config-crypto-map)# match address VPN-TRAFFIC
Router-Milano(config-crypto-map)# exit

! ── Applica la Crypto Map all'interfaccia WAN ────────────────────────────────
!   La crypto map si applica sull'interfaccia che "guarda" verso Internet
!   Da questo momento, tutto il traffico in uscita/entrata viene analizzato
Router-Milano(config)# interface GigabitEthernet0/1
Router-Milano(config-if)# crypto map VPN-MAP
Router-Milano(config-if)# exit

! ── Salvataggio configurazione ───────────────────────────────────────────────
Router-Milano(config)# end
Router-Milano# copy running-config startup-config
```

### Router-Roma — IPsec Phase 2 completa (speculare)

```
Router-Roma# configure terminal

! ── Transform-Set: IDENTICO a Router-Milano ─────────────────────────────────
Router-Roma(config)# crypto ipsec transform-set VPN-TRANSFORM esp-aes esp-sha-hmac

! ── ACL: traffico da Roma verso Milano (SPECULARE rispetto a Milano!) ─────────
!   NOTA CRITICA: sorgente e destinazione sono INVERTITE rispetto a Router-Milano
!   Su Router-Roma: sorgente = LAN Roma, destinazione = LAN Milano
Router-Roma(config)# ip access-list extended VPN-TRAFFIC
Router-Roma(config-ext-nacl)# permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255
Router-Roma(config-ext-nacl)# exit

! ── Crypto Map: speculare con IP peer invertito ───────────────────────────────
!   IP peer = Router-Milano (203.0.113.2)
Router-Roma(config)# crypto map VPN-MAP 10 ipsec-isakmp
Router-Roma(config-crypto-map)# set peer 203.0.113.2
Router-Roma(config-crypto-map)# set transform-set VPN-TRANSFORM
Router-Roma(config-crypto-map)# match address VPN-TRAFFIC
Router-Roma(config-crypto-map)# exit

! ── Applica Crypto Map sull'interfaccia WAN ──────────────────────────────────
Router-Roma(config)# interface GigabitEthernet0/1
Router-Roma(config-if)# crypto map VPN-MAP
Router-Roma(config-if)# exit

! ── Salvataggio configurazione ───────────────────────────────────────────────
Router-Roma(config)# end
Router-Roma# copy running-config startup-config
```

> 📸 **Screenshot 6** — Configurazione IPsec Phase 2 e crypto map su entrambi i router

---

## STEP 7 — Attivazione del tunnel VPN

Il tunnel VPN IPsec è **lazy**: non si attiva da solo ma si negozia solo quando arriva
traffico "interessante" (quello che corrisponde all'ACL VPN-TRAFFIC).

### Attivazione tramite ping

Da **PC-MI1**, esegui un ping verso PC-RO1:

```
C:\> ping 192.168.2.10
```

Questo traffico (192.168.1.10 → 192.168.2.10) corrisponde all'ACL VPN-TRAFFIC,
quindi il Router-Milano avvia la negoziazione IKE con Router-Roma.

I **primi ping potrebbero andare in timeout** mentre il tunnel si negozia — è normale!
Riesegui il ping dopo qualche secondo; una volta attivo il tunnel, i ping devono funzionare.

### Verifica Phase 1 — `show crypto isakmp sa`

Su Router-Milano:

```
Router-Milano# show crypto isakmp sa
```

Output atteso con tunnel UP:
```
IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
203.0.113.6     203.0.113.2     QM_IDLE           1001 ACTIVE
```

| Campo | Significato |
|-------|-------------|
| `dst` | IP del peer remoto (Router-Roma) |
| `src` | Proprio IP WAN (Router-Milano) |
| `QM_IDLE` | Phase 1 attiva, in attesa di negoziazioni Phase 2 |
| `ACTIVE` | SA Phase 1 stabilita con successo ✅ |

Se vedi `MM_NO_STATE` o nessun output → problema Phase 1 (vedi Troubleshooting).

### Verifica Phase 2 — `show crypto ipsec sa`

Su Router-Milano:

```
Router-Milano# show crypto ipsec sa
```

Output atteso con tunnel attivo:

```
interface: GigabitEthernet0/1
    Crypto map tag: VPN-MAP, local addr 203.0.113.2

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.168.1.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (192.168.2.0/255.255.255.0/0/0)
   current_peer 203.0.113.6 port 500

    #pkts encaps: 25, #pkts encrypt: 25, #pkts digest: 25
    #pkts decaps: 25, #pkts decrypt: 25, #pkts verify: 25
    #send errors 0, #recv errors 0
```

Cerca i contatori `#pkts encaps` e `#pkts decaps` — devono essere > 0 dopo i ping.

Cerca i contatori `#pkts encaps` e `#pkts decaps` — devono essere > 0 dopo i ping.

> 📸 **Screenshot 7** — Output di `show crypto isakmp sa` con stato QM_IDLE / ACTIVE

---

## STEP 8 — Verifica avanzata e test completo

### Test connettività completo

Esegui questi ping e annota i risultati nella tabella:

| Test | Da | A | Atteso | Esito |
|------|-----|---|--------|-------|
| 1 | PC-MI1 | PC-RO1 (192.168.2.10) | ✅ OK | |
| 2 | PC-MI1 | PC-RO2 (192.168.2.11) | ✅ OK | |
| 3 | PC-MI1 | Server-RO (192.168.2.20) | ✅ OK | |
| 4 | PC-MI2 | PC-RO1 (192.168.2.10) | ✅ OK | |
| 5 | Server-MI | Server-RO (192.168.2.20) | ✅ OK | |
| 6 | PC-RO1 | PC-MI1 (192.168.1.10) | ✅ OK | |
| 7 | PC-RO2 | Server-MI (192.168.1.20) | ✅ OK | |

### Verifica contatori IPsec

Dopo aver eseguito i ping, controlla i contatori su Router-Milano:

```
Router-Milano# show crypto ipsec sa

interface: GigabitEthernet0/1
    Crypto map tag: VPN-MAP, local addr 203.0.113.2

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.168.1.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (192.168.2.0/255.255.255.0/0/0)
   current_peer 203.0.113.6 port 500

    #pkts encaps: 25, #pkts encrypt: 25, #pkts digest: 25
    #pkts decaps: 25, #pkts decrypt: 25, #pkts verify: 25
    #send errors 0, #recv errors 0
```

✅ `encaps > 0` = Router-Milano sta cifrando pacchetti verso Roma  
✅ `decaps > 0` = Router-Milano sta decifriando pacchetti da Roma  
❌ `send errors > 0` = problema di trasmissione  

### Verifica con Simulation Mode (con VPN attiva)

1. Attiva la Simulation Mode in PT
2. Esegui un ping da PC-MI1 verso PC-RO1
3. Osserva i pacchetti che passano per Router-ISP
4. I pacchetti ora mostrano **ESP** invece di ICMP puro — il traffico è cifrato!

> 📸 **Screenshot 8** — Output completo `show crypto ipsec sa` con contatori > 0  
> 📸 **Screenshot 9** — Simulation Mode con traffico ESP cifrato tra i router

---

## STEP 9 — Salvataggio

Salva il progetto come `es08a_vpn.pkt`:

1. In Packet Tracer: **File → Save As...**
2. Nome file: `es08a_vpn.pkt`
3. Salva nella tua cartella di lavoro

> 📸 **Screenshot 10** — Finestra di salvataggio o conferma file salvato

---

## 🔧 Comandi CLI completi — Copia-incolla pronti

### CONFIGURAZIONE COMPLETA — Router-Milano

```
enable
configure terminal
hostname Router-Milano
!
interface GigabitEthernet0/0
 description LAN Milano
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description WAN verso ISP
 ip address 203.0.113.2 255.255.255.252
 no shutdown
!
ip route 192.168.2.0 255.255.255.0 203.0.113.1
!
crypto isakmp policy 10
 encryption aes
 hash sha
 authentication pre-share
 group 2
 lifetime 86400
!
crypto isakmp key VPN_KEY_SECRET address 203.0.113.6
!
crypto ipsec transform-set VPN-TRANSFORM esp-aes esp-sha-hmac
!
ip access-list extended VPN-TRAFFIC
 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
!
crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.6
 set transform-set VPN-TRANSFORM
 match address VPN-TRAFFIC
!
interface GigabitEthernet0/1
 crypto map VPN-MAP
!
end
write memory
```

### CONFIGURAZIONE COMPLETA — Router-Roma

```
enable
configure terminal
hostname Router-Roma
!
interface GigabitEthernet0/0
 description LAN Roma
 ip address 192.168.2.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description WAN verso ISP
 ip address 203.0.113.6 255.255.255.252
 no shutdown
!
ip route 192.168.1.0 255.255.255.0 203.0.113.5
!
crypto isakmp policy 10
 encryption aes
 hash sha
 authentication pre-share
 group 2
 lifetime 86400
!
crypto isakmp key VPN_KEY_SECRET address 203.0.113.2
!
crypto ipsec transform-set VPN-TRANSFORM esp-aes esp-sha-hmac
!
ip access-list extended VPN-TRAFFIC
 permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255
!
crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.2
 set transform-set VPN-TRANSFORM
 match address VPN-TRAFFIC
!
interface GigabitEthernet0/1
 crypto map VPN-MAP
!
end
write memory
```

### CONFIGURAZIONE COMPLETA — Router-ISP

```
enable
configure terminal
hostname Router-ISP
!
interface FastEthernet0/0
 description Collegamento verso Milano
 ip address 203.0.113.1 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 description Collegamento verso Roma
 ip address 203.0.113.5 255.255.255.252
 no shutdown
!
ip route 192.168.1.0 255.255.255.0 203.0.113.2
ip route 192.168.2.0 255.255.255.0 203.0.113.6
!
end
write memory
```

---

## 🛠️ Troubleshooting VPN

### Problema 1: Tunnel non si forma (ISAKMP SA non UP)

**Sintomo**: `show crypto isakmp sa` è vuoto o mostra `MM_NO_STATE`

**Cause possibili e soluzioni**:

| Causa | Come verificare | Soluzione |
|-------|----------------|-----------|
| Policy mismatch | Confronta `show crypto isakmp policy` su entrambi i router | Rendere i parametri identici |
| PSK errata | Controlla la chiave con `show running-config \| include isakmp key` | Riconfigurare con chiave identica |
| No connettività IP | `ping 203.0.113.6` da Router-Milano | Verificare routing e cablaggio |
| Crypto map non applicata | `show interface Gi0/1` — verifica "Outgoing crypto map" | Riapplicare `crypto map VPN-MAP` sull'interfaccia |

### Problema 2: Phase 1 OK ma Phase 2 non si forma

**Sintomo**: `show crypto isakmp sa` mostra QM_IDLE, ma `show crypto ipsec sa` è vuoto

**Cause possibili**:
- ❌ ACL VPN-TRAFFIC non simmetrica tra i due router
- ❌ Transform-set diverso tra i due router
- ❌ Nessun traffico "interessante" generato (non è stato eseguito alcun ping)

**Soluzione**: Verifica che le ACL siano speculari (sorgente e destinazione invertite),
poi esegui un ping per generare traffico interessante.

### Problema 3: Tunnel UP ma ping fallisce

**Sintomo**: SA Phase 1 e Phase 2 sono UP, ma i ping tra le LAN non funzionano

**Cause possibili**:
- ❌ Routing verso i PC non configurato correttamente
- ❌ Gateway dei PC errato
- ❌ ACL VPN-TRAFFIC troppo restrittiva (esclude alcune reti)

**Verifica**: `show crypto ipsec sa` — controlla se `encaps` aumenta quando esegui il ping.
Se encaps non aumenta → il pacchetto non arriva all'interfaccia con crypto map → problema routing.
Se encaps aumenta ma decaps no → problema dall'altro lato.

### Problema 4: Traffico asimmetrico

**Sintomo**: ping da Milano→Roma funziona, Roma→Milano no (o viceversa)

**Causa**: ACL VPN-TRAFFIC configurata solo su un router, oppure routing asimmetrico.

**Soluzione**: Verifica che ENTRAMBI i router abbiano:
1. ACL VPN-TRAFFIC con sorgente/destinazione speculare
2. Crypto map applicata sulla propria interfaccia WAN
3. Route statica verso la LAN remota

### Comandi di debug (⚠️ solo in ambiente lab!)

```
Router-Milano# debug crypto isakmp
!   Mostra i messaggi IKE in tempo reale (molto verboso!)

Router-Milano# debug crypto ipsec
!   Mostra i messaggi IPsec in tempo reale

Router-Milano# undebug all
!   IMPORTANTE: disattiva TUTTI i debug (o la console si riempie di log!)
```

> ⚠️ **AVVERTENZA**: I comandi debug sono molto verbosi e in ambienti di produzione
> possono rallentare il router. Usali SOLO in laboratorio e sempre seguiti da `undebug all`.

---

## 📝 Note tecniche e limitazioni di Packet Tracer

### Limitazioni di PT per IPsec

| Funzionalità | Supporto in PT | Note |
|-------------|---------------|-------|
| IKEv1 (ISAKMP) | ✅ Supportato | Funziona come in questa esercitazione |
| IKEv2 | ❌ Non supportato | Solo su hardware reale o GNS3/EVE-NG |
| AES-128 | ✅ Supportato | Usato in questo lab |
| SHA-256 | ⚠️ Parziale | Usare SHA-1 (`hash sha`) per compatibilità |
| GRE over IPsec | ⚠️ Limitato | In alcune versioni PT non funziona correttamente |
| Certificati RSA | ❌ Non supportato | Solo PSK in PT |

### GRE vs IPsec — differenze principali

| Caratteristica | GRE puro | IPsec puro | GRE over IPsec |
|---------------|----------|------------|----------------|
| Cifratura | ❌ No | ✅ Sì | ✅ Sì |
| Routing protocols (OSPF, EIGRP) | ✅ Sì | ❌ No | ✅ Sì |
| Multicast | ✅ Sì | ❌ No | ✅ Sì |
| Complessità | Bassa | Media | Alta |
| Uso tipico | Tunneling interno | VPN sicura punto-punto | VPN con routing dinamico |

### Split Tunneling

Il **split tunneling** è una modalità in cui solo il traffico verso le reti aziendali
viene instradato nella VPN, mentre il traffico Internet normale (YouTube, Gmail, ecc.)
usa la connessione locale del client.

- ✅ **Vantaggio**: riduce il carico sul tunnel VPN e migliora le prestazioni
- ❌ **Rischio sicurezza**: il traffico non-VPN non è protetto e bypassa i controlli aziendali
- In questa esercitazione NON usiamo split tunneling: tutto il traffico tra le LAN passa nel tunnel
