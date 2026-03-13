# VPN Troubleshooting su Cisco IOS

> **Guida teorica** — ES08 VPN  
> Consulta questa guida durante e dopo gli Esercizi A e B.

---

## 🔍 Comandi di verifica VPN

### `show crypto isakmp sa` — Stato Phase 1

Mostra lo stato delle SA IKE Phase 1 (ISAKMP SA) attive sul router.

```
Router-Milano# show crypto isakmp sa

IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
203.0.113.6     203.0.113.2     QM_IDLE           1001 ACTIVE
```

| Campo | Significato |
|-------|-------------|
| `dst` | IP del peer remoto (destinazione tunnel) |
| `src` | Proprio IP WAN (sorgente tunnel) |
| `state` | Stato della SA (vedi tabella stati) |
| `conn-id` | ID connessione interno |
| `status` | ACTIVE = SA valida ✅ |

**Possibili stati ISAKMP**:

| Stato | Significato | Azione |
|-------|-------------|--------|
| `QM_IDLE` | Phase 1 UP, in attesa di Phase 2 | ✅ Normale |
| `MM_ACTIVE` | Main Mode completato | ✅ Phase 1 OK |
| `MM_NO_STATE` | Phase 1 avviata ma fallita | ❌ Verifica policy/PSK |
| `MM_SA_SETUP` | Negoziazione SA in corso | ⏳ Attendere |
| `MM_KEY_EXCH` | Scambio DH in corso | ⏳ Attendere |
| `AG_NO_STATE` | Aggressive Mode fallito | ❌ Verifica config |
| *(vuoto)* | Nessuna SA, Phase 1 mai avviata | ❌ Nessun traffico interessante o config errata |

---

### `show crypto ipsec sa` — Stato Phase 2

Mostra lo stato delle SA IPsec Phase 2 e i contatori di traffico cifrato/decifrato.

```
Router-Milano# show crypto ipsec sa

interface: GigabitEthernet0/1
    Crypto map tag: VPN-MAP, local addr 203.0.113.2

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.168.1.0/255.255.255.0/0/0)   ← rete locale
   remote ident (addr/mask/prot/port): (192.168.2.0/255.255.255.0/0/0)   ← rete remota
   current_peer 203.0.113.6 port 500                                       ← peer IP

    #pkts encaps: 47, #pkts encrypt: 47, #pkts digest: 47                 ← pacchetti cifrati
    #pkts decaps: 52, #pkts decrypt: 52, #pkts verify: 52                 ← pacchetti decifrati
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 10, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0                                         ← errori

   local crypto endpt.: 203.0.113.2, remote crypto endpt.: 203.0.113.6
   path mtu 1500, ip mtu 1500, ip mtu idb GigabitEthernet0/1
   current outbound spi: 0x12345678(305419896)

   inbound esp sas:                                                         ← SA in entrata
    spi: 0xABCDEF01(2882400001)
      transform: esp-aes esp-sha-hmac
      in use settings ={Tunnel, }
      conn id: 2001, flow_id: 1, sibling_flags 80000040, crypto map: VPN-MAP
      sa timing: remaining key lifetime (k/sec): (4607994/3540)
      IV size: 16 bytes
      replay detection support: Y   Status: ACTIVE

   outbound esp sas:                                                        ← SA in uscita
    spi: 0x12345678(305419896)
      transform: esp-aes esp-sha-hmac
      in use settings ={Tunnel, }
      conn id: 2002, flow_id: 2, sibling_flags 80000040, crypto map: VPN-MAP
      sa timing: remaining key lifetime (k/sec): (4607993/3540)
      IV size: 16 bytes
      replay detection support: Y   Status: ACTIVE
```

### Guida all'interpretazione campo per campo

| Campo | Significato | Valore corretto |
|-------|-------------|----------------|
| `interface` | Interfaccia con crypto map | Deve essere l'interfaccia WAN |
| `Crypto map tag` | Nome e addr locale della crypto map | Deve corrispondere alla configurazione |
| `local ident` | Rete locale cifrata (da ACL VPN-TRAFFIC) | 192.168.1.0/255.255.255.0 |
| `remote ident` | Rete remota cifrata (da ACL VPN-TRAFFIC) | 192.168.2.0/255.255.255.0 |
| `current_peer` | IP del peer remoto | 203.0.113.6 |
| `#pkts encaps` | Pacchetti cifrati e incapsulati in uscita | Deve aumentare con ping |
| `#pkts encrypt` | Pacchetti cifrati | Deve = encaps |
| `#pkts digest` | Pacchetti autenticati | Deve = encaps |
| `#pkts decaps` | Pacchetti ricevuti e decapsulati | Deve aumentare |
| `#pkts decrypt` | Pacchetti decifrati | Deve = decaps |
| `#pkts verify` | Pacchetti autenticati verificati | Deve = decaps |
| `#send errors` | Errori in trasmissione | Deve essere 0 |
| `#recv errors` | Errori in ricezione | Deve essere 0 |
| `spi` | Security Parameter Index | Deve essere diverso su ogni SA |
| `transform` | Algoritmi usati | Deve corrispondere al transform-set |
| `replay detection: Y` | Anti-replay attivo | Deve essere Y |
| `Status: ACTIVE` | SA attiva | Deve essere ACTIVE |

---

### Altri comandi di verifica utili

```
! Mostra le crypto map configurate e a quali interfacce sono applicate
Router# show crypto map

! Mostra le ISAKMP policy configurate
Router# show crypto isakmp policy

! Mostra lo stato dell'interfaccia WAN (verifica che crypto map sia applicata)
Router# show ip interface GigabitEthernet0/1
! Output: "Outgoing crypto map: VPN-MAP" se applicata correttamente

! Panoramica di tutte le sessioni VPN attive
Router# show crypto session

! Mostra il running config filtrato per la configurazione crypto
Router# show running-config | section crypto

! Verifica la chiave PSK configurata (mostrala solo se necessario per debug)
Router# show running-config | include isakmp key
```

---

## 🛠️ Procedura di troubleshooting in 5 passi

### PASSO 1 — Verifica connettività IP base

**Prima di tutto** assicurati che i router possano comunicare a livello IP
senza VPN, usando i loro indirizzi WAN pubblici.

```
Router-Milano# ping 203.0.113.6         ! Ping verso WAN di Router-Roma
Router-Milano# ping 203.0.113.1         ! Ping verso Router-ISP

Router-Milano# show ip route            ! Verifica tabella di routing
```

**Cosa verificare**:
- Il ping tra IP WAN deve funzionare
- La tabella di routing deve avere un percorso verso la rete remota
- Se il ping tra IP WAN fallisce → problema di routing/cablaggio, NON di VPN

**Se fallisce**: verifica IP interfacce, subnet mask, cablaggio, route statiche.
La VPN non può funzionare senza connettività IP base!

---

### PASSO 2 — Verifica Phase 1 (ISAKMP SA)

Genera traffico tra le LAN (ping da un PC locale verso PC remoto) per attivare
la negoziazione IKE, poi verifica la Phase 1:

```
Router-Milano# show crypto isakmp sa
```

**Scenario OK** (Phase 1 UP):
```
IPv4 Crypto ISAKMP SA
dst             src             state      conn-id status
203.0.113.6     203.0.113.2     QM_IDLE    1001 ACTIVE
```

**Scenario KO** (Phase 1 fallita o non avviata):
```
IPv4 Crypto ISAKMP SA
dst             src             state      conn-id status
203.0.113.6     203.0.113.2     MM_NO_STATE 0   ACTIVE
```
oppure output completamente vuoto.

**Cause del fallimento Phase 1**:

| Causa | Come verificare | Soluzione |
|-------|----------------|-----------|
| Policy mismatch | Confronta `show crypto isakmp policy` su entrambi i router | I parametri devono essere identici |
| PSK errata | Controlla con `show run \| include isakmp key` | La chiave deve essere identica e case-sensitive |
| IP peer errato | Verifica `crypto isakmp key X address Y` | Y deve essere l'IP WAN del peer |
| Crypto map non applicata | `show ip int Gi0/1` → Outgoing crypto map | Applica `crypto map VPN-MAP` sull'interfaccia |
| No traffico interessante | La negoziazione non parte senza traffico | Genera un ping da PC a PC |

---

### PASSO 3 — Verifica Phase 2 (IPsec SA)

Se Phase 1 è UP ma i ping non funzionano ancora, verifica la Phase 2:

```
Router-Milano# show crypto ipsec sa
```

**Scenario OK**: vedi `inbound esp sas` e `outbound esp sas` con `Status: ACTIVE`

**Scenario KO**: la sezione `inbound/outbound esp sas` è assente o i contatori `encaps` sono 0.

**Cause del fallimento Phase 2**:

| Causa | Sintomo | Soluzione |
|-------|---------|-----------|
| ACL VPN-TRAFFIC asimmetrica | Phase 1 OK, Phase 2 assente | Verifica che le ACL siano speculari tra i due router |
| Transform-set diverso | Phase 1 OK, Phase 2 fallisce | I transform-set devono essere identici |
| ACL sbagliata nella crypto map | `match address` punta ad ACL errata | Verifica `show crypto map` |
| Traffico non corrisponde all'ACL | encaps = 0 | Verifica sorgente/destinazione del ping vs ACL |

**Verifica contatori encaps**:
- Esegui un ping da PC-MI1 a PC-RO1
- Riesegui `show crypto ipsec sa`
- Se `encaps` aumenta → il pacchetto viene cifrato ✅
- Se `encaps` = 0 → il traffico non raggiunge l'interfaccia con crypto map → problema routing

---

### PASSO 4 — Verifica routing e ACL

Se i pacchetti non vengono cifrati (`encaps` = 0), il problema è probabilmente
nel routing o nelle ACL:

```
! Verifica routing verso rete remota
Router-Milano# show ip route 192.168.2.10

! Traceroute per vedere dove si ferma il traffico
Router-Milano# traceroute 192.168.2.10

! Verifica ACL VPN-TRAFFIC
Router-Milano# show ip access-lists VPN-TRAFFIC

! Verifica configurazione completa crypto map
Router-Milano# show crypto map
```

**Problemi comuni di routing e ACL**:

| Problema | Sintomo | Soluzione |
|---------|---------|-----------|
| Route mancante | `show ip route` non trova il percorso | Aggiungere route statica |
| Gateway sbagliato | Traffico esce dall'interfaccia sbagliata | Correggere route statica |
| ACL con wildcard errata | Alcuni host funzionano, altri no | Correggere wildcard mask (es. 0.0.0.255) |
| ACL non speculare | Funziona solo in una direzione | Inverti sorgente/destinazione su router remoto |
| Crypto map su interfaccia sbagliata | Traffico non cifrato | Rimuovi e riapplica crypto map sulla WAN |

---

### PASSO 5 — Debug (⚠️ solo in laboratorio!)

I comandi debug mostrano i messaggi IKE e IPsec in tempo reale nella console.

```
! Debug IKE Phase 1
Router-Milano# debug crypto isakmp

! Debug IPsec Phase 2
Router-Milano# debug crypto ipsec

! Debug entrambi
Router-Milano# debug crypto isakmp
Router-Milano# debug crypto ipsec
```

**Esempio output debug crypto isakmp** (Phase 1 riuscita):
```
ISAKMP:(0): SA request profile is (NULL)
ISAKMP: Created a peer struct for 203.0.113.6, peer port 500
ISAKMP:(0):beginning Main Mode exchange
ISAKMP:(0): processing SA payload. message ID = 0
ISAKMP:(0):Checking ISAKMP transform 1 against priority 10 policy
ISAKMP:      encryption AES-CBC
ISAKMP:      hash SHA
ISAKMP:      default group 2
ISAKMP:      auth pre-share
ISAKMP:      life type in seconds
ISAKMP:      life duration (basic) of 86400
ISAKMP:(0):atts are acceptable. Next payload is 0
ISAKMP:(0):SA is doing pre-shared key authen.
...
ISAKMP:(1001):SA has been authenticated with 203.0.113.6   ← Phase 1 OK!
```

**Esempio output debug crypto isakmp** (Phase 1 fallita — policy mismatch):
```
ISAKMP:(0): processing SA payload. message ID = 0
ISAKMP:(0):Checking ISAKMP transform 1 against priority 10 policy
ISAKMP:      encryption AES-CBC
ISAKMP:      hash MD5    ← Router remoto usa MD5, noi SHA → MISMATCH!
ISAKMP:(0):atts are not acceptable. Next payload is 0
ISAKMP:(0):no offers accepted!
ISAKMP:(0): phase 1 SA policy not acceptable!
```

**Come disattivare il debug**:

```
Router-Milano# undebug all
!   OPPURE:
Router-Milano# no debug crypto isakmp
Router-Milano# no debug crypto ipsec
```

> ⚠️ **AVVERTENZA IMPORTANTE**: I comandi debug sono **estremamente verbosi** e consumano
> molte risorse del router. In un router di produzione, l'uso di debug può:
> - Rallentare il router al punto da causare interruzioni di servizio
> - Riempire il buffer di log e sovrascrivere informazioni importanti
> - Esporre informazioni sensibili sulla configurazione VPN
>
> **Regola d'oro**: usa sempre `undebug all` immediatamente dopo aver raccolto
> le informazioni necessarie. Mai lasciare il debug attivo in produzione!

---

## 📋 Tabella problemi comuni e soluzioni

| Problema | Sintomo | Causa probabile | Soluzione |
|---------|---------|-----------------|-----------|
| **Phase 1 non si forma** | `show crypto isakmp sa` vuoto dopo ping | Policy mismatch o PSK errata | Confrontare policy su entrambi i router; verificare PSK identica e case-sensitive |
| **Phase 1 vuota — no traffico** | Nessuna SA anche con ping | Crypto map non applicata o traffico non corrisponde ACL | `show ip int Gi0/1` — verifica Outgoing crypto map |
| **Phase 2 non si forma** | Phase 1 UP, encaps=0 | ACL VPN-TRAFFIC asimmetrica o transform-set diverso | ACL deve essere speculare; transform-set identico |
| **Tunnel UP ma ping fallisce** | SA ACTIVE, encaps>0 ma decaps=0 | Routing errato lato remoto o ACL errata | Verifica routing su router remoto |
| **Ping solo in una direzione** | MI→RO OK, RO→MI fallisce | ACL o crypto map mancante su uno dei router | Verifica configurazione su Router-Roma |
| **Tunnel si abbatte periodicamente** | SA cade ogni X minuti | Lifetime troppo basso o keepalive mancante | Aumentare lifetime o aggiungere `isakmp keepalive` |
| **NAT interferisce** | Pacchetti cifrati ma non decifrati | NAT applicato prima di IPsec | Aggiungere NAT exemption (route-map o ACL) |
| **recv errors aumenta** | `#recv errors > 0` | Pacchetti corrotti o SA non più valida | Cancellare SA e riattivare tunnel |
| **send errors aumenta** | `#send errors > 0` | Problema di trasmissione o MTU | Verificare MTU e frammentazione |
| **Tunnel lento** | SA UP ma prestazioni basse | MTU troppo alto, frammentazione | Abbassare TCP MSS con `ip tcp adjust-mss` |

---

## 🔄 Comandi per resettare il tunnel VPN

A volte è necessario forzare la rinegoziazione del tunnel:

```
! Cancella tutte le SA IKE (riavvia la negoziazione Phase 1 e 2)
Router-Milano# clear crypto isakmp

! Cancella SA IKE con peer specifico
Router-Milano# clear crypto isakmp 203.0.113.6

! Cancella SA IPsec (Phase 2)
Router-Milano# clear crypto sa

! Cancella SA IPsec per peer specifico
Router-Milano# clear crypto sa peer 203.0.113.6

! Dopo il reset, genera traffico per riattivare il tunnel
Router-Milano# ping 192.168.2.10 source 192.168.1.1
```

> 💡 Dopo un `clear crypto isakmp` o `clear crypto sa`, il tunnel viene
> ricreato automaticamente al primo pacchetto che corrisponde all'ACL VPN-TRAFFIC.
> I primi ping potrebbero andare in timeout durante la rinegoziazione.

---

## 📊 Checklist troubleshooting completa

Usa questa checklist quando la VPN non funziona:

```
LIVELLO 1 — CONNETTIVITÀ BASE
[ ] Router-Milano può pingare 203.0.113.1 (Router-ISP) ?
[ ] Router-Milano può pingare 203.0.113.6 (Router-Roma WAN) ?
[ ] show ip route mostra percorso verso 192.168.2.0/24 ?
[ ] PC-MI1 può pingare 192.168.1.1 (gateway) ?

LIVELLO 2 — CONFIGURAZIONE IPsec
[ ] crypto isakmp policy 10 configurata su entrambi i router ?
[ ] Parametri identici: encryption, hash, authentication, group, lifetime ?
[ ] PSK configurata su entrambi (con IP peer inverso) ?
[ ] PSK identica su entrambi (case-sensitive!) ?
[ ] transform-set con stessi parametri su entrambi ?

LIVELLO 3 — ACL e CRYPTO MAP
[ ] ACL VPN-TRAFFIC configurata su entrambi ?
[ ] ACL speculare (sorgente/destinazione invertite) ?
[ ] Crypto map con `set peer` puntante all'IP WAN corretto ?
[ ] Crypto map con `set transform-set` e `match address` corretti ?
[ ] Crypto map applicata sull'interfaccia WAN (non LAN!) ?
[ ] show ip interface [WAN] mostra "Outgoing crypto map: VPN-MAP" ?

LIVELLO 4 — VERIFICA FASE 1
[ ] show crypto isakmp sa mostra QM_IDLE / ACTIVE ?
[ ] Se MM_NO_STATE → problema Phase 1 (vedi livello 2) ?

LIVELLO 5 — VERIFICA FASE 2
[ ] show crypto ipsec sa mostra inbound/outbound esp sas ACTIVE ?
[ ] #pkts encaps > 0 dopo un ping ?
[ ] #pkts decaps > 0 dopo un ping ?
[ ] #send errors = 0 e #recv errors = 0 ?
```

---

## 💡 Tips & Tricks

### Ping di test con sorgente specificata

Il ping normale dal router usa l'IP dell'interfaccia di uscita (WAN),
che NON corrisponde all'ACL VPN-TRAFFIC (che usa IP LAN).
Usa sempre ping con sorgente LAN per testare il tunnel:

```
! Ping con sorgente LAN (attiva il tunnel!)
Router-Milano# ping 192.168.2.10 source GigabitEthernet0/0
! Oppure:
Router-Milano# ping 192.168.2.10 source 192.168.1.1
```

### Verifica rapida tunnel UP

```
Router-Milano# show crypto session
Crypto session current status

Interface: GigabitEthernet0/1
Session status: UP-ACTIVE    ← ✅ Tunnel funzionante
Peer: 203.0.113.6 port 500
  Session ID: 0
  IKEv1 SA: local 203.0.113.2/500 remote 203.0.113.6/500 Active
  IPSEC FLOW: permit ip 192.168.1.0/255.255.255.0 192.168.2.0/255.255.255.0
        Active SAs: 2, origin: crypto map
```

### Verificare che la crypto map sia applicata all'interfaccia

```
Router-Milano# show interfaces GigabitEthernet0/1 | include crypto
  Outgoing crypto map: VPN-MAP   ← ✅ Crypto map applicata
```

Se non appare "Outgoing crypto map", la crypto map non è stata applicata:

```
Router-Milano(config)# interface GigabitEthernet0/1
Router-Milano(config-if)# crypto map VPN-MAP
```
