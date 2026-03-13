# 04 — Configurazione VPN IPsec su Cisco IOS

> **Guida pratica** — ES08 VPN  
> Riferimento completo per la configurazione IPsec Site-to-Site e GRE su Cisco IOS.  
> Tutti i comandi sono testati su Cisco Packet Tracer 8.x con router 2901.

---

## 📖 Indice

1. [Configurazione IPsec Site-to-Site (Crypto Map)](#1--configurazione-ipsec-site-to-site-crypto-map)
2. [Configurazione GRE Tunnel](#2--configurazione-gre-tunnel)
3. [Configurazione GRE over IPsec](#3--configurazione-gre-over-ipsec)
4. [Comandi di verifica](#4--comandi-di-verifica)
5. [Configurazioni complete copia-incolla](#5--configurazioni-complete-copia-incolla)

---

## 1 — Configurazione IPsec Site-to-Site (Crypto Map)

La configurazione IPsec Site-to-Site con Crypto Map richiede **4 blocchi** da eseguire in ordine:

```
STEP A → ISAKMP Policy (Phase 1)
STEP B → Pre-shared Key
STEP C → IPsec Transform Set + Crypto ACL + Crypto Map (Phase 2)
STEP D → Applicazione Crypto Map all'interfaccia WAN
```

---

### STEP A — ISAKMP Policy (IKE Phase 1)

Definisce come i due router si autenticano e negoziano le chiavi.

```
Router(config)# crypto isakmp policy 10
Router(config-isakmp)#  encryption aes 256
Router(config-isakmp)#  hash sha
Router(config-isakmp)#  authentication pre-share
Router(config-isakmp)#  group 5
Router(config-isakmp)#  lifetime 86400
Router(config-isakmp)# exit
```

**Spiegazione parametri:**

| Parametro | Valore usato | Significato | Alternativa sicura |
|-----------|-------------|-------------|-------------------|
| `encryption` | `aes 256` | Cifratura AES 256-bit | `aes 128` (meno sicuro) |
| `hash` | `sha` | SHA-1 per integrità | `sha256` (più sicuro, IOS 15+) |
| `authentication` | `pre-share` | Autenticazione con chiave condivisa | `rsa-sig` (certificati PKI) |
| `group` | `5` | Diffie-Hellman Group 5 (1536-bit) | `14` (2048-bit, più sicuro) |
| `lifetime` | `86400` | Durata SA in secondi (= 24 ore) | Valori tra 3600 e 86400 |

> ⚠️ **Importante**: i parametri ISAKMP **devono essere identici** su entrambi i router.  
> Se non corrispondono il tunnel non si stabilisce (errore `MM_NO_STATE`).

---

### STEP B — Pre-shared Key

Specifica la chiave segreta condivisa e l'IP del peer remoto.

```
Router(config)# crypto isakmp key CHIAVE_SEGRETA address IP_DEL_PEER
```

**Esempi:**
```
! Su Router-Milano (peer = Router-Roma 203.0.113.6)
Router-Milano(config)# crypto isakmp key VPN_SECRET_2024 address 203.0.113.6

! Su Router-Roma (peer = Router-Milano 203.0.113.2)
Router-Roma(config)# crypto isakmp key VPN_SECRET_2024 address 203.0.113.2
```

> 💡 La chiave deve essere **identica** su entrambi i router, ma l'IP del peer è **opposto**.  
> Usa chiavi robuste: almeno 12 caratteri, misto di lettere, numeri e simboli.

---

### STEP C — Transform Set, Crypto ACL e Crypto Map (Phase 2)

**1. Transform Set** — definisce gli algoritmi per cifrare i dati:

```
Router(config)# crypto ipsec transform-set NOME-SET esp-aes 256 esp-sha-hmac
Router(cfg-crypto-trans)# mode tunnel
Router(cfg-crypto-trans)# exit
```

| Parametro | Significato |
|-----------|-------------|
| `esp-aes 256` | Cifratura ESP con AES 256-bit |
| `esp-sha-hmac` | Integrità ESP con HMAC-SHA1 |
| `mode tunnel` | Incapsula l'intero pacchetto IP (default per site-to-site) |

**2. Crypto ACL** — definisce il "traffico interessante" da cifrare:

```
Router(config)# ip access-list extended NOME-ACL
Router(config-ext-nacl)#  permit ip RETE_LOCALE WILDCARD_LOCALE RETE_REMOTA WILDCARD_REMOTA
Router(config-ext-nacl)# exit
```

**Esempi:**
```
! Su Router-Milano: cifra traffico 192.168.1.0/24 ↔ 192.168.2.0/24
Router-Milano(config)# ip access-list extended VPN-TRAFFIC
Router-Milano(config-ext-nacl)# permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
Router-Milano(config-ext-nacl)# exit

! Su Router-Roma: ACL speculare (sorgente e destinazione invertite)
Router-Roma(config)# ip access-list extended VPN-TRAFFIC
Router-Roma(config-ext-nacl)# permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255
Router-Roma(config-ext-nacl)# exit
```

> ⚠️ La Crypto ACL su Router-A e Router-B deve essere **speculare**:  
> - Router-A: `permit ip LAN-A LAN-B`  
> - Router-B: `permit ip LAN-B LAN-A`

**3. Crypto Map** — collega transform set, ACL e peer:

```
Router(config)# crypto map NOME-MAP NUMERO ipsec-isakmp
Router(config-crypto-map)#  set peer IP_PEER_REMOTO
Router(config-crypto-map)#  set transform-set NOME-SET
Router(config-crypto-map)#  match address NOME-ACL
Router(config-crypto-map)# exit
```

**Esempio:**
```
! Su Router-Milano
Router-Milano(config)# crypto map VPN-MAP 10 ipsec-isakmp
Router-Milano(config-crypto-map)#  set peer 203.0.113.6
Router-Milano(config-crypto-map)#  set transform-set VPN-TRANSFORM
Router-Milano(config-crypto-map)#  match address VPN-TRAFFIC
Router-Milano(config-crypto-map)# exit
```

> 💡 Il numero `10` è la priorità (più basso = priorità maggiore). Utile quando ci sono  
> più crypto map sullo stesso router (es. Hub-and-Spoke con numeri 10, 20, 30...).

---

### STEP D — Applicazione all'interfaccia WAN

La crypto map deve essere applicata all'**interfaccia fisica WAN** (non alla LAN):

```
Router(config)# interface GigabitEthernet0/1
Router(config-if)#  crypto map NOME-MAP
Router(config-if)# exit
```

> ✅ Dopo questo comando il tunnel è configurato. Il tunnel si attiverà automaticamente  
> quando passa il primo pacchetto che corrisponde alla Crypto ACL.

---

## 2 — Configurazione GRE Tunnel

GRE crea un'interfaccia tunnel virtuale. Non cifra il traffico ma supporta routing protocol e multicast.

```
Router(config)# interface Tunnel0
Router(config-if)#  ip address IP_LOCALE_TUNNEL SUBNET_MASK
Router(config-if)#  tunnel source INTERFACCIA_O_IP_LOCALE
Router(config-if)#  tunnel destination IP_PEER_REMOTO
Router(config-if)#  tunnel mode gre ip
Router(config-if)#  no shutdown
Router(config-if)# exit
```

**Esempio — Router-Milano e Router-Roma connessi via GRE:**

```
! ===== Router-Milano =====
Router-Milano(config)# interface Tunnel0
Router-Milano(config-if)#  ip address 10.0.0.1 255.255.255.252
Router-Milano(config-if)#  tunnel source GigabitEthernet0/1
Router-Milano(config-if)#  tunnel destination 203.0.113.6
Router-Milano(config-if)#  tunnel mode gre ip
Router-Milano(config-if)#  no shutdown
Router-Milano(config-if)# exit

! Routing verso LAN-Roma tramite tunnel GRE
Router-Milano(config)# ip route 192.168.2.0 255.255.255.0 Tunnel0

! ===== Router-Roma =====
Router-Roma(config)# interface Tunnel0
Router-Roma(config-if)#  ip address 10.0.0.2 255.255.255.252
Router-Roma(config-if)#  tunnel source GigabitEthernet0/1
Router-Roma(config-if)#  tunnel destination 203.0.113.2
Router-Roma(config-if)#  tunnel mode gre ip
Router-Roma(config-if)#  no shutdown
Router-Roma(config-if)# exit

Router-Roma(config)# ip route 192.168.1.0 255.255.255.0 Tunnel0
```

**Pianificazione indirizzi tunnel GRE:**

```
Interfaccia Tunnel0 di ciascun router riceve un indirizzo IP privato della /30:
  Router-Milano:   10.0.0.1/30
  Router-Roma:     10.0.0.2/30
  Rete tunnel:     10.0.0.0/30
  Gateway tunnel:  (indirizzo direttamente connesso)
```

> 💡 Usa reti /30 per i link di tunnel (solo 2 host, nessuno spreco).  
> Convezione comune: `10.255.x.0/30` per i tunnel GRE.

---

## 3 — Configurazione GRE over IPsec

Combina GRE (flessibilità, routing dinamico) con IPsec (cifratura). Due fasi:  
**Prima configura GRE**, poi **applica IPsec sopra il tunnel GRE**.

```
! FASE 1: configura GRE (vedi sezione precedente)

! FASE 2: aggiungi IPsec — la Crypto ACL deve proteggere il traffico GRE
!         (GRE usa protocollo IP 47)
Router(config)# ip access-list extended GRE-IPSEC-ACL
Router(config-ext-nacl)#  permit gre host IP_LOCALE_WAN host IP_REMOTO_WAN
Router(config-ext-nacl)# exit

! Crypto Map per proteggere il GRE
Router(config)# crypto map VPN-MAP 10 ipsec-isakmp
Router(config-crypto-map)#  set peer IP_REMOTO_WAN
Router(config-crypto-map)#  set transform-set VPN-TRANSFORM
Router(config-crypto-map)#  match address GRE-IPSEC-ACL
Router(config-crypto-map)# exit

Router(config)# interface GigabitEthernet0/1
Router(config-if)#  crypto map VPN-MAP
Router(config-if)# exit
```

**Schema del traffico GRE over IPsec:**

```
Pacchetto originale:  [IP: 192.168.1.10 → 192.168.2.10] [TCP] [dati]
       ↓ Incapsulamento GRE
Pacchetto GRE:        [IP: 203.0.113.2 → 203.0.113.6] [GRE] [IP orig.] [TCP] [dati]
       ↓ Cifratura IPsec ESP
Pacchetto finale:     [IP: 203.0.113.2 → 203.0.113.6] [ESP cifrato]
```

---

## 4 — Comandi di verifica

### Verifica IPsec Phase 1 (ISAKMP)

```
Router# show crypto isakmp sa
```

Output atteso (tunnel attivo):
```
IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
203.0.113.6     203.0.113.2     QM_IDLE           1001 ACTIVE
```

| Stato | Significato |
|-------|-------------|
| `QM_IDLE` | ✅ Phase 1 stabilita, tunnel attivo |
| `MM_NO_STATE` | ❌ Phase 1 fallita — controlla policy e pre-shared key |
| `MM_SA_SETUP` | ⏳ Negoziazione in corso |
| `AG_NO_STATE` | ❌ Aggressive Mode fallito |

---

### Verifica IPsec Phase 2

```
Router# show crypto ipsec sa
```

Output chiave da cercare:
```
interface: GigabitEthernet0/1
    Crypto map tag: VPN-MAP, local addr 203.0.113.2

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.168.1.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (192.168.2.0/255.255.255.0/0/0)
   current_peer 203.0.113.6 port 500
    PERMIT, flags={origin_is_acl,}
   #pkts encaps: 10, #pkts encrypt: 10, #pkts digest: 10   ← pacchetti cifrati
   #pkts decaps: 10, #pkts decrypt: 10, #pkts verify: 10   ← pacchetti decifrati
```

> ✅ I contatori `encaps` e `decaps` **devono aumentare** ad ogni ping: significa che il tunnel cifra/decifra correttamente.

---

### Verifica Crypto Map

```
Router# show crypto map
```

Mostra la crypto map configurata, il peer, il transform-set e la ACL associata.

---

### Verifica tunnel GRE

```
Router# show interface Tunnel0
```

Output atteso:
```
Tunnel0 is up, line protocol is up     ← ✅ tunnel attivo
  Hardware is Tunnel
  Internet address is 10.0.0.1/30
  Tunnel source 203.0.113.2 (GigabitEthernet0/1), destination 203.0.113.6
  Tunnel protocol/transport GRE/IP
```

Se appare `line protocol is down` → problema di routing verso il destination IP del tunnel.

---

### Ping con interfaccia sorgente specificata

```
! Ping dalla LAN locale verso la LAN remota (importante: usa source corretto)
Router# ping 192.168.2.10 source GigabitEthernet0/0

! Oppure da PC: ping normale (il router gestisce il tunnel)
PC> ping 192.168.2.10
```

> ⚠️ Un semplice `ping 192.168.2.10` dal router usa come sorgente l'IP WAN,  
> che potrebbe NON corrispondere alla Crypto ACL. Specifica sempre il source!

---

### Altri comandi utili

```
Router# show crypto isakmp policy          ! mostra le policy ISAKMP configurate
Router# show crypto ipsec transform-set    ! mostra i transform-set configurati
Router# show running-config | section crypto   ! mostra tutta la config VPN
Router# show ip route                      ! verifica routing verso reti remote
```

---

## 5 — Configurazioni complete copia-incolla

### TOPOLOGIA DI RIFERIMENTO

```
                      INTERNET (simulata)
LAN-MILANO                                          LAN-ROMA
192.168.1.0/24        203.0.113.0/30              192.168.2.0/24

PC-MI-1 (.10)         Router-ISP                  PC-RO-1 (.10)
PC-MI-2 (.11)     .2 /        \ .5                PC-RO-2 (.11)
Server-MI (.20)  /                \              Server-RO (.20)
                                   \
Switch-MI          203.0.113.4/30   Switch-RO
    |              .6           .6      |
Router-Milano(Gi0/0)         Router-Roma(Gi0/0)
192.168.1.1                  192.168.2.1
    |Gi0/1                       |Gi0/1
203.0.113.1                  203.0.113.6
```

**Tabella IP completa:**

| Dispositivo | Interfaccia | Indirizzo IP | Subnet Mask | Gateway |
|-------------|-------------|--------------|-------------|---------|
| Router-Milano | Gi0/0 (LAN) | 192.168.1.1 | 255.255.255.0 | — |
| Router-Milano | Gi0/1 (WAN) | 203.0.113.1 | 255.255.255.252 | — |
| Router-ISP | Gi0/0 | 203.0.113.2 | 255.255.255.252 | — |
| Router-ISP | Gi0/1 | 203.0.113.5 | 255.255.255.252 | — |
| Router-Roma | Gi0/0 (LAN) | 192.168.2.1 | 255.255.255.0 | — |
| Router-Roma | Gi0/1 (WAN) | 203.0.113.6 | 255.255.255.252 | — |
| PC-MI-1 | NIC | 192.168.1.10 | 255.255.255.0 | 192.168.1.1 |
| PC-MI-2 | NIC | 192.168.1.11 | 255.255.255.0 | 192.168.1.1 |
| Server-MI | NIC | 192.168.1.20 | 255.255.255.0 | 192.168.1.1 |
| PC-RO-1 | NIC | 192.168.2.10 | 255.255.255.0 | 192.168.2.1 |
| PC-RO-2 | NIC | 192.168.2.11 | 255.255.255.0 | 192.168.2.1 |
| Server-RO | NIC | 192.168.2.20 | 255.255.255.0 | 192.168.2.1 |

---

### CONFIGURAZIONE COMPLETA — Router-ISP

```
! ============================================================
! Router-ISP — router Internet simulato (NO VPN qui)
! ============================================================
enable
configure terminal

hostname Router-ISP

! Interfaccia verso Router-Milano
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.252
 no shutdown

! Interfaccia verso Router-Roma
interface GigabitEthernet0/1
 ip address 203.0.113.5 255.255.255.252
 no shutdown

! Routing statico verso le LAN private (necessario per rispondere ai ping)
ip route 192.168.1.0 255.255.255.0 203.0.113.1
ip route 192.168.2.0 255.255.255.0 203.0.113.6

end
write memory
```

---

### CONFIGURAZIONE COMPLETA — Router-Milano (VPN IPsec)

```
! ============================================================
! Router-Milano — Sede centrale
! Peer VPN: Router-Roma (203.0.113.6)
! LAN locale:  192.168.1.0/24
! LAN remota:  192.168.2.0/24
! ============================================================
enable
configure terminal

hostname Router-Milano

! ----- INTERFACCE -----
interface GigabitEthernet0/0
 description LAN-Milano
 ip address 192.168.1.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/1
 description WAN-verso-Internet
 ip address 203.0.113.1 255.255.255.252
 no shutdown

! ----- ROUTING STATICO BASE -----
! Rotta di default verso ISP
ip route 0.0.0.0 0.0.0.0 203.0.113.2

! ----- ISAKMP PHASE 1 -----
crypto isakmp policy 10
 encryption aes 256
 hash sha
 authentication pre-share
 group 5
 lifetime 86400

! Pre-shared key — deve corrispondere su Router-Roma
crypto isakmp key VPN_SECRET_2024 address 203.0.113.6

! ----- IPSEC PHASE 2 -----
! Transform set: cifratura AES256 + integrità SHA
crypto ipsec transform-set VPN-TRANSFORM esp-aes 256 esp-sha-hmac
 mode tunnel

! Crypto ACL: traffico Milano→Roma da cifrare
ip access-list extended VPN-TRAFFIC
 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255

! Crypto map: collega tutto insieme
crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.6
 set transform-set VPN-TRANSFORM
 match address VPN-TRAFFIC

! ----- APPLICA CRYPTO MAP ALL'INTERFACCIA WAN -----
interface GigabitEthernet0/1
 crypto map VPN-MAP

end
write memory
```

---

### CONFIGURAZIONE COMPLETA — Router-Roma (VPN IPsec)

```
! ============================================================
! Router-Roma — Filiale
! Peer VPN: Router-Milano (203.0.113.1)
! LAN locale:  192.168.2.0/24
! LAN remota:  192.168.1.0/24
! ============================================================
enable
configure terminal

hostname Router-Roma

! ----- INTERFACCE -----
interface GigabitEthernet0/0
 description LAN-Roma
 ip address 192.168.2.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/1
 description WAN-verso-Internet
 ip address 203.0.113.6 255.255.255.252
 no shutdown

! ----- ROUTING STATICO BASE -----
ip route 0.0.0.0 0.0.0.0 203.0.113.5

! ----- ISAKMP PHASE 1 -----
crypto isakmp policy 10
 encryption aes 256
 hash sha
 authentication pre-share
 group 5
 lifetime 86400

! Pre-shared key (identica a Router-Milano, IP peer invertito)
crypto isakmp key VPN_SECRET_2024 address 203.0.113.1

! ----- IPSEC PHASE 2 -----
crypto ipsec transform-set VPN-TRANSFORM esp-aes 256 esp-sha-hmac
 mode tunnel

! Crypto ACL speculare: traffico Roma→Milano
ip access-list extended VPN-TRAFFIC
 permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255

crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.1
 set transform-set VPN-TRANSFORM
 match address VPN-TRAFFIC

! ----- APPLICA CRYPTO MAP -----
interface GigabitEthernet0/1
 crypto map VPN-MAP

end
write memory
```

---

### CONFIGURAZIONE AGGIUNTIVA — Router-Milano (GRE over IPsec)

Se vuoi aggiungere anche un tunnel GRE protetto da IPsec (bonus):

```
! Dopo la configurazione IPsec base, aggiungi il tunnel GRE
enable
configure terminal

! Crea interfaccia tunnel GRE
interface Tunnel0
 ip address 10.255.0.1 255.255.255.252
 tunnel source GigabitEthernet0/1
 tunnel destination 203.0.113.6
 tunnel mode gre ip
 no shutdown

! Routing verso LAN-Roma tramite tunnel GRE
ip route 192.168.2.0 255.255.255.0 Tunnel0

! Modifica la Crypto ACL per proteggere il traffico GRE
! (rimuovi la vecchia e aggiungi una che matcha il GRE)
no ip access-list extended VPN-TRAFFIC
ip access-list extended VPN-TRAFFIC
 permit gre host 203.0.113.1 host 203.0.113.6

end
write memory
```

---

## 📋 Checklist configurazione VPN

Usa questa checklist per verificare ogni passo prima di fare i test:

**Configurazione base:**
- [ ] Tutti gli IP sono configurati correttamente (router + PC + server)
- [ ] Routing di default verso ISP funziona (ping tra WAN degli router ✅)
- [ ] ISAKMP policy configurata identicamente su entrambi i router
- [ ] Pre-shared key identica su entrambi, con IP peer corretto
- [ ] Transform-set configurato (nome, algoritmi)
- [ ] Crypto ACL configurata (speculare sui due router)
- [ ] Crypto Map configurata (peer, transform-set, ACL)
- [ ] Crypto Map applicata all'interfaccia WAN su entrambi i router

**Verifica:**
- [ ] `show crypto isakmp sa` → stato `QM_IDLE` ✅
- [ ] `show crypto ipsec sa` → contatori `encaps`/`decaps` aumentano ✅
- [ ] Ping PC-MI → PC-RO funziona ✅
- [ ] Ping PC-RO → PC-MI funziona ✅
- [ ] File `.pkt` salvato ✅

---

## 🔑 Parametri IPsec — tabella riepilogativa

| Parametro | Valore per Packet Tracer | Equivalente produzione |
|-----------|------------------------|------------------------|
| Cifratura Phase 1 | `aes 256` | `aes 256` (✅ ok) |
| Hash Phase 1 | `sha` (SHA-1) | `sha256` o `sha384` |
| DH Group | `group 5` (1536-bit) | `group 14` (2048-bit) |
| Autenticazione | `pre-share` | `pre-share` o PKI (certificati) |
| Lifetime Phase 1 | `86400` sec (24h) | 28800 sec (8h) in prod. |
| Cifratura Phase 2 | `esp-aes 256` | `esp-aes 256` (✅ ok) |
| Integrità Phase 2 | `esp-sha-hmac` | `esp-sha256-hmac` |
| Modalità | `tunnel` | `tunnel` (site-to-site) |

> ⚠️ Packet Tracer supporta solo **IKEv1**. In ambienti reali si usa **IKEv2** che è  
> più sicuro ed efficiente. I comandi di configurazione sono diversi (`crypto ikev2 ...`).

---

*ES08 — Sistemi e Reti | Versione 1.0 | Cisco Packet Tracer 8.x*
