# 03 — GRE e tecnologie di tunneling

> **Guida teorica** — ES08 VPN  
> Leggi questa guida prima dell'Esercizio B.

---

## 🌐 GRE — Generic Routing Encapsulation

### Cos'è GRE?

**GRE (Generic Routing Encapsulation)** è un protocollo di tunneling generico
definito nella RFC 2784. Permette di incapsulare un qualsiasi pacchetto di rete
(non solo IP) all'interno di un pacchetto IP, creando un tunnel punto-a-punto virtuale.

- **Numero protocollo IP**: 47
- **Sviluppato da**: Cisco Systems (1994)
- **Standard**: RFC 2784, RFC 2890

### Come funziona GRE

GRE aggiunge due intestazioni al pacchetto originale:
1. Un'**intestazione GRE** (4–20 byte) con informazioni sul protocollo incapsulato
2. Un'**intestazione IP esterna** con gli indirizzi IP pubblici del tunnel

```
Pacchetto originale (dal router sorgente):
┌───────────────────────────────────────────────┐
│ IP header (10.1.1.1 → 10.2.2.2) │ payload     │
└───────────────────────────────────────────────┘

Dopo incapsulamento GRE:
┌──────────────────┬────────────┬───────────────────────────────────┐
│ Outer IP header  │ GRE header │ Inner IP header + payload         │
│ (203.x → 203.y)  │ (proto=47) │ (10.1.1.1 → 10.2.2.2) │ payload   │
└──────────────────┴────────────┴───────────────────────────────────┘
         ↑                                  ↑
  IP pubblici del tunnel            IP originali incapsulati
```

### Struttura dettagliata del pacchetto GRE

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
│C│ Reserved0 │K│S│    Reserved1    │         Protocol Type     │
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
│      Checksum (optional)          │       Reserved (optional) │
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
│                         Key (optional)                        │
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
│                   Sequence Number (optional)                  │
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

C = Checksum Present
K = Key Present
S = Sequence Number Present
Protocol Type = tipo del pacchetto incapsulato (0x0800 = IPv4, 0x86DD = IPv6, ecc.)
```

### Vantaggi di GRE

| Vantaggio | Descrizione |
|-----------|-------------|
| 🌍 **Multi-protocollo** | Incapsula IPv4, IPv6, IPX, AppleTalk, e altri |
| 📡 **Routing protocols** | OSPF, EIGRP, RIP possono girare attraverso il tunnel |
| 📢 **Multicast/Broadcast** | Supporta multicast e broadcast (IPsec puro no!) |
| 🔄 **Flessibilità** | Si comporta come un'interfaccia punto-a-punto virtuale |
| 🛠️ **Semplicità** | Configurazione più semplice di IPsec |

### Svantaggi di GRE

| Svantaggio | Descrizione |
|-----------|-------------|
| ❌ **Nessuna cifratura** | Il contenuto del tunnel è in chiaro! |
| ❌ **Nessuna autenticazione** | Non verifica l'identità dei peer |
| ❌ **Overhead aggiuntivo** | 24 byte di overhead (4 GRE + 20 IP header) |
| ⚠️ **Frammentazione MTU** | L'overhead riduce l'MTU effettivo del tunnel |

> ⚠️ **GRE da solo non è sicuro per comunicazioni su Internet!**
> Se usato su reti pubbliche, DEVE essere combinato con IPsec.

---

## ⚙️ Configurazione GRE Tunnel su Cisco IOS

### Configurazione base di un GRE Tunnel

Scenario: tunnel GRE tra Router-A (IP WAN: 203.0.113.2) e Router-B (IP WAN: 203.0.113.6)

```cisco
! ─── Su Router-A ─────────────────────────────────────────────────────────────
interface Tunnel0
 description Tunnel GRE verso Router-B
 ip address 10.10.10.1 255.255.255.252
 !   IP del tunnel (rete virtuale punto-a-punto)
 tunnel source GigabitEthernet0/1
 !   Interfaccia fisica da cui parte il tunnel (WAN)
 tunnel destination 203.0.113.6
 !   IP pubblico del router remoto
 tunnel mode gre ip
 !   Modalità: GRE su IPv4 (default, si può omettere)
 no shutdown

! Route verso le reti remote via tunnel (non via interfaccia fisica!)
ip route 192.168.2.0 255.255.255.0 Tunnel0
! Oppure: ip route 192.168.2.0 255.255.255.0 10.10.10.2

! ─── Su Router-B (speculare) ─────────────────────────────────────────────────
interface Tunnel0
 description Tunnel GRE verso Router-A
 ip address 10.10.10.2 255.255.255.252
 tunnel source GigabitEthernet0/1
 tunnel destination 203.0.113.2
 tunnel mode gre ip
 no shutdown

ip route 192.168.1.0 255.255.255.0 Tunnel0
```

### Verifica tunnel GRE

```
Router-A# show interface Tunnel0
Tunnel0 is up, line protocol is up
  Hardware is Tunnel
  Description: Tunnel GRE verso Router-B
  Internet address is 10.10.10.1/30
  MTU 17916 bytes, BW 100 Kbit/sec, DLY 50000 usec,
  Tunnel source 203.0.113.2 (GigabitEthernet0/1), destination 203.0.113.6
  Tunnel protocol/transport GRE/IP

Router-A# show ip interface brief | include Tunnel
Tunnel0    10.10.10.1    YES manual  up    up
```

---

## 🔒 GRE over IPsec

### Perché combinare GRE e IPsec?

IPsec puro ha una limitazione importante: **non supporta routing protocols né multicast**.
Questo significa che non puoi far girare OSPF o EIGRP direttamente su un tunnel IPsec.

La soluzione classica è **GRE over IPsec**:
- **GRE** crea un'interfaccia virtuale su cui girare i routing protocols e multicast
- **IPsec** cifra tutto il traffico GRE per garantire la sicurezza

```
GRE over IPsec — struttura pacchetto:
┌──────────────┬──────────┬────────────┬─────────────────────────────┐
│ Outer IP hdr │ ESP hdr  │ GRE hdr    │ Inner IP hdr + payload      │
│ (pub. addrs) │(cifrato→)│(incapsulato│(192.168.x.x — cifrato!)     │
└──────────────┴──────────┴────────────┴─────────────────────────────┘
                          └───────────────── CIFRATO da IPsec ────────┘
```

### Configurazione GRE over IPsec su Cisco IOS

```cisco
! ─── Passo 1: Configura il tunnel GRE (come sopra) ─────────────────────────
interface Tunnel0
 ip address 10.10.10.1 255.255.255.252
 tunnel source GigabitEthernet0/1
 tunnel destination 203.0.113.6
 tunnel mode gre ip

! ─── Passo 2: Configura IPsec (per cifrare il traffico GRE) ─────────────────
crypto isakmp policy 10
 encryption aes
 hash sha
 authentication pre-share
 group 2
 lifetime 86400

crypto isakmp key GRE_VPN_KEY address 203.0.113.6

crypto ipsec transform-set GRE-TRANSFORM esp-aes esp-sha-hmac

! ─── Passo 3: ACL per il traffico GRE (protocollo 47) ────────────────────────
ip access-list extended GRE-TRAFFIC
 permit gre host 203.0.113.2 host 203.0.113.6
 !   Cifra tutto il traffico GRE tra i due IP pubblici

! ─── Passo 4: Crypto Map ─────────────────────────────────────────────────────
crypto map GRE-IPsec-MAP 10 ipsec-isakmp
 set peer 203.0.113.6
 set transform-set GRE-TRANSFORM
 match address GRE-TRAFFIC

! ─── Passo 5: Applica crypto map sull'interfaccia FISICA (non sul tunnel!) ──
interface GigabitEthernet0/1
 crypto map GRE-IPsec-MAP

! ─── Passo 6: Routing via tunnel GRE ────────────────────────────────────────
ip route 192.168.2.0 255.255.255.0 Tunnel0

! ─── Opzionale: routing protocol sul tunnel ──────────────────────────────────
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
 network 10.10.10.0 0.0.0.3 area 0
 !   OSPF gira sull'interfaccia Tunnel0 — impossibile con IPsec puro!
```

### Confronto: IPsec puro vs GRE over IPsec vs DMVPN

| Caratteristica | IPsec puro | GRE over IPsec | DMVPN |
|---------------|-----------|----------------|-------|
| Cifratura | ✅ Sì | ✅ Sì | ✅ Sì |
| Routing protocols (OSPF/EIGRP) | ❌ No | ✅ Sì | ✅ Sì |
| Multicast | ❌ No | ✅ Sì | ✅ Sì |
| Complessità configurazione | Media | Alta | Molto alta |
| Scalabilità (molte sedi) | Bassa | Media | ✅ Alta |
| Tunnel spoke-to-spoke diretti | ❌ No | ❌ No | ✅ Dinamici |
| Supporto in Packet Tracer | ✅ Buono | ⚠️ Parziale | ❌ Limitato |

---

## 🌐 DMVPN — Dynamic Multipoint VPN

### Cos'è DMVPN?

**DMVPN** risolve il problema di scalabilità dell'Hub-and-Spoke statico permettendo
ai nodi spoke di creare tunnel diretti tra loro dinamicamente, senza configurazione
statica su ogni router.

**Componenti di DMVPN**:

| Componente | Funzione |
|-----------|---------|
| **mGRE** (Multipoint GRE) | Interfaccia tunnel che accetta connessioni da N peer dinamici |
| **NHRP** (Next Hop Resolution Protocol) | "Rubrica telefonica" per trovare gli IP dei peer spoke |
| **IPsec** | Cifratura del traffico del tunnel mGRE |

### Come funziona DMVPN

1. Tutti gli spoke si registrano all'NHS (Next-Hop Server) = router HUB
2. Quando Spoke-A vuole comunicare con Spoke-B:
   - Spoke-A chiede all'NHS l'IP di Spoke-B
   - NHS risponde con l'IP pubblico di Spoke-B
   - Spoke-A crea un tunnel GRE diretto con Spoke-B (senza passare per HUB)

```
DMVPN — Flusso:
              NHRP Registration
   Spoke-A ──────────────────→ NHS (HUB)
   Spoke-B ──────────────────→ NHS (HUB)
   
   NHRP Resolution:
   Spoke-A: "Chi è Spoke-B?" → NHS (HUB)
   Spoke-A: ←─ "IP di Spoke-B è 203.0.113.9" ─ NHS (HUB)
   
   Tunnel diretto spoke-to-spoke:
   Spoke-A ══════════════════════ Spoke-B (tunnel on-demand!)
```

### Fasi DMVPN (Phase 1, 2, 3)

| Fase | Comportamento | Traffico spoke-to-spoke |
|------|--------------|------------------------|
| Phase 1 | Hub-and-spoke puro, nessun tunnel diretto | Passa per HUB |
| Phase 2 | Tunnel diretti spoke-to-spoke on-demand | Diretto (dopo prima connessione) |
| Phase 3 | Ottimizzato con NHRP redirect | Diretto con ottimizzazioni |

---

## 🔗 L2TP — Layer 2 Tunneling Protocol

### Cos'è L2TP?

**L2TP (Layer 2 Tunneling Protocol)** è un protocollo di tunneling che opera a **Layer 2**
(livello datalink). Incapsula frame PPP all'interno di pacchetti UDP.

- **Porta**: UDP 1701
- **Standard**: RFC 2661
- **Sviluppato da**: Cisco (L2F) + Microsoft (PPTP) → L2TP
- **Da solo**: NO cifratura, NO autenticazione forte

### L2TP/IPsec

La combinazione più comune: L2TP per il tunneling + IPsec per la sicurezza.

```
L2TP/IPsec — struttura:
┌──────────────┬──────────┬──────────────────────────────────────┐
│ IP header    │ ESP      │ UDP 1701 | L2TP | PPP | IP | payload │
│ (pubblico)   │(cifrato→)│             CIFRATO                  │
└──────────────┴──────────┴──────────────────────────────────────┘
```

**Caratteristiche L2TP/IPsec**:
- ✅ Supportato nativamente in Windows, macOS, iOS, Android
- ✅ Non richiede client aggiuntivo (built-in nel sistema operativo)
- ✅ Supporta autenticazione utente (username/password)
- ⚠️ Problema con NAT (richiede NAT-T)
- ⚠️ Più lento di IKEv2 (doppio incapsulamento)
- ❌ Vulnerabile se usato con PSK debole

**Uso tipico**: VPN Remote Access legacy, specialmente per dispositivi mobili prima
della diffusione di IKEv2/WireGuard.

### Confronto L2TP/IPsec vs IKEv2 vs WireGuard per Remote Access

| Tecnologia | Sicurezza | Velocità | Supporto nativo | Complessità |
|-----------|-----------|----------|-----------------|-------------|
| L2TP/IPsec | ⚠️ Media | ⚠️ Lenta | ✅ Universale | Bassa |
| IKEv2/IPsec | ✅ Alta | ✅ Veloce | ✅ Windows/iOS/Android | Media |
| OpenVPN | ✅ Alta | ⚠️ Media | ❌ Richiede client | Media |
| WireGuard | ✅ Molto alta | ✅ Molto veloce | ⚠️ Linux nativo, altri con app | Bassa |

---

## 📊 Riepilogo: quando usare quale tecnologia

| Scenario | Tecnologia consigliata | Perché |
|----------|----------------------|--------|
| VPN Site-to-Site semplice | IPsec (IKEv1/IKEv2) | Standard, hardware supportato |
| VPN Site-to-Site con routing dinamico | GRE over IPsec | Supporta OSPF/EIGRP/multicast |
| VPN Site-to-Site scalabile (molte sedi) | DMVPN | Tunnel spoke-to-spoke dinamici |
| VPN Remote Access enterprise | SSL VPN (Cisco AnyConnect) o IKEv2 | Client facile, scalabile |
| VPN Remote Access open source | OpenVPN o WireGuard | Gratuito, multipiattaforma |
| VPN privata consumer | WireGuard | Semplice, veloce, sicuro |
| Legacy / dispositivi vecchi | L2TP/IPsec | Supporto universale |
| Lab Packet Tracer | IPsec puro (IKEv1) | Unico supportato da PT |
