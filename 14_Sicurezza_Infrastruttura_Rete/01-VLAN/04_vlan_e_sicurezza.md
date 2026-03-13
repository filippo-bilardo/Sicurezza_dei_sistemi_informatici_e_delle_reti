# Capitolo 50.4 - VLAN e Sicurezza

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 50 — Network Segmentation e VLAN Security**

---

## Introduzione

Le VLAN migliorano la sicurezza della rete, ma sono anche soggette a specifici attacchi se mal configurate. **VLAN hopping**, **double tagging**, **ARP spoofing inter-VLAN**, e altri vettori sfruttano debolezze nella configurazione degli switch. Questa guida analizza gli attacchi alle VLAN e le contromisure corrispondenti, incluse funzionalità avanzate come DHCP Snooping, Dynamic ARP Inspection e IP Source Guard.

### Obiettivi di Apprendimento
- Comprendere e riprodurre gli attacchi VLAN hopping (switch spoofing e double tagging)
- Configurare le difese: BPDU Guard, Root Guard, DHCP Snooping, DAI
- Implementare Port Security per limitare i MAC address per porta
- Applicare IP Source Guard per prevenire spoofing IP
- Definire una security baseline per switch Layer 2

---

## Attacchi alle VLAN

### 1. Switch Spoofing (DTP Abuse)

Lo switch negozia automaticamente le porte trunk tramite **DTP (Dynamic Trunking Protocol)**. Un attaccante può inviare messaggi DTP per far credere allo switch che il suo laptop sia un altro switch, ottenendo una porta trunk con accesso a **tutte le VLAN**.

```
Attaccante                    Switch vittima
    |                               |
    |---[DTP Desirable/Auto]------->|
    |<--[Trunk Negotiated]----------|
    |                               |
    | Ora riceve traffico di TUTTE  |
    | le VLAN (non solo la propria) |
```

**Tool:** `yersinia -G` (attacchi Layer 2), `scapy`

**Contromisura:**
```
! Disabilitare DTP su TUTTE le porte access
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate

! Disabilitare DTP anche sulle porte trunk (negoziazione non necessaria)
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport nonegotiate
```

### 2. VLAN Hopping — Double Tagging

L'attaccante invia frame con **due tag 802.1Q**. Il primo tag corrisponde alla VLAN nativa (rimosso dal primo switch senza ispezione), il secondo tag contiene la VLAN target. Il frame arriva nella VLAN vittima **senza passare per il router/firewall inter-VLAN**.

```
Attaccante (VLAN 10)                Switch A              Switch B
    |                                    |                     |
    |---[Eth][Tag:10][Tag:30][Payload]-->|                     |
                                         | Strip tag 10        |
                                         | (VLAN nativa)       |
                                         |---[Eth][Tag:30][P]->|
                                                               |
                                                   Forward to VLAN 30
                                                   (Finance ha saltato DMZ!)
```

> ⚠️ **Limitazione:** l'attacco è **unidirezionale** — la risposta non può tornare all'attaccante tramite lo stesso meccanismo.

**Condizione necessaria:** la VLAN nativa dell'attaccante deve coincidere con la VLAN nativa del trunk.

**Contromisura:**
```
! Usare una VLAN nativa dedicata e inutilizzata (es. 999)
Switch(config-if)# switchport trunk native vlan 999

! Taggare esplicitamente anche la VLAN nativa (disabilita il "native untagged" behavior)
Switch(config)# vlan dot1q tag native

! Non assegnare MAI porte access alla VLAN nativa del trunk
```

### 3. MAC Flooding — CAM Table Overflow

La **CAM table** (Content Addressable Memory) di uno switch ha dimensioni finite. Un attaccante inonda lo switch con frame con MAC sorgente casuali, riempiendo la tabella. Quando la tabella è piena, lo switch inizia a fare **flooding** di tutti i frame (come un hub) → l'attaccante può sniffare il traffico di tutti.

```
Attaccante                    Switch (CAM table piena)
    |                               |
    |---[Frame MAC:AA:..random]---->| CAM full!
    |---[Frame MAC:BB:..random]---->| Switch ora fa flooding
    |---[Frame MAC:CC:..random]---->|
    |                               |──[Frame di tutti]──> Attaccante
```

**Tool:** `macof` (da dsniff), `scapy`

**Contromisura: Port Security**
```
Switch(config-if)# switchport port-security               ! Abilitare port security
Switch(config-if)# switchport port-security maximum 3     ! Max 3 MAC per porta
Switch(config-if)# switchport port-security violation restrict  ! Log, non shutdown
! oppure: violation shutdown (disabilita porta, più sicuro)
! oppure: violation protect (scarta frame silenziosamente)
Switch(config-if)# switchport port-security mac-address sticky  ! Apprende MAC automaticamente
```

### 4. ARP Spoofing

L'attaccante invia ARP reply false per associare il proprio MAC all'IP del gateway, intercettando tutto il traffico (Man-in-the-Middle).

```
Attaccante → [ARP Reply: "192.168.10.1 è MAC:AA:BB:CC:DD:EE:FF"] → Vittima
Vittima ora invia traffico verso gateway all'attaccante
```

**Contromisura: Dynamic ARP Inspection (DAI)**

---

## Funzionalità di Sicurezza Switch

### DHCP Snooping

**DHCP Snooping** distingue porte **trusted** (verso il server DHCP legittimo) da porte **untrusted** (verso i client). Frame DHCP OFFER e ACK da porte untrusted vengono bloccati, prevenendo **DHCP spoofing** (rogue DHCP server).

```
[Server DHCP Legittimo]──[Porta TRUSTED]──[Switch]──[Porta UNTRUSTED]──[Client PC]
                                                   ↑
                                    [Porta UNTRUSTED]
                                    [Rogue DHCP Server] → BLOCCATO da DHCP Snooping
```

Il DHCP Snooping costruisce una **binding table**: associazione IP ↔ MAC ↔ porta ↔ VLAN, usata da DAI e IP Source Guard.

```
! Abilitare globalmente e per VLAN
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10,20,30

! Porta trusted (verso server DHCP o uplink)
Switch(config-if)# ip dhcp snooping trust

! Limite rate DHCP su porte untrusted (anti-DHCP starvation)
Switch(config-if)# ip dhcp snooping limit rate 15   ! 15 pacchetti/sec max

! Verificare
Switch# show ip dhcp snooping binding
Switch# show ip dhcp snooping statistics
```

### Dynamic ARP Inspection (DAI)

DAI usa la binding table di DHCP Snooping per validare i pacchetti ARP: se l'associazione IP-MAC in un ARP reply non corrisponde alla binding table, il frame viene scartato.

```
! Abilitare DAI per VLAN
Switch(config)# ip arp inspection vlan 10,20,30

! Porta trusted (uplink, router — non validare ARP su questi)
Switch(config-if)# ip arp inspection trust

! Rate limit ARP su porte untrusted (anti-ARP flood)
Switch(config-if)# ip arp inspection limit rate 100   ! 100 ARP/sec max

! Validazione opzionale aggiuntiva
Switch(config)# ip arp inspection validate src-mac dst-mac ip

! Verificare
Switch# show ip arp inspection vlan 10
Switch# show ip arp inspection statistics vlan 10
```

### IP Source Guard

Previene lo **IP spoofing**: blocca frame con IP sorgente non corrispondente alla binding table DHCP Snooping. Solo i frame con IP+MAC assegnati tramite DHCP (o staticamente) vengono permessi.

```
Switch(config-if)# ip verify source             ! Filtra per IP (+ MAC se specificato)
Switch(config-if)# ip verify source port-security  ! Filtra per IP e MAC

! Voce statica per host con IP statico (non DHCP)
Switch(config)# ip source binding 00:11:22:33:44:55 vlan 10 192.168.10.50 interface GigabitEthernet0/5

! Verificare
Switch# show ip verify source
```

### BPDU Guard e Root Guard

**Spanning Tree Protocol (STP)** elegge il Root Bridge in base alla priorità e al MAC. Un attaccante può inviare BPDU con priorità bassa per diventare Root Bridge e intercettare il traffico.

```
! BPDU Guard: spegne la porta se riceve BPDU (solo su porte access/endpoint)
Switch(config-if)# spanning-tree bpduguard enable

! Globale: abilitare BPDU Guard su tutte le porte PortFast
Switch(config)# spanning-tree portfast bpduguard default

! Root Guard: impedisce che una porta diventi uplink verso un nuovo Root Bridge
! (applicare sulle porte verso switch "inferiori" che non devono mai diventare root path)
Switch(config-if)# spanning-tree guard root

! Verificare
Switch# show spanning-tree inconsistentports
Switch# show spanning-tree detail | include BPDU
```

---

## Security Baseline per Switch Layer 2

### Checklist di Hardening

```
GESTIONE:
  ☐ Password enable con algoritmo type 9 (scrypt): enable algorithm-type scrypt secret
  ☐ SSH v2 abilitato, Telnet disabilitato
  ☐ Banner di avviso legale configurato
  ☐ Timeout sessione: exec-timeout 5 0
  ☐ VTY accessibile solo dalla VLAN di management (ACL)
  ☐ SNMP v3 con autenticazione e cifratura (no v1/v2c in produzione)

PORTE:
  ☐ Tutte le porte inutilizzate: shutdown + VLAN 999 (blackhole)
  ☐ DTP disabilitato (switchport nonegotiate) su tutte le porte
  ☐ Port Security abilitato su porte access
  ☐ BPDU Guard abilitato su tutte le porte access/PortFast
  ☐ Storm Control configurato (broadcast/multicast/unicast)

VLAN:
  ☐ VLAN nativa = 999 (inutilizzata, senza IP)
  ☐ vlan dot1q tag native abilitato
  ☐ Trunk con allowed VLAN esplicito (no "all")
  ☐ VLAN 1 non usata per traffico dati

SICUREZZA L2:
  ☐ DHCP Snooping abilitato per tutte le VLAN dati
  ☐ Dynamic ARP Inspection abilitato
  ☐ IP Source Guard abilitato su porte untrusted
  ☐ VTP modalità transparent o off

LOGGING:
  ☐ Syslog verso server centralizzato
  ☐ NTP sincronizzato (timestamp corretti nei log)
  ☐ Logging buffer size adeguato
```

### Configurazione Hardening Completo (Cisco)

```
! Sicurezza accesso gestione
Switch(config)# enable algorithm-type scrypt secret MyStr0ngSecret!
Switch(config)# service password-encryption
Switch(config)# no enable password

! Banner
Switch(config)# banner motd ^
  ACCESSO AUTORIZZATO ESCLUSIVAMENTE AL PERSONALE AZIENDALE.
  OGNI ACCESSO VIENE REGISTRATO E MONITORATO.
^

! SSH v2
Switch(config)# ip domain-name azienda.local
Switch(config)# crypto key generate rsa modulus 4096
Switch(config)# ip ssh version 2
Switch(config)# ip ssh time-out 60
Switch(config)# ip ssh authentication-retries 3

! VTY: solo SSH, solo da rete di management
Switch(config)# ip access-list standard MGMT_ACCESS
Switch(config-std-nacl)# permit 10.99.0.0 0.0.0.255
Switch(config-std-nacl)# deny any log

Switch(config)# line vty 0 15
Switch(config-line)# transport input ssh
Switch(config-line)# access-class MGMT_ACCESS in
Switch(config-line)# exec-timeout 5 0
Switch(config-line)# logging synchronous

! Disabilitare servizi non necessari
Switch(config)# no ip http server
Switch(config)# no ip http secure-server
Switch(config)# no service pad
Switch(config)# no cdp run         ! Valutare: CDP utile per troubleshooting
Switch(config)# no lldp run        ! Valutare: LLDP utile per telefoni IP

! NTP e logging
Switch(config)# ntp server 10.99.0.1
Switch(config)# clock timezone CET 1
Switch(config)# logging host 10.99.0.20
Switch(config)# logging trap informational
Switch(config)# service timestamps log datetime msec localtime
```

---

## Domande di Verifica

1. **Descrivi l'attacco VLAN hopping con double tagging. Quali condizioni devono essere presenti affinché l'attacco funzioni e come si previene?**

2. **Cos'è il MAC flooding e come porta a una situazione di sniffing passivo? Qual è la contromisura principale e come si configura su Cisco?**

3. **Spiega il ruolo del DHCP Snooping binding table. Quali altre funzionalità di sicurezza dipendono da essa e perché?**

4. **Cos'è il Dynamic ARP Inspection (DAI)? Perché le porte trunk/uplink devono essere configurate come trusted?**

5. **Descrivi un attacco STP (Spanning Tree Protocol) in cui un attaccante diventa Root Bridge. Come BPDU Guard e Root Guard prevengono questo scenario?**

6. **Elenca 5 best practice di hardening per uno switch Layer 2 aziendale, spiegando la motivazione di sicurezza per ciascuna.**

---

## Riferimenti

### Documentazione Cisco
- [DHCP Snooping Configuration](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/sec/b_176_sec_9300_cg/configuring_dhcp_features.html)
- [Dynamic ARP Inspection](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/sec/b_176_sec_9300_cg/configuring_dynamic_arp_inspection.html)
- [Layer 2 Security Best Practices](https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/13013-10.html)

### Paper e Ricerca
- "VLAN Security White Paper" — Cisco Systems
- "Yersinia: A Framework for Layer 2 Attacks" — Alfredo Ortega, Hernán Ochoa

---

**Sezione Precedente**: [50.3 - VTP e Inter-VLAN Routing](./03_vtp_e_intervlan_routing.md)  
**Prossima Sezione**: [50.5 - DMZ Design Avanzato](./05_dmz_design_avanzato.md)
