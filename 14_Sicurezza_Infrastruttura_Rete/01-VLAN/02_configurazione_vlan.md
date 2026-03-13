# Capitolo 50.2 - Configurazione delle VLAN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 50 — Network Segmentation e VLAN Security**

---

## Introduzione

Questa guida approfondisce la configurazione pratica delle VLAN in scenari reali: dalla progettazione dello schema di indirizzamento, alla configurazione di switch Layer 2 e Layer 3, fino al routing inter-VLAN e alla gestione centralizzata. Viene trattata sia la configurazione Cisco IOS che quella su switch Linux/Open vSwitch.

### Obiettivi di Apprendimento
- Progettare uno schema VLAN coerente e scalabile
- Configurare VLAN su switch Cisco Layer 2 e Layer 3
- Implementare il routing inter-VLAN (router-on-a-stick e SVI)
- Configurare VLAN su Linux con Open vSwitch
- Applicare best practice di naming e documentazione

---

## Progettazione dello Schema VLAN

### Criteri di Segmentazione

Prima di configurare, definire la segmentazione in base a:

| Criterio | Esempio |
|----------|---------|
| **Funzione/Reparto** | Finance, HR, IT, Marketing |
| **Tipo di dispositivo** | Server, Client, Stampanti, IoT, IP Phone |
| **Livello di sicurezza** | DMZ, Trusted, Restricted |
| **Compliance** | PCI (carte di pagamento), HIPAA (dati sanitari) |
| **Rete ospiti** | WiFi guest isolata |

### Schema VLAN Raccomandato

```
ID VLAN  | Nome           | Subnet              | Scopo
---------|----------------|---------------------|----------------------------------
10       | CORP_Finance   | 192.168.10.0/24     | Reparto Finance
20       | CORP_HR        | 192.168.20.0/24     | Risorse Umane
30       | CORP_IT        | 192.168.30.0/24     | IT e sviluppatori
40       | CORP_Marketing | 192.168.40.0/24     | Marketing
100      | SRV_App        | 10.10.100.0/24      | Server applicativi
110      | SRV_DB         | 10.10.110.0/24      | Database (accesso ristretto)
120      | SRV_DMZ        | 172.16.0.0/24       | DMZ (server pubblici)
200      | WIFI_Corp      | 192.168.200.0/23    | WiFi aziendale autenticato
210      | WIFI_Guest     | 172.31.0.0/24       | WiFi ospiti (internet only)
300      | VOIP           | 10.30.0.0/24        | Telefonia IP
400      | IoT            | 10.40.0.0/24        | Dispositivi IoT (accesso limitato)
99       | MGMT           | 10.99.0.0/24        | Management switch/AP/stampanti
999      | NATIVE_UNUSED  | —                   | VLAN nativa (non assegnare IP)
```

---

## Configurazione Switch Cisco Layer 2 (Access Layer)

### Setup Iniziale

```
! Configurazione base sicurezza switch
Switch# configure terminal
Switch(config)# hostname SW-L2-PIANO1
Switch(config)# no ip domain-lookup
Switch(config)# enable secret StrongPassword!2024

! Disabilitare servizi non necessari
Switch(config)# no ip http server
Switch(config)# no ip http secure-server
Switch(config)# no cdp run          ! Opzionale: disabilitare CDP verso l'esterno

! Configurare VLAN di management con IP
Switch(config)# interface vlan 99
Switch(config-if)# description Management
Switch(config-if)# ip address 10.99.0.10 255.255.255.0
Switch(config-if)# no shutdown

Switch(config)# ip default-gateway 10.99.0.1
```

### Creazione VLAN in Bulk

```
Switch(config)# vlan 10
Switch(config-vlan)# name CORP_Finance
Switch(config)# vlan 20
Switch(config-vlan)# name CORP_HR
Switch(config)# vlan 30
Switch(config-vlan)# name CORP_IT
Switch(config)# vlan 99
Switch(config-vlan)# name MGMT
Switch(config)# vlan 999
Switch(config-vlan)# name NATIVE_UNUSED
```

### Template Access Port (macro)

```
! Definire macro per porte utente standard
Switch(config)# macro name ACCESS_PORT_USER
Enter macro commands one per line. End with the character '@'.
switchport mode access
spanning-tree portfast
spanning-tree bpduguard enable
storm-control broadcast level 20
storm-control action shutdown
ip dhcp snooping limit rate 15
no shutdown
@

! Applicare la macro a una porta
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# description Finance_PC_Scrivania1
Switch(config-if)# switchport access vlan 10
Switch(config-if)# macro apply ACCESS_PORT_USER
```

### Configurazione Trunk verso Core

```
Switch(config)# interface GigabitEthernet0/48
Switch(config-if)# description TRUNK_to_CORE_SW
Switch(config-if)# switchport trunk encapsulation dot1q
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport nonegotiate          ! Disabilita DTP (sicurezza)
Switch(config-if)# switchport trunk native vlan 999
Switch(config-if)# switchport trunk allowed vlan 10,20,30,99
Switch(config-if)# no shutdown
```

### Disabilitare Porte Non Utilizzate

```
! Disabilitare e mettere in una VLAN "blackhole" le porte inutilizzate
Switch(config)# interface range GigabitEthernet0/10 - 24
Switch(config-if-range)# description UNUSED_PORT
Switch(config-if-range)# switchport mode access
Switch(config-if-range)# switchport access vlan 999
Switch(config-if-range)# shutdown
```

---

## Routing Inter-VLAN

I dispositivi in VLAN diverse non possono comunicare direttamente — serve un Layer 3 device (router o switch L3).

### Metodo 1: Router-on-a-Stick

Un singolo link fisico tra switch e router, diviso in subinterface logiche (una per VLAN).

```
[Switch L2] ════[Trunk 802.1Q]════ [Router]
                                      ├── eth0.10 (gateway VLAN 10: 192.168.10.1)
                                      ├── eth0.20 (gateway VLAN 20: 192.168.20.1)
                                      └── eth0.30 (gateway VLAN 30: 192.168.30.1)
```

**Configurazione Router Cisco (router-on-a-stick):**

```
Router(config)# interface GigabitEthernet0/0
Router(config-if)# no shutdown

Router(config)# interface GigabitEthernet0/0.10
Router(config-subif)# description Gateway_VLAN10_Finance
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.20
Router(config-subif)# description Gateway_VLAN20_HR
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.99
Router(config-subif)# description Gateway_VLAN99_MGMT
Router(config-subif)# encapsulation dot1Q 99 native  ! VLAN nativa
Router(config-subif)# ip address 10.99.0.1 255.255.255.0
```

**Limiti:** il link fisico è un collo di bottiglia per tutto il traffico inter-VLAN.

### Metodo 2: Switch Layer 3 con SVI (Switched Virtual Interface)

Su uno switch L3 (es. Cisco Catalyst 3650, 9300), ogni VLAN ha una SVI che funge da gateway:

```
[Switch L3 Core]
  ├── SVI VLAN 10: ip 192.168.10.1/24
  ├── SVI VLAN 20: ip 192.168.20.1/24
  └── SVI VLAN 30: ip 192.168.30.1/24
  (routing hardware, massime performance)
```

```
Switch-L3(config)# ip routing                  ! Abilitare routing IP

! SVI per VLAN 10
Switch-L3(config)# interface vlan 10
Switch-L3(config-if)# description Gateway_Finance
Switch-L3(config-if)# ip address 192.168.10.1 255.255.255.0
Switch-L3(config-if)# ip helper-address 10.99.0.50   ! DHCP relay
Switch-L3(config-if)# no shutdown

! SVI per VLAN 20
Switch-L3(config)# interface vlan 20
Switch-L3(config-if)# description Gateway_HR
Switch-L3(config-if)# ip address 192.168.20.1 255.255.255.0
Switch-L3(config-if)# ip helper-address 10.99.0.50
Switch-L3(config-if)# no shutdown

! Default route verso firewall/router upstream
Switch-L3(config)# ip route 0.0.0.0 0.0.0.0 10.99.0.254
```

---

## Configurazione con Open vSwitch (Linux)

Open vSwitch è il software di switching virtuale standard per ambienti KVM, OpenStack, e datacenter Linux.

### Installazione

```bash
sudo apt install openvswitch-switch -y
sudo systemctl enable --now openvswitch-switch
```

### Creazione Bridge e VLAN

```bash
# Creare bridge OVS
sudo ovs-vsctl add-br ovs-bridge

# Aggiungere porta fisica (uplink verso switch fisico)
sudo ovs-vsctl add-port ovs-bridge eth0 trunk=10,20,30,99

# Aggiungere porte per VM con VLAN specifiche (access)
sudo ovs-vsctl add-port ovs-bridge vnet0 tag=10     # VM nella VLAN 10
sudo ovs-vsctl add-port ovs-bridge vnet1 tag=20     # VM nella VLAN 20

# Creare interfaccia interna per il gateway VLAN 10 sull'host
sudo ovs-vsctl add-port ovs-bridge vlan10-gw tag=10 \
    -- set Interface vlan10-gw type=internal
sudo ip addr add 192.168.10.1/24 dev vlan10-gw
sudo ip link set vlan10-gw up

# Verificare configurazione
sudo ovs-vsctl show
sudo ovs-ofctl show ovs-bridge
```

### Isolamento VLAN con regole OpenFlow

```bash
# Bloccare il traffico inter-VLAN direttamente sullo switch OVS
# (prima del routing, per isolamento assoluto)
sudo ovs-ofctl add-flow ovs-bridge \
    "priority=100,in_port=vnet0,dl_vlan=10,actions=output:eth0"

# Bloccare traffico tra VLAN 10 e VLAN 20
sudo ovs-ofctl add-flow ovs-bridge \
    "priority=200,dl_vlan=10,dl_vlan_pcp=0,actions=drop" 
```

---

## Verifica e Troubleshooting

### Comandi Cisco

```
! Visualizzare tutte le VLAN
Switch# show vlan brief

! Dettaglio VLAN specifica
Switch# show vlan id 10

! Verificare trunk
Switch# show interfaces trunk
Switch# show interfaces GigabitEthernet0/48 trunk

! Verificare SVI (L3)
Switch# show ip interface brief | include Vlan

! Tabella MAC per VLAN
Switch# show mac address-table vlan 10

! Contatori errori porta
Switch# show interfaces GigabitEthernet0/1 counters errors
```

### Comandi Linux

```bash
# Visualizzare VLAN configurate
cat /proc/net/vlan/config

# Statistiche interfaccia VLAN
ip -s link show eth0.10

# Catturare traffico taggato
sudo tcpdump -i eth0 -e vlan

# OVS: stato porte e VLAN
sudo ovs-vsctl show
sudo ovs-vsctl list port
```

---

## Domande di Verifica

1. **Descrivi il routing inter-VLAN con il metodo "router-on-a-stick". Quali sono i suoi limiti rispetto all'uso di uno switch Layer 3 con SVI?**

2. **Perché è importante usare `switchport nonegotiate` su una porta trunk? Quale attacco previene?**

3. **Come si configura il DHCP relay (ip helper-address) su una SVI Cisco? Perché è necessario in un ambiente con VLAN multiple?**

4. **Elenca almeno 5 criteri per progettare uno schema di segmentazione VLAN aziendale. Fornisci un esempio di VLAN per ciascun criterio.**

5. **Perché le porte inutilizzate devono essere disabilitate e assegnate a una VLAN "blackhole"? Quale tipo di attacco previene questa pratica?**

---

## Riferimenti

### Documentazione
- [Cisco VLAN Configuration Guide IOS-XE](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/vlan/b_176_vlan_9300_cg/configuring_vlans.html)
- [Open vSwitch Documentation](https://docs.openvswitch.org/en/latest/)
- [Open vSwitch VLAN Tutorial](https://docs.openvswitch.org/en/latest/tutorials/vlan-configuration-cookbook/)

---

**Sezione Precedente**: [50.1 - VLAN e 802.1Q](./01_vlan_e_8021q.md)  
**Prossima Sezione**: [50.3 - VTP e Inter-VLAN Routing](./03_vtp_e_intervlan_routing.md)
