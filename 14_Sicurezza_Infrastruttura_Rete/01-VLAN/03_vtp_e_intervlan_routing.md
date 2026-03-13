# Capitolo 50.3 - VTP e Inter-VLAN Routing

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 50 — Network Segmentation e VLAN Security**

---

## Introduzione

**VTP (VLAN Trunking Protocol)** è un protocollo proprietario Cisco che sincronizza automaticamente il database VLAN tra switch su link trunk. Nato per semplificare la gestione in reti con molti switch, è anche noto per essere causa di **disastri di rete** se mal configurato. Questa guida analizza VTP in dettaglio, i suoi rischi, e approfondisce le tecniche di routing inter-VLAN in scenari complessi.

### Obiettivi di Apprendimento
- Comprendere il funzionamento e le modalità VTP
- Identificare i rischi di sicurezza di VTP e come mitigarli
- Implementare routing inter-VLAN avanzato
- Configurare HSRP/VRRP per ridondanza gateway
- Valutare alternative sicure a VTP

---

## VTP — VLAN Trunking Protocol

### Funzionamento

VTP distribuisce le informazioni VLAN (database) tra switch Cisco attraverso i link trunk. Quando si crea/modifica/elimina una VLAN sul server VTP, la modifica si propaga automaticamente a tutti gli switch client nel dominio.

```
Dominio VTP: "AZIENDA"

[Core Switch — SERVER VTP]
   VLAN DB: 10, 20, 30, 99
        |
        |══ trunk ══[Distribution SW — CLIENT VTP]
        |                   VLAN DB: sincronizzato automaticamente
        |══ trunk ══[Access SW 1 — CLIENT VTP]
                            VLAN DB: sincronizzato automaticamente
```

### Modalità VTP

| Modalità | Può creare/modificare VLAN | Sincronizza da server | Propaga ai client |
|----------|---------------------------|----------------------|-------------------|
| **Server** | ✅ Sì | ✅ Sì | ✅ Sì |
| **Client** | ❌ No | ✅ Sì | ✅ Sì |
| **Transparent** | ✅ (solo locale) | ❌ No (ignora) | ✅ Passa messaggi |
| **Off** (VTPv3) | ✅ (solo locale) | ❌ No | ❌ No |

### Configurazione VTP

```
! Server VTP (switch principale)
Switch-Core(config)# vtp mode server
Switch-Core(config)# vtp domain AZIENDA
Switch-Core(config)# vtp password VTPsecret2024!
Switch-Core(config)# vtp version 3          ! VTPv3 più sicuro

! Client VTP (switch di accesso)
Switch-Access(config)# vtp mode client
Switch-Access(config)# vtp domain AZIENDA
Switch-Access(config)# vtp password VTPsecret2024!

! Transparent (non partecipa ma passa messaggi)
Switch-DMZ(config)# vtp mode transparent

! Verificare
Switch# show vtp status
Switch# show vtp counters
```

---

## Rischi di Sicurezza VTP

### Il "Disastro VTP"

VTP usa un **Revision Number** per determinare quale database è più aggiornato. Uno switch con revision number più alto **sovrascrive il database** di tutti gli altri nel dominio.

```
Scenario catastrofico:
1. Tecnico configura switch di test con VTP dominio "AZIENDA"
   e crea/elimina molte VLAN → revision number alto (es. 150)

2. Tecnico collega lo switch di test alla rete di produzione

3. Switch di test ha revision 150, switch core ha revision 80

4. VTP propaga il database del test (con VLAN diverse/mancanti)
   a TUTTI gli switch della rete → porte assegnate a VLAN
   inesistenti → INTERRUZIONE DI RETE TOTALE
```

> ⚠️ **Questo scenario è reale e documentato.** Ha causato outage di ore in reti aziendali.

### Attacco VTP Injection

Un attaccante connesso a un trunk può inviare messaggi VTP falsificati con revision number elevato per eliminare tutte le VLAN dalla rete:

```
[Attaccante con laptop] ──── porta trunk ──── [Switch]
   Invia VTP advertisement con revision=9999
   Database VLAN: vuoto
   → Tutti gli switch cancellano le loro VLAN
   → Blackout di rete
```

### Mitigazioni

```
1. Usare VTP modalità TRANSPARENT o OFF su tutti gli switch
   (rinunciare alla comodità della sincronizzazione automatica)

2. Usare VTPv3 con password e primary server designato

3. Prima di connettere un nuovo switch: azzerare il revision number
   Switch(config)# vtp mode transparent
   Switch(config)# vtp mode client

4. Non usare DTP (Dynamic Trunking Protocol):
   Switch(config-if)# switchport nonegotiate
   (impedisce negoziazione automatica trunk)

5. Segmentare i domini VTP per zona di sicurezza

6. Monitorare i log per advertisement VTP inaspettati
```

### Raccomandazione

In ambienti moderni con pochi switch o alta sicurezza richiesta, **non usare VTP**. Gestire le VLAN manualmente o tramite strumenti di automazione (Ansible, Cisco DNA Center) è più sicuro e controllabile.

---

## Routing Inter-VLAN

### Perché è Necessario

Per definizione, dispositivi in VLAN diverse appartengono a subnet IP diverse e **non possono comunicare direttamente** a livello Layer 2 — lo switch si limita a isolarli. Per permettere la comunicazione tra VLAN serve un dispositivo di **Layer 3** (un router o uno switch L3) che instrada i pacchetti tra le subnet.

```
SENZA routing inter-VLAN:

PC-Finance (192.168.10.5)  ─────────────────────────────────────  NO COMUNICAZIONE
                                    [Switch L2]
PC-HR      (192.168.20.5)  ─────────────────────────────────────  NO COMUNICAZIONE

Il PC Finance non può pingare il PC HR: sono su VLAN/subnet diverse,
lo switch L2 non esegue routing.

CON routing inter-VLAN:

PC-Finance (192.168.10.5)
    │  GW: 192.168.10.1
    │
[Switch] ──── [Router / Switch L3]  ←── conosce entrambe le subnet
    │              192.168.10.1 (VLAN 10)
    │              192.168.20.1 (VLAN 20)
    │
PC-HR (192.168.20.5)
    GW: 192.168.20.1

Flusso pacchetto Finance → HR:
1. PC-Finance invia a GW 192.168.10.1 (non conosce il percorso diretto)
2. Router riceve su interfaccia VLAN 10, cerca rotta per 192.168.20.0/24
3. Router instrada verso interfaccia VLAN 20, invia a PC-HR
```

### Tre Metodi a Confronto

| Metodo | Dispositivo | Performance | Complessità | Uso tipico |
|--------|------------|-------------|-------------|------------|
| **Router-on-a-Stick** | Router con subinterface | Bassa (un link fisico) | Bassa | Reti piccole, lab |
| **Switch L3 con SVI** | Switch Layer 3 | Alta (hardware ASIC) | Media | Reti aziendali |
| **Routed Port** | Switch L3 | Alta | Bassa | Uplink punto-punto |

### Metodo 1: Router-on-a-Stick

Un singolo link trunk tra switch L2 e router. Il router crea **subinterface logiche** (una per ogni VLAN), ciascuna con il proprio indirizzo IP che funge da gateway.

```
[Switch L2]
  VLAN 10 ─── porta trunk (802.1Q) ─── [Router eth0]
  VLAN 20                                  ├── eth0.10  192.168.10.1/24  (GW VLAN 10)
  VLAN 30                                  ├── eth0.20  192.168.20.1/24  (GW VLAN 20)
                                           └── eth0.30  192.168.30.1/24  (GW VLAN 30)
```

**Configurazione Cisco:**

```
Router(config)# interface GigabitEthernet0/0
Router(config-if)# no shutdown

Router(config)# interface GigabitEthernet0/0.10
Router(config-subif)# encapsulation dot1Q 10          ! Tag VLAN 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.30
Router(config-subif)# encapsulation dot1Q 30
Router(config-subif)# ip address 192.168.30.1 255.255.255.0
```

**Configurazione Linux (iproute2):**

```bash
# Creare subinterface VLAN
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip addr add 192.168.10.1/24 dev eth0.10
sudo ip link set eth0.10 up

sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip addr add 192.168.20.1/24 dev eth0.20
sudo ip link set eth0.20 up

# Abilitare ip forwarding
sudo sysctl -w net.ipv4.ip_forward=1
```

**Limite:** tutto il traffico inter-VLAN percorre fisicamente lo stesso cavo (il trunk), creando un collo di bottiglia.

### Metodo 2: Switch Layer 3 con SVI

Lo switch L3 esegue il routing **internamente in hardware** tramite **SVI (Switched Virtual Interface)**: interfacce logiche associate a ciascuna VLAN, che fungono da gateway.

```
[Switch L3]
  ├── SVI Vlan 10: 192.168.10.1/24  ← gateway per tutti gli host VLAN 10
  ├── SVI Vlan 20: 192.168.20.1/24  ← gateway per tutti gli host VLAN 20
  └── SVI Vlan 30: 192.168.30.1/24  ← gateway per tutti gli host VLAN 30

Il routing avviene internamente al chip ASIC → latenza microseconds,
nessun collo di bottiglia fisico.
```

**Configurazione Cisco:**

```
Switch-L3(config)# ip routing                      ! Abilitare il routing

Switch-L3(config)# interface vlan 10
Switch-L3(config-if)# ip address 192.168.10.1 255.255.255.0
Switch-L3(config-if)# no shutdown

Switch-L3(config)# interface vlan 20
Switch-L3(config-if)# ip address 192.168.20.1 255.255.255.0
Switch-L3(config-if)# no shutdown

Switch-L3(config)# interface vlan 30
Switch-L3(config-if)# ip address 192.168.30.1 255.255.255.0
Switch-L3(config-if)# no shutdown

! Rotta di default verso il firewall/router upstream
Switch-L3(config)# ip route 0.0.0.0 0.0.0.0 10.99.0.254
```

**Verifica:**

```
Switch-L3# show ip route
Switch-L3# show ip interface brief | include Vlan
Switch-L3# ping 192.168.20.5 source vlan 10      ! Test routing inter-VLAN
```

### Routing Inter-VLAN Avanzato

### Layer 3 Switch — Architettura Completa

```
                    [Firewall / Router]
                           |
                    [Core Switch L3]
                    ip routing abilitato
                    ├── SVI VLAN 10: 192.168.10.1
                    ├── SVI VLAN 20: 192.168.20.1
                    ├── SVI VLAN 100: 10.10.100.1
                    └── Routed port verso firewall
                           |
              ┌────────────┴────────────┐
     [Distribution SW]         [Distribution SW]
          |     |                    |     |
     [Access]  [Access]         [Access]  [Access]
```

### Policy di Routing Inter-VLAN con ACL

Non tutto il traffico inter-VLAN deve essere permesso. Usare ACL sulle SVI per controllare i flussi:

```
! Esempio: Finance (VLAN 10) può accedere ai Server (VLAN 100)
!          ma non a HR (VLAN 20) e viceversa

! ACL per VLAN 10 (Finance)
Switch-L3(config)# ip access-list extended VLAN10_POLICY
Switch-L3(config-ext-nacl)# permit ip 192.168.10.0 0.0.0.255 10.10.100.0 0.0.0.255  ! Verso server
Switch-L3(config-ext-nacl)# permit ip 192.168.10.0 0.0.0.255 host 10.99.0.50        ! Verso DHCP
Switch-L3(config-ext-nacl)# permit ip 192.168.10.0 0.0.0.255 host 10.99.0.10        ! Verso DNS
Switch-L3(config-ext-nacl)# deny   ip 192.168.10.0 0.0.0.255 192.168.0.0 0.0.255.255 ! NO altri reparti
Switch-L3(config-ext-nacl)# permit ip any any                                         ! Tutto il resto OK

! Applicare alla SVI VLAN 10 (in ingresso = traffico proveniente da VLAN 10)
Switch-L3(config)# interface vlan 10
Switch-L3(config-if)# ip access-group VLAN10_POLICY in
```

### Private VLAN (PVLAN)

Le **Private VLAN** permettono un ulteriore isolamento all'interno della stessa VLAN: dispositivi nella stessa subnet non possono comunicare direttamente tra loro.

```
PVLAN 100 (Primary)
  ├── Community VLAN 101: i server web possono parlarsi tra loro
  ├── Community VLAN 102: i server DB possono parlarsi tra loro
  └── Isolated VLAN 103: ogni server è completamente isolato dagli altri
```

**Uso tipico:** hosting provider, DMZ dove i server non devono comunicare tra loro (riduce blast radius in caso di compromissione).

```
! Configurazione PVLAN su Cisco
Switch(config)# vlan 101
Switch(config-vlan)# private-vlan community

Switch(config)# vlan 103
Switch(config-vlan)# private-vlan isolated

Switch(config)# vlan 100
Switch(config-vlan)# private-vlan primary
Switch(config-vlan)# private-vlan association 101,103

! Porta promiscua (gateway/router vede tutte le secondary VLAN)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport mode private-vlan promiscuous
Switch(config-if)# switchport private-vlan mapping 100 101,103

! Porta isolated (nessuna comunicazione con altri host)
Switch(config)# interface GigabitEthernet0/5
Switch(config-if)# switchport mode private-vlan host
Switch(config-if)# switchport private-vlan host-association 100 103
```

---

## HSRP/VRRP — Ridondanza del Gateway

In ambienti con due switch L3 core (ridondanza), ogni VLAN ha bisogno di un **gateway virtuale** che rimanga raggiungibile anche se uno switch si guasta.

### HSRP (Hot Standby Router Protocol) — Cisco proprietario

```
[Switch L3-A]  ←→  [Switch L3-B]
SVI VLAN 10:          SVI VLAN 10:
192.168.10.2          192.168.10.3
        ↘                 ↙
   Gateway Virtuale: 192.168.10.1 (HSRP VIP)
   → PC Finance usa 192.168.10.1 come default GW
   → Se L3-A cade, L3-B assume 192.168.10.1 in ~3 secondi
```

```
! Switch L3-A (Active per VLAN 10)
Switch-A(config)# interface vlan 10
Switch-A(config-if)# ip address 192.168.10.2 255.255.255.0
Switch-A(config-if)# standby version 2
Switch-A(config-if)# standby 10 ip 192.168.10.1      ! VIP
Switch-A(config-if)# standby 10 priority 110          ! Più alto = Active
Switch-A(config-if)# standby 10 preempt               ! Riacquista ruolo Active quando torna su
Switch-A(config-if)# standby 10 authentication md5 key-string HSRPsecret!

! Switch L3-B (Standby per VLAN 10)
Switch-B(config)# interface vlan 10
Switch-B(config-if)# ip address 192.168.10.3 255.255.255.0
Switch-B(config-if)# standby version 2
Switch-B(config-if)# standby 10 ip 192.168.10.1
Switch-B(config-if)# standby 10 priority 100          ! Più basso = Standby
Switch-B(config-if)# standby 10 authentication md5 key-string HSRPsecret!

! Verificare
Switch# show standby brief
Switch# show standby vlan 10
```

### VRRP (Virtual Router Redundancy Protocol) — Standard IETF RFC 5798

VRRP è l'equivalente open standard di HSRP, supportato da tutti i vendor:

```bash
# Linux con keepalived
# /etc/keepalived/keepalived.conf

vrrp_instance VLAN10_GW {
    state MASTER          # BACKUP sul secondo router
    interface eth0.10
    virtual_router_id 10  # Deve essere uguale su entrambi i router
    priority 110          # 100 sul backup
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass VRRPsecret!
    }
    virtual_ipaddress {
        192.168.10.1/24
    }
}
```

---

## Domande di Verifica

1. **Descrivi il meccanismo del "VTP disaster". Perché il revision number è critico e come si azzera prima di connettere un nuovo switch?**

2. **Qual è la differenza tra VTP mode Server, Client, Transparent e Off? In quale modalità è più sicuro configurare switch in ambienti ad alta sicurezza?**

3. **Cos'è una Private VLAN? Descrivi la differenza tra porta promiscua, community e isolated. In quale scenario è utile?**

4. **Spiega il funzionamento di HSRP. Cosa succede al traffico dei client se lo switch Active si guasta? Quanto tempo impiega il failover?**

5. **Configura un'ACL inter-VLAN che permetta alla VLAN Finance (192.168.10.0/24) di accedere solo ai server nella VLAN 100 (10.10.100.0/24), bloccando l'accesso a tutte le altre VLAN.**

---

## Riferimenti

### Standard
- [RFC 5798](https://tools.ietf.org/html/rfc5798) — VRRP
- [RFC 2338](https://tools.ietf.org/html/rfc2338) — VRRP (originale)

### Documentazione Cisco
- [VTP Configuration Guide](https://www.cisco.com/c/en/us/support/docs/lan-switching/vtp/10558-21.html)
- [HSRP Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/configuration/xe-16/fhp-xe-16-book/fhp-hsrp-v2.html)
- [Private VLAN Configuration](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/vlan/b_176_vlan_9300_cg/configuring_private_vlans.html)

---

**Sezione Precedente**: [50.2 - Configurazione delle VLAN](./02_configurazione_vlan.md)  
**Prossima Sezione**: [50.4 - VLAN e Sicurezza](./04_vlan_e_sicurezza.md)
