# pfSense: Firewall e Router Open Source

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**

---

## Introduzione

**pfSense** è una distribuzione firewall/router open source basata su FreeBSD. È uno dei firewall più utilizzati al mondo sia in ambienti enterprise che didattici.

### Caratteristiche Principali

- **Firewall Stateful** con regole granulari
- **Interfaccia Web GUI** intuitiva (WebConfigurator)
- **NAT/PAT** avanzato con port forwarding
- **VPN**: OpenVPN, IPsec, WireGuard
- **Traffic Shaping** (QoS - Quality of Service)
- **IDS/IPS** integrato (Snort/Suricata)
- **High Availability** (CARP - Common Address Redundancy Protocol)
- **Multi-WAN** con load balancing e failover
- **DHCP/DNS Server** integrati
- **Captive Portal** per autenticazione
- **Packages** estendibili (Squid, HAProxy, pfBlockerNG)

### Perché pfSense?

```
┌─────────────────────────────────────────────────────────┐
│ VANTAGGI pfSense                                        │
├─────────────────────────────────────────────────────────┤
│ ✅ Open Source (Apache 2.0)                            │
│ ✅ GUI web user-friendly                                │
│ ✅ Community attiva (forum, documentazione)             │
│ ✅ Hardware requirements bassi (2GB RAM, 8GB disk)      │
│ ✅ Supporto hardware comune (Intel, AMD, ARM)           │
│ ✅ Aggiornamenti frequenti e sicuri                     │
│ ✅ Alternative commerciale: pfSense Plus, Netgate       │
│ ✅ Ideale per didattica (VM, container, bare metal)     │
└─────────────────────────────────────────────────────────┘
```

---

## Requisiti Hardware

### Minimi

| Componente | Specifiche Minime |
|------------|-------------------|
| CPU | 1 core @ 500 MHz (x86-64) |
| RAM | 1 GB |
| Storage | 8 GB |
| Interfacce di rete | Minimo 2 (WAN + LAN) |

### Raccomandati

| Componente | Specifiche Raccomandate |
|------------|-------------------------|
| CPU | 2+ core @ 2 GHz |
| RAM | 4 GB+ |
| Storage | 40 GB SSD |
| Interfacce di rete | 3+ (WAN, LAN, DMZ, OPT) |

### Considerazioni

- **CPU**: più core per IDS/IPS, VPN encryption
- **RAM**: 4GB+ se usi Snort/Suricata, Squid proxy
- **Storage**: SSD per logging ad alte performance
- **NIC**: Intel o Realtek per migliore compatibilità

---

## Installazione

### Download ISO

```bash
# Sito ufficiale
https://www.pfsense.org/download/

# Seleziona:
# - Architecture: AMD64 (64-bit)
# - Installer: DVD Image (ISO)
# - Mirror: più vicino geograficamente
```

### Installazione su VirtualBox

#### 1. Crea VM

```
Nome: pfSense-Firewall
Tipo: BSD
Versione: FreeBSD (64-bit)
RAM: 2048 MB
Disco: 20 GB (VDI, dinamico)
```

#### 2. Configura Network

```
Adapter 1 (WAN):
  Attached to: NAT
  
Adapter 2 (LAN):
  Attached to: Internal Network
  Name: intnet_lan
  
Adapter 3 (DMZ) - opzionale:
  Attached to: Internal Network
  Name: intnet_dmz
```

#### 3. Avvia Installazione

1. Boot da ISO pfSense
2. Accettare Copyright e distribuire
3. Seleziona **Install** → **OK**
4. Keymap: **US** (o italiano)
5. Partitioning: **Auto (ZFS)** → Stripe (single disk)
6. Seleziona disco → **YES**
7. Attendere installazione (5-10 min)
8. **Reboot** (rimuovi ISO)

---

## Configurazione Iniziale

### Console Setup (primo avvio)

```
pfSense Console Setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Should VLANs be set up now? [y|n]: n

Enter WAN interface name: em0
Enter LAN interface name: em1
Enter Optional 1 interface name (DMZ): em2

Proceed? [y|n]: y

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Assegnazione completata:

WAN  -> em0 -> 10.0.2.15/24 (DHCP from VirtualBox NAT)
LAN  -> em1 -> 192.168.1.1/24
DMZ  -> em2 -> unassigned
```

### Configurazione IP LAN

```
Menu pfSense:

2) Set interface(s) IP address

Scegli LAN (2):

Configure IPv4 address LAN interface via DHCP? [n]: n

Enter new LAN IPv4 address: 192.168.1.1
Enter subnet bit count: 24

Enter new LAN IPv4 upstream gateway: [nessuno]

Configure IPv6? [n]: n

Enable DHCP server on LAN? [y]: y
Start address: 192.168.1.100
End address: 192.168.1.200

Revert to HTTP as webConfigurator protocol? [n]: n
```

---

## WebConfigurator (GUI)

### Primo Accesso

1. **Da PC nella LAN** (o collegato a pfSense LAN)
2. Browser: `https://192.168.1.1`
3. Accetta certificato self-signed
4. Login:
   - Username: `admin`
   - Password: `pfsense`

### Setup Wizard

#### Step 1: Netgate Global Support
- Click **Next** (skip)

#### Step 2: General Information
```
Hostname: pfSense
Domain: localdomain (o tuo dominio)
Primary DNS: 8.8.8.8
Secondary DNS: 8.8.4.4
☐ Override DNS (se vuoi usare DNS del WAN)
```

#### Step 3: Time Server
```
Timezone: Europe/Rome
Time Server: 0.pfsense.pool.ntp.org
```

#### Step 4: WAN Interface
```
Type: DHCP (o Static per IP fisso)
MAC Address: [vuoto]
MTU: [vuoto]
MSS: [vuoto]

☐ Block RFC1918 Private Networks (disabilita per LAN dietro NAT)
☐ Block bogon networks (abilita per WAN Internet)
```

#### Step 5: LAN Interface
```
LAN IP: 192.168.1.1
Subnet Mask: 24 (255.255.255.0)
```

#### Step 6: Admin Password
```
New Password: [password sicura]
Confirm: [ripeti password]

⚠️ CAMBIA SUBITO! Password default è insicura!
```

#### Step 7: Reload
- Click **Reload** → Attendi applicazione configurazione
- Click **Finish**

---

## Dashboard

### Panoramica Dashboard

```
╔════════════════════════════════════════════════════════╗
║ pfSense Dashboard                                      ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ [System Information]  [Interfaces]  [Firewall Logs]   ║
║                                                        ║
║ Version: 2.7.2                                         ║
║ Platform: FreeBSD 14.0-RELEASE-p6                      ║
║ Uptime: 2 days 3 hours                                 ║
║                                                        ║
║ WAN (em0):  ↑ 1.2 Mbps  ↓ 0.5 Mbps  IP: 10.0.2.15    ║
║ LAN (em1):  ↑ 0.3 Mbps  ↓ 0.8 Mbps  IP: 192.168.1.1   ║
║                                                        ║
║ [CPU Usage: 15%]  [Memory: 25% / 2048 MB]             ║
║ [Disk: 12% / 20 GB]   [Temp: 45°C]                    ║
║                                                        ║
║ States: 245/12000  [||||------] 2%                     ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
```

**Widget utili:**
- **System Information**: versione, uptime, CPU
- **Interfaces**: status, IP, traffico real-time
- **Firewall Logs**: log filtrati in tempo reale
- **Services Status**: DHCP, DNS, OpenVPN
- **Traffic Graphs**: grafici bandwidth per interfaccia

---

## Firewall Rules

### Filosofia pfSense

```
Default Deny:
  ✗ Tutto il traffico è bloccato di default
  ✓ Solo traffico esplicitamente permesso passa

Ordine valutazione regole:
  1. Floating rules (se presenti)
  2. Interface rules (WAN, LAN, DMZ)
  3. Prima regola che matcha vince (top-down)
  4. Default deny implicito
```

### Regole Default

#### LAN → Any (Default Allow)

```
Action: Pass
Interface: LAN
Protocol: Any
Source: LAN net (192.168.1.0/24)
Destination: Any
Description: Default allow LAN to any rule

→ Permette PC LAN accedere a Internet/WAN
```

#### WAN → Any (Default Block)

```
Action: Block
Interface: WAN
Protocol: Any
Source: Any
Destination: Any
Description: Default deny rule (implicito)

→ Blocca tutto il traffico in ingresso da WAN
```

### Creare Regola: Allow HTTP/HTTPS da Internet a Web Server DMZ

**Scenario:**
- Web server in DMZ: `192.168.2.10`
- Permetti Internet → Web Server (porta 80/443)
- Blocca tutto il resto

#### 1. Firewall → Rules → WAN

Click **Add ↑** (in alto)

#### 2. Configurazione Regola

```
Action: Pass
Disabled: ☐
Interface: WAN
Address Family: IPv4
Protocol: TCP

Source:
  Source: Any
  
Destination:
  Destination: WAN address
  Destination Port Range:
    From: HTTP (80)
    To: HTTP (80)

Extra Options:
  Log: ☑ Log packets that are handled by this rule
  
Description: Allow HTTP to Web Server DMZ

Advanced Options:
  Gateway: Default
```

#### 3. Redirect a DMZ (Port Forward)

⚠️ Regola WAN permette traffico a IP WAN, ma serve **NAT/Port Forward** per redirectare a DMZ!

**Firewall → NAT → Port Forward**

```
Interface: WAN
Protocol: TCP
Destination: WAN address
Destination Port: 80
Redirect target IP: 192.168.2.10
Redirect target Port: 80
Description: HTTP to Web Server DMZ
Filter rule association: Add associated filter rule
```

Click **Save** → **Apply Changes**

---

## NAT e Port Forwarding

### Tipi di NAT in pfSense

#### 1. Outbound NAT (Source NAT)

Traduce IP privati LAN → IP pubblico WAN per uscire su Internet.

```
LAN Client: 192.168.1.50 → Request to 8.8.8.8
             ↓
pfSense NAT: 192.168.1.50 → 203.0.113.100 (WAN IP)
             ↓
Internet vede: 203.0.113.100 come sorgente
```

**Modalità:**
- **Automatic Outbound NAT** (default): NAT automatico per LAN
- **Hybrid Outbound NAT**: mix automatico + regole custom
- **Manual Outbound NAT**: controllo completo

#### 2. Port Forward (Destination NAT/DNAT)

Redirection traffico WAN → server interno.

```
Internet: Request to 203.0.113.100:22 (SSH)
          ↓
pfSense Port Forward: 203.0.113.100:22 → 192.168.1.10:22
          ↓
Server interno 192.168.1.10 riceve connessione SSH
```

**Esempio: SSH a Server Interno**

**Firewall → NAT → Port Forward → Add**

```
Interface: WAN
Protocol: TCP
Destination: WAN address
Destination Port: 2222 (porta pubblica custom)
Redirect target IP: 192.168.1.10
Redirect target Port: 22
Description: SSH to Internal Server
```

Ora: `ssh user@<WAN_IP> -p 2222` → arriva al server 192.168.1.10:22

#### 3. 1:1 NAT

NAT statico 1-to-1 tra IP pubblico e IP privato.

```
IP Pubblico: 203.0.113.101
             ↕
IP Privato:  192.168.1.50

Tutte le porte di 203.0.113.101 → 192.168.1.50
```

**Use case:** server che necessita di IP pubblico dedicato.

---

## DMZ Configuration

### Scenario Tipico

```
Internet
   │
   ├─ WAN (em0): 203.0.113.100/24
   │
[pfSense]
   │
   ├─ LAN (em1): 192.168.1.1/24   (Rete uffici)
   │     └─ PC, Server interni
   │
   └─ DMZ (em2): 192.168.2.1/24   (Zona demilitarizzata)
         └─ Web Server, Mail Server (pubblici)
```

### Step 1: Assegna Interfaccia DMZ

**Interfaces → Assignments**

- Available Network Ports: `em2`
- Click **Add** → rinomina in "DMZ"

**Interfaces → DMZ**

```
Enable: ☑ Enable interface
Description: DMZ
IPv4 Configuration Type: Static IPv4
IPv4 Address: 192.168.2.1 / 24
```

Save → Apply Changes

### Step 2: DHCP Server per DMZ (opzionale)

**Services → DHCP Server → DMZ**

```
Enable: ☑ Enable DHCP server on DMZ
Range: 192.168.2.100 - 192.168.2.200
```

### Step 3: Firewall Rules DMZ

**Obiettivo:**
- DMZ → WAN: permesso (per aggiornamenti)
- DMZ → LAN: **BLOCCATO** (isolamento!)
- LAN → DMZ: permesso (admin)
- WAN → DMZ: permesso (solo porte servizi pubblici)

**Firewall → Rules → DMZ**

#### Regola 1: Block DMZ → LAN

```
Action: Block
Protocol: Any
Source: DMZ net
Destination: LAN net
Description: Block DMZ to LAN
```

#### Regola 2: Allow DMZ → WAN

```
Action: Pass
Protocol: Any
Source: DMZ net
Destination: Any
Description: Allow DMZ to Internet
```

**Firewall → Rules → LAN**

#### Regola: Allow LAN → DMZ

```
Action: Pass
Protocol: Any
Source: LAN net
Destination: DMZ net
Description: Allow LAN to DMZ (admin access)
```

---

## VPN: OpenVPN Server

### Scenario: Remote Access VPN

Dipendenti remoti accedono alla LAN tramite OpenVPN.

### Step 1: Certificate Authority (CA)

**System → Cert. Manager → CAs → Add**

```
Descriptive Name: pfSense-CA
Method: Create internal CA
Key Type: RSA
Key Length: 2048
Digest Algorithm: SHA256
Lifetime: 3650 days
Common Name: pfSense-CA
Country: IT
```

Save

### Step 2: Server Certificate

**System → Cert. Manager → Certificates → Add/Sign**

```
Method: Create internal certificate
Descriptive Name: OpenVPN-Server-Cert
Certificate Authority: pfSense-CA
Key Type: RSA
Key Length: 2048
Certificate Type: Server Certificate
Common Name: openvpn.pfSense.localdomain
```

Save

### Step 3: User Certificates

**System → User Manager → Users → Add**

```
Username: mario.rossi
Password: [password sicura]

Certificate: ☑ Click to create user certificate
Descriptive Name: mario.rossi-cert
Certificate Authority: pfSense-CA
```

Save

### Step 4: OpenVPN Server

**VPN → OpenVPN → Servers → Add**

```
Server mode: Remote Access (SSL/TLS + User Auth)
Backend for authentication: Local Database
Protocol: UDP on IPv4 only
Interface: WAN
Local Port: 1194
Description: OpenVPN Remote Access

TLS Configuration:
  Peer Certificate Authority: pfSense-CA
  Server Certificate: OpenVPN-Server-Cert
  DH Parameter Length: 2048
  Encryption Algorithm: AES-256-CBC (256 bit)
  Auth Digest Algorithm: SHA256

Tunnel Settings:
  IPv4 Tunnel Network: 10.8.0.0/24
  IPv4 Local Network: 192.168.1.0/24
  IPv4 Remote Network: [vuoto]
  
Client Settings:
  Dynamic IP: ☑ Allow connected clients to retain their connections
  DNS Servers: 192.168.1.1
  
Advanced:
  Custom Options: push "route 192.168.1.0 255.255.255.0"
```

Save → Apply

### Step 5: Firewall Rule OpenVPN

**Firewall → Rules → WAN → Add**

```
Action: Pass
Protocol: UDP
Source: Any
Destination: WAN address
Destination Port: 1194
Description: Allow OpenVPN
```

**Firewall → Rules → OpenVPN → Add**

```
Action: Pass
Protocol: Any
Source: OpenVPN net (10.8.0.0/24)
Destination: LAN net
Description: Allow VPN to LAN
```

### Step 6: Export Client Config

**VPN → OpenVPN → Client Export**

```
Remote Access Server: OpenVPN Remote Access
Host Name Resolution: IP Address (o hostname pubblico)
```

**Download:**
- **Inline Configurations**: Most Clients (mario-rossi-config.ovpn)

### Step 7: Client Connection

**Windows/Linux/macOS:**

```bash
# Installa OpenVPN client
sudo apt install openvpn  # Linux
# brew install openvpn    # macOS

# Connetti
sudo openvpn mario-rossi-config.ovpn

# Output:
# Initialization Sequence Completed
# ✓ Connesso!
```

**Verifica:**
```bash
ip route  # Linux
# 10.8.0.0/24 via 10.8.0.5
# 192.168.1.0/24 via 10.8.0.1

ping 192.168.1.1  # pfSense LAN
ping 192.168.1.10 # Server interno
```

---

## IDS/IPS: Suricata

### Installazione

**System → Package Manager → Available Packages**

Cerca: `suricata`

Click **Install** → Conferma

### Configurazione

**Services → Suricata → Global Settings**

```
Install ETOpen Emerging Threats rules: ☑
Enable Snort GPLv2 Community rules: ☑

Update Interval: 12 hours
```

Save → **Update** (forza update regole)

**Services → Suricata → Interfaces → Add**

```
Interface: WAN
Description: WAN IDS
Enable: ☑

Detection Performance:
  IDS Mode: IPS Mode (Inline)
  
Alert Settings:
  Block Offenders: ☑
  Kill States: ☑
```

Save → **Start** (avvia Suricata su WAN)

### Visualizza Alerts

**Services → Suricata → Alerts**

```
Interface: WAN
Show: Last 500 alerts
```

**Esempio alert:**
```
[1:2100498:12] GPL ATTACK_RESPONSE id check returned root
Priority: High
Protocol: TCP
Source: 203.0.113.50:45123
Destination: 192.168.1.10:22
```

**Azioni:**
- **Block**: aggiungi IP sorgente a blocklist
- **Suppress**: non mostrare più questo alert

---

## Traffic Shaping (QoS)

### Scenario: Prioritizzare VoIP e Limitare P2P

**Firewall → Traffic Shaper → Wizards**

Seleziona: **Multiple Lan/Wan**

#### Step 1: Interfaces

```
Inside Interfaces: LAN
Outside Interfaces: WAN
```

#### Step 2: Bandwidth

```
WAN Upload: 10 Mbps (upload reale)
WAN Download: 100 Mbps (download reale)
```

#### Step 3: Voice over IP

```
☑ Enable Voice over IP
VoIP Priority: High
```

#### Step 4: Penalties

```
☑ Peer-to-peer networking
P2P: Lower priority
Penalty: 1 (lower)
```

#### Step 5: Finish

Apply → Regole create automaticamente!

**Verifica:** Firewall → Traffic Shaper → Queues

```
qWANRoot (WAN)
  ├─ qVOIP (20%)    Priority: 7  (VoIP)
  ├─ qOther (80%)   Priority: 1  (Default)
  └─ qP2P (20%)     Priority: 1  (P2P penalty)
```

---

## High Availability (CARP)

### Scenario: 2 pfSense in HA

```
Internet
   │
   ├─────────┬─────────┐
   │         │         │
[pfSense 1] [pfSense 2] [VIP]
 MASTER      BACKUP    (CARP)
 .10         .11       .1
   │         │         │
   └─────────┴─────────┘
          LAN Switch
```

**Requisiti:**
- 2 pfSense identiche (hardware, versione)
- Interfaccia dedicata per sync (opzionale)
- IP virtuali (VIP) condivisi

### Configurazione

#### pfSense 1 (MASTER)

**System → High Avail. Sync**

```
Synchronize Config to IP: 192.168.1.11 (pfSense 2)
Remote System Username: admin
Remote System Password: [password]

Synchronize:
  ☑ Synchronize states
  ☑ Synchronize firewall rules
  ☑ Synchronize NAT
```

**Firewall → Virtual IPs → Add**

```
Type: CARP
Interface: LAN
Address: 192.168.1.1 / 24
VHID Group: 1
Advertising Frequency: 1
Description: LAN VIP
```

#### pfSense 2 (BACKUP)

Stessa configurazione VIP CARP, ma:
- Advertising Frequency: 2 (più alta = backup)

**Test Failover:**
1. Spegni pfSense 1
2. pfSense 2 diventa MASTER automaticamente (< 5s)
3. Traffico continua senza interruzione

---

## Backup e Restore

### Backup Configurazione

**Diagnostics → Backup & Restore**

```
Backup area: All

Options:
  ☑ Skip packages
  ☑ Encryption

Password: [password backup]
```

Click **Download configuration as XML**

File salvato: `config-pfSense.localdomain-20260321.xml`

### Restore

**Diagnostics → Backup & Restore → Restore**

```
Configuration file: [Browse → config-pfSense.xml]
```

Click **Restore Configuration** → Riavvio automatico

### Backup Automatico (Cloud)

**System → Package Manager → Install: `AutoConfigBackup`**

**Services → Auto Config Backup → Settings**

```
☑ Enable
Backup on Save: ☑
Hostname: [pfSense hostname]
```

Backup automatici su cloud Netgate (encrypted).

---

## Monitoring e Logging

### Grafici Traffico

**Status → Traffic Graph**

Grafici real-time per interfaccia (WAN, LAN, DMZ).

### Log Firewall

**Status → System Logs → Firewall**

```
[2026/03/21 10:30:45] Block WAN TCP:443 203.0.113.50 → 192.168.1.1
[2026/03/21 10:30:46] Pass  LAN TCP:443 192.168.1.50 → 8.8.8.8
```

**Filtri:**
- Interface: WAN/LAN/DMZ
- Protocol: TCP/UDP/ICMP
- Action: Pass/Block

### Syslog Remoto

**Status → System Logs → Settings**

```
☑ Enable Remote Logging
Remote Log Servers: 192.168.1.100:514
Remote Syslog Contents: Everything
```

Log inviati a server Syslog/SIEM esterno (ELK, Splunk).

---

## Package Utili

### pfBlockerNG

**Blocco geografico e blacklist IP/domini**

```bash
# Installazione
System → Package Manager → Available → pfBlockerNG-devel

# Configurazione
Firewall → pfBlockerNG

# Blocca nazioni
IP → Africa → Add

# Blocca malware domains
DNSBL → Enable
Feeds: Abuse.ch, Spamhaus
```

### Squid Proxy

**Proxy cache HTTP/HTTPS**

### HAProxy

**Load balancer per server backend**

### Snort

**IDS alternativo a Suricata**

### ntopng

**Network traffic monitoring avanzato**

---

## Troubleshooting

### Problema: Non Riesco ad Accedere alla GUI

**Causa:** IP LAN errato o cavo scollegato

**Soluzione:**
1. Console pfSense → Menu
2. `2) Set interface(s) IP address`
3. Verifica IP LAN: `192.168.1.1`
4. Ping da PC: `ping 192.168.1.1`

### Problema: Nessuna Connettività Internet

**Causa:** WAN non configurato o gateway mancante

**Diagnostics → Routes**

Verifica default gateway presente:
```
Destination: 0.0.0.0/0
Gateway: 10.0.2.1 (WAN_DHCP)
```

**Se mancante:**
- System → Routing → Gateways
- Verify WAN gateway present

### Problema: Port Forward Non Funziona

**Checklist:**
1. ☑ NAT rule WAN → internal IP
2. ☑ Firewall rule WAN allow port
3. ☑ Server interno listening su porta: `netstat -tuln`
4. ☑ pfSense può pingare server interno
5. ☑ Test da esterno (non da LAN!)

**Test port forward da console:**
```bash
# Da pfSense console
tcpdump -i em0 port 80

# Da esterno
curl http://<WAN_IP>:80
```

---

## Best Practices

### Sicurezza

```
✓ Cambia password admin subito
✓ Abilita HTTPS per GUI (default)
✓ Disabilita regola "Anti-Lockout" dopo setup completo
✓ Abilita IDS/IPS (Suricata) su WAN
✓ Usa certificati CA per OpenVPN (non shared key)
✓ Implementa regole firewall least-privilege
✓ Abilita logging per regole critiche
✓ Backup settimanale automatico
✓ Mantieni pfSense aggiornato (System → Update)
✓ Implementa 2FA per admin (package: FreeRADIUS + Google Authenticator)
```

### Performance

```
✓ SSD per storage (logging intensivo)
✓ Disable packet filter se non usi (Firewall → Advanced)
✓ Limita logging solo a regole importanti
✓ Usa hardware crypto acceleration se disponibile
✓ Traffic shaping solo se necessario (overhead CPU)
```

### Monitoraggio

```
✓ Dashboard widgets: Interfaces, Services, Firewall Logs
✓ Syslog remoto per retention lungo termine
✓ ntopng per analisi traffico dettagliato
✓ Email alerts per eventi critici (System → Advanced → Notifications)
```

---

## Domande di Verifica

1. **Qual è la differenza tra Outbound NAT e Port Forward in pfSense?**

2. **Spiega la filosofia "default deny" di pfSense. Come influenza la creazione delle regole firewall?**

3. **Descrivi i passi necessari per configurare una DMZ sicura in pfSense. Quali regole firewall sono essenziali?**

4. **Come funziona CARP per High Availability? Cosa succede quando il Master fallisce?**

5. **Elenca 5 best practice di sicurezza per hardening di pfSense.**

6. **Differenza tra IDS mode e IPS mode in Suricata. Quando useresti uno vs l'altro?**

---

## Riferimenti

### Documentazione Ufficiale
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [pfSense Book](https://www.netgate.com/resources/pfsense-book)
- [Netgate Forum](https://forum.netgate.com/)

### Video Tutorial
- [Lawrence Systems YouTube Channel](https://www.youtube.com/c/LAWRENCESYSTEMS)
- [Netgate pfSense Hangouts](https://www.netgate.com/resources/videos/hangouts)

### Libri
- "pfSense: The Definitive Guide" - Christopher M. Buechler, Jim Pingle
- "Mastering pfSense" - David Zientara

---

**Sezione Precedente**: [07 - Firewall Comportamentali](./07_Firewall_Comportamentali.md)  
**Indice Principale**: [README](../../README.md)
