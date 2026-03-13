# Capitolo 49.4 - Split Tunneling

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 49 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

Lo **Split Tunneling** è una configurazione VPN in cui solo una parte del traffico dell'utente viene instradata attraverso il tunnel VPN cifrato, mentre il resto raggiunge Internet direttamente. Questa tecnica rappresenta un compromesso fondamentale tra sicurezza e performance, con implicazioni significative per la postura di sicurezza aziendale.

### Obiettivi di Apprendimento
- Comprendere i modelli di split tunneling e le differenze architetturali
- Analizzare i rischi di sicurezza dello split tunneling
- Configurare split tunneling in OpenVPN e WireGuard
- Implementare controlli compensativi
- Valutare il trade-off sicurezza vs. performance

---

## Concetti Principali

### Full Tunnel vs Split Tunnel

**Full Tunnel (redirect-gateway):**
```
Client VPN
    |
    ├──[Traffico Internet]──────────►[VPN Gateway]──►Internet
    |                                     |
    └──[Traffico Aziendale]──────────►[LAN Aziendale]

Tutto il traffico: 0.0.0.0/0 → VPN
```

**Split Tunnel:**
```
Client VPN
    |
    ├──[Traffico Internet]───────────────────────────►Internet
    |       (YouTube, Gmail, social...)      (connessione diretta)
    |
    └──[Traffico Aziendale]──────►[VPN Gateway]──►[LAN Aziendale]
            (192.168.0.0/16)          (solo reti aziendali)
```

### Tipi di Split Tunneling

#### 1. Include-Based (Route-Based)
Solo le reti specificate usano il tunnel VPN. Tutto il resto va direttamente su Internet.

```
AllowedIPs/Route via VPN:
  - 10.0.0.0/8      (rete VPN)
  - 192.168.1.0/24  (LAN sede centrale)
  - 172.16.0.0/12   (datacenter)

Tutto il resto → Internet diretto
```

#### 2. Exclude-Based (Inverse Split Tunnel)
Tutto il traffico usa la VPN **tranne** le eccezioni specificate (es. traffico Microsoft 365, Zoom, etc.).

```
Escludi dalla VPN (vai diretto su Internet):
  - 13.107.0.0/14   (Microsoft 365)
  - 204.79.197.0/24 (Office CDN)
  - 8.30.0.0/12     (Zoom)

Tutto il resto → VPN
```

#### 3. Application-Based Split Tunneling
Il traffico viene selezionato per applicazione, non per destinazione IP. Disponibile in client VPN avanzati (Cisco AnyConnect, Palo Alto GlobalProtect).

```
App tramite VPN:    SAP, Oracle, RDP, SSH verso server aziendali
App dirette:        Chrome per internet, Teams, Zoom
```

---

## Rischi di Sicurezza

### 1. Bypass dei Controlli Aziendali

Con split tunnel, il traffico internet dell'utente bypassa:
- **Proxy/Web Filter aziendale** (es. Zscaler, Bluecoat)
- **IDS/IPS aziendale** (non vede il traffico internet)
- **DNS aziendale** (con DNS leak potenziale)
- **DLP (Data Loss Prevention)**

```
Scenario di rischio:
1. Dipendente connesso alla VPN aziendale con split tunnel
2. Visita un sito malevolo tramite connessione diretta
3. Download di malware → infezione del laptop
4. Il laptop è ora DENTRO la rete aziendale tramite VPN
5. Il malware si propaga lateralmente nella LAN aziendale
```

### 2. DNS Leak

Con split tunnel, le query DNS potrebbero essere risolte dal DNS dell'ISP anziché dal DNS aziendale, rivelando informazioni sui siti visitati:

```
Con split tunnel mal configurato:
query "crm.azienda.it" → DNS ISP (non cifrato) → risposta
                              ↑
                    Visibile all'ISP e a chiunque intercetti
```

### 3. Hair-Pinning e Routing Loops

Split tunnel mal configurati possono creare routing asimmetrico o loop.

### 4. Compromissione del Dispositivo come Pivot Point

```
Attaccante
    |
    ↓ (attraverso connessione internet diretta del laptop)
[Laptop Compromesso] ←──── Split Tunnel ────► [LAN Aziendale]
    |                                              |
    └──────────────── Pivot ─────────────►[Server Interno]
```

---

## Configurazione Split Tunnel

### OpenVPN - Include-Based

**Server configuration (`server.conf`):**
```ini
# Non pusciare redirect-gateway (no full tunnel)
# push "redirect-gateway def1"

# Pushare solo le rotte aziendali
push "route 192.168.1.0 255.255.255.0"
push "route 10.0.0.0 255.255.0.0"
push "route 172.16.0.0 255.240.0.0"

# DNS aziendale (solo per risolvere domini interni)
push "dhcp-option DNS 10.0.0.53"
push "dhcp-option DOMAIN azienda.local"
```

**Client configuration (`client.ovpn`):**
```ini
# Nessuna modifica al routing di default del client
# (il server pushherà solo le rotte specifiche)
client
dev tun
proto udp
remote vpn.azienda.com 1194
...
# NON includere: redirect-gateway def1
```

### OpenVPN - Exclude-Based (Full Tunnel con Eccezioni)

```ini
# server.conf - Full tunnel
push "redirect-gateway def1 bypass-dhcp"

# Il client dovrà configurare le eccezioni manualmente
# Non è possibile farlo server-side in OpenVPN base
```

**Script client per eccezioni (`client-up.sh`):**
```bash
#!/bin/bash
# Aggiunto come: up /etc/openvpn/client-up.sh

# Recuperare il gateway di default originale
ORIGINAL_GW=$(ip route | grep "default" | grep -v "tun" | awk '{print $3}' | head -1)

# Escludere traffico Microsoft 365 dalla VPN
for subnet in 13.107.0.0/14 204.79.197.0/24 40.96.0.0/13; do
    ip route add $subnet via $ORIGINAL_GW
done

# Escludere traffico Zoom
for subnet in 8.30.0.0/12 99.96.0.0/13; do
    ip route add $subnet via $ORIGINAL_GW
done
```

### WireGuard - Include-Based

```ini
# Client wg0.conf
[Interface]
Address = 10.8.0.2/24
PrivateKey = <PRIVATE_KEY>
DNS = 10.8.0.1       # DNS aziendale solo per domini interni

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = vpn.azienda.com:51820

# SPLIT TUNNEL: solo reti aziendali attraverso la VPN
AllowedIPs = 10.8.0.0/24, 192.168.1.0/24, 10.0.0.0/16
# (nessun 0.0.0.0/0 → non è full tunnel)
```

### WireGuard - Full Tunnel (per confronto)

```ini
[Peer]
# FULL TUNNEL: tutto il traffico attraverso la VPN
AllowedIPs = 0.0.0.0/0, ::/0
```

### Cisco AnyConnect - Application-Based Split Tunnel

```xml
<!-- Profile XML per Cisco AnyConnect -->
<AnyConnectProfile>
  <ServerList>
    <HostEntry>
      <HostName>vpn.azienda.com</HostName>
    </HostEntry>
  </ServerList>
  <ClientInitialization>
    <SplitTunnel>tunnelSpecified</SplitTunnel>
    <SplitTunnelList>
      <NetworkAddress acl-network="192.168.0.0" acl-mask="255.255.0.0"/>
      <NetworkAddress acl-network="10.0.0.0" acl-mask="255.0.0.0"/>
    </SplitTunnelList>
    <!-- Applicazioni escluse dal tunnel -->
    <ExcludeLocalLAN>true</ExcludeLocalLAN>
    <PPPExclusion>disable</PPPExclusion>
  </ClientInitialization>
</AnyConnectProfile>
```

---

## Controlli Compensativi

### DNS Sicuro per Split Tunnel

```ini
# OpenVPN server.conf - DNS split
# Pushare DNS aziendale solo per domini interni
push "dhcp-option DNS 10.0.0.53"
push "dhcp-option DOMAIN azienda.local"

# Configurazione DNS split su client Linux (/etc/systemd/resolved.conf.d/vpn.conf):
# [Resolve]
# DNS=10.0.0.53
# Domains=~azienda.local ~azienda.it
# (il ~ indica che quel DNS è usato SOLO per quel dominio)
```

### Endpoint Security per Split Tunnel

```python
#!/usr/bin/env python3
"""
vpn_security_monitor.py
Monitora il traffico in uscita su connessioni con split tunnel attivo.
Invia alert se rileva traffico sospetto.
"""
import subprocess
import re
import time
from datetime import datetime

SUSPICIOUS_PORTS = {22, 23, 3389, 445, 139}  # SSH, Telnet, RDP, SMB
VPN_INTERFACE = "tun0"
LOG_FILE = "/var/log/vpn_monitor.log"

def get_active_connections():
    """Recupera connessioni di rete attive"""
    result = subprocess.run(
        ["ss", "-tnp", "state", "established"],
        capture_output=True, text=True
    )
    connections = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "local": parts[3],
                "remote": parts[4],
                "process": parts[5] if len(parts) > 5 else "unknown"
            })
    return connections

def is_vpn_route(ip: str) -> bool:
    """Verifica se un IP è instradato tramite VPN"""
    result = subprocess.run(
        ["ip", "route", "get", ip],
        capture_output=True, text=True
    )
    return VPN_INTERFACE in result.stdout

def monitor_split_tunnel():
    """Monitora traffico sospetto su connessioni dirette"""
    print(f"[*] Monitoraggio split tunnel attivo - {datetime.now()}")
    
    while True:
        conns = get_active_connections()
        for conn in conns:
            remote_ip = conn["remote"].split(":")[0]
            remote_port = int(conn["remote"].split(":")[-1]) if ":" in conn["remote"] else 0
            
            # Rilevare connessioni dirette su porte sospette
            if remote_port in SUSPICIOUS_PORTS and not is_vpn_route(remote_ip):
                alert = (f"[ALERT] {datetime.now()} - Connessione diretta sospetta: "
                        f"{conn['local']} → {conn['remote']} "
                        f"({conn['process']}) - NON passa per VPN!")
                print(alert)
                with open(LOG_FILE, "a") as f:
                    f.write(alert + "\n")
        
        time.sleep(30)

if __name__ == "__main__":
    monitor_split_tunnel()
```

---

## Policy Aziendale per Split Tunneling

### Matrice Rischio/Beneficio

| Scenario | Consiglio | Motivazione |
|----------|-----------|-------------|
| Accesso a risorse cloud pubbliche (M365, Google) | Exclude from tunnel | Latenza ridotta, nessun rischio aggiuntivo |
| Accesso a dati sensibili (HR, Finance) | Full tunnel obbligatorio | Massima protezione, DLP attivo |
| Sviluppatori con accesso a server interni | Split tunnel + endpoint security | Bilanciamento produttività/sicurezza |
| Ambienti con BYOD | Full tunnel o no-VPN con ZTNA | Dispositivi non controllati dall'azienda |
| Connessioni da Paesi ad alto rischio | Full tunnel sempre | Potenziale sorveglianza di stato |

### Checklist Sicurezza Split Tunnel

```
☐ DNS leak test eseguito (dnsleaktest.com)
☐ DNS split configurato per domini interni
☐ Endpoint security (EDR) attivo sul dispositivo
☐ Politica di accesso minimo privilegio sulle risorse VPN
☐ Logging attività VPN abilitato sul gateway
☐ Aggiornamenti automatici abilitati sul client
☐ Esclusione reti locali (evitare accesso a stampanti/NAS home)
☐ Test di penetrazione periodici sulla configurazione VPN
```

---

## Domande di Verifica

1. **Quali sono i tre principali tipi di split tunneling? Descrivi le differenze architetturali tra include-based e exclude-based.**

2. **Spiega lo scenario in cui uno split tunnel può permettere a un malware di penetrare nella rete aziendale. Come si chiama questo tipo di attacco?**

3. **Cosa è un "DNS leak" in contesto VPN? Come si verifica e come si previene in uno scenario con split tunnel?**

4. **Un'azienda vuole ridurre il carico sul proprio gateway VPN escludendo il traffico Microsoft 365. Quali sono i rischi di sicurezza di questa scelta e quali controlli compensativi implementeresti?**

5. **Configura in WireGuard un profilo client con split tunnel che instrada solo il traffico verso 10.0.0.0/8 e 192.168.0.0/16 attraverso la VPN.**

6. **Perché l'application-based split tunneling è considerato più sicuro del route-based? Quali limitazioni ha?**

---

## Riferimenti

### Documentazione e Standard
- [NIST SP 800-113](https://csrc.nist.gov/publications/detail/sp/800-113/final) - Guide to SSL VPNs
- [NIST SP 800-77r1](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) - Guide to IPsec VPNs
- [NSA VPN Security Guidance](https://media.defense.gov/2021/Sep/28/2002863171/-1/-1/0/CSI_SELECTING-AND-HARDENING-REMOTE-ACCESS-VPNS_20210928.PDF)

### Tools
- [DNS Leak Test](https://www.dnsleaktest.com/) - Verifica DNS leak
- [IP Leak Test](https://ipleak.net/) - Test completo leak VPN

---

**Sezione Precedente**: [49.3 - SSL VPN vs IPsec VPN](./49_3_ssl_vpn_vs_ipsec_vpn.md)  
**Prossima Sezione**: [49.5 - VPN Kill Switch e DNS Leak](./49_5_vpn_kill_switch_e_dns_leak.md)
