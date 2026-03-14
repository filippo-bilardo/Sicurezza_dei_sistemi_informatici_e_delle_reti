# Capitolo 02 - SSL VPN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 02 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

Una **SSL VPN** (Secure Sockets Layer VPN) è una tipologia di VPN che utilizza il protocollo **TLS** (Transport Layer Security, successore di SSL) per creare tunnel sicuri su connessioni HTTPS standard. A differenza di IPsec, opera a livello applicativo e non richiede configurazioni speciali sui firewall intermedi, poiché sfrutta la porta 443 (HTTPS) già ampiamente permessa.

### Obiettivi di Apprendimento
- Comprendere l'architettura e il funzionamento di SSL VPN
- Distinguere le modalità clientless, thin-client e full-tunnel
- Configurare un gateway SSL VPN con OpenConnect/ocserv
- Analizzare i rischi di sicurezza specifici delle SSL VPN
- Conoscere i principali prodotti enterprise e le loro vulnerabilità storiche

---

## Architettura SSL VPN

### Come Funziona

Una SSL VPN sfrutta TLS per due scopi:
1. **Autenticazione** del server (e opzionalmente del client) tramite certificati X.509
2. **Cifratura** del traffico con algoritmi simmetrici negoziati durante l'handshake TLS

```
Client                         SSL VPN Gateway              Rete Interna
  |                                   |                          |
  |---[HTTPS GET /vpn]--------------->|                          |
  |<--[TLS Certificate]---------------|                          |
  |---[Client Auth (cert/password)]-->|                          |
  |<--[VPN Session Token]-------------|                          |
  |                                   |                          |
  |====[Tunnel TLS (porta 443)]======>|----[Traffico interno]--->|
  |    (traffico app incapsulato)      |   (decifratura e routing)|
```

### Differenza con TLS Standard

In una connessione HTTPS normale, TLS protegge una singola applicazione. In una SSL VPN, TLS diventa il **trasporto** per tutto il traffico IP o per sessioni specifiche.

---

## Modalità Operative

### 1. Clientless (Web-Based)

L'utente accede tramite browser senza installare alcun software VPN. Il gateway SSL VPN funge da **proxy applicativo reverso**.

```
Browser → [HTTPS] → SSL VPN Portal → [HTTP/RDP/SSH] → Applicazioni Interne
```

**Risorse accessibili:**
- Applicazioni web interne (intranet, portali)
- RDP via HTML5 (es. Apache Guacamole integrato)
- SSH via browser
- Condivisione file via WebDAV/SMB proxy

**Vantaggi:**
- Nessun software da installare → supporto BYOD
- Accesso da qualsiasi dispositivo (tablet, PC aziendale altrui)
- Nessuna modifica al routing del client

**Limitazioni:**
- Solo applicazioni web e alcuni protocolli specifici
- Non supporta applicazioni desktop arbitrarie
- Dipendente dalle funzionalità del browser

### 2. Thin-Client (Port Forwarding)

Un piccolo plugin/applet scaricato dal browser crea un port forwarding per applicazioni specifiche.

```
App Client (TCP 3389) → Thin-Client Plugin → [TLS] → Gateway → [TCP] → Server RDP Interno
```

**Uso tipico:** accesso a specifiche applicazioni client/server (RDP, SSH, Citrix, database).

### 3. Full Network Extension (Tunnel Mode)

Un client VPN completo stabilisce un tunnel di rete layer 3, assegnando un IP VPN al client. Funzionalmente equivalente a OpenVPN o WireGuard, ma su TLS/HTTPS.

```
[VPN Client] → [TLS Tunnel porta 443] → [SSL VPN Gateway] → [LAN Aziendale]
  tun0: 10.8.0.5                          10.8.0.1           192.168.1.0/24
```

---

## Confronto Modalità

| Caratteristica | Clientless | Thin-Client | Full Tunnel |
|----------------|------------|-------------|-------------|
| Software richiesto | No | Plugin browser | Client VPN |
| Applicazioni supportate | Web + HTML5 | Specifiche | Tutte |
| Performance | Bassa | Media | Alta |
| Granularità accesso | Alta | Media | Bassa (rete) |
| BYOD friendly | ★★★★★ | ★★★ | ★★ |
| Semplicità utente | ★★★★★ | ★★★ | ★★★ |

---

## Configurazione: ocserv (OpenConnect VPN Server)

**ocserv** è il server open source compatibile con il protocollo Cisco AnyConnect. È la scelta più comune per un gateway SSL VPN self-hosted.

### Installazione

```bash
sudo apt update && sudo apt install ocserv gnutls-bin -y
```

### Creazione PKI con GnuTLS

```bash
# Creazione directory PKI
mkdir -p ~/ocserv-pki && cd ~/ocserv-pki

# Generare CA
certtool --generate-privkey --outfile ca-key.pem
cat > ca.tmpl << EOF
cn = "VPN CA Aziendale"
organization = "Azienda SRL"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF
certtool --generate-self-signed --load-privkey ca-key.pem \
         --template ca.tmpl --outfile ca-cert.pem

# Generare certificato server
certtool --generate-privkey --outfile server-key.pem
cat > server.tmpl << EOF
cn = "vpn.azienda.com"
organization = "Azienda SRL"
serial = 2
expiration_days = 820
dns_name = "vpn.azienda.com"
signing_key
tls_www_server
EOF
certtool --generate-certificate \
         --load-privkey server-key.pem \
         --load-ca-certificate ca-cert.pem \
         --load-ca-privkey ca-key.pem \
         --template server.tmpl \
         --outfile server-cert.pem

# Copiare nella directory ocserv
sudo cp ca-cert.pem /etc/ocserv/
sudo cp server-cert.pem /etc/ocserv/
sudo cp server-key.pem /etc/ocserv/
sudo chmod 600 /etc/ocserv/server-key.pem
```

### Configurazione (`/etc/ocserv/ocserv.conf`)

```ini
# Autenticazione: password (PAM) + opzionalmente certificato
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
# Per MFA con TOTP:
# auth = "pam"

# Porta e protocolli
tcp-port = 443
udp-port = 443   # DTLS per performance (UDP over TLS)

# Certificati
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem

# Limiti
max-clients = 200
max-same-clients = 2        # Max connessioni per utente
rate-limit-ms = 100

# Rete VPN
ipv4-network = 10.50.0.0/24
ipv4-netmask = 255.255.255.0
dns = 10.50.0.1
dns = 8.8.8.8

# Routing - full tunnel
route = default
# Split tunnel (invece di "route = default"):
# route = 192.168.1.0/255.255.255.0
# route = 10.0.0.0/255.0.0.0

# Keepalive
keepalive = 32400
dpd = 90
mobile-dpd = 1800

# Persistenza sessione (riconnessione senza re-autenticazione)
persistent-cookies = true
session-timeout = 86400    # 24 ore

# Sicurezza TLS
tls-priorities = "SECURE256:+SECURE128:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.3"

# Logging
log-level = 2

# Privilege dropping
run-as-user = nobody
run-as-group = daemon

# Script post-autenticazione (assegna IP, logging, etc.)
# connect-script = /etc/ocserv/scripts/connect.sh
# disconnect-script = /etc/ocserv/scripts/disconnect.sh
```

### Gestione Utenti

```bash
# Aggiungere un utente (password stored in /etc/ocserv/ocpasswd)
sudo ocpasswd -c /etc/ocserv/ocpasswd mario.rossi

# Bloccare un utente
sudo ocpasswd -l mario.rossi

# Sbloccare un utente
sudo ocpasswd -u mario.rossi

# Listare sessioni attive
sudo occtl show users

# Disconnettere un utente specifico
sudo occtl disconnect user mario.rossi

# Statistiche
sudo occtl show stats
```

### Abilitare Forwarding e NAT

```bash
# IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT
sudo iptables -t nat -A POSTROUTING -s 10.50.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i vpns+ -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o vpns+ -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Avvio Servizio

```bash
sudo systemctl enable --now ocserv
sudo systemctl status ocserv

# Monitorare log
sudo journalctl -fu ocserv
```

### Client: OpenConnect

```bash
# Connessione base
sudo openconnect vpn.azienda.com

# Con certificato client
sudo openconnect --certificate client-cert.pem \
                 --sslkey client-key.pem \
                 vpn.azienda.com

# Specificare credenziali da linea di comando (script)
echo "password123" | sudo openconnect -u mario.rossi \
                          --passwd-on-stdin \
                          vpn.azienda.com

# Connessione in background
sudo openconnect --background \
                 --pid-file=/var/run/openconnect.pid \
                 vpn.azienda.com
```

---

## Prodotti SSL VPN Enterprise

### Panoramica

| Prodotto | Vendor | Protocollo | Note |
|----------|--------|------------|------|
| AnyConnect / Secure Client | Cisco | DTLS/TLS | Standard enterprise |
| GlobalProtect | Palo Alto Networks | IPsec + SSL | ZTNA integrato |
| FortiClient | Fortinet | SSL/IPsec | Suite FortiGate |
| Pulse Connect Secure | Ivanti (ex Pulse) | SSL | Molte CVE critiche |
| Citrix Gateway | Citrix | SSL | Ex NetScaler |
| SonicWall NetExtender | SonicWall | SSL | PMI e enterprise |

### Vulnerabilità Storiche Critiche

Le SSL VPN enterprise sono state bersaglio di attacchi mirati ad alto impatto:

```
CVE-2019-11510 (Pulse Secure)
  └── Path traversal non autenticato → lettura /etc/passwd e certificati privati
  └── Sfruttato da gruppi APT (Lazarus, REvil) per accedere a reti governative

CVE-2019-19781 (Citrix ADC/Gateway)
  └── Directory traversal → RCE non autenticata
  └── 80.000 server vulnerabili scansionati in 24h dalla pubblicazione PoC

CVE-2018-13379 (Fortinet SSL VPN)
  └── Path traversal → lettura file VPN session con credenziali
  └── Database di credenziali rubate pubblicate su forum underground

CVE-2021-22893 (Pulse Secure - 0-day)
  └── RCE non autenticata, sfruttato prima del patch disponibile
  └── Target: infrastrutture critiche USA ed europee
```

**Lezione:** i gateway SSL VPN sono "front door" della rete aziendale. Devono essere:
- Aggiornati immediatamente (patch critiche entro 24-48h)
- Monitorati con IDS/IPS
- Accessibili solo da IP autorizzati ove possibile
- Sottoposti a penetration test periodici

---

## Sicurezza Avanzata

### Autenticazione a Due Fattori con TOTP

```bash
# Installare google-authenticator-libpam
sudo apt install libpam-google-authenticator -y

# Configurare PAM per ocserv
# /etc/pam.d/ocserv
auth required pam_google_authenticator.so
auth required pam_unix.so

# Ogni utente deve configurare il proprio TOTP
google-authenticator
```

### Rate Limiting e Protezione Brute Force

```bash
# fail2ban per ocserv
# /etc/fail2ban/filter.d/ocserv.conf
[Definition]
failregex = ocserv\[.*\]: .*user '.*' (failed authentication|AUTH_FAILED)
ignoreregex =

# /etc/fail2ban/jail.d/ocserv.conf
[ocserv]
enabled = true
port = 443
filter = ocserv
logpath = /var/log/syslog
maxretry = 5
bantime = 3600
findtime = 600
```

### Monitoring con Script Python

```python
#!/usr/bin/env python3
"""
ocserv_monitor.py - Monitora sessioni attive e anomalie ocserv
"""
import subprocess
import json
from datetime import datetime

def get_active_sessions():
    """Recupera sessioni VPN attive tramite occtl"""
    result = subprocess.run(
        ["occtl", "-j", "show", "users"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

def check_anomalies(sessions: list) -> list:
    """Rileva sessioni anomale"""
    alerts = []
    user_sessions = {}
    
    for session in sessions:
        user = session.get("username", "unknown")
        if user not in user_sessions:
            user_sessions[user] = []
        user_sessions[user].append(session)
    
    for user, user_sess in user_sessions.items():
        # Alert: più di 2 sessioni contemporanee
        if len(user_sess) > 2:
            alerts.append(f"[ALERT] Utente '{user}' ha {len(user_sess)} sessioni attive!")
        
        # Alert: connessioni da IP geograficamente distanti (semplificato)
        ips = {s.get("remote-ip", "") for s in user_sess}
        if len(ips) > 1:
            alerts.append(f"[WARN] Utente '{user}' connesso da più IP: {ips}")
    
    return alerts

def print_dashboard():
    sessions = get_active_sessions()
    print(f"\n=== ocserv Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"Sessioni attive: {len(sessions)}")
    
    for s in sessions:
        print(f"  • {s.get('username','?'):<20} IP: {s.get('remote-ip','?'):<20} "
              f"Da: {s.get('connected-at','?')}")
    
    alerts = check_anomalies(sessions)
    if alerts:
        print("\n--- ANOMALIE ---")
        for a in alerts:
            print(f"  {a}")

if __name__ == "__main__":
    print_dashboard()
```

---

## Domande di Verifica

1. **Descrivi le tre modalità operative di una SSL VPN (clientless, thin-client, full tunnel). In quale scenario è preferibile ciascuna?**

2. **Perché la SSL VPN è considerata più "firewall friendly" rispetto a IPsec? Quali porte utilizza e perché questo è un vantaggio?**

3. **Analizza CVE-2019-11510 (Pulse Secure). Che tipo di vulnerabilità è? Quali dati poteva esfiltrare un attaccante non autenticato?**

4. **Cosa è DTLS (Datagram TLS) e perché viene usato da Cisco AnyConnect e ocserv come alternativa a TLS su TCP?**

5. **Configura in ocserv uno split tunnel che instrada attraverso la VPN solo il traffico verso 192.168.0.0/16. Mostra la direttiva di configurazione.**

6. **Perché la modalità clientless è preferita in ambienti BYOD? Quali sono i rischi di sicurezza specifici dell'accesso da dispositivi non gestiti?**

---

## Riferimenti

### Documentazione
- [ocserv Documentation](https://ocserv.gitlab.io/www/manual.html)
- [OpenConnect VPN](https://www.infradead.org/openconnect/)
- [Cisco AnyConnect Administrator Guide](https://www.cisco.com/c/en/us/support/security/anyconnect-secure-mobility-client/products-installation-and-configuration-guides-list.html)

### Sicurezza e CVE
- [CVE-2019-11510 Analysis](https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/)
- [CISA Alert: VPN Vulnerabilities Exploited by APT](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-073a)
- [NSA Selecting and Hardening VPNs](https://media.defense.gov/2021/Sep/28/2002863171/-1/-1/0/CSI_SELECTING-AND-HARDENING-REMOTE-ACCESS-VPNS_20210928.PDF)

### Standard
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3
- [NIST SP 800-113](https://csrc.nist.gov/publications/detail/sp/800-113/final) - Guide to SSL VPNs

---

**Sezione Precedente**: [01 - Le VPN](./01_le_vpn.md)  
**Prossima Sezione**: [03 - IPsec VPN](./03_ipsec_vpn.md)
