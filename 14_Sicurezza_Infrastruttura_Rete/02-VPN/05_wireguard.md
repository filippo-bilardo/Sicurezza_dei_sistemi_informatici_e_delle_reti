# Capitolo 05 - WireGuard

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 05 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

**WireGuard** è un protocollo VPN moderno e ad alte prestazioni, progettato con l'obiettivo di essere semplice, veloce e criptograficamente robusto. Creato da Jason A. Donenfeld, è ora integrato direttamente nel kernel Linux (dalla versione 5.6) ed è considerato lo stato dell'arte per le VPN moderne.

### Obiettivi di Apprendimento
- Comprendere il design e le scelte crittografiche di WireGuard
- Installare e configurare un server/client WireGuard
- Confrontare WireGuard con soluzioni VPN tradizionali
- Implementare scenari di rete avanzati (road warrior, site-to-site)
- Gestire chiavi e peer in modo sicuro

---

## Concetti Principali

### Design Philosophy

WireGuard nasce dalla critica alle VPN esistenti (OpenVPN, IPsec) che soffrono di:
- **Eccessiva complessità**: OpenVPN ~70.000 righe di codice, IPsec ~400.000
- **Superficie d'attacco ampia**: più codice = più vulnerabilità potenziali
- **Negoziazione crittografica**: permettere la scelta degli algoritmi introduce configurazioni insicure

**WireGuard risponde con:**
- ~4.000 righe di codice (facilmente verificabili)
- **Cryptographic opinionation**: algoritmi fissi, nessuna negoziazione
- Implementazione nel kernel per massime performance
- **Stateless**: nessuno stato persistente tra i peer

### Suite Crittografica

WireGuard utilizza un insieme fisso e moderno di algoritmi:

| Funzione | Algoritmo |
|----------|-----------|
| Scambio chiavi | **Curve25519** (ECDH) |
| Cifratura | **ChaCha20-Poly1305** (AEAD) |
| Hash | **BLAKE2s** |
| KDF | **HKDF** |
| Handshake | **Noise Protocol Framework** |
| Timestamp | **TAI64N** |

**Vantaggi di questa scelta:**
- ChaCha20 è più veloce di AES su hardware senza accelerazione hardware AES-NI
- Curve25519 è immune agli attacchi side-channel della curva NIST P-256
- BLAKE2s è più veloce di SHA-2 mantenendo sicurezza equivalente

### Modello di Funzionamento

```
Peer A (Client)                    Peer B (Server)
  |                                    |
  | Chiave pubblica A: PubA            |
  | Chiave privata A: PrivA            |
  |                                    |
  |        Configurazione:             |
  |  "Conosco PubB, gli mando traffico |
  |   per 10.0.0.2"                    |
  |                                    |
  |---[Handshake Noise IKpsk2]-------->|
  |<--[Handshake Response]-------------|
  |                                    |
  |====[Pacchetti UDP cifrati]========>|
  |       (incapsulamento diretto)     |
```

**Caratteristica chiave: Cryptokey Routing**
- Ogni interfaccia WireGuard ha una coppia di chiavi (pubblica/privata)
- Ogni peer è identificato dalla sua chiave pubblica
- Le chiavi pubbliche determinano quali IP sono autorizzati per quel peer (allowed IPs)

---

## Installazione e Configurazione

### Installazione (Ubuntu 20.04+)

```bash
# Ubuntu 20.04+
sudo apt update && sudo apt install wireguard -y

# Verificare installazione
sudo modprobe wireguard
lsmod | grep wireguard
```

### Generazione Chiavi

```bash
# Generare coppia di chiavi server
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
sudo chmod 600 /etc/wireguard/server_private.key

# Generare coppia di chiavi client
wg genkey | tee client_private.key | wg pubkey | tee client_public.key

# Generare chiave pre-condivisa (preshared key) - opzionale, sicurezza extra
wg genpsk | sudo tee /etc/wireguard/psk_client1.key
sudo chmod 600 /etc/wireguard/psk_client1.key
```

### Configurazione Server (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
# Indirizzo IP del server sull'interfaccia WireGuard
Address = 10.0.0.1/24

# Porta di ascolto (default 51820)
ListenPort = 51820

# Chiave privata del server
PrivateKey = <SERVER_PRIVATE_KEY>

# Script post-up/down per iptables (NAT e forwarding)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; \
         iptables -A FORWARD -o %i -j ACCEPT; \
         iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; \
           iptables -D FORWARD -o %i -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Peer: Client 1
[Peer]
PublicKey = <CLIENT1_PUBLIC_KEY>
PresharedKey = <PSK_CLIENT1>          # Opzionale - sicurezza post-quantum
AllowedIPs = 10.0.0.2/32             # IP assegnato a questo client
PersistentKeepalive = 25             # Utile per NAT traversal

# Peer: Client 2
[Peer]
PublicKey = <CLIENT2_PUBLIC_KEY>
AllowedIPs = 10.0.0.3/32
```

### Abilitazione IP Forwarding

```bash
# Abilitare IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Avvio e Gestione

```bash
# Avviare WireGuard
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0

# Verificare stato
sudo wg show
sudo wg show wg0

# Monitorare traffico
sudo wg show wg0 transfer

# Riavviare dopo modifiche alla configurazione
sudo wg-quick down wg0 && sudo wg-quick up wg0
```

### Configurazione Client

```ini
[Interface]
# IP assegnato al client
Address = 10.0.0.2/24
PrivateKey = <CLIENT_PRIVATE_KEY>

# DNS da usare quando connesso alla VPN
DNS = 10.0.0.1

[Peer]
# Server
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = <PSK_CLIENT1>           # Deve corrispondere a quello del server
Endpoint = vpn.esempio.com:51820

# Full tunnel: tutto il traffico passa per la VPN
AllowedIPs = 0.0.0.0/0, ::/0

# Split tunnel (solo traffico VPN interno):
# AllowedIPs = 10.0.0.0/24, 192.168.1.0/24

# Mantiene la connessione attiva attraverso NAT
PersistentKeepalive = 25
```

---

## Scenari Avanzati

### Site-to-Site VPN

```
Sede A (192.168.1.0/24)          Sede B (192.168.2.0/24)
     Gateway A                        Gateway B
     wg0: 10.0.0.1                   wg0: 10.0.0.2
         |                               |
         |======[WireGuard Tunnel]======|
         |       10.0.0.0/24            |
```

**Gateway A (`/etc/wireguard/wg0.conf`):**
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <GATEWAY_A_PRIVATE_KEY>
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT

[Peer]
PublicKey = <GATEWAY_B_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32, 192.168.2.0/24   # Raggiungere la rete della sede B
Endpoint = sede-b.esempio.com:51820
PersistentKeepalive = 25
```

### Script di Gestione Peer

```python
#!/usr/bin/env python3
"""
wireguard_manager.py - Gestione semplificata dei peer WireGuard
"""
import subprocess
import ipaddress
from pathlib import Path

WG_CONFIG = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
VPN_SUBNET = ipaddress.IPv4Network("10.0.0.0/24")

def generate_keypair():
    """Genera una nuova coppia di chiavi WireGuard"""
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = subprocess.check_output(
        ["wg", "pubkey"], input=private_key.encode()
    ).decode().strip()
    psk = subprocess.check_output(["wg", "genpsk"]).decode().strip()
    return private_key, public_key, psk

def get_used_ips():
    """Recupera gli IP già assegnati dalla configurazione"""
    used = set()
    with open(WG_CONFIG) as f:
        for line in f:
            if "AllowedIPs" in line:
                ip_str = line.split("=")[1].strip().split("/")[0]
                used.add(ipaddress.IPv4Address(ip_str))
    return used

def next_available_ip():
    """Trova il prossimo IP disponibile nella subnet VPN"""
    used = get_used_ips()
    for ip in VPN_SUBNET.hosts():
        if ip not in used and str(ip) != "10.0.0.1":  # Escludiamo il server
            return ip
    raise ValueError("Subnet VPN esaurita")

def add_peer(name: str) -> dict:
    """Aggiunge un nuovo peer alla configurazione WireGuard"""
    private_key, public_key, psk = generate_keypair()
    vpn_ip = next_available_ip()

    # Aggiungere peer alla config server
    peer_config = f"""
# Peer: {name}
[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {vpn_ip}/32
"""
    with open(WG_CONFIG, "a") as f:
        f.write(peer_config)

    # Aggiungere peer all'interfaccia live (senza riavvio)
    subprocess.run([
        "wg", "set", WG_INTERFACE,
        "peer", public_key,
        "preshared-key", "/dev/stdin",
        "allowed-ips", f"{vpn_ip}/32"
    ], input=psk.encode())

    print(f"[+] Peer '{name}' aggiunto con IP {vpn_ip}")
    return {
        "name": name,
        "vpn_ip": str(vpn_ip),
        "private_key": private_key,
        "public_key": public_key,
        "psk": psk
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: wireguard_manager.py <nome_peer>")
        sys.exit(1)
    peer = add_peer(sys.argv[1])
    print(f"Chiave privata client: {peer['private_key']}")
```

---

## WireGuard vs OpenVPN: Confronto

| Caratteristica | WireGuard | OpenVPN |
|----------------|-----------|---------|
| Linee di codice | ~4.000 | ~70.000 |
| Crittografia | Fissa (moderna) | Configurabile |
| Velocità | Molto alta (kernel) | Moderata (userspace) |
| Handshake | ~1 RTT | ~3-4 RTT |
| Supporto NAT | Nativo | Tramite plugin |
| Autenticazione | Solo chiavi | Certificati, PSK, password |
| Logging | Minimo (privacy) | Configurabile |
| Roaming | Trasparente | Richiede reinizializzazione |
| Standard audit | Verificato 2020 | Verificato più volte |
| UDP/TCP | Solo UDP | UDP e TCP |

### Quando scegliere WireGuard:
- Massime performance (embedded, mobile, server)
- Semplicità di configurazione e manutenzione
- Privacy (minimo logging)
- Ambienti con roaming frequente (laptop, mobile)

### Quando scegliere OpenVPN:
- TCP necessario (firewall restrittivi su UDP)
- Autenticazione con username/password o 2FA
- Infrastrutture certificate complesse (PKI enterprise)
- Compatibilità con sistemi legacy

---

## Troubleshooting

```bash
# Visualizzare stato completo e traffico
sudo wg show all

# Verificare che i pacchetti arrivino all'interfaccia
sudo tcpdump -i eth0 udp port 51820

# Debug handshake
sudo wg show wg0 latest-handshakes

# Verificare routing
ip route show table main
ip rule show

# Testare connettività al peer
ping -I wg0 10.0.0.2

# Resettare un peer (forza nuovo handshake)
sudo wg set wg0 peer <PUBLIC_KEY> persistent-keepalive 0
```

---

## Domande di Verifica

1. **Perché WireGuard utilizza algoritmi crittografici fissi invece di permettere la negoziazione come IPsec/OpenVPN? Quali sono i vantaggi e i potenziali svantaggi di questo approccio?**

2. **Spiega il concetto di "Cryptokey Routing" in WireGuard. Come determina WireGuard verso quale peer instradare un pacchetto?**

3. **Cosa è una Preshared Key (PSK) in WireGuard e quale protezione aggiuntiva fornisce?**

4. **WireGuard non mantiene lo stato della connessione nel senso tradizionale. Come gestisce l'autenticazione di ogni pacchetto ricevuto?**

5. **Descrivi come configureresti una VPN site-to-site con WireGuard tra due uffici con sottoreti diverse (192.168.1.0/24 e 192.168.2.0/24).**

6. **Perché `PersistentKeepalive` è importante quando un client WireGuard è dietro NAT? Quale valore è generalmente raccomandato?**

---

## Riferimenti

### Documentazione Ufficiale
- [WireGuard Official Website](https://www.wireguard.com/)
- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)

### Risorse Aggiuntive
- [Noise Protocol Framework](http://www.noiseprotocol.org/)
- [WireGuard Security Audit (2021)](https://cure53.de/pentest-report_wireguard.pdf)
- [WireGuard Road Warrior Setup](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence)

### Libri e Paper
- "WireGuard: Next Generation Kernel Network Tunnel" - Jason A. Donenfeld (paper originale)
- "Linux Kernel Networking" - Rami Rosen

---

**Sezione Precedente**: [04 - OpenVPN](./04_openvpn.md)  
**Prossima Sezione**: [06 - SSL VPN vs IPsec VPN](./06_split_tunneling.md)
