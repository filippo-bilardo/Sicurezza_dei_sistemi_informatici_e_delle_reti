# Capitolo 49.5 - VPN Kill Switch e DNS Leak

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 49 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

Due delle vulnerabilità più comuni e sottovalutate nelle configurazioni VPN sono il **DNS Leak** e la mancanza di un **Kill Switch**. Il primo espone le query DNS dell'utente all'ISP anche mentre si usa una VPN; il secondo permette al traffico di uscire senza protezione in caso di disconnessione VPN improvvisa. Entrambi possono compromettere silenziosamente la privacy e la sicurezza.

### Obiettivi di Apprendimento
- Comprendere come avvengono i DNS leak e il loro impatto
- Implementare un Kill Switch a livello firewall e applicativo
- Testare efficacemente la propria configurazione VPN
- Configurare soluzioni robuste per Linux, Windows e macOS
- Integrare protezioni DNS avanzate (DoH, DoT)

---

## DNS Leak

### Cos'è un DNS Leak

Un **DNS Leak** si verifica quando le query DNS vengono inoltrate a server DNS al di fuori del tunnel VPN, tipicamente al DNS dell'ISP o al DNS configurato localmente. Questo espone:
- I **siti visitati** dall'utente
- I **domini** a cui si connette
- **Pattern di comportamento** (orari, frequenza)

```
Scenario DNS Leak:

SENZA LEAK (corretto):
App → query "google.com" → [tun0/wg0] → VPN Gateway → DNS 10.0.0.53
                               ↑
                        Tunnel cifrato

CON LEAK (vulnerabile):
App → query "google.com" → [eth0] → ISP DNS 8.8.8.8 (non cifrato!)
                               ↑
                    Bypassa completamente il tunnel VPN
```

### Cause Comuni di DNS Leak

1. **Windows Smart Multi-Homed Name Resolution**: Windows invia query DNS a **tutte** le interfacce disponibili contemporaneamente, usando la risposta più veloce. Se eth0/Wi-Fi risponde prima di tun0, usa il DNS dell'ISP.

2. **IPv6 Leak su tunnel solo IPv4**: La VPN copre solo IPv4 ma il sistema usa IPv6 per le query DNS.

3. **DHCP override**: Il router DHCP sovrascrive il DNS configurato dalla VPN.

4. **Split DNS mal configurato**: Il DNS aziendale risponde solo ai domini interni; le richieste esterne vengono inoltrate al DNS dell'ISP.

5. **WebRTC leak** (browser): Il browser rivela l'IP reale tramite WebRTC anche con VPN attiva.

### Rilevamento DNS Leak

```bash
# Test da riga di comando - verificare quale DNS risponde
dig +short whoami.akamai.net
nslookup whoami.akamai.net

# Verificare l'IP di provenienza delle query DNS
dig +short o-o.myaddr.l.google.com TXT

# Verificare interfaccia usata per DNS
systemd-resolve --status | grep "DNS Server"

# Test con tcpdump - verificare che le query DNS escano dal tunnel
sudo tcpdump -i eth0 -n port 53  # Non deve mostrare nulla con VPN
sudo tcpdump -i tun0 -n port 53  # Deve mostrare le query DNS
```

**Tool online:**
- https://dnsleaktest.com
- https://ipleak.net
- https://browserleaks.com/dns

### Prevenzione DNS Leak su Linux

#### Metodo 1: systemd-resolved con routing DNS per interfaccia

```bash
# /etc/systemd/resolved.conf
[Resolve]
DNS=10.0.0.53
FallbackDNS=           # Rimuovere il fallback!
Domains=~.             # "~." = usare questo DNS per TUTTI i domini
DNSOverTLS=yes
DNSSEC=yes
```

```bash
# Per interfaccia VPN specifica (NetworkManager)
nmcli connection modify "VPN Connection" ipv4.dns "10.0.0.53"
nmcli connection modify "VPN Connection" ipv4.dns-priority -100
# Priorità negativa = DNS preferenziale rispetto ad altri
```

#### Metodo 2: OpenVPN con update-resolv-conf

```bash
# Installare
sudo apt install openresolv -y

# In client.ovpn aggiungere:
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
```

#### Metodo 3: WireGuard con DNS forzato

```ini
# /etc/wireguard/wg0.conf
[Interface]
DNS = 10.0.0.53
# wg-quick gestirà automaticamente il DNS tramite resolvconf/systemd-resolved
```

### Prevenzione DNS Leak su Windows

```powershell
# Disabilitare Smart Multi-Homed Name Resolution tramite registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "DisableSmartNameResolution" -Value 1 -Type DWORD

# Disabilitare IPv6 su interfacce non-VPN (se VPN è solo IPv4)
Get-NetAdapter | Where-Object {$_.Name -notmatch "tun|vpn|wg"} | ForEach-Object {
    Set-NetAdapterBinding -Name $_.Name -ComponentID "ms_tcpip6" -Enabled $false
}

# Forzare DNS solo sull'interfaccia VPN
# Prima trovare l'InterfaceIndex della VPN
Get-NetAdapter | Select-Object Name, InterfaceIndex

# Poi impostare DNS
Set-DnsClientServerAddress -InterfaceIndex <VPN_INDEX> -ServerAddresses "10.0.0.53"
```

### DNS over HTTPS/TLS per Protezione Aggiuntiva

```bash
# Installare dnscrypt-proxy
sudo apt install dnscrypt-proxy -y

# /etc/dnscrypt-proxy/dnscrypt-proxy.toml
listen_addresses = ['127.0.0.53:53']
server_names = ['cloudflare', 'google']

# Forzare uso DoH/DoT
require_dnssec = true
require_nolog = true
require_nofilter = false

# Routing tramite VPN (dnscrypt-proxy usa il tunnel WireGuard/OpenVPN)
```

---

## VPN Kill Switch

### Cos'è un Kill Switch

Un **Kill Switch** (o Network Lock) è un meccanismo che **blocca tutto il traffico di rete** nel momento in cui la connessione VPN cade, impedendo che il traffico esca "in chiaro" attraverso la connessione ISP.

```
SENZA Kill Switch:
VPN attiva:   Traffico → [tun0] → VPN Server → Internet
VPN cade:     Traffico → [eth0] → ISP → Internet  ← IP REALE ESPOSTO!

CON Kill Switch:
VPN attiva:   Traffico → [tun0] → VPN Server → Internet
VPN cade:     Traffico → [BLOCCATO da firewall] → nessuna connessione
```

### Kill Switch con iptables (Linux)

#### Approccio Blocca-Tutto con Eccezioni

```bash
#!/bin/bash
# kill_switch_on.sh - Attiva il Kill Switch

VPN_SERVER_IP="1.2.3.4"          # IP del server VPN
VPN_PORT="1194"                   # Porta del server VPN
VPN_PROTO="udp"                   # Protocollo VPN
LOCAL_NET="192.168.1.0/24"        # Rete locale (per accesso a gateway/stampanti)
WG_INTERFACE="wg0"                # Interfaccia VPN (wg0 per WireGuard, tun0 per OpenVPN)

echo "[*] Attivazione Kill Switch..."

# Pulire regole esistenti
iptables -F
iptables -X
ip6tables -F
ip6tables -X

# Policy di default: BLOCCA tutto
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Permettere loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permettere connessioni già stabilite
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Permettere connessione al SERVER VPN (necessario per riconnettere)
iptables -A OUTPUT -d $VPN_SERVER_IP -p $VPN_PROTO --dport $VPN_PORT -j ACCEPT

# Permettere traffico VPN (una volta connessi)
iptables -A INPUT -i $WG_INTERFACE -j ACCEPT
iptables -A OUTPUT -o $WG_INTERFACE -j ACCEPT

# Permettere traffico LAN locale (opzionale, rimuovere per massima sicurezza)
# iptables -A INPUT -s $LOCAL_NET -j ACCEPT
# iptables -A OUTPUT -d $LOCAL_NET -j ACCEPT

# BLOCCARE tutto il resto (incluso DNS non-VPN)
# (le regole di default DROP si applicano)

# Bloccare IPv6 completamente (se VPN è solo IPv4)
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

echo "[+] Kill Switch attivo. Solo traffico VPN permesso."
iptables -L -n --line-numbers
```

```bash
#!/bin/bash
# kill_switch_off.sh - Disattiva il Kill Switch

iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

ip6tables -F
ip6tables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

echo "[+] Kill Switch disattivato. Traffico normale ripristinato."
```

### Kill Switch con nftables (Linux moderno)

```bash
# /etc/nftables-killswitch.conf

table inet kill_switch {
    chain input {
        type filter hook input priority 0; policy drop;
        
        iif lo accept
        ct state established,related accept
        iifname "wg0" accept
    }
    
    chain output {
        type filter hook output priority 0; policy drop;
        
        oif lo accept
        ct state established,related accept
        oifname "wg0" accept
        
        # Permettere connessione iniziale al server VPN
        ip daddr 1.2.3.4 udp dport 51820 accept
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
```

```bash
# Applicare
sudo nft -f /etc/nftables-killswitch.conf

# Verificare
sudo nft list ruleset
```

### Kill Switch con WireGuard (Metodo Integrato)

WireGuard supporta un kill switch nativo tramite le opzioni `PreUp`/`PostUp`:

```ini
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.2/24
PrivateKey = <PRIVATE_KEY>
DNS = 10.0.0.1

# Kill Switch integrato WireGuard
# Blocca tutto tranne il traffico WireGuard
PreUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PostDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT ; ip6tables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = vpn.esempio.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Kill Switch su Windows con PowerShell

```powershell
# killswitch_windows.ps1 - Kill Switch tramite Windows Firewall

$VPN_SERVER = "1.2.3.4"
$VPN_INTERFACE = "WireGuard*"   # Nome interfaccia VPN (adattare)

# Bloccare tutto il traffico outbound tranne VPN
New-NetFirewallRule -DisplayName "KillSwitch-BlockAll" `
    -Direction Outbound `
    -Action Block `
    -Priority 1000 `
    -Enabled True

# Permettere solo traffico su interfaccia VPN
New-NetFirewallRule -DisplayName "KillSwitch-AllowVPN" `
    -Direction Outbound `
    -InterfaceAlias $VPN_INTERFACE `
    -Action Allow `
    -Priority 100 `
    -Enabled True

# Permettere connessione al server VPN (per riconnessione)
New-NetFirewallRule -DisplayName "KillSwitch-AllowVPNServer" `
    -Direction Outbound `
    -RemoteAddress $VPN_SERVER `
    -Protocol UDP `
    -RemotePort 51820 `
    -Action Allow `
    -Priority 50 `
    -Enabled True

Write-Host "[+] Kill Switch Windows attivato"

# Per disattivare:
# Remove-NetFirewallRule -DisplayName "KillSwitch-*"
```

---

## Script di Test Completo

```bash
#!/bin/bash
# vpn_security_test.sh - Test completo di sicurezza VPN

echo "====== VPN Security Test ======"
echo ""

# 1. Test IP Pubblico
echo "[1] Verifica IP Pubblico:"
PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "ERRORE")
echo "    IP corrente: $PUBLIC_IP"
echo ""

# 2. Test DNS Leak
echo "[2] Test DNS Leak:"
DNS_IP=$(dig +short myip.opendns.com @208.67.222.222 2>/dev/null || echo "ERRORE")
echo "    IP visto dal DNS OpenDNS: $DNS_IP"

# Verificare quali DNS server vengono usati
echo "    DNS server in uso:"
systemd-resolve --status 2>/dev/null | grep "DNS Server" | head -5
echo ""

# 3. Test interfacce di rete
echo "[3] Interfacce di rete attive:"
ip -4 addr show | grep -E "^[0-9]|inet " | grep -v "127.0.0.1"
echo ""

# 4. Test routing
echo "[4] Default route:"
ip route show default
echo ""

# 5. Test DNS effettivo
echo "[5] Test risoluzione DNS (tramite quale interfaccia?):"
sudo tcpdump -i any -n port 53 -c 5 &
TCPDUMP_PID=$!
dig google.com > /dev/null 2>&1
sleep 1
kill $TCPDUMP_PID 2>/dev/null
echo ""

# 6. Test WebRTC (solo indicativo)
echo "[6] Controlla manualmente WebRTC leak su: https://browserleaks.com/webrtc"
echo ""

# Sommario
echo "====== Sommario ======"
if ip route show | grep -q "tun0\|wg0"; then
    echo "[+] Interfaccia VPN ATTIVA"
else
    echo "[-] Nessuna interfaccia VPN rilevata"
fi

echo "Per test completo visita:"
echo "  - https://dnsleaktest.com"
echo "  - https://ipleak.net"
```

---

## Domande di Verifica

1. **Spiega come avviene un DNS Leak su Windows con la funzionalità "Smart Multi-Homed Name Resolution". Come si disabilita?**

2. **Qual è la differenza tra un DNS Leak e un IP Leak (WebRTC)? Quali informazioni espone ciascuno?**

3. **Descrivi come implementeresti un Kill Switch con iptables. Quali regole sono essenziali e in quale ordine devono essere applicate?**

4. **Perché è importante permettere le connessioni al server VPN anche con il Kill Switch attivo? Cosa succederebbe altrimenti?**

5. **WireGuard ha un meccanismo di Kill Switch integrato tramite `PreUp`/`PostDown`. Spiega come funziona la logica delle regole iptables usate.**

6. **Un utente attiva la VPN ma le query DNS continuano ad andare verso il DNS dell'ISP (8.8.8.8). Elenca tre possibili cause e come diagnosticarle/risolverle.**

---

## Riferimenti

### Tool e Test
- [DNS Leak Test](https://dnsleaktest.com) - Test DNS leak
- [IP Leak](https://ipleak.net) - Test completo (IP, DNS, WebRTC)
- [Browser Leaks](https://browserleaks.com) - Test completo browser
- [Wireshark](https://www.wireshark.org) - Analisi pacchetti DNS

### Documentazione
- [WireGuard Kill Switch Documentation](https://www.wireguard.com/netns/)
- [OpenVPN DNS Configuration](https://openvpn.net/faq/dns-leak/)
- [nftables Documentation](https://wiki.nftables.org/)

### Standard e Guide
- [EFF Privacy Badger](https://www.eff.org/privacybadger)
- [NSA Remote Work Guide](https://media.defense.gov/2020/Jul/16/2002457639/-1/-1/0/TELEWORK_GUIDANCE.PDF)

---

**Sezione Precedente**: [49.4 - Split Tunneling](./49_4_split_tunneling.md)  
**Prossima Sezione**: [49.6 - Zero Trust Network Access (ZTNA)](./49_6_zero_trust_network_access.md)
