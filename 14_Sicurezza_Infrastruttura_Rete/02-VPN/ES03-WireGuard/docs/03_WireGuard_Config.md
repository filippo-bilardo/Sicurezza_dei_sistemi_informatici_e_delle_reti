# Configurazione WireGuard — Riferimento Completo

> **ES03 — WireGuard** | Documento pratico 03

---

## wg0.conf Server — Configurazione Completa

```ini
# /etc/wireguard/wg0.conf — SERVER

[Interface]
# Chiave privata del server (generata con: wg genkey)
PrivateKey = <CHIAVE_PRIVATA_SERVER>

# IP dell'interfaccia VPN del server
Address = 10.0.0.1/24

# Porta di ascolto WireGuard
ListenPort = 51820

# Abilitare routing e NAT (eseguiti prima dell'attivazione dell'interfaccia)
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; \
           iptables -A FORWARD -o %i -j ACCEPT; \
           iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; \
           sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -D FORWARD -i %i -j ACCEPT; \
           iptables -D FORWARD -o %i -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# --- PEER 1: Mario Rossi ---
[Peer]
# Chiave pubblica del client Mario (generata sul laptop di Mario)
PublicKey = <CHIAVE_PUBBLICA_MARIO>
# IP VPN assegnato a Mario (solo /32 — un singolo IP)
AllowedIPs = 10.0.0.2/32

# --- PEER 2: Anna Verdi ---
[Peer]
PublicKey = <CHIAVE_PUBBLICA_ANNA>
AllowedIPs = 10.0.0.3/32
```

> ⚠️ Sostituire `eth0` nella riga PostUp/PostDown con l'interfaccia WAN effettiva del server.

---

## wg0.conf Client — Full Tunnel

```ini
# /etc/wireguard/wg0.conf — CLIENT (Mario Rossi) — FULL TUNNEL

[Interface]
# Chiave privata di Mario (generata sul suo laptop)
PrivateKey = <CHIAVE_PRIVATA_MARIO>

# IP VPN del client
Address = 10.0.0.2/24

# DNS aziendale (opzionale)
DNS = 10.0.0.1

[Peer]
# Chiave pubblica del server
PublicKey = <CHIAVE_PUBBLICA_SERVER>

# IP pubblico e porta del server VPN
Endpoint = 203.0.113.10:51820

# Full tunnel: tutto il traffico passa per la VPN
AllowedIPs = 0.0.0.0/0

# Mantieni il tunnel attivo anche dietro NAT
PersistentKeepalive = 25
```

## wg0.conf Client — Split Tunnel

```ini
# /etc/wireguard/wg0.conf — CLIENT (Anna Verdi) — SPLIT TUNNEL

[Interface]
PrivateKey = <CHIAVE_PRIVATA_ANNA>
Address = 10.0.0.3/24

[Peer]
PublicKey = <CHIAVE_PUBBLICA_SERVER>
Endpoint = 203.0.113.10:51820

# Split tunnel: solo il traffico verso la rete aziendale passa per la VPN
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24

PersistentKeepalive = 25
```

---

## Comandi wg-quick

```bash
# Attivare l'interfaccia VPN
sudo wg-quick up wg0

# Disattivare l'interfaccia VPN
sudo wg-quick down wg0

# Abilitare all'avvio
sudo systemctl enable wg-quick@wg0

# Verificare lo stato dei peer
sudo wg show

# Ricaricare la configurazione senza interrompere le connessioni attive
sudo wg syncconf wg0 <(wg-quick strip wg0)
```

---

## Comandi di Verifica

### Sul server

```bash
# Stato del tunnel e dei peer connessi
sudo wg show

# Output di esempio:
# interface: wg0
#   public key: YamzMVRVhFxxIW+...
#   private key: (hidden)
#   listening port: 51820
#
# peer: abc123...  (Mario)
#   endpoint: 192.168.100.5:54321
#   allowed ips: 10.0.0.2/32
#   latest handshake: 30 seconds ago
#   transfer: 1.5 MiB received, 2.3 MiB sent

# Interfaccia wg0
ip addr show wg0

# Tabella di routing
ip route show | grep wg0
```

### Sul client

```bash
# Dopo wg-quick up wg0, verificare l'IP VPN
ip addr show wg0
# Deve mostrare: inet 10.0.0.2/24

# Verificare routing (full tunnel: 0.0.0.0/0 via wg0)
ip route show | head -5

# Testare connettività al server VPN
ping -c 3 10.0.0.1

# Testare accesso alla LAN aziendale
ping -c 3 192.168.1.1
```

---

## Aggiungere un Nuovo Peer Senza Riavviare

```bash
# Generare le chiavi per il nuovo peer (Carlo Bruni)
wg genkey | tee carlo_private | wg pubkey > carlo_public

# Aggiungere il peer al server in tempo reale (senza down/up)
sudo wg set wg0 peer $(cat carlo_public) allowed-ips 10.0.0.4/32

# Salvare la modifica in wg0.conf
sudo wg-quick save wg0
```

---

*Prossimo documento: [04 — Troubleshooting](04_Troubleshooting.md)*
