# WireGuard — Troubleshooting

> **ES03 — WireGuard** | Documento pratico 04

---

## Errori Comuni e Soluzioni

### Il tunnel si attiva ma non c'è traffico

```bash
# 1. Verificare che il server stia effettivamente ascoltando
sudo ss -ulnp | grep 51820
# Deve mostrare: udp UNCONN 0 0 0.0.0.0:51820

# 2. Verificare che la porta 51820/udp sia aperta nel firewall
sudo ufw status | grep 51820
sudo ufw allow 51820/udp   # Se necessario

# 3. Verificare ip_forward sul server
cat /proc/sys/net/ipv4/ip_forward
# Deve essere: 1

# 4. Verificare le regole iptables sul server
sudo iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE
sudo iptables -L FORWARD -n -v

# 5. Verificare che AllowedIPs sia corretto su entrambi i lati
sudo wg show
```

---

### `wg show` non mostra "latest handshake"

Se non c'è handshake, i peer non si sono ancora connessi.

```bash
# Sul client: verificare che l'Endpoint sia corretto (IP e porta del server)
cat /etc/wireguard/wg0.conf | grep Endpoint

# Verificare che il server sia raggiungibile
ping 203.0.113.10   # IP del server
nc -zu 203.0.113.10 51820   # Test porta UDP
```

---

### Errore: "RTNETLINK answers: Operation not supported"

WireGuard non è disponibile/caricato nel kernel.

```bash
# Verificare che il modulo sia caricato
lsmod | grep wireguard

# Caricare manualmente
sudo modprobe wireguard

# Su kernel molto vecchi (<5.6), installare il modulo DKMS
sudo apt install wireguard-dkms -y
```

---

### Il client si connette ma non raggiunge la LAN aziendale

```bash
# 1. Verificare che il server abbia una route verso la LAN
ip route show | grep 192.168.1

# 2. Verificare che AllowedIPs del client includa la LAN
# /etc/wireguard/wg0.conf sul client:
# AllowedIPs = 0.0.0.0/0       # full tunnel (include LAN)
# AllowedIPs = 192.168.1.0/24  # split tunnel (deve includere la LAN esplicitamente)

# 3. Verificare NAT sul server
sudo iptables -t nat -L -n -v
```

---

## Comandi Diagnostica Rapida

```bash
# === SUL SERVER ===

# Stato peer e statistiche traffico
sudo wg show

# Interfaccia e IP
ip addr show wg0

# Regole routing
ip route show

# Firewall e NAT
sudo iptables -t nat -L -n -v
sudo iptables -L FORWARD -n -v

# Porta in ascolto
sudo ss -ulnp | grep 51820

# === SUL CLIENT ===

# Stato tunnel
sudo wg show

# Interfaccia VPN
ip addr show wg0

# Routing (verifica full/split tunnel)
ip route show

# Ping al server VPN
ping -c 3 10.0.0.1

# Ping alla LAN aziendale
ping -c 3 192.168.1.1
```

---

## Checklist Pre-Connessione

```
Server:
  ☐ wg-quick@wg0 è attivo (systemctl status wg-quick@wg0)
  ☐ Porta 51820/udp aperta nel firewall (ufw status)
  ☐ ip_forward = 1
  ☐ Regola MASQUERADE presente in iptables
  ☐ La chiave pubblica del client è nella sezione [Peer] di wg0.conf
  ☐ AllowedIPs del client contiene il suo IP VPN (/32)

Client:
  ☐ L'Endpoint nel wg0.conf ha l'IP:porta corretti del server
  ☐ La chiave pubblica del server è nella sezione [Peer]
  ☐ AllowedIPs include le reti che vuoi raggiungere (o 0.0.0.0/0 per full tunnel)
  ☐ Le chiavi privata/pubblica sono correttamente generate sul client
```
