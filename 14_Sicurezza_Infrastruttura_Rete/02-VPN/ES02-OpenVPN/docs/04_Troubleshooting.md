# OpenVPN — Troubleshooting

> **ES02 — OpenVPN** | Documento pratico 04

---

## Errori Comuni e Soluzioni

### Errore: TLS handshake failed

```
TLS Error: TLS handshake failed
```

**Cause possibili:**
1. `tc.key` diverso tra server e client → ricopiare la chiave dal server
2. `ca.crt` non corrisponde → usare lo stesso `ca.crt` del server
3. Il server non è raggiungibile sulla porta 1194 → verificare firewall
4. Orario sistema non sincronizzato (i certificati hanno date di validità)

```bash
# Verificare che la porta 1194 sia aperta sul server
sudo ufw status
sudo ufw allow 1194/udp    # Se UFW è attivo

# Sincronizzare l'orologio
sudo timedatectl set-ntp true
```

---

### Errore: VERIFY ERROR (certificato revocato o scaduto)

```
VERIFY ERROR: depth=0, error=certificate revoked
```

Il certificato del client è stato revocato. Se è un test, revocare e ricreare il certificato.

```
VERIFY ERROR: depth=0, error=certificate has expired
```

Il certificato è scaduto. Rigenerare il certificato (Easy-RSA default: 10 anni).

---

### Errore: Cannot open TUN/TAP device

```
Cannot open TUN/TAP dev /dev/net/tun: No such file or directory
```

```bash
# Caricare il modulo tun
sudo modprobe tun
echo "tun" | sudo tee -a /etc/modules
```

---

### Il client si connette ma non raggiungo la LAN aziendale

```bash
# 1. Verificare che IP forwarding sia attivo sul server
cat /proc/sys/net/ipv4/ip_forward
# Deve essere 1

# 2. Verificare la regola NAT
sudo iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE

# 3. Verificare che il server VPN abbia una route verso la LAN
# (se la LAN è su un'altra interfaccia)
ip route show

# 4. Verificare che il server.conf faccia il push della route
grep "push.*route" /etc/openvpn/server/server.conf

# 5. Sul client: verificare le route ricevute
ip route show | grep 192.168.1
```

---

### Disconnessioni frequenti

```bash
# Aumentare il keepalive nel server.conf
keepalive 10 120    # Ping ogni 10s, timeout 120s

# Verificare la stabilità della connessione UDP
# Se il client è dietro un firewall con timeout NAT brevi, usare TCP:
proto tcp
```

---

## Comandi Diagnostica Rapida

```bash
# === SUL SERVER ===

# Stato del servizio
sudo systemctl status openvpn-server@server

# Log in tempo reale
sudo tail -f /var/log/openvpn/openvpn.log

# Client connessi (con IP e traffico)
sudo cat /var/log/openvpn/status.log

# Interfaccia tun0 del server
ip addr show tun0

# Regole iptables NAT
sudo iptables -t nat -L -n -v

# === SUL CLIENT ===

# Connettersi con output verboso
sudo openvpn --config mario-rossi.ovpn --verb 5

# Verificare interfaccia tun0
ip addr show tun0

# Verificare routing
ip route show

# Testare connettività verso la LAN
ping -c 3 192.168.1.1
traceroute 192.168.1.1
```

---

## Checklist Pre-Connessione

```
Server:
  ☐ openvpn-server@server è in esecuzione (systemctl status)
  ☐ Porta 1194/udp aperta nel firewall (ufw/iptables)
  ☐ ip_forward = 1 (cat /proc/sys/net/ipv4/ip_forward)
  ☐ Regola MASQUERADE presente in iptables
  ☐ ca.crt, server.crt, server.key, dh.pem, tc.key in /etc/openvpn/server/
  ☐ crl.pem aggiornata (se ci sono certificati revocati)

Client:
  ☐ File .ovpn ha l'IP/hostname corretto del server
  ☐ ca.crt nel .ovpn è quello della CA del server
  ☐ Certificato client non scaduto e non revocato
  ☐ tc.key nel .ovpn è lo stesso del server
```
