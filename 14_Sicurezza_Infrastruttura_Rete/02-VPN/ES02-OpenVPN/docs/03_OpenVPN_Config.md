# Configurazione OpenVPN — Riferimento Completo

> **ES02 — OpenVPN** | Documento pratico 03

---

## server.conf — Configurazione Server

```ini
# /etc/openvpn/server/server.conf

# --- Rete ---
port 1194                        # Porta di ascolto
proto udp                        # UDP è più performante di TCP
dev tun                          # Interfaccia tunnel Layer 3

# --- Certificati e chiavi ---
ca   /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key  /etc/openvpn/server/server.key   # Tenere segreto
dh   /etc/openvpn/server/dh.pem

# --- Revoca certificati ---
crl-verify /etc/openvpn/server/crl.pem

# --- Range IP VPN ---
server 10.8.0.0 255.255.255.0    # Assegna ai client IP da 10.8.0.2 in poi
                                  # Il server prende 10.8.0.1

# --- Routing verso la LAN aziendale ---
push "route 192.168.1.0 255.255.255.0"   # Client impara il percorso verso la LAN

# --- DNS ---
push "dhcp-option DNS 192.168.1.1"       # DNS aziendale (opzionale)

# --- Full tunnel (commentare per split tunnel) ---
push "redirect-gateway def1 bypass-dhcp"  # Forza tutto il traffico nel tunnel

# --- Persistenza e stabilità ---
keepalive 10 120                 # Ping ogni 10s, timeout dopo 120s
persist-key
persist-tun
user nobody
group nogroup

# --- Sicurezza ---
tls-crypt /etc/openvpn/server/tc.key    # Cifra il canale di controllo
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# --- Log ---
status /var/log/openvpn/status.log 10
log-append /var/log/openvpn/openvpn.log
verb 3                           # Verbosità (0=silenzioso, 9=debug)
```

---

## Abilitare IP Forwarding e NAT

Dopo aver configurato il server, bisogna abilitare il routing nel kernel Linux e il NAT:

```bash
# Abilitare ip_forward (permanente)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT: i client VPN (10.8.0.0/24) escono con l'IP del server verso Internet
# Sostituire "eth0" con l'interfaccia WAN del server
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT

# Rendere permanente il NAT (Ubuntu con iptables-persistent)
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

---

## Avviare il Server OpenVPN

```bash
# Avviare il servizio
sudo systemctl start openvpn-server@server
sudo systemctl enable openvpn-server@server   # Avvio automatico al boot

# Verificare lo stato
sudo systemctl status openvpn-server@server

# Seguire i log in tempo reale
sudo tail -f /var/log/openvpn/openvpn.log
```

---

## client.ovpn — Configurazione Client

```ini
# mario-rossi.ovpn

client
dev tun
proto udp
remote 203.0.113.10 1194    # IP pubblico o hostname del server VPN

resolv-retry infinite
nobind
persist-key
persist-tun

# Sicurezza
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
verb 3

# Certificati (inline — tutto in un file)
<ca>
-----BEGIN CERTIFICATE-----
... (contenuto ca.crt) ...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
... (contenuto mario-rossi.crt) ...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
... (contenuto mario-rossi.key) ...
-----END PRIVATE KEY-----
</key>

<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
... (contenuto tc.key) ...
-----END OpenVPN Static key V1-----
</tls-crypt>
```

### Script per generare .ovpn automaticamente

```bash
#!/bin/bash
# Uso: ./genera_ovpn.sh mario-rossi

CLIENT=$1
PKI_DIR=/etc/openvpn/easy-rsa/pki
OUTPUT=~/${CLIENT}.ovpn

cat > $OUTPUT <<EOF
client
dev tun
proto udp
remote 203.0.113.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
<ca>
$(cat $PKI_DIR/ca.crt)
</ca>
<cert>
$(cat $PKI_DIR/issued/${CLIENT}.crt)
</cert>
<key>
$(cat $PKI_DIR/private/${CLIENT}.key)
</key>
<tls-crypt>
$(cat $PKI_DIR/tc.key)
</tls-crypt>
EOF

echo "Profilo generato: $OUTPUT"
```

---

## Comandi di Verifica

### Sul server

```bash
# Client connessi in questo momento
sudo cat /var/log/openvpn/status.log

# Interfaccia tun0
ip addr show tun0

# Tabella di routing (deve includere 10.8.0.0/24)
ip route show

# Connessioni attive sulla porta VPN
sudo ss -ulnp | grep 1194
```

### Sul client Linux

```bash
# Connettersi con il profilo .ovpn
sudo openvpn --config mario-rossi.ovpn

# Dopo la connessione, verificare l'IP VPN
ip addr show tun0
# Deve mostrare: inet 10.8.0.2/24

# Verificare che le route aziendali siano presenti
ip route show | grep 192.168.1

# Testare la connettività con la rete aziendale
ping 192.168.1.1

# Verificare che il DNS aziendale funzioni (se configurato)
nslookup server.azienda.local
```

---

*Prossimo documento: [04 — Troubleshooting](04_Troubleshooting.md)*
