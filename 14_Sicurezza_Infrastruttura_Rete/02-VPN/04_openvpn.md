# Capitolo 04 - OpenVPN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 04 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

**OpenVPN** è una soluzione VPN open-source basata su SSL/TLS che permette di creare tunnel cifrati su reti pubbliche. È uno degli standard de facto per le VPN aziendali e personali grazie alla sua flessibilità, sicurezza e compatibilità multipiattaforma.

### Obiettivi di Apprendimento
- Comprendere l'architettura e il funzionamento di OpenVPN
- Configurare un server OpenVPN da zero
- Gestire certificati e PKI per OpenVPN
- Implementare policy di sicurezza avanzate
- Effettuare troubleshooting delle connessioni VPN

---

## Concetti Principali

### Definizione

OpenVPN è un'implementazione VPN che utilizza il protocollo **SSL/TLS** per la cifratura del canale di controllo e dati. Può operare su UDP (preferito per performance) o TCP (per compatibilità con firewall restrittivi).

**Caratteristiche distintive:**
- Utilizza la libreria **OpenSSL** per la crittografia
- Supporta modalità **tun** (layer 3, routing) e **tap** (layer 2, bridging)
- Autenticazione tramite **certificati X.509**, chiavi pre-condivise o username/password
- Attraversamento di NAT e firewall tramite UDP/TCP su porta configurabile (default 1194)
- Supporto a plugin e script per estendibilità

### Architettura

```
Client                          Server
  |                               |
  |---[TLS Handshake]------------>|
  |<--[Certificato Server]--------|
  |---[Certificato Client]------->|
  |                               |
  |====[Canale Controllo TLS]====|
  |                               |
  |---[Push/Pull Opzioni]-------->|
  |<--[IP, Route, DNS]------------|
  |                               |
  |====[Canale Dati Cifrato]=====>|
       (AES-256-GCM default)
```

**Componenti chiave:**
- **PKI (Public Key Infrastructure)**: CA, certificati server e client
- **TLS Auth / TLS Crypt**: protezione contro DoS e port scanning
- **Data Channel**: traffico utente cifrato con algoritmo simmetrico
- **Control Channel**: gestione connessione, rekeying periodico

---

## Installazione e Configurazione

### Installazione Server (Ubuntu/Debian)

```bash
# Installazione
sudo apt update && sudo apt install openvpn easy-rsa -y

# Creazione struttura PKI
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
```

### Configurazione PKI con Easy-RSA 3

```bash
# Inizializzazione PKI
./easyrsa init-pki

# Creazione CA
./easyrsa build-ca nopass

# Generazione certificato e chiave server
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generazione parametri Diffie-Hellman
./easyrsa gen-dh

# Generazione certificati client
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1

# Generazione chiave TLS-Auth (protezione DoS)
openvpn --genkey secret ta.key
```

### Configurazione Server (`/etc/openvpn/server.conf`)

```ini
# Protocollo e porta
port 1194
proto udp
dev tun

# Certificati PKI
ca   /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key  /etc/openvpn/pki/private/server.key
dh   /etc/openvpn/pki/dh.pem

# Range IP per i client VPN
server 10.8.0.0 255.255.255.0

# Persistenza IP client (associa IP fisso a certificato)
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Spingere rotte ai client
push "route 192.168.1.0 255.255.255.0"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Protezione TLS avanzata
tls-auth /etc/openvpn/ta.key 0
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Crittografia
cipher AES-256-GCM
auth SHA256
ncp-ciphers AES-256-GCM:AES-128-GCM

# Compressione (disabilitata per sicurezza - attacco VORACLE)
# compress lz4-v2  # NON abilitare su server pubblici

# Keepalive e timeout
keepalive 10 120
max-clients 100

# Privilege dropping
user nobody
group nogroup
persist-key
persist-tun

# Logging
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3

# CRL per revocare certificati compromessi
crl-verify /etc/openvpn/pki/crl.pem
```

### Abilitazione IP Forwarding e NAT

```bash
# Abilitare IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Regola iptables per NAT (sostituire eth0 con l'interfaccia corretta)
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Persistere le regole iptables
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### Avvio e Gestione Servizio

```bash
# Avviare il servizio
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server

# Verificare stato
sudo systemctl status openvpn@server

# Monitorare connessioni attive
sudo cat /var/log/openvpn/openvpn-status.log
```

### Configurazione Client (`client.ovpn`)

```ini
client
dev tun
proto udp
remote vpn.esempio.com 1194

# Verifica hostname nel certificato server
verify-x509-name server name

resolv-retry infinite
nobind

# Privilege dropping (Linux)
user nobody
group nogroup

persist-key
persist-tun

# Protezione TLS
tls-auth ta.key 1
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

cipher AES-256-GCM
auth SHA256

remote-cert-tls server

verb 3

# Certificati inline (opzionale, tutto in un file)
<ca>
-----BEGIN CERTIFICATE-----
...CA CERTIFICATE...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
...CLIENT CERTIFICATE...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
...CLIENT PRIVATE KEY...
-----END PRIVATE KEY-----
</key>

<tls-auth>
-----BEGIN OpenVPN Static key V1-----
...TLS AUTH KEY...
-----END OpenVPN Static key V1-----
</tls-auth>
```

---

## Sicurezza Avanzata

### TLS-Crypt (OpenVPN 2.4+)

`tls-crypt` è più sicuro di `tls-auth`: cifra **e** autentica il canale di controllo TLS, rendendo impossible l'identificazione dei pacchetti OpenVPN da parte di un osservatore esterno (utile contro firewall DPI).

```bash
# Generazione chiave tls-crypt
openvpn --genkey secret tc.key
```

```ini
# Nel server.conf (sostituisce tls-auth)
tls-crypt /etc/openvpn/tc.key
```

### Revoca Certificati (CRL)

```bash
# Revocare un certificato compromesso
cd ~/openvpn-ca
./easyrsa revoke client1
./easyrsa gen-crl

# Copiare la CRL aggiornata nella directory OpenVPN
sudo cp pki/crl.pem /etc/openvpn/pki/crl.pem
sudo chmod 644 /etc/openvpn/pki/crl.pem
sudo systemctl restart openvpn@server
```

### Two-Factor Authentication con PAM

```ini
# In server.conf aggiungere:
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login

# In client.conf aggiungere:
auth-user-pass
```

### Script di Generazione Client Automatizzata

```bash
#!/bin/bash
# generate_client.sh - Genera un profilo .ovpn completo per un nuovo client

CLIENT_NAME=$1
OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="$HOME/openvpn-ca"
OUTPUT_DIR="$HOME/client-configs"

if [ -z "$CLIENT_NAME" ]; then
    echo "Uso: $0 <nome_client>"
    exit 1
fi

# Generare certificato client
cd "$EASYRSA_DIR"
./easyrsa gen-req "$CLIENT_NAME" nopass
./easyrsa sign-req client "$CLIENT_NAME"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/${CLIENT_NAME}.ovpn"

# Creare file .ovpn
cat > "$OUTPUT_FILE" << EOF
client
dev tun
proto udp
remote vpn.esempio.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>

<cert>
$(cat "$EASYRSA_DIR/pki/issued/${CLIENT_NAME}.crt")
</cert>

<key>
$(cat "$EASYRSA_DIR/pki/private/${CLIENT_NAME}.key")
</key>

<tls-crypt>
$(cat "$OPENVPN_DIR/tc.key")
</tls-crypt>
EOF

echo "[+] Profilo generato: $OUTPUT_FILE"
```

---

## Troubleshooting

### Problemi Comuni

| Problema | Possibile Causa | Soluzione |
|----------|----------------|-----------|
| `TLS handshake failed` | Mismatch CA o certificati scaduti | Verificare CA e date certificati |
| `AUTH_FAILED` | Credenziali errate o certificato revocato | Verificare CRL e credenziali |
| `Connection timed out` | Firewall blocca porta 1194/UDP | Provare TCP o porta 443 |
| Traffico lento | MTU non ottimale | Aggiungere `tun-mtu 1400` |
| `SIGUSR1[soft,ping-restart]` | Keepalive scaduto, rete instabile | Aumentare timeout keepalive |

### Comandi di Diagnostica

```bash
# Verificare i log del server
sudo journalctl -u openvpn@server -f

# Monitorare client connessi in tempo reale
sudo watch -n 2 cat /var/log/openvpn/openvpn-status.log

# Test connettività porta
nc -uvz vpn.esempio.com 1194

# Verificare certificato
openssl x509 -in /etc/openvpn/pki/issued/server.crt -text -noout | grep -E "Not|Subject|Issuer"

# Debug connessione client (aumentare verbosità)
openvpn --config client.ovpn --verb 6
```

---

## Domande di Verifica

1. **Qual è la differenza tra modalità `tun` e `tap` in OpenVPN? In quali scenari useresti ciascuna?**

2. **Spiega la differenza tra `tls-auth` e `tls-crypt`. Perché `tls-crypt` è considerato più sicuro?**

3. **Come si revoca un certificato client in OpenVPN? Quali passaggi sono necessari per garantire che il client revocato non possa più connettersi?**

4. **Perché la compressione (opzione `compress`) è considerata un rischio di sicurezza in OpenVPN? Quale attacco sfrutta questa vulnerabilità?**

5. **Descrivi il processo di autenticazione in OpenVPN con certificati X.509. Quali informazioni vengono verificate durante il TLS handshake?**

6. **Come configureresti OpenVPN per il full-tunnel (tutto il traffico attraverso la VPN) vs split-tunnel? Quali sono i vantaggi e svantaggi di ciascun approccio?**

---

## Riferimenti

### Documentazione Ufficiale
- [OpenVPN Documentation](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/)
- [Easy-RSA 3 Documentation](https://easy-rsa.readthedocs.io/en/latest/)
- [OpenVPN Security Overview](https://openvpn.net/security-overview/)

### Risorse Aggiuntive
- [OpenVPN Hardening Guide](https://community.openvpn.net/openvpn/wiki/Hardening)
- [VORACLE Attack (CVE)](https://openvpn.net/security-advisories/the-voracle-attack-vulnerability/)
- [OpenVPN + MFA con Google Authenticator](https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-ubuntu-20-04)

### Libri
- "Mastering OpenVPN" - Eric F Crist, Jan Just Keijser
- "Network Security with OpenSSL" - John Viega, Matt Messier

---

**Sezione Precedente**: [03 - IPsec VPN](./03_ipsec_vpn.md)  
**Prossima Sezione**: [05 - WireGuard](./05_wireguard.md)
