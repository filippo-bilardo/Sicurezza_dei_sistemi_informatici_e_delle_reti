# ES03-A — Laboratorio guidato: Server WireGuard Road Warrior

> **Tipo**: 🔬 Laboratorio guidato  
> **Durata stimata**: 2–3 ore  
> **Punteggio**: 100 punti  
> **File da consegnare**: screenshot nella cartella `img/` + file `wg0.conf`

---

## 📸 Riepilogo Screenshot Richiesti

| # | Screenshot | Step | Descrizione |
|---|-----------|------|-------------|
| 📸1 | `es03a_01_install.png` | STEP 1 | Installazione WireGuard completata |
| 📸2 | `es03a_02_chiavi_server.png` | STEP 2 | Generazione chiavi sul server |
| 📸3 | `es03a_03_chiavi_client.png` | STEP 2 | Generazione chiavi sul client |
| 📸4 | `es03a_04_server_conf.png` | STEP 3 | Contenuto di wg0.conf sul server |
| 📸5 | `es03a_05_server_up.png` | STEP 3 | `wg show` sul server dopo wg-quick up |
| 📸6 | `es03a_06_client_conf.png` | STEP 4 | Contenuto di wg0.conf sul client |
| 📸7 | `es03a_07_wg_show.png` | STEP 5 | `wg show` sul client — handshake avvenuto |
| 📸8 | `es03a_08_ip_wg0.png` | STEP 5 | `ip addr show wg0` sul client: IP 10.0.0.2 |
| 📸9 | `es03a_09_ping_lan.png` | STEP 6 | Ping dal client alla LAN aziendale |
| 📸10 | `es03a_10_wg_show_server.png` | STEP 6 | `wg show` sul server — peer connesso con traffico |

---

## 🌐 Scenario

L'azienda **TechItalia S.r.l.** vuole migrare la propria VPN da OpenVPN a **WireGuard** per ottenere prestazioni migliori e una configurazione più semplice da manutenere.

Il tecnico **Mario Rossi** deve potersi connettere alla rete aziendale (`192.168.56.0/24`) tramite WireGuard con full tunnel.

---

## 🗺️ Topologia

```
CASA (Client)                          SEDE AZIENDALE (Server)
VM Client Ubuntu                        VM Server Ubuntu
────────────────                        ─────────────────────
eth0: 192.168.56.10                     eth0: 192.168.56.1
(Host-Only — simula Internet)

Dopo la connessione VPN:
wg0: 10.0.0.2                           wg0: 10.0.0.1

Obiettivo: ping da 10.0.0.2 → 192.168.56.1 (e tutta la rete aziendale)
```

> Utilizza le stesse VM dell'esercitazione ES02 (stesso ambiente VirtualBox).

---

## STEP 1 — Installazione WireGuard (10 punti)

**Su entrambe le VM:**

```bash
sudo apt update && sudo apt install wireguard wireguard-tools -y
```

**Verifica:**

```bash
wg --version
# WireGuard Tools, v1.0.x

# Verificare che il modulo kernel sia disponibile
lsmod | grep wireguard
# Se vuoto: sudo modprobe wireguard
```

📸 **Screenshot 1**: output di `wg --version` su entrambe le VM

---

## STEP 2 — Generazione delle Chiavi (20 punti)

### Sul server

```bash
# Creare la directory di configurazione
sudo mkdir -p /etc/wireguard
cd /etc/wireguard

# Generare le chiavi
wg genkey | sudo tee /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

# Visualizzare le chiavi (annotarle!)
echo "=== CHIAVE PRIVATA SERVER (tenere segreta) ==="
sudo cat /etc/wireguard/private.key

echo "=== CHIAVE PUBBLICA SERVER (condividere con i client) ==="
cat /etc/wireguard/public.key

# Proteggere la chiave privata
sudo chmod 600 /etc/wireguard/private.key
```

📸 **Screenshot 2**: chiave pubblica del server (annotarla per il STEP 4)

### Sul client

```bash
sudo mkdir -p /etc/wireguard
wg genkey | sudo tee /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

echo "=== CHIAVE PUBBLICA CLIENT (da inserire nel server) ==="
cat /etc/wireguard/public.key

sudo chmod 600 /etc/wireguard/private.key
```

📸 **Screenshot 3**: chiave pubblica del client (annotarla per il STEP 3)

---

## STEP 3 — Configurazione Server (25 punti)

```bash
sudo nano /etc/wireguard/wg0.conf
```

```ini
[Interface]
# Incollare la chiave privata del server
PrivateKey = <CHIAVE_PRIVATA_SERVER>
Address = 10.0.0.1/24
ListenPort = 51820

# NAT e forwarding (sostituire eth0 con l'interfaccia WAN del server)
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; \
           iptables -A FORWARD -o %i -j ACCEPT; \
           iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; \
           sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -D FORWARD -i %i -j ACCEPT; \
           iptables -D FORWARD -o %i -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Incollare la chiave pubblica del CLIENT (copiata dallo screenshot 3)
PublicKey = <CHIAVE_PUBBLICA_CLIENT>
AllowedIPs = 10.0.0.2/32
```

```bash
# Proteggere il file di configurazione
sudo chmod 600 /etc/wireguard/wg0.conf

# Attivare l'interfaccia
sudo wg-quick up wg0

# Abilitare all'avvio
sudo systemctl enable wg-quick@wg0

# Verificare
sudo wg show
```

📸 **Screenshot 4**: contenuto di `wg0.conf` del server  
📸 **Screenshot 5**: output di `sudo wg show` — interfaccia attiva, peer in ascolto

---

## STEP 4 — Configurazione Client (25 punti)

```bash
sudo nano /etc/wireguard/wg0.conf
```

```ini
[Interface]
# Incollare la chiave privata del CLIENT
PrivateKey = <CHIAVE_PRIVATA_CLIENT>
Address = 10.0.0.2/24

[Peer]
# Incollare la chiave pubblica del SERVER (copiata dallo screenshot 2)
PublicKey = <CHIAVE_PUBBLICA_SERVER>

# IP:porta del server (interfaccia Host-Only del server)
Endpoint = 192.168.56.1:51820

# Full tunnel: tutto il traffico passa per la VPN
AllowedIPs = 0.0.0.0/0

# Keepalive per mantenere il tunnel attivo dietro NAT
PersistentKeepalive = 25
```

```bash
sudo chmod 600 /etc/wireguard/wg0.conf
```

📸 **Screenshot 6**: contenuto di `wg0.conf` del client

---

## STEP 5 — Connessione e Verifica Tunnel (12 punti)

**Sul client:**

```bash
# Attivare il tunnel
sudo wg-quick up wg0

# Verificare l'interfaccia VPN
ip addr show wg0
# Deve mostrare: inet 10.0.0.2/24

# Verificare lo stato del peer
sudo wg show
# Deve mostrare: latest handshake: X seconds ago
```

📸 **Screenshot 7**: `sudo wg show` con `latest handshake`  
📸 **Screenshot 8**: `ip addr show wg0` con IP `10.0.0.2`

---

## STEP 6 — Test Connettività (8 punti)

```bash
# Dal client: ping al server VPN tramite il tunnel
ping -c 4 10.0.0.1
# Deve rispondere!

# Sul server: verificare che il client appaia connesso con traffico
sudo wg show
```

📸 **Screenshot 9**: ping `10.0.0.1` con risposta dal client  
📸 **Screenshot 10**: `wg show` sul server — peer con `transfer` non zero

---

## 📝 Domande di Riflessione

Rispondi in `risposte_a.md`:

1. **`AllowedIPs = 0.0.0.0/0` nel client — cosa significa? Tutto il traffico passa per la VPN, anche YouTube?**
2. **Prova a cambiare `AllowedIPs = 10.0.0.0/24`. Cosa cambia? Riesci ancora a fare ping a 10.0.0.1?**
3. **Quanto è stato più semplice configurare WireGuard rispetto a OpenVPN (ES02)? Elenca le differenze principali.**

---

## 📊 Punteggio

| Sezione | Punti |
|---------|-------|
| STEP 1 — Installazione | 10 |
| STEP 2 — Generazione chiavi | 20 |
| STEP 3 — Configurazione server | 25 |
| STEP 4 — Configurazione client | 25 |
| STEP 5 — Connessione e verifica | 12 |
| STEP 6 — Test connettività | 8 |
| **Totale** | **100** |

---

*ES03-A — Sistemi e Reti | Laboratorio guidato WireGuard*
