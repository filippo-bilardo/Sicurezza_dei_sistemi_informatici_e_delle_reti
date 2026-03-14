# ES02-A — Laboratorio guidato: Server OpenVPN Road Warrior

> **Tipo**: 🔬 Laboratorio guidato  
> **Durata stimata**: 3–4 ore  
> **Punteggio**: 100 punti  
> **File da consegnare**: screenshot nella cartella `img/` + file di configurazione

---

## 📸 Riepilogo Screenshot Richiesti

| # | Screenshot | Step | Descrizione |
|---|-----------|------|-------------|
| 📸1 | `es02a_01_vm_layout.png` | STEP 1 | Due VM in VirtualBox: Server e Client |
| 📸2 | `es02a_02_install.png` | STEP 2 | Installazione OpenVPN completata |
| 📸3 | `es02a_03_pki_ca.png` | STEP 3 | Creazione CA con Easy-RSA |
| 📸4 | `es02a_04_certificati.png` | STEP 3 | Certificati server e client generati |
| 📸5 | `es02a_05_server_conf.png` | STEP 4 | Contenuto di server.conf |
| 📸6 | `es02a_06_server_running.png` | STEP 4 | `systemctl status openvpn-server@server` — Active |
| 📸7 | `es02a_07_client_connect.png` | STEP 5 | Client in connessione al server |
| 📸8 | `es02a_08_tun0_ip.png` | STEP 5 | `ip addr show tun0` sul client: IP 10.8.0.x |
| 📸9 | `es02a_09_ping_lan.png` | STEP 6 | Ping dalla VPN verso la LAN aziendale |
| 📸10 | `es02a_10_status_log.png` | STEP 6 | status.log del server con il client connesso |

---

## 🌐 Scenario

L'azienda **TechItalia S.r.l.** ha la propria sede con server interni accessibili solo dalla LAN (`192.168.56.0/24`). Il tecnico **Mario Rossi** lavora da casa e deve connettersi in modo sicuro alla rete aziendale per accedere al file server.

La soluzione: un server **OpenVPN** sul gateway aziendale che accetta connessioni TLS, verifica l'identità di Mario tramite certificato digitale e gli assegna un indirizzo VPN da cui può raggiungere tutti i server interni.

---

## 🗺️ Topologia

```
CASA (Client)                          SEDE AZIENDALE (Server)
VM Client Ubuntu                        VM Server Ubuntu
────────────────                        ───────────────────────────
eth0: 192.168.56.10                     eth0: 192.168.56.1
      (Host-Only — simula Internet)           (Host-Only — simula Internet/WAN)
                                        eth1: 10.0.0.1
                                              (Internal — LAN aziendale)

Dopo la connessione VPN:
tun0: 10.8.0.2/24 (client)   ════ tunnel OpenVPN ════  tun0: 10.8.0.1/24 (server)

Obiettivo: il client accede a 10.0.0.0/24 (LAN aziendale) tramite la VPN
```

> **Nota sulle VM**: utilizziamo VirtualBox con due reti:
> - **Host-Only** (`192.168.56.0/24`): simula Internet tra client e server
> - **Internal Network** (`10.0.0.0/24`): simula la LAN aziendale (solo server e macchine interne)

---

## STEP 1 — Preparazione dell'Ambiente (8 punti)

### 1.1 Creare le VM in VirtualBox

Crea **due VM Ubuntu Server 22.04**:

| VM | Nome | RAM | Rete 1 | Rete 2 |
|----|------|-----|--------|--------|
| Server VPN | `vpn-server` | 1 GB | Host-Only (`vboxnet0`) | Internal (`intnet`) |
| Client VPN | `vpn-client` | 512 MB | Host-Only (`vboxnet0`) | — |

### 1.2 Configurare gli IP statici

**Sul Server (`/etc/netplan/01-netcfg.yaml`):**

```yaml
network:
  version: 2
  ethernets:
    enp0s3:                    # Interfaccia Host-Only (nome potrebbe variare)
      addresses: [192.168.56.1/24]
    enp0s8:                    # Interfaccia Internal (LAN aziendale simulata)
      addresses: [10.0.0.1/24]
```

```bash
sudo netplan apply
```

**Sul Client (`/etc/netplan/01-netcfg.yaml`):**

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.56.10/24]
      routes:
        - to: default
          via: 192.168.56.1
```

```bash
sudo netplan apply
```

### 1.3 Verifica

```bash
# Dal client: verifica che il server sia raggiungibile
ping -c 3 192.168.56.1

# Dal server: verifica le interfacce
ip addr show
```

📸 **Screenshot 1**: finestra VirtualBox con le due VM avviate

---

## STEP 2 — Installazione OpenVPN e Easy-RSA (10 punti)

**Su entrambe le VM:**

```bash
sudo apt update && sudo apt install openvpn easy-rsa -y
```

**Verifica:**

```bash
openvpn --version
# deve mostrare OpenVPN 2.5.x o superiore
```

📸 **Screenshot 2**: output di `openvpn --version` sulla VM server

---

## STEP 3 — Creazione PKI e Certificati (25 punti)

**Sul server VPN:**

### 3.1 Inizializzare Easy-RSA

```bash
make-cadir ~/openvpn-pki
cd ~/openvpn-pki
./easyrsa init-pki
```

### 3.2 Creare la CA

```bash
./easyrsa build-ca nopass
# Common Name: TechItalia-VPN-CA
```

📸 **Screenshot 3**: output della creazione CA

### 3.3 Generare certificato server

```bash
./easyrsa gen-req server nopass
# Common Name: server

./easyrsa sign-req server server
# Digitare: yes
```

### 3.4 Generare parametri DH e chiave TLS-Crypt

```bash
./easyrsa gen-dh      # Attendere 1–5 minuti

openvpn --genkey secret ~/openvpn-pki/pki/tc.key
```

### 3.5 Generare certificato client (Mario Rossi)

```bash
./easyrsa gen-req mario-rossi nopass
# Common Name: mario-rossi

./easyrsa sign-req client mario-rossi
# Digitare: yes
```

### 3.6 Copiare i file nella directory OpenVPN

```bash
sudo mkdir -p /etc/openvpn/server

sudo cp ~/openvpn-pki/pki/ca.crt                    /etc/openvpn/server/
sudo cp ~/openvpn-pki/pki/issued/server.crt          /etc/openvpn/server/
sudo cp ~/openvpn-pki/pki/private/server.key         /etc/openvpn/server/
sudo cp ~/openvpn-pki/pki/dh.pem                     /etc/openvpn/server/
sudo cp ~/openvpn-pki/pki/tc.key                     /etc/openvpn/server/

# Proteggere le chiavi private
sudo chmod 600 /etc/openvpn/server/*.key
```

📸 **Screenshot 4**: output di `ls -la /etc/openvpn/server/`

---

## STEP 4 — Configurazione Server OpenVPN (25 punti)

### 4.1 Creare server.conf

```bash
sudo nano /etc/openvpn/server/server.conf
```

```ini
port 1194
proto udp
dev tun

ca   /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key  /etc/openvpn/server/server.key
dh   /etc/openvpn/server/dh.pem

server 10.8.0.0 255.255.255.0

# Route verso la LAN aziendale (10.0.0.0/24)
push "route 10.0.0.0 255.255.255.0"

keepalive 10 120
tls-crypt /etc/openvpn/server/tc.key
cipher AES-256-GCM
auth SHA256
persist-key
persist-tun
user nobody
group nogroup

status /var/log/openvpn/status.log 10
log-append /var/log/openvpn/openvpn.log
verb 3
```

```bash
sudo mkdir -p /var/log/openvpn
```

### 4.2 Abilitare IP forwarding e NAT

```bash
# IP forwarding permanente
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT per i client VPN
sudo apt install iptables-persistent -y

sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o enp0s8 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT

sudo netfilter-persistent save
```

> ⚠️ Sostituire `enp0s8` con l'interfaccia della LAN aziendale (verifica con `ip addr`).

### 4.3 Avviare il server

```bash
sudo systemctl start openvpn-server@server
sudo systemctl enable openvpn-server@server
sudo systemctl status openvpn-server@server
```

📸 **Screenshot 5**: contenuto di `server.conf`  
📸 **Screenshot 6**: `systemctl status openvpn-server@server` — **Active (running)**

---

## STEP 5 — Configurazione Client (20 punti)

### 5.1 Creare il profilo .ovpn

**Sul server**, eseguire lo script (consultare `docs/03_OpenVPN_Config.md` per il testo):

```bash
# Creare e adattare lo script genera_ovpn.sh
# poi eseguire:
bash genera_ovpn.sh mario-rossi
```

**Oppure creare manualmente** `mario-rossi.ovpn` con i contenuti di:
- `ca.crt`
- `mario-rossi.crt`
- `mario-rossi.key`
- `tc.key`

### 5.2 Trasferire il profilo al client

```bash
# Dal server al client tramite SCP
scp ~/mario-rossi.ovpn utente@192.168.56.10:~/
```

### 5.3 Connettersi dal client

**Sul client:**

```bash
sudo openvpn --config ~/mario-rossi.ovpn
```

📸 **Screenshot 7**: output del client durante la connessione (riga `Initialization Sequence Completed`)

### 5.4 Verificare l'IP VPN

```bash
# In un altro terminale sul client
ip addr show tun0
# Deve mostrare: inet 10.8.0.2/24
```

📸 **Screenshot 8**: output di `ip addr show tun0` con `10.8.0.2`

---

## STEP 6 — Verifica della Connettività (12 punti)

### Dal client, testare l'accesso alla LAN aziendale:

```bash
# Ping al gateway LAN aziendale
ping -c 4 10.0.0.1
# Deve rispondere!

# Verificare la route
ip route show | grep 10.0.0
```

### Sul server, verificare il log:

```bash
sudo cat /var/log/openvpn/status.log
```

📸 **Screenshot 9**: ping dal client a `10.0.0.1` con risposta  
📸 **Screenshot 10**: `status.log` che mostra `mario-rossi` connesso con IP `10.8.0.2`

---

## 📝 Domande di Riflessione (incluse nel punteggio)

Rispondi brevemente a queste domande nel file `risposte_a.md`:

1. **Perché il file `mario-rossi.key` deve essere trasmesso in modo sicuro al client?**
2. **Cosa succederebbe se due client usassero lo stesso certificato contemporaneamente?**
3. **Nel server.conf, la direttiva `push "route 10.0.0.0 255.255.255.0"` serve al server o al client? Spiega.**
4. **Perché è necessario abilitare `ip_forward` sul server? Cosa fa esattamente questa impostazione?**

---

## 📊 Punteggio

| Sezione | Punti |
|---------|-------|
| STEP 1 — Setup VM e rete | 8 |
| STEP 2 — Installazione | 10 |
| STEP 3 — PKI e certificati | 25 |
| STEP 4 — Configurazione server | 25 |
| STEP 5 — Configurazione client | 20 |
| STEP 6 — Verifica connettività | 12 |
| **Totale** | **100** |

---

*ES02-A — Sistemi e Reti | Laboratorio guidato OpenVPN*
