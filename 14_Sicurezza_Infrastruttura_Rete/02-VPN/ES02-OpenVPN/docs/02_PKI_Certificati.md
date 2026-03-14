# PKI e Certificati con Easy-RSA

> **ES02 — OpenVPN** | Documento teorico 02

---

## Cos'è una PKI

**PKI (Public Key Infrastructure)** è l'insieme di componenti che permette di creare, distribuire e revocare certificati digitali. In OpenVPN, la PKI serve a risolvere il problema fondamentale: **come fa il server a sapere che il client è un dipendente autorizzato?**

La risposta: ogni dispositivo autorizzato riceve un **certificato digitale firmato** dalla CA aziendale. Il server accetta solo connessioni da chi presenta un certificato valido.

```
CA (Certificate Authority)
 │
 ├── firma → Certificato Server  (identifica il server VPN)
 ├── firma → Certificato Client-Mario  (identifica Mario Rossi)
 ├── firma → Certificato Client-Anna   (identifica Anna Verdi)
 └── CRL (Certificate Revocation List)  ← certif. revocati
```

---

## Componenti PKI

| Componente | File | Descrizione |
|------------|------|-------------|
| **Chiave CA** | `ca.key` | 🔐 SEGRETO — non distribuire mai |
| **Certificato CA** | `ca.crt` | 📢 Pubblico — installato su server e client |
| **Chiave server** | `server.key` | 🔐 Solo sul server |
| **Certificato server** | `server.crt` | 📢 Solo sul server |
| **Chiave client** | `client.key` | 🔐 Solo sul client (un file per utente) |
| **Certificato client** | `client.crt` | 📢 Firmato dalla CA |
| **DH params** | `dh.pem` | Parametri Diffie-Hellman per lo scambio chiavi |
| **TLS-crypt key** | `tc.key` | 🔐 Chiave HMAC condivisa tra server e tutti i client |
| **CRL** | `crl.pem` | Lista certificati revocati |

---

## Easy-RSA: Creazione PKI Passo per Passo

**Easy-RSA** è lo strumento ufficiale di OpenVPN per gestire la PKI.

### Installazione

```bash
sudo apt install easy-rsa -y
```

### 1. Inizializzare la PKI

```bash
# Creare directory di lavoro
make-cadir ~/openvpn-pki
cd ~/openvpn-pki

# Inizializzare la PKI
./easyrsa init-pki
```

### 2. Creare la Certificate Authority (CA)

```bash
./easyrsa build-ca nopass

# Rispondere al prompt:
# Common Name: AziendaVPN-CA
```

Questo crea:
- `pki/ca.crt` — certificato CA (distribuire a tutti)
- `pki/private/ca.key` — chiave privata CA (**tenere al sicuro!**)

### 3. Generare il Certificato Server

```bash
./easyrsa gen-req server nopass

# Common Name: server  (oppure il nome dell'azienda)

./easyrsa sign-req server server

# Digitare "yes" per confermare
```

Questo crea:
- `pki/issued/server.crt`
- `pki/private/server.key`

### 4. Generare i Parametri Diffie-Hellman

```bash
./easyrsa gen-dh
# Operazione lenta (1–5 minuti) — crea pki/dh.pem
```

### 5. Generare la Chiave TLS-Crypt

```bash
openvpn --genkey secret ~/openvpn-pki/pki/tc.key
```

### 6. Generare Certificati Client

```bash
# Un certificato per ogni dipendente
./easyrsa gen-req mario-rossi nopass
./easyrsa sign-req client mario-rossi

./easyrsa gen-req anna-verdi nopass
./easyrsa sign-req client anna-verdi
```

### Riepilogo File Generati

```
~/openvpn-pki/pki/
├── ca.crt                    ← distribuire a server e tutti i client
├── dh.pem                    ← solo sul server
├── tc.key                    ← distribuire a server e tutti i client
├── issued/
│   ├── server.crt            ← solo sul server
│   ├── mario-rossi.crt       ← solo a Mario Rossi
│   └── anna-verdi.crt        ← solo ad Anna Verdi
└── private/
    ├── ca.key                ← MAI distribuire (tenerlo offline!)
    ├── server.key            ← solo sul server
    ├── mario-rossi.key       ← solo a Mario Rossi
    └── anna-verdi.key        ← solo ad Anna Verdi
```

---

## Revoca di un Certificato (CRL)

Se un dipendente lascia l'azienda o perde il dispositivo, il suo certificato va **revocato**:

```bash
# Revocare il certificato
./easyrsa revoke mario-rossi

# Generare la CRL aggiornata
./easyrsa gen-crl

# Copiare la CRL sul server OpenVPN
sudo cp pki/crl.pem /etc/openvpn/server/

# Assicurarsi che server.conf abbia:
# crl-verify /etc/openvpn/server/crl.pem
```

Alla prossima connessione, Mario Rossi riceverà un errore TLS e non potrà connettersi.

---

## Il File .ovpn (Profilo Client)

Il file `.ovpn` è un profilo "tutto in uno" che contiene la configurazione e i certificati da distribuire al dipendente:

```ini
# mario-rossi.ovpn
client
dev tun
proto udp
remote vpn.azienda.com 1194

resolv-retry infinite
nobind
persist-key
persist-tun

cipher AES-256-GCM
auth SHA256
verb 3

<ca>
-----BEGIN CERTIFICATE-----
[contenuto di ca.crt]
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
[contenuto di mario-rossi.crt]
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
[contenuto di mario-rossi.key]
-----END PRIVATE KEY-----
</key>

<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
[contenuto di tc.key]
-----END OpenVPN Static key V1-----
</tls-crypt>
```

---

## Domande di Riepilogo

1. Perché il file `ca.key` non deve mai essere distribuito?
2. Cosa succede se un attaccante ottiene il file `ca.key`?
3. Come si revoca un certificato client? Cosa deve fare il server per applicare la revoca?
4. Perché si usa un certificato separato per ogni client (invece di uno condiviso)?

---

*Prossimo documento: [03 — Configurazione OpenVPN](03_OpenVPN_Config.md)*
