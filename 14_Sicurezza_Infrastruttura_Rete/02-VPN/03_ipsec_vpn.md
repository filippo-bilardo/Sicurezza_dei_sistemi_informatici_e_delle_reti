# Capitolo 03 - IPsec VPN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

**IPsec (Internet Protocol Security)** è un framework di protocolli standardizzato dall'IETF che fornisce sicurezza a livello rete (Layer 3). A differenza delle SSL VPN e di OpenVPN che operano a livello applicativo, IPsec protegge direttamente i pacchetti IP, rendendolo trasparente alle applicazioni e particolarmente adatto a connessioni site-to-site permanenti ad alte prestazioni.

### Obiettivi di Apprendimento
- Comprendere l'architettura IPsec e i suoi componenti (AH, ESP, IKE)
- Distinguere le modalità Transport e Tunnel
- Configurare tunnel IPsec site-to-site con strongSwan
- Configurare un server IKEv2 per client road warrior
- Applicare criteri di hardening e scegliere suite crittografiche sicure

---

## Architettura IPsec

IPsec non è un singolo protocollo ma un **framework** composto da più elementi che cooperano:

```
┌─────────────────────────────────────────────────┐
│                  Framework IPsec                │
├──────────────────┬──────────────────────────────┤
│  Protocolli dati │  Gestione chiavi             │
│  ├── AH          │  └── IKE (IKEv1 / IKEv2)     │
│  └── ESP         │                              │
├──────────────────┴──────────────────────────────┤
│  Security Association (SA)                      │
│  Security Policy Database (SPD)                 │
│  Security Association Database (SAD)            │
└─────────────────────────────────────────────────┘
```

---

## Protocolli Dati

### AH — Authentication Header (RFC 4302)

AH autentica e garantisce l'integrità dei pacchetti IP, **senza cifrare** il payload.

```
Pacchetto con AH:
[IP Header][AH Header][TCP/UDP Header][Payload]
 ↑_____autenticato (incluso IP Header)_____↑
 (nessuna cifratura)
```

**Campi AH Header:**
- Next Header (tipo di payload seguente)
- Payload Length
- SPI (Security Parameters Index) — identifica la SA
- Sequence Number — protezione anti-replay
- ICV (Integrity Check Value) — HMAC del pacchetto

**Problema con NAT:** AH autentica l'header IP, ma il NAT modifica gli indirizzi IP → il checksum AH non corrisponde più. Per questo AH **non è compatibile con NAT** ed è raramente usato nelle reti moderne.

### ESP — Encapsulating Security Payload (RFC 4303)

ESP è il protocollo IPsec predominante: cifra e autentica il payload.

```
Pacchetto con ESP (modalità Transport):
[IP Header][ESP Header][TCP/UDP][Payload][ESP Trailer][ESP Auth]
            ↑_SPI,SeqNum_↑  ↑____cifrato_____↑         ↑_HMAC_↑

Pacchetto con ESP (modalità Tunnel):
[Nuovo IP][ESP Header][IP Originale][TCP/UDP][Payload][ESP Trailer][ESP Auth]
           ↑__SPI,Seq_↑  ↑____________tutto cifrato____________↑    ↑_HMAC_↑
```

**Algoritmi ESP (raccomandati):**
- Cifratura: AES-256-GCM (AEAD — autentica e cifra in un solo passaggio)
- Integrità: integrata in GCM (non serve HMAC separato)
- Legacy (evitare): 3DES, DES, MD5, SHA-1

---

## Modalità di Funzionamento

### Transport Mode

Protegge solo il payload del pacchetto IP originale. L'header IP originale rimane visibile.

```
Originale:   [IP: A→B][TCP][Dati]
Transport:   [IP: A→B][ESP Header][TCP][Dati cifrati][ESP Trailer][Auth]
              ↑visibile↑
```

**Uso tipico:** comunicazione host-to-host (es. due server nello stesso datacenter che devono comunicare in modo sicuro).

### Tunnel Mode

Incapsula l'intero pacchetto originale (header IP incluso) in un nuovo pacchetto. Gli indirizzi reali dei comunicanti sono nascosti.

```
Originale:   [IP: A→B][TCP][Dati]
Tunnel:      [IP: GW1→GW2][ESP][IP: A→B][TCP][Dati cifrati][ESP Trailer][Auth]
              ↑ indirizzo gateway ↑  ↑_________ nascosti e cifrati _________↑
```

**Uso tipico:** site-to-site VPN tra gateway (router, firewall). È la modalità più comune nelle VPN aziendali.

---

## IKE — Internet Key Exchange

IKE è il protocollo che negozia e gestisce le **Security Associations (SA)**: gli accordi tra peer che specificano algoritmi, chiavi e parametri di sicurezza.

### Security Association (SA)

Una SA è **unidirezionale**: per una comunicazione bidirezionale servono due SA. È identificata da:
- **SPI** (Security Parameters Index)
- **Indirizzo IP destinazione**
- **Protocollo** (AH o ESP)

### IKEv1 vs IKEv2

| Caratteristica | IKEv1 | IKEv2 |
|----------------|-------|-------|
| RFC | 2409 | 7296 |
| Messaggi handshake | 9 (main) / 6 (aggressive) | 4 |
| NAT Traversal | Estensione (RFC 3947) | Nativo |
| MOBIKE (mobilità) | No | Sì (RFC 4555) |
| EAP (autenticazione estesa) | No | Sì |
| Dead Peer Detection | Estensione | Nativo |
| Sicurezza | Aggressive Mode vulnerabile | Più robusto |

> ⚠️ **IKEv1 Aggressive Mode** è vulnerabile: invia l'hash della PSK in chiaro, consentendo attacchi di dizionario offline. Usare sempre IKEv2.

### Handshake IKEv2

```
Initiator (Client)                    Responder (Server)
      |                                      |
      |---[IKE_SA_INIT: SA, KE, Nonce]------>|  Propone algoritmi + DH public key
      |<--[IKE_SA_INIT: SA, KE, Nonce]-------|  Accetta + risponde con DH public key
      |                                      |
      |   (entrambi calcolano la chiave DH condivisa)
      |                                      |
      |---[IKE_AUTH: IDi, AUTH, TSi, TSr]--->|  Autenticazione + Traffic Selectors
      |<--[IKE_AUTH: IDr, AUTH, SA, TSi,TSr]-|  Autenticazione server + SA dati
      |                                      |
      |======[Tunnel ESP attivo]============>|
```

**Traffic Selectors (TS):** definiscono quale traffico deve entrare nel tunnel (es. da 192.168.1.0/24 verso 10.0.0.0/8).

---

## NAT Traversal (NAT-T)

IPsec con ESP usa il protocollo IP numero 50 (non TCP/UDP), incompatibile con il NAT tradizionale. NAT-T risolve il problema incapsulando ESP in UDP porta 4500.

```
Senza NAT-T:       [IP][ESP Proto 50][...]      ← il NAT non sa come gestirlo
Con NAT-T (UDP):   [IP][UDP 4500][ESP][...]     ← il NAT gestisce UDP normalmente
```

IKEv2 include NAT-T nativamente: rileva la presenza di NAT durante l'handshake e passa automaticamente a UDP 4500.

---

## Configurazione con strongSwan

**strongSwan** è l'implementazione IPsec/IKEv2 open source più diffusa su Linux.

### Installazione

```bash
sudo apt update && sudo apt install strongswan strongswan-pki \
     libcharon-extra-plugins libcharon-extauth-plugins -y
```

### Scenario 1: Site-to-Site IKEv2

```
[LAN A: 192.168.1.0/24] — [Gateway A: 1.2.3.4] ══IPsec══ [Gateway B: 5.6.7.8] — [LAN B: 192.168.2.0/24]
```

**`/etc/ipsec.conf` su Gateway A:**

```ini
config setup
    charondebug="ike 1, knl 1, cfg 0"

conn site-to-site
    auto=start              # Avvia tunnel all'avvio
    keyexchange=ikev2
    type=tunnel

    # Algoritmi (no negoziazione — suite esplicita)
    ike=aes256gcm16-sha384-ecp384!
    esp=aes256gcm16-ecp384!

    # Gateway A (locale)
    left=1.2.3.4
    leftid=@gw-a.azienda.com
    leftsubnet=192.168.1.0/24
    leftcert=gw-a-cert.pem          # Autenticazione con certificato

    # Gateway B (remoto)
    right=5.6.7.8
    rightid=@gw-b.azienda.com
    rightsubnet=192.168.2.0/24

    # DPD (Dead Peer Detection)
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s

    # PFS (Perfect Forward Secrecy)
    pfs=yes
```

**`/etc/ipsec.secrets` su Gateway A:**

```
# Chiave privata del certificato
: RSA "gw-a-key.pem"

# Alternativa con PSK (meno sicuro):
# @gw-a.azienda.com @gw-b.azienda.com : PSK "SuperSecretKey_min32chars!"
```

### PKI per IPsec

```bash
mkdir -p ~/ipsec-pki/{cacerts,certs,private} && cd ~/ipsec-pki

# CA
ipsec pki --gen --type rsa --size 4096 --outform pem > private/ca-key.pem
ipsec pki --self --ca --lifetime 3650 \
  --in private/ca-key.pem --type rsa \
  --dn "CN=IPsec CA, O=Azienda SRL" \
  --outform pem > cacerts/ca-cert.pem

# Certificato Gateway A
ipsec pki --gen --type rsa --size 4096 --outform pem > private/gw-a-key.pem
ipsec pki --pub --in private/gw-a-key.pem --type rsa \
  | ipsec pki --issue --lifetime 1825 \
    --cacert cacerts/ca-cert.pem \
    --cakey private/ca-key.pem \
    --dn "CN=gw-a.azienda.com" \
    --san "gw-a.azienda.com" \
    --san "1.2.3.4" \
    --flag serverAuth \
    --outform pem > certs/gw-a-cert.pem

# Copiare nella directory strongSwan
sudo cp -r cacerts certs private /etc/ipsec.d/
```

### Scenario 2: Road Warrior IKEv2 (client remoti)

```
[Laptop/Mobile] ══ IKEv2/IPsec ══ [VPN Server] ══ [LAN Aziendale]
  IP dinamico                       203.0.113.1       10.0.0.0/24
  VPN IP: 10.10.10.x
```

**`/etc/ipsec.conf` server road warrior:**

```ini
config setup
    charondebug="ike 2, knl 1, cfg 1, esp 1"
    uniqueids=no

conn ikev2-roadwarrior
    auto=add
    keyexchange=ikev2
    type=tunnel
    compress=no
    forceencaps=yes       # Forza NAT-T (UDP 4500) anche senza NAT

    # Suite crittografica
    ike=aes256gcm16-sha384-ecp384,aes256-sha256-ecp256!
    esp=aes256gcm16-ecp384,aes256-sha256!

    # Server
    left=%any
    leftid=@vpn.azienda.com
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0    # Full tunnel: tutto il traffico client passa qui

    # Client (road warrior)
    right=%any
    rightid=%any
    rightauth=eap-mschapv2  # Autenticazione username/password
    rightsourceip=10.10.10.0/24  # Pool IP per i client
    rightdns=10.0.0.53,8.8.8.8

    eap_identity=%identity
    dpdaction=clear
    dpddelay=300s
    rekey=no
```

**`/etc/ipsec.secrets` server road warrior:**

```
# Chiave privata server
: RSA "server-key.pem"

# Utenti EAP-MSCHAPv2
mario.rossi : EAP "Password!Sicura1"
anna.verdi  : EAP "Password!Sicura2"
```

### Gestione e Monitoraggio

```bash
# Avvio e stato
sudo systemctl start strongswan
sudo ipsec statusall

# Verificare SA attive
sudo ipsec status

# Statistiche traffico per SA
sudo ipsec statusall | grep -A5 "Security Associations"

# Avviare/riavviare una connessione specifica
sudo ipsec up site-to-site
sudo ipsec down site-to-site
sudo ipsec restart

# Log in tempo reale
sudo journalctl -fu strongswan

# Monitorare pacchetti ESP
sudo tcpdump -i eth0 esp -n
sudo tcpdump -i eth0 udp port 500 or udp port 4500 -n
```

---

## Suite Crittografiche: Raccomandazioni

### Sicure (usare)

```ini
# IKE Phase 1 — preferite
ike=aes256gcm16-prfsha384-ecp384!    # AES-256-GCM, SHA-384, ECDH P-384
ike=aes256-sha384-ecp384!            # AES-256-CBC, SHA-384, ECDH P-384

# ESP Phase 2 — preferite
esp=aes256gcm16-ecp384!              # AES-256-GCM (AEAD), PFS con P-384
esp=aes256-sha256-ecp256!            # AES-256-CBC, HMAC-SHA-256, PFS P-256
```

### Da Evitare

```ini
# OBSOLETI E VULNERABILI:
ike=3des-md5-modp1024    # 3DES + MD5 + DH 1024-bit (rotto)
esp=des-md5              # DES è rotto (56-bit)
ike=aes256-sha1-modp768  # DH group 1 (768-bit, vulnerabile)

# IKEv1 Aggressive Mode: mai usare
aggressive=yes           # Espone hash PSK → dizionario offline
```

### Tabella DH Groups

| Group | Tipo | Bit | Sicurezza |
|-------|------|-----|-----------|
| 1 | MODP | 768 | ❌ Rotto |
| 2 | MODP | 1024 | ❌ Debole |
| 5 | MODP | 1536 | ⚠️ Sconsigliato |
| 14 | MODP | 2048 | ✅ Minimo accettabile |
| 19 | ECP | 256 | ✅ Buono (P-256) |
| 20 | ECP | 384 | ✅ Raccomandato (P-384) |
| 21 | ECP | 521 | ✅ Massima sicurezza |
| 31 | Curve25519 | 256 | ✅ Eccellente |

---

## IPsec vs Alternativa WireGuard: Quando Scegliere IPsec

| Scenario | Scelta consigliata |
|----------|--------------------|
| Interoperabilità con router/firewall hardware (Cisco, Palo Alto) | **IPsec** |
| Connessione con cloud provider (AWS, Azure, GCP site-to-site) | **IPsec** |
| Standard compliance (es. FIPS 140-2 richiesto) | **IPsec** |
| Massima performance su hardware moderno | **WireGuard** |
| Semplicità di configurazione e manutenzione | **WireGuard** |
| Client mobile con roaming frequente | **WireGuard** o IKEv2/MOBIKE |

---

## Domande di Verifica

1. **Quali sono le differenze tra AH e ESP in IPsec? Perché AH non è compatibile con NAT e come ESP risolve questo problema?**

2. **Spiega la differenza tra modalità Transport e Tunnel in IPsec. In quale scenario è appropriata ciascuna modalità?**

3. **Descrivi le due fasi dell'handshake IKEv2. Cosa viene negoziato in ciascuna fase?**

4. **Perché IKEv1 Aggressive Mode è considerato insicuro? Quale tipo di attacco rende pericolosa l'autenticazione con PSK in questa modalità?**

5. **Cos'è una Security Association (SA) in IPsec? Perché sono unidirezionali e come vengono identificate?**

6. **Configura in strongSwan un tunnel site-to-site IKEv2 tra due gateway. Indica le direttive principali di `/etc/ipsec.conf` e spiega il significato di `leftsubnet`, `rightsubnet` e `auto=start`.**

7. **Cosa significa PFS (Perfect Forward Secrecy) in IPsec? Come si abilita in strongSwan e perché è importante?**

---

## Riferimenti

### Standard e RFC
- [RFC 4301](https://tools.ietf.org/html/rfc4301) — IPsec Architecture
- [RFC 4302](https://tools.ietf.org/html/rfc4302) — Authentication Header (AH)
- [RFC 4303](https://tools.ietf.org/html/rfc4303) — Encapsulating Security Payload (ESP)
- [RFC 7296](https://tools.ietf.org/html/rfc7296) — IKEv2
- [RFC 4555](https://tools.ietf.org/html/rfc4555) — MOBIKE (mobilità IKEv2)

### Documentazione
- [strongSwan Documentation](https://docs.strongswan.org/)
- [strongSwan Wiki — IKEv2 Cipher Suites](https://wiki.strongswan.org/projects/strongswan/wiki/IKEv2CipherSuites)
- [NIST SP 800-77r1](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) — Guide to IPsec VPNs

### Libri
- "IPsec: The New Security Standard" — Naganand Doraswamy, Dan Harkins
- "Network Security: Private Communication in a Public World" — Kaufman, Perlman, Speciner

---

**Sezione Precedente**: [02 - SSL VPN](./02_ssl_vpn.md)  
**Prossima Sezione**: [04 - OpenVPN](./04_openvpn.md)
