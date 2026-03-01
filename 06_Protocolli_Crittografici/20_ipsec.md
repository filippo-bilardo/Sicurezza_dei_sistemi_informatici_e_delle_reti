# Capitolo 20 - IPsec

> **Corso**: Sistemi e Reti 3  
> **Parte**: 6 - Protocolli Crittografici  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**IPsec** (Internet Protocol Security) è un insieme di protocolli e standard che fornisce sicurezza a livello di rete (Layer 3 del modello OSI/TCP-IP). A differenza di SSL/TLS che protegge singole applicazioni, IPsec cifra e autentica **tutto il traffico IP** in modo trasparente per le applicazioni.

IPsec è la tecnologia alla base di quasi tutte le **VPN aziendali** (Virtual Private Network) e viene usata per connettere sedi remote, proteggere comunicazioni tra data center e garantire accesso remoto sicuro.

---

## Obiettivi di Apprendimento
- Comprendere l'architettura e i componenti del framework IPsec
- Distinguere i protocolli AH e ESP e il loro utilizzo
- Comprendere le differenze tra modalità Trasporto e Tunnel
- Analizzare il processo di negoziazione IKE (Internet Key Exchange)
- Configurare una VPN IPsec con StrongSwan su Linux
- Confrontare IPsec con altre soluzioni VPN (OpenVPN, WireGuard)

---

## Architettura di IPsec

### Componenti Principali

IPsec non è un unico protocollo, ma un **framework** composto da più standard:

```
┌────────────────────────────────────────────────────────────┐
│                    FRAMEWORK IPsec                         │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │     AH       │  │     ESP      │  │  IKE / IKEv2     │  │
│  │Autenticazione│  │  Cifratura + │  │  Negoziazione    │  │
│  │(no cifratura)│  │  Autenticaz. │  │  delle chiavi    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │    SAD       │  │    SPD       │  │   Algoritmi      │  │
│  │  Security    │  │  Security    │  │  AES, SHA, DH,   │  │
│  │  Assoc. DB   │  │  Policy DB   │  │  RSA, ECC...     │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

| Componente | Descrizione |
|------------|-------------|
| **AH** (Authentication Header) | Garanzia di autenticazione e integrità, senza cifratura |
| **ESP** (Encapsulating Security Payload) | Cifratura + autenticazione del payload |
| **IKE/IKEv2** | Protocollo di negoziazione e scambio chiavi |
| **SAD** (Security Association Database) | Archivio delle SA (associazioni sicure) attive |
| **SPD** (Security Policy Database) | Regole che definiscono il traffico da proteggere |

---

### Security Association (SA)

Una **Security Association** è un accordo unidirezionale tra due peer che definisce:

- Algoritmo di cifratura e chiave
- Algoritmo di integrità (HMAC) e chiave
- Durata della SA (lifetime in secondi o byte)
- Modalità (Trasporto o Tunnel)

Ogni SA è identificata dalla tripletta:
```
(SPI, Indirizzo IP destinazione, Protocollo AH|ESP)
```

> ⚠️ Le SA sono **unidirezionali**: una VPN bidirezionale richiede due SA, una per ogni direzione.

```
Peer A ──────SA1 (A→B)──────► Peer B
Peer A ◄─────SA2 (B→A)────── Peer B
```

---

## Protocolli AH ed ESP

### AH — Authentication Header

AH protegge l'**integrità** del pacchetto IP (header incluso) ma **non cifra** i dati. Oggi è poco usato perché ESP può fare tutto ciò che fa AH e in più cifra.

```
Pacchetto IPv4 con AH:
┌──────────┬────────────────┬────────────────────────────────┐
│ IP Header│  AH Header     │         Payload (in chiaro)    │
│(orig.)   │ ┌────────────┐ │                                │
│          │ │ Next Header│ │                                │
│          │ │ Payload Len│ │                                │
│          │ │ SPI        │ │                                │
│          │ │ Seq Number │ │                                │
│          │ │ ICV (HMAC) │ │                                │
│          │ └────────────┘ │                                │
└──────────┴────────────────┴────────────────────────────────┘
           ◄───────── autenticato ───────────────────────────►
```

**Cosa autentica AH:**
- Header IP (eccetto campi variabili: TTL, ToS, checksum)
- AH header
- Payload

**Problema con NAT:** AH autentica l'IP header, quindi è **incompatibile con NAT** (che modifica gli indirizzi IP). Per questo motivo viene quasi sempre usato ESP.

---

### ESP — Encapsulating Security Payload

ESP fornisce **cifratura + autenticazione** del payload. È il protocollo IPsec più usato in pratica.

```
Pacchetto IPv4 con ESP:
┌──────────┬────────────┬─────────────────────────┬──────────┐
│ IP Header│ ESP Header │       Payload           │ ESP Auth │
│          │ ┌────────┐ │  ┌───────────────────┐  │ (ICV)    │
│          │ │  SPI   │ │  │  Dati originali   │  │          │
│          │ │  Seq.  │ │  │  cifrati con AES  │  │          │
│          │ └────────┘ │  └───────────────────┘  │          │
└──────────┴────────────┴─────────────────────────┴──────────┘
                        ◄─────── cifrato ──────────►
           ◄────────────────── autenticato ─────────────────►
```

**Cosa cifra ESP:** il payload (dati applicativi)  
**Cosa autentica ESP:** ESP header + payload cifrato (ma non l'IP header esterno)

> ✅ **ESP è compatibile con NAT** perché l'IP header non è incluso nell'autenticazione.

---

### Confronto AH vs ESP

| Caratteristica | AH | ESP |
|----------------|----|----|
| **Cifratura** | ❌ No | ✅ Sì |
| **Autenticazione payload** | ✅ Sì | ✅ Sì |
| **Autenticazione IP header** | ✅ Sì | ❌ No |
| **Compatibilità NAT** | ❌ No | ✅ Sì (con NAT-T) |
| **Uso pratico** | Raro | Quasi sempre |
| **Protocollo IP** | 51 | 50 |

---

## Modalità di Funzionamento

### Modalità Trasporto (Transport Mode)

In modalità Trasporto, IPsec protegge solo il **payload** del pacchetto IP originale; l'header IP rimane invariato.

```
ORIGINALE:
┌──────────┬─────────────────────────────────────────┐
│ IP Header│            Payload (TCP/UDP/...)        │
│ src→dst  │                                         │
└──────────┴─────────────────────────────────────────┘

DOPO ESP in modalità TRASPORTO:
┌──────────┬────────────┬────────────────────┬────────┐
│ IP Header│ ESP Header │  Payload cifrato   │ESP Auth│
│ src→dst  │            │  (TCP/UDP/...)     │        │
└──────────┴────────────┴────────────────────┴────────┘
```

**Utilizzo:** comunicazione host-to-host (es. due server nello stesso datacenter).

**Vantaggi:** overhead minimo, l'IP originale è visibile per il routing.  
**Svantaggi:** espone gli indirizzi IP sorgente e destinazione.

---

### Modalità Tunnel (Tunnel Mode)

In modalità Tunnel, l'**intero pacchetto IP originale** (header + payload) viene incapsulato in un nuovo pacchetto IP con un nuovo header.

```
ORIGINALE:
┌──────────┬─────────────────────────────────────────┐
│ IP Header│            Payload                      │
│ src→dst  │                                         │
└──────────┴─────────────────────────────────────────┘

DOPO ESP in modalità TUNNEL:
┌────────────┬────────────┬─────────────────────────────┬────────┐
│ Nuovo      │ ESP Header │  IP Header originale        │ESP Auth│
│ IP Header  │            │  +  Payload originale       │        │
│ gw1→gw2    │            │  (tutto cifrato)            │        │
└────────────┴────────────┴─────────────────────────────┴────────┘
```

**Utilizzo:** VPN site-to-site (tra due gateway) e VPN accesso remoto.

**Vantaggi:** nasconde completamente la topologia della rete interna.  
**Svantaggi:** overhead maggiore (doppio header IP).

---

### Confronto Transport vs Tunnel

```
TRANSPORT MODE — host-to-host:

  Host A ─────────── [ESP] ─────────────── Host B
  10.0.1.10                                 10.0.2.20
  (IP visibile nel pacchetto)


TUNNEL MODE — site-to-site VPN:

  Rete A ──── Gateway A ═══[ESP tunnel]═══ Gateway B ──── Rete B
  10.0.1.0/24  192.168.1.1                  192.168.2.1  10.0.2.0/24
               (IP visibile:                (IP nascosto: 10.0.1.x)
                solo gateway)
```

| Caratteristica | Transport | Tunnel |
|----------------|-----------|--------|
| **Cosa viene protetto** | Solo payload | Intero pacchetto IP |
| **IP originale visibile** | ✅ Sì | ❌ No |
| **Overhead** | Basso | Maggiore (+20 byte) |
| **Uso tipico** | Host-to-host | VPN gateway |
| **Nasconde topologia** | ❌ No | ✅ Sì |

---

## IKE — Internet Key Exchange

**IKE** (Internet Key Exchange) è il protocollo che gestisce la **negoziazione automatica** delle SA: algoritmi, chiavi e parametri vengono scambiati in modo sicuro prima che inizi il traffico protetto.

Porta UDP: **500** (o 4500 con NAT traversal)

### IKEv1 vs IKEv2

| Caratteristica | IKEv1 | IKEv2 |
|----------------|-------|-------|
| **Standard** | RFC 2409 (1998) | RFC 7296 (2014) |
| **Fasi** | 2 fasi (Main/Aggressive + Quick) | 1 scambio semplificato |
| **Messaggi** | 9+ messaggi | 4 messaggi (initial) |
| **NAT traversal** | Estensione opzionale | Integrato |
| **EAP** | Non supportato | Supportato |
| **Mobilità** | No | MOBIKE integrato |
| **Sicurezza** | Vulnerabilità note | Più robusto |
| **Raccomandato** | Legacy | ✅ Sì |

---

### IKEv2 — Processo di Negoziazione

```
Initiator                              Responder
    │                                      │
    │──── IKE_SA_INIT Request ────────────►│
    │     (algoritmi proposti, DH pubblico,│
    │      nonce casuale)                  │
    │                                      │
    │◄─── IKE_SA_INIT Response ────────────│
    │     (algo scelto, DH pubblico,       │
    │      nonce casuale)                  │
    │                                      │
    │  [Entrambi calcolano il master key]  │
    │      SK = KDF(DH_secret, nonces)     │
    │                                      │
    │──── IKE_AUTH Request ───────────────►│
    │     (cifrato con SK:                 │
    │      identità, certificato/PSK,      │
    │      firma, proposta Child SA)       │
    │                                      │
    │◄─── IKE_AUTH Response ───────────────│
    │     (cifrato con SK:                 │
    │      identità, certificato/PSK,      │
    │      firma, Child SA accettata)      │
    │                                      │
    │  ✅ IKE SA stabilita                 │
    │  ✅ Child SA (IPsec SA) attiva       │
    │                                      │
    │══════ Traffico IPsec protetto ═══════│
```

### Metodi di Autenticazione IKE

| Metodo | Descrizione | Uso tipico |
|--------|-------------|------------|
| **PSK** (Pre-Shared Key) | Segreto condiviso manualmente | VPN piccole, test |
| **Certificati X.509** | PKI, CA firma i certificati | Ambienti enterprise |
| **EAP** (IKEv2 only) | Username/password, token OTP | VPN accesso remoto |
| **Raw Public Key** | Chiave pubblica senza CA | IoT, implementazioni minimali |

---

### Perfect Forward Secrecy (PFS)

Con PFS abilitato, IKE usa lo scambio **Diffie-Hellman** per ogni nuova SA: anche se la chiave a lungo termine venisse compromessa, le sessioni precedenti restano sicure.

```
Senza PFS:                    Con PFS:
  chiave_master                 SA1_key = DH_exchange_1
  ↓                             SA2_key = DH_exchange_2
  SA1_key = derive(master)      SA3_key = DH_exchange_3
  SA2_key = derive(master)
  SA3_key = derive(master)      Compromise di una chiave →
                                solo una SA compromessa
  Compromise di master →
  TUTTE le SA compromesse      ✅ PFS garantisce isolamento
```

---

## Algoritmi Crittografici in IPsec

### Algoritmi Supportati

| Categoria | Algoritmo | Sicurezza | Note |
|-----------|-----------|-----------|------|
| **Cifratura** | AES-128-CBC | ✅ Buona | Standard |
| | AES-256-CBC | ✅ Ottima | Consigliato |
| | AES-128-GCM | ✅ Ottima | AEAD, più efficiente |
| | AES-256-GCM | ✅ Eccellente | ✅ Raccomandato |
| | 3DES | ⚠️ Accettabile | Legacy, da evitare |
| | DES | ❌ Obsoleto | Rotto, mai usare |
| **Integrità** | HMAC-SHA1 | ⚠️ Accettabile | Legacy |
| | HMAC-SHA256 | ✅ Buona | Consigliato |
| | HMAC-SHA384/512 | ✅ Ottima | Per requisiti elevati |
| **Scambio chiavi** | DH group 2 (768 bit) | ❌ Insicuro | Rotto |
| | DH group 14 (2048 bit) | ✅ Minimo | Accettabile |
| | DH group 19 (ECC 256) | ✅ Ottimo | ✅ Raccomandato |
| | DH group 20 (ECC 384) | ✅ Eccellente | Massima sicurezza |

> ⚠️ **Evitare rigorosamente:** DES, 3DES, MD5, DH group 1/2/5, IKEv1 Aggressive Mode.

---

## NAT Traversal (NAT-T)

Quando uno o entrambi i peer sono dietro NAT, AH non funziona e ESP può avere problemi. **NAT-T** risolve incapsulando i pacchetti ESP in UDP (porta 4500):

```
Senza NAT-T (ESP diretto, protocollo IP 50):
  Client ─── NAT ─── Internet ─── VPN server
                ↑
         NAT modifica IP → AH si rompe
         NAT non traccia protocollo 50 → ESP può rompersi

Con NAT-T (ESP in UDP/4500):
  Client ─── NAT ─── Internet ─── VPN server
  [ESP dentro UDP/4500]
         ↑
  NAT traccia UDP normalmente ✅
```

NAT-T viene rilevato automaticamente da IKEv2 durante la fase `IKE_SA_INIT`.

---

## Configurazione Pratica con StrongSwan

**StrongSwan** è l'implementazione IPsec open source più diffusa su Linux. È usata da Ubuntu, Debian, Fedora e da numerosi apparati di rete.

### Installazione

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install strongswan strongswan-pki

# Fedora/RHEL
sudo dnf install strongswan

# Verifica
ipsec version
swanctl --version
```

### Struttura dei File di Configurazione

```
/etc/ipsec.conf          ← configurazione principale (legacy)
/etc/ipsec.secrets       ← chiavi e segreti (legacy)
/etc/swanctl/            ← nuovo formato (raccomandato)
  ├── swanctl.conf       ← configurazione unificata
  └── conf.d/            ← file di configurazione aggiuntivi
/etc/strongswan.conf     ← parametri del demone
```

---

### Scenario 1: VPN Site-to-Site con PSK

**Topologia:**
```
Sede A:  10.0.1.0/24 ── GW-A (1.2.3.4) ════[IPsec]════ GW-B (5.6.7.8) ── 10.0.2.0/24  :Sede B
```

**Configurazione su GW-A** (`/etc/swanctl/swanctl.conf`):

```ini
connections {
  site-to-site {
    # Indirizzi dei gateway
    local_addrs  = 1.2.3.4          # IP pubblico di GW-A
    remote_addrs = 5.6.7.8          # IP pubblico di GW-B

    # Autenticazione PSK
    local {
      auth = psk
      id   = gw-a@esempio.it
    }
    remote {
      auth = psk
      id   = gw-b@esempio.it
    }

    # Traffico da proteggere (Child SA)
    children {
      lan-to-lan {
        local_ts  = 10.0.1.0/24    # rete locale sede A
        remote_ts = 10.0.2.0/24    # rete locale sede B
        mode      = tunnel          # modalità tunnel
        esp_proposals = aes256gcm128-x25519  # cifratura AES-256-GCM
        dpd_action    = restart     # rileva peer inattivi e riconnette
      }
    }

    # Proposta IKEv2
    version    = 2
    proposals  = aes256-sha256-x25519  # IKE: AES-256 + SHA-256 + ECC
    rekey_time = 4h                    # rinnova IKE SA ogni 4 ore
  }
}

# Pre-Shared Key
secrets {
  ike-site-to-site {
    id-1 = gw-a@esempio.it
    id-2 = gw-b@esempio.it
    secret = "ChiavePSK_SuperSicura_256bit!"
  }
}
```

**Avviare e verificare:**
```bash
# Carica la configurazione
sudo swanctl --load-all

# Avvia la connessione
sudo swanctl --initiate --child lan-to-lan

# Visualizza le SA attive
sudo swanctl --list-sas

# Mostra le policy IPsec
sudo ip xfrm policy

# Mostra le SA a livello kernel
sudo ip xfrm state
```

---

### Scenario 2: VPN Accesso Remoto con Certificati (Road Warrior)

Scenario tipico: dipendenti che si connettono da remoto all'ufficio.

```
Laptop remoto ─── Internet ─── VPN Gateway (ufficio)
192.168.100.x                   10.0.0.0/24
(IP virtuale assegnato)
```

**Generare il CA e i certificati:**

```bash
# Genera la CA
ipsec pki --gen --type ecdsa --size 256 --outform pem > ca_key.pem
ipsec pki --self \
  --in ca_key.pem \
  --dn "CN=VPN CA, O=Scuola, C=IT" \
  --ca \
  --outform pem > ca_cert.pem

# Genera la chiave e il certificato del server
ipsec pki --gen --type ecdsa --size 256 --outform pem > server_key.pem
ipsec pki --pub --in server_key.pem |
  ipsec pki --issue \
    --cacert ca_cert.pem \
    --cakey  ca_key.pem \
    --dn     "CN=vpn.scuola.it, O=Scuola, C=IT" \
    --san    vpn.scuola.it \
    --flag   serverAuth \
    --outform pem > server_cert.pem

# Installa i certificati
sudo cp ca_cert.pem     /etc/ipsec.d/cacerts/
sudo cp server_cert.pem /etc/ipsec.d/certs/
sudo cp server_key.pem  /etc/ipsec.d/private/
```

**Configurazione Road Warrior** (`/etc/swanctl/swanctl.conf`):

```ini
connections {
  road-warrior {
    local_addrs  = %any               # accetta connessioni su qualsiasi IP
    remote_addrs = %any               # client da qualsiasi indirizzo

    local {
      auth  = pubkey                  # autentica il server con certificato
      certs = server_cert.pem
      id    = vpn.scuola.it
    }
    remote {
      auth   = eap-mschapv2           # autentica il client con user/pass
      eap_id = %any                   # accetta qualsiasi username
    }

    children {
      road-warrior {
        local_ts  = 0.0.0.0/0         # tutto il traffico passa per la VPN
        mode      = tunnel
        esp_proposals = aes256gcm128-x25519
        dpd_action    = clear
      }
    }

    version    = 2
    proposals  = aes256-sha256-x25519
    send_certreq = yes

    # Pool di indirizzi IP per i client
    pools = client_pool
  }
}

pools {
  client_pool {
    addrs = 192.168.100.0/24          # range IP assegnati ai client VPN
    dns   = 8.8.8.8, 8.8.4.4
  }
}

# Credenziali EAP degli utenti
secrets {
  eap-mario {
    id     = mario
    secret = "PasswordMario2026!"
  }
  eap-lucia {
    id     = lucia
    secret = "PasswordLucia2026!"
  }
}
```

```bash
sudo swanctl --load-all
sudo systemctl restart strongswan
sudo swanctl --list-conns       # verifica connessioni configurate
```

---

### Comandi di Gestione e Diagnostica

```bash
# Stato generale di StrongSwan
sudo ipsec statusall
sudo swanctl --list-sas    # Security Associations attive
sudo swanctl --list-pols   # Policy attive
sudo swanctl --list-conns  # Connessioni configurate

# Terminare una connessione
sudo swanctl --terminate --ike site-to-site

# Rinnovare le chiavi (rekey)
sudo swanctl --rekey --child lan-to-lan

# Livello kernel (ip xfrm)
sudo ip xfrm state       # mostra le SA IPsec a livello kernel
sudo ip xfrm policy      # mostra le policy IPsec a livello kernel
sudo ip xfrm monitor     # monitora eventi in tempo reale

# Log (seguire in tempo reale)
sudo journalctl -u strongswan -f

# Test ping attraverso il tunnel (da sede A verso sede B)
ping -I eth0 10.0.2.1    # usa eth0 come sorgente per forzare il tunnel
```

---

## IPsec e Firewall

Quando si usa IPsec è necessario aprire le porte sul firewall:

```bash
# Porte necessarie per IKEv2
sudo ufw allow 500/udp    # IKE
sudo ufw allow 4500/udp   # NAT-T

# Protocolli necessari (non sono porte TCP/UDP)
# ESP = protocollo IP 50
# AH  = protocollo IP 51
sudo iptables -A INPUT  -p esp -j ACCEPT
sudo iptables -A OUTPUT -p esp -j ACCEPT

# Con nftables (sistemi moderni)
sudo nft add rule inet filter input  ip protocol esp accept
sudo nft add rule inet filter output ip protocol esp accept

# Forwarding per il traffico VPN (modalità tunnel / gateway)
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
```

---

## Confronto IPsec con Altre VPN

| Caratteristica | IPsec/IKEv2 | OpenVPN | WireGuard |
|----------------|-------------|---------|-----------|
| **Layer** | 3 (Network) | 3 (via TUN/TAP) | 3 (Network) |
| **Standard** | IETF RFC | Proprio | IETF RFC (in avanzamento) |
| **Protocollo** | UDP 500/4500 | TCP 443 o UDP | UDP (qualsiasi porta) |
| **Kernel** | Nativo Linux | Userspace | Nativo dal kernel 5.6 |
| **Performance** | Alta | Media | Molto alta |
| **Interoperabilità** | ✅ Eccellente | ✅ Buona | ⚠️ Crescente |
| **Configurazione** | Complessa | Media | Semplice |
| **Mobile (iOS/Android)** | ✅ Nativo | Plugin | App |
| **Firewall bypass** | Difficile (porta 500) | Facile (TCP 443) | Difficile |
| **Codebase** | Grande | Grande | ~4000 righe |
| **Audit sicurezza** | Esteso | Esteso | Recente |

---

## Best Practices

1. **Usa IKEv2** invece di IKEv1 — più sicuro, più efficiente e supporta MOBIKE
2. **Usa AES-256-GCM** (AEAD) invece di AES-CBC + HMAC separati — elimina alcune classi di attacchi
3. **Abilita PFS** (Perfect Forward Secrecy) con gruppi DH ECC (group 19/20)
4. **Usa certificati X.509** per ambienti enterprise — i PSK vanno bene solo per test
5. **Imposta lifetime brevi** per le SA (es. 1-4 ore per IKE SA, 30-60 minuti per Child SA) e abilita il rekey automatico
6. **Abilita Dead Peer Detection (DPD)** per rilevare peer irraggiungibili e ripristinare i tunnel
7. **Usa NAT-T** (UDP 4500) invece di disabilitare il NAT — è più pratico e sicuro
8. **Monitora i log** di StrongSwan per rilevare tentativi di accesso non autorizzati
9. **Limita i tunnel a reti specifiche** nella SPD — evita di autorizzare `0.0.0.0/0` se non necessario
10. **Aggiorna regolarmente** StrongSwan — le implementazioni IPsec hanno avuto vulnerabilità critiche in passato

---

## Esercizi

### Esercizio 20.1 (★☆☆) — Analisi di pacchetti IPsec

1. Installa Wireshark (`sudo apt install wireshark`)
2. Cattura traffico sulla scheda di rete: `sudo tcpdump -i any -w capture.pcap udp port 500 or udp port 4500`
3. Apri la cattura in Wireshark e filtra con `isakmp` — identifica i messaggi IKE_SA_INIT e IKE_AUTH
4. Filtra con `esp` — verifica che il payload sia cifrato e illeggibile
5. Identifica nel pacchetto ESP: il numero SPI, il sequence number

**Domande:**
- Perché il payload ESP è completamente illeggibile in Wireshark?
- Come si differenzia un pacchetto IKE_SA_INIT da un IKE_AUTH?

### Esercizio 20.2 (★★☆) — Configurazione VPN site-to-site in locale

Usando due VM o due container Docker in rete:

1. Installa StrongSwan su entrambi i nodi
2. Configura una VPN site-to-site con PSK secondo lo Scenario 1
3. Verifica il tunnel con `sudo swanctl --list-sas`
4. Esegui `ping` tra le due reti e cattura il traffico: i pacchetti interni sono cifrati?
5. Confronta `ip route` prima e dopo l'attivazione del tunnel

**Domande:**
- Cosa succede al routing quando il tunnel si attiva?
- Come si distingue il traffico IPsec da quello normale in `ip xfrm state`?

### Esercizio 20.3 (★★★) — Road Warrior con certificati

1. Genera una CA locale e un certificato server secondo le istruzioni della Sezione "Scenario 2"
2. Configura StrongSwan come server Road Warrior
3. Installa un client (es. `network-manager-strongswan` su Linux, o usa il client IKEv2 nativo di Windows)
4. Connettiti con username/password (EAP)
5. Verifica che tutto il traffico passi per il tunnel con `ip route` e `curl ifconfig.me`
6. Disconnetti il client e verifica che le SA vengano rimosse dal server

**Domande:**
- Qual è la differenza tra autenticare il server con PSK o con certificato?
- Perché è importante che il client verifichi il certificato del server?

---

## Domande di Verifica

1. Qual è la differenza tra AH e ESP? In quale caso si preferirebbe AH?
2. Perché AH non è compatibile con NAT e come risolve questo problema ESP?
3. Descrivi le due modalità operative di IPsec (Trasporto e Tunnel): quando si usa ciascuna?
4. Cosa si intende per Security Association (SA) e perché ne servono due per una comunicazione bidirezionale?
5. Qual è il ruolo di IKE/IKEv2 nel framework IPsec?
6. Cosa garantisce il Perfect Forward Secrecy (PFS) e perché è importante abilitarlo?
7. Elenca almeno tre algoritmi di cifratura usati in IPsec e indica quale è raccomandato oggi.
8. Confronta IPsec con WireGuard: quali sono i principali vantaggi e svantaggi di ciascuno?

---

## Riferimenti

- [IPsec — RFC 4301 (Security Architecture)](https://datatracker.ietf.org/doc/html/rfc4301)
- [ESP — RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303)
- [AH — RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302)
- [IKEv2 — RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296)
- [StrongSwan Documentation](https://docs.strongswan.org/)
- [StrongSwan swanctl.conf Reference](https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html)
- [Algo VPN — Best Practice IPsec](https://github.com/trailofbits/algo)

---

**Capitolo Precedente**: [19 - SSH](./19_ssh_secure_shell.md)  
**Prossimo Capitolo**: [21 - PGP/GPG](./21_pgpgpg.md)
