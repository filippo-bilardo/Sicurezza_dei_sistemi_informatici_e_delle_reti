# Capitolo 49.1 - Le VPN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 49 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

Una **VPN (Virtual Private Network)** è una tecnologia che permette di creare un canale di comunicazione cifrato e autenticato attraverso una rete pubblica (come Internet), emulando il comportamento di una rete privata dedicata. È uno dei pilastri della sicurezza nell'accesso remoto e nella connessione tra sedi aziendali.

### Obiettivi di Apprendimento
- Comprendere il concetto di VPN e la sua utilità
- Conoscere le principali tipologie di VPN
- Distinguere i modelli di deployment (site-to-site, remote access, cloud)
- Analizzare i protocolli VPN e i loro livelli di sicurezza
- Valutare scenari d'uso appropriati per ciascun tipo di VPN

---

## Concetti Fondamentali

### Definizione e Scopo

Una VPN nasce per rispondere a tre esigenze fondamentali:

1. **Riservatezza (Confidentiality)**: il traffico viene cifrato, impedendo intercettazioni sulla rete pubblica
2. **Autenticità (Authentication)**: solo utenti/sistemi autorizzati possono entrare nella VPN
3. **Integrità (Integrity)**: i dati non possono essere modificati in transito senza essere rilevati

```
SENZA VPN (traffico in chiaro):
[Utente Remoto] ──────────── Internet ──────────── [Rete Aziendale]
                  ↑ Visibile a chiunque intercetti ↑

CON VPN (tunneling cifrato):
[Utente Remoto] ══[Tunnel Cifrato]══ Internet ══[Tunnel Cifrato]══ [Rete Aziendale]
                  ↑ Traffico cifrato, non leggibile ↑
```

### Concetti Chiave

**Tunneling**: incapsulamento dei pacchetti originali all'interno di nuovi pacchetti per il trasporto sicuro attraverso la rete pubblica.

```
Senza VPN:
[IP Header | TCP Header | Dati applicazione]

Con VPN (es. IPsec in tunnel mode):
[Nuovo IP Header | ESP Header | [IP Originale | TCP | Dati] | ESP Trailer | Auth]
 ↑ Indirizzo VPN ↑              ↑_____________cifrato_______________↑
```

**Endpoint VPN**: il dispositivo (server, firewall, router) che termina il tunnel VPN e instrada il traffico nella rete privata.

**SA (Security Association)**: un accordo unidirezionale tra due endpoint VPN che definisce l'algoritmo di cifratura, la chiave e i parametri di sicurezza da usare.

---

## Tipologie di VPN

### 1. Remote Access VPN (Road Warrior)

Permette a singoli utenti (dipendenti remoti, telelavoratori) di connettersi alla rete aziendale da qualsiasi luogo.

```
[Laptop dipendente] ──── Internet ──── [VPN Gateway Aziendale] ──── [LAN Aziendale]
    VPN Client                              VPN Server
    10.8.0.5                                10.8.0.1                  192.168.1.0/24
```

**Caratteristiche:**
- Connessione iniziata sempre dal client
- Autenticazione individuale (certificato, username/password, MFA)
- IP dinamico assegnato dal server VPN
- Supporta sia full tunnel che split tunnel

**Uso tipico:** smart working, accesso a risorse aziendali da casa o in viaggio.

### 2. Site-to-Site VPN

Collega permanentemente due o più sedi aziendali, creando una rete unificata.

```
[LAN Sede A] ──── [Gateway A] ════════[Tunnel IPsec]════════ [Gateway B] ──── [LAN Sede B]
192.168.1.0/24    10.0.0.1                                    10.0.0.2         192.168.2.0/24
```

**Caratteristiche:**
- Tunnel sempre attivo (always-on)
- Autenticazione tra dispositivi (certificati o PSK)
- Trasparente agli utenti finali
- Spesso implementato su router/firewall dedicati

**Uso tipico:** connessione tra filiali, datacenter, cloud provider.

### 3. Client-to-Site VPN (variante remote access)

Simile al Remote Access, ma il client avvia sempre la connessione verso un concentratore VPN centrale.

### 4. Cloud VPN

Connette reti on-premise o utenti alle risorse cloud (AWS, Azure, GCP).

```
[LAN Aziendale] ──── [VPN Gateway] ════════════ [AWS VPC / Azure VNet]
                                   ↑
                           IPsec o WireGuard
```

### 5. MPLS VPN (provider-managed)

VPN gestita dall'operatore di rete tramite MPLS (Multi-Protocol Label Switching). Non usa Internet pubblico — il traffico viaggia sulla rete privata del provider.

---

## Protocolli VPN: Panoramica

### Tabella Comparativa

| Protocollo | Layer OSI | Cifratura | Performance | Firewall Friendly | Stato |
|------------|-----------|-----------|-------------|-------------------|-------|
| **WireGuard** | 3 (Rete) | ChaCha20-Poly1305 | ★★★★★ | Media (UDP 51820) | ✅ Raccomandato |
| **IPsec/IKEv2** | 3 (Rete) | AES-256-GCM | ★★★★ | Media (UDP 500/4500) | ✅ Raccomandato |
| **OpenVPN** | 4-7 | AES-256-GCM (TLS) | ★★★ | Alta (TCP/UDP 443) | ✅ Buono |
| **SSL VPN** | 4-7 | TLS 1.3 | ★★★ | Alta (HTTPS 443) | ✅ Buono |
| **IKEv1** | 3 (Rete) | AES (negoziato) | ★★★★ | Media | ⚠️ Legacy, evitare Aggressive Mode |
| **L2TP/IPsec** | 2+3 | AES (via IPsec) | ★★★ | Media | ⚠️ Legacy, ancora diffuso |
| **SSTP** | 4-7 | TLS | ★★★ | Alta (TCP 443) | ⚠️ Solo Windows |
| **PPTP** | 2 | MPPE (40/128-bit) | ★★★★ | Alta | ❌ OBSOLETO, vulnerabile |

> ⚠️ **PPTP non deve essere usato**: MS-CHAPv2 è completamente rotto, attacchi offline in poche ore con hardware consumer.

### Dettaglio Protocolli Moderni

#### WireGuard
Integrato nel kernel Linux dalla versione 5.6 (2020). Usa un set crittografico fisso e moderno: **Curve25519** per lo scambio di chiavi, **ChaCha20-Poly1305** per la cifratura AEAD, **BLAKE2s** per l'hashing. Con ~4.000 righe di codice è verificabile molto più agevolmente di OpenVPN (~70.000) o IPsec (~400.000). Il modello di autenticazione è basato esclusivamente su chiavi pubbliche.

#### IPsec/IKEv2
Standard IETF (RFC 7296) ampiamente supportato da router, firewall e dispositivi mobili nativamente. IKEv2 supporta **MOBIKE** (RFC 4555) per il roaming senza riconnessione. Suite crittografica negoziabile: scegliere esplicitamente AES-256-GCM + ECDH P-384 per massima sicurezza, evitare DH group < 14.

#### OpenVPN
Opera su TLS, utilizza OpenSSL come backend crittografico. Supporta UDP (preferito) e TCP (porta 443 per compatibilità firewall). Flessibile: certificati X.509, PSK, username/password, plugin MFA. Più lento di WireGuard e IPsec perché opera in userspace.

#### SSL VPN
Non è un singolo protocollo ma una categoria. Utilizza TLS/HTTPS sulla porta 443. Supporta tre modalità: clientless (browser), thin-client (port forwarding), full-tunnel (client VPN). Vedi guida dedicata [49.2 - SSL VPN](./49_2_ssl_vpn.md).

#### PPTP
Protocollo obsoleto sviluppato da Microsoft negli anni '90. Usa MPPE per la cifratura, ma è vulnerabile a numerosi attacchi (MS-CHAPv2 è rotto). Non deve essere usato in ambienti moderni.

### Porte e Protocolli di Rete

| VPN | Protocollo di trasporto | Porte |
|-----|------------------------|-------|
| WireGuard | UDP | 51820 (configurabile) |
| IPsec IKE | UDP | 500 (negoziazione), 4500 (NAT-T) |
| IPsec ESP | IP Proto 50 | — (non usa porte) |
| OpenVPN | UDP/TCP | 1194 (default), 443 (firewall bypass) |
| SSL VPN | TCP | 443 |
| L2TP | UDP | 1701 (+ IPsec su 500/4500) |
| PPTP | TCP | 1723 + GRE (IP Proto 47) |

---

## Confronto con Altre Soluzioni

Le VPN non sono l'unico approccio per garantire accesso remoto sicuro. Con l'evoluzione del cloud e del modello Zero Trust, sono emerse alternative che in alcuni contesti le superano.

### VPN vs ZTNA (Zero Trust Network Access)

| Caratteristica | VPN Tradizionale | ZTNA |
|----------------|-----------------|------|
| Modello di fiducia | Implicita dopo autenticazione ("castle and moat") | Mai fiducia implicita, verifica continua |
| Accesso garantito a | Intera subnet/rete | Singola applicazione/risorsa |
| Visibilità traffico | Limitata (tunnel opaco) | Granulare per applicazione |
| Gestione dispositivi | Spesso assente | Integrata (device posture check) |
| Scalabilità cloud | Limitata (gateway centralizzato) | Cloud-native, distribuita |
| Latenza | Dipende dalla posizione del gateway | Ottimizzata (edge proxy) |
| Esempi | OpenVPN, WireGuard, IPsec | Zscaler ZPA, Cloudflare Access, BeyondCorp |

**Quando preferire ZTNA:** ambienti cloud-first, workforce distribuita, accesso a singole SaaS/app web, ambienti BYOD ad alto rischio.  
**Quando preferire VPN:** accesso a risorse legacy (non web), protocolli non-HTTP (RDP, SSH, database), site-to-site tra datacenter.

### VPN vs SD-WAN

**SD-WAN** (Software Defined Wide Area Network) è pensata per connettere sedi aziendali ottimizzando il traffico su link multipli (MPLS + Internet + LTE). Include cifratura dei tunnel ma con focus su performance e routing intelligente, non sulla sicurezza privacy-oriented.

```
VPN:    Sicurezza e privacy del canale → focus su cifratura e autenticazione
SD-WAN: Ottimizzazione WAN → focus su performance, failover, QoS
        (include cifratura come funzionalità, non come obiettivo primario)
```

### VPN vs Proxy / Tor

| Soluzione | Scopo principale | Anonimato | Performance | Caso d'uso |
|-----------|-----------------|-----------|-------------|------------|
| VPN | Accesso remoto sicuro / privacy | Parziale (fiducia nel provider) | Alta | Aziendale, smart working |
| Proxy HTTP/S | Bypass filtri web | Minimo | Alta | Accesso a contenuti |
| Tor | Anonimato forte | Alto (multihop) | Bassa | Privacy estrema, giornalismo |
| SSH Tunnel | Tunneling applicativo | No | Alta | Accesso specifico porta/servizio |

### VPN vs SSH Tunneling

Per scenari semplici (accesso a un singolo server o servizio), un tunnel SSH può essere preferibile a una VPN completa:

```bash
# SSH Local Port Forwarding: accedere a DB interno sulla porta locale 5432
ssh -L 5432:db-interno.azienda.local:5432 utente@jumphost.azienda.com

# SSH Dynamic (SOCKS proxy): proxare tutto il browser
ssh -D 1080 utente@server.azienda.com
```

**Limiti SSH tunnel:** non instrada traffico arbitrario, no split tunneling avanzato, richiede un host SSH raggiungibile.

---

## Componenti Architetturali

### VPN Gateway / Concentratore

Il cuore dell'infrastruttura VPN server-side. Può essere:
- **Dedicated hardware**: Cisco ASA, Palo Alto, Fortinet
- **Software su server**: OpenVPN, WireGuard, strongSwan
- **Cloud-native**: AWS Client VPN, Azure VPN Gateway, GCP Cloud VPN
- **Firewall integrato**: molti firewall moderni includono funzionalità VPN

### Client VPN

Software installato sul dispositivo dell'utente per stabilire il tunnel:
- **OpenVPN client**: multipiattaforma, open source
- **WireGuard client**: disponibile su tutti i SO principali
- **Cisco AnyConnect / Secure Client**: enterprise, ampia compatibilità
- **Native OS clients**: Windows (IKEv2), macOS (IKEv2), iOS/Android (IKEv2, L2TP)

### PKI e Gestione delle Chiavi

Un'infrastruttura VPN sicura richiede una PKI (Public Key Infrastructure) per:
- Emissione e revoca di certificati (CA)
- Autenticazione dei client tramite certificati X.509
- Cifratura asimmetrica per lo scambio di chiavi di sessione

---

## Sicurezza delle VPN: Considerazioni Generali

### Vettori di Attacco Comuni

```
1. Credenziali compromesse
   Attaccante → [VPN Gateway] con credenziali rubate → accesso rete interna

2. Vulnerabilità del software VPN
   CVE critiche storiche: Pulse Secure (CVE-2019-11510), Citrix ADC (CVE-2019-19781),
   Fortinet (CVE-2018-13379) — lettura file arbitraria senza autenticazione

3. Weak cipher suites
   Configurazioni che abilitano algoritmi obsoleti (3DES, RC4, DH-1024)

4. VPN split brain / misconfiguration
   Routing errato che espone risorse interne

5. Credential stuffing
   Attacchi automatizzati con credenziali leaked da altri breach
```

### Best Practice di Hardening

```
☐ Usare protocolli moderni (WireGuard, IKEv2, OpenVPN) — mai PPTP
☐ Abilitare MFA (Multi-Factor Authentication) per tutti gli utenti VPN
☐ Principio del minimo privilegio: ogni utente accede solo alle risorse necessarie
☐ Separare le reti con VLAN/segmentazione dopo l'accesso VPN
☐ Aggiornare tempestivamente il software VPN (patch critiche!)
☐ Monitorare e loggare tutti gli accessi VPN
☐ Implementare un Kill Switch per gli utenti remoti
☐ Usare certificate-based auth invece di sole password
☐ Disabilitare cipher suite obsolete
☐ Implementare timeout di sessione e re-autenticazione periodica
```

### Registro delle Vulnerabilità Critiche Storiche

| Anno | Prodotto | CVE | Impatto |
|------|----------|-----|---------|
| 2019 | Pulse Secure | CVE-2019-11510 | Lettura file arbitraria non autenticata |
| 2019 | Citrix ADC | CVE-2019-19781 | RCE non autenticata |
| 2018 | Fortinet SSL VPN | CVE-2018-13379 | Traversal path, leak credenziali |
| 2021 | Pulse Secure | CVE-2021-22893 | RCE non autenticata (0-day) |
| 2022 | OpenVPN | CVE-2022-0547 | Bypass autenticazione MFA |

> Queste vulnerabilità hanno causato breach significativi in organizzazioni governative e aziendali. Il patching tempestivo dei gateway VPN è critico.

---

## Modello di Minaccia VPN

```
┌─────────────────────────────────────────────────────┐
│                  MINACCE VPN                        │
├──────────────────┬──────────────────────────────────┤
│ Esterne          │ Interne                          │
├──────────────────┼──────────────────────────────────┤
│ • Brute force    │ • Credenziali condivise          │
│ • Exploit 0-day  │ • Certificati non revocati       │
│ • MITM su UDP    │ • Accesso eccessivo (no PoLP)    │
│ • DDoS gateway   │ • Dispositivi non gestiti (BYOD) │
│ • Credential     │ • Logging insufficiente          │
│   stuffing       │ • Mancanza di MFA                │
└──────────────────┴──────────────────────────────────┘
```

---

## Domande di Verifica

1. **Descrivi le tre proprietà di sicurezza fondamentali che una VPN deve garantire. Come vengono tecnicamente implementate in una VPN moderna?**

2. **Qual è la differenza tra una VPN Remote Access e una VPN Site-to-Site? Fornisci un esempio di scenario d'uso per ciascuna.**

3. **Perché PPTP è considerato obsoleto e insicuro? Quale attacco specifico ne ha dimostrato la debolezza crittografica?**

4. **Cosa si intende per "tunneling" in una VPN? Descrivi come viene incapsulato un pacchetto in IPsec modalità tunnel.**

5. **Elenca almeno 5 best practice per l'hardening di un'infrastruttura VPN aziendale.**

6. **Perché le vulnerabilità nei gateway VPN (es. Pulse Secure, Citrix) sono particolarmente pericolose rispetto alle vulnerabilità in altri sistemi?**

---

## Riferimenti

### Standard e Linee Guida
- [NIST SP 800-77r1](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) - Guide to IPsec VPNs
- [NIST SP 800-113](https://csrc.nist.gov/publications/detail/sp/800-113/final) - Guide to SSL VPNs
- [NSA VPN Hardening Guide](https://media.defense.gov/2021/Sep/28/2002863171/-1/-1/0/CSI_SELECTING-AND-HARDENING-REMOTE-ACCESS-VPNS_20210928.PDF)
- [CISA VPN Security Guidance](https://www.cisa.gov/vpn)

### Libri
- "Network Security Essentials" - William Stallings
- "IPsec: The New Security Standard" - Naganand Doraswamy
- "Firewalls and Internet Security" - Cheswick, Bellovin, Rubin

---

**Sezione Precedente**: [48.5 - RPZ (Response Policy Zones)](#)  
**Prossima Sezione**: [49.2 - SSL VPN](./49_2_ssl_vpn.md)
