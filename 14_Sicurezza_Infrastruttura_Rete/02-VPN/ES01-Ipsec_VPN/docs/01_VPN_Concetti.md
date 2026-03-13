# 01 — Concetti fondamentali VPN

## 🌐 Cos'è una VPN?

Una **VPN (Virtual Private Network)** è una tecnologia che permette di creare una
connessione sicura e privata attraverso una rete pubblica come Internet. Il termine
"virtuale" indica che non esiste un cavo fisico dedicato tra le due sedi, ma viene
simulata una connessione privata grazie alla cifratura e al tunneling.

### Breve storia

- **Anni '90**: Le aziende collegavano le proprie sedi tramite linee dedicate (leased line) o Frame Relay, soluzioni molto costose e poco flessibili. La necessità di ridurre i costi e aumentare la scalabilità porta alla ricerca di alternative su reti pubbliche.
- **1996**: Microsoft introduce **PPTP (Point-to-Point Tunneling Protocol)**, il primo protocollo VPN ampiamente adottato, pensato per facilitare il collegamento remoto dei dipendenti Windows. PPTP permette di creare tunnel cifrati su Internet, ma col tempo si rivelerà insicuro.
- **1999**: Viene standardizzato **IPsec (Internet Protocol Security)** con le RFC 2401, 2402 e 2406. IPsec diventa il riferimento per la sicurezza a livello di rete, adottato da produttori di router/firewall e sistemi operativi. Nello stesso periodo nasce **OpenVPN**, soluzione open source basata su SSL/TLS, che offre maggiore flessibilità e portabilità.
- **Anni 2000**: Con la diffusione del telelavoro e la necessità di accesso remoto sicuro, emergono le **SSL VPN**, che sfruttano il protocollo HTTPS per attraversare firewall e NAT, semplificando la connessione da qualsiasi luogo e dispositivo.
- **2010-2018**: Cresce la consapevolezza dei rischi per la privacy su reti pubbliche (Wi-Fi, hotspot), portando all'adozione massiccia di VPN anche in ambito consumer. Nel frattempo, i limiti di prestazioni e complessità di IPsec/OpenVPN stimolano la ricerca di soluzioni più moderne.
- **2019**: **WireGuard** viene integrato nel kernel Linux. Si distingue per semplicità, codice ridotto (~4000 righe), sicurezza moderna (ChaCha20, Curve25519) e prestazioni elevate. In breve tempo viene adottato anche su Windows, macOS, Android e iOS.
- **Oggi**: Le VPN sono uno strumento fondamentale sia per aziende (site-to-site, smart working, cloud) sia per utenti privati (privacy, aggirare censure e geo-blocking). L'evoluzione continua: si diffondono soluzioni "zero trust", VPN mesh e servizi cloud-native.

> **Curiosità:** Oggi miliardi di persone usano VPN ogni giorno, spesso senza rendersene conto (ad esempio tramite app aziendali, browser, o servizi di streaming che integrano VPN per motivi di sicurezza e privacy).

### Perché si usa una VPN?

| Scenario | Problema senza VPN | Soluzione con VPN |
|----------|-------------------|------------------|
| 🏢 Sedi aziendali remote | Dati aziendali in chiaro su Internet | Tunnel cifrato tra sedi |
| 👨‍💻 Smart working | Dipendente non può accedere ai sistemi aziendali da casa | Client VPN → rete aziendale |
| 🛡️ Privacy su Wi-Fi pubblico | Chiunque può sniffare il traffico | Tutto il traffico cifrato |
| 🌍 Geo-restriction | Contenuti bloccati per area geografica | VPN con server in altro paese |
| 🔒 Compliance normativa | GDPR richiede protezione dei dati in transito | VPN garantisce cifratura |

---

## 🏛️ I tre pilastri della VPN

### 1. 🔒 Tunneling (Incapsulamento)

Il tunneling è il processo di **incapsulamento di un pacchetto all'interno di un altro pacchetto**.
Permette a due reti private di comunicare attraverso una rete pubblica come se fossero
direttamente connesse.

```
SENZA TUNNEL:
┌───────────────────────────────────────────────────────┐
│ IP header (192.168.1.10 → 192.168.2.10) | payload TCP │
└───────────────────────────────────────────────────────┘
        ↓ Viaggia in chiaro su Internet ↓

CON TUNNEL IPsec (ESP Tunnel Mode):
┌──────────────────────┬───────────────────────────────────────────────────┐
│ Outer IP header      │ ESP | IP header (192.168.1.10→192.168.2.10) | TCP │
│ (203.0.113.2 →       │     |   CIFRATO — nessuno può leggere!            │
│  203.0.113.6)        │                                                   │
└──────────────────────┴───────────────────────────────────────────────────┘
        ↓ Viaggia su Internet — solo gli IP pubblici sono visibili ↓
```

**Come funziona**:
- Il router sorgente (Milano) riceve un pacchetto dalla LAN interna
- Lo incapsula in un nuovo pacchetto con header IP pubblici
- Lo invia attraverso Internet verso il router destinazione (Roma)
- Il router di Roma rimuove l'incapsulamento e consegna il pacchetto originale

### 2. 🔑 Cifratura (Confidenzialità)

La cifratura trasforma i dati in formato illeggibile usando algoritmi matematici.
Solo chi possiede la chiave corretta può decifrare e leggere i dati.

**Algoritmi di cifratura simmetrica** (usati per i dati):
- **AES-128/192/256**: standard oro, veloce, sicuro — usato in IPsec
- **3DES**: tre applicazioni di DES, lento e obsoleto
- **DES**: 56-bit, completamente insicuro (rotto in <24h)

**Algoritmi asimmetrici** (usati per lo scambio chiavi):
- **RSA**: per autenticazione con certificati
- **Diffie-Hellman**: per generare chiavi condivise senza trasmetterle

### 3. 🛡️ Autenticazione e Integrità

**Autenticazione**: verifica l'identità del peer (chi sei?):
- **Pre-Shared Key (PSK)**: password segreta configurata su entrambi i router
- **Certificati RSA**: più sicuro, scalabile, ma più complesso da gestire
- **XAUTH / EAP**: autenticazione utente aggiuntiva (per Remote Access VPN)

**Integrità**: verifica che i dati non siano stati modificati durante il transito:
- **HMAC-MD5**: hash 128-bit, veloce ma considerato debole
- **HMAC-SHA1**: hash 160-bit, buon compromesso
- **HMAC-SHA256**: hash 256-bit, raccomandato oggi

---

## 🗂️ Tipi di VPN

### VPN Site-to-Site (LAN-to-LAN)

Collega due o più reti aziendali attraverso Internet.
Il tunnel è sempre attivo e trasparente agli utenti finali.

```
SEDE CENTRALE (Milano)     INTERNET      FILIALE (Roma)
┌──────────────┐                        ┌──────────────┐
│  LAN interna │                        │  LAN interna │
│  192.168.1.x │     🔒═══════════🔒   │  192.168.2.x │
│              │    Tunnel sempre UP    │              │
│  Router-MI   ├────────────────────────┤  Router-RO   │
│  203.0.113.2 │                        │  203.0.113.6 │
└──────────────┘                        └──────────────┘
```

**Caratteristiche**:
- Configurata sui router/firewall perimetrali, non sui PC
- Trasparente agli utenti: non devono fare nulla di speciale
- Sempre attiva (o attivata automaticamente dal traffico)
- Usata per connettere sedi aziendali, datacenter, partner commerciali

**Protocolli tipici**: IPsec, GRE over IPsec, DMVPN

### VPN Remote Access (Client-to-Site)

Permette a singoli utenti (dipendenti in smart working) di connettersi alla rete aziendale.

```
PC di casa (10.10.10.x)              Rete aziendale (192.168.1.x)
  ┌──────────┐                           ┌──────────────┐
  │ Dipend.  │    🔒═══════════🔒       │  Server VPN  │
  │ con      ├───────────────────────────┤  aziendale   │
  │ client   │  Tunnel quando connesso   │              │
  │ VPN      │                           └──────────────┘
  └──────────┘
```

**Caratteristiche**:
- Richiede software client sul dispositivo dell'utente
- Tunnel creato a richiesta (non sempre attivo)
- L'utente si autentica con username/password + certificato/token
- Supporta split tunneling (solo traffico aziendale nella VPN)

**Protocolli tipici**: SSL/TLS (OpenVPN, Cisco AnyConnect), IPsec/IKEv2, WireGuard, L2TP/IPsec

### SSL VPN vs IPsec VPN

| Caratteristica | IPsec VPN | SSL/TLS VPN |
|---------------|-----------|------------|
| Livello OSI | Network (L3) | Transport/Application (L4/L7) |
| Client richiesto | Sì (o router) | Spesso solo browser |
| Porta usata | UDP 500/4500, IP 50/51 | TCP 443 (HTTPS) |
| Problemi con NAT | Sì (NAT-T risolve) | Raramente |
| Problemi con firewall | Spesso bloccato | Raramente bloccato |
| Prestazioni | Alte | Più basse (overhead TLS) |
| Uso tipico oggi | Site-to-Site | Remote Access |

---

## 🗺️ Topologie VPN

### Point-to-Point (semplice)

```
Sede A ════════════════ Sede B
       1 tunnel VPN
```
- 1 tunnel, 2 sedi
- Semplice da configurare e mantenere
- Usato nell'Esercizio A di questa unità

### Hub-and-Spoke

```
       Filiale Nord
            │
Filiale Ovest ─── HQ ─── Filiale Est
            │
       Filiale Sud
```
- 1 hub centrale (HQ), N spoke (filiali)
- N tunnel VPN (uno per ogni filiale verso HQ)
- Traffico filiale→filiale passa per HQ
- Semplice da gestire, HQ è Single Point of Failure

### Full-Mesh

```
   Nord ────── Est
    │  ╲      ╱ │
    │   ╲    ╱  │
    │    ╲  ╱   │
   Sud ────── Ovest
```
- Ogni sede collegata direttamente a tutte le altre
- N*(N-1)/2 tunnel VPN (con 4 sedi: 6 tunnel)
- Traffico diretto tra sedi, massima resilienza
- Complesso da gestire, non scala bene con molte sedi

### DMVPN (Dynamic Multipoint VPN)

- Inizia come Hub-and-Spoke
- I nodi spoke si "trovano" dinamicamente tramite NHRP
- Crea tunnel spoke-to-spoke on-demand
- Scalabile, riduce carico su HQ
- Componenti: mGRE + NHRP + IPsec

---

## 🔧 Confronto tecnologie VPN

| Tecnologia | Sicurezza | Prestazioni | Complessità | Piattaforma | Uso principale |
|-----------|-----------|-------------|-------------|------------|---------------|
| **IPsec/IKEv2** | ✅ Alta | ✅ Alta | ⚠️ Media | Universale | Site-to-Site, Remote Access enterprise |
| **OpenVPN** | ✅ Alta | ⚠️ Media | ⚠️ Media | Universale | Remote Access, open source |
| **WireGuard** | ✅ Alta | ✅ Molto alta | ✅ Bassa | Linux, Windows, iOS, Android | Remote Access, moderna |
| **L2TP/IPsec** | ✅ Buona | ⚠️ Media | ⚠️ Media | Universale | Remote Access (legacy) |
| **PPTP** | ❌ Insicuro | ✅ Alta | ✅ Bassa | Legacy | **NON USARE** (vulnerabile) |
| **SSL VPN** | ✅ Alta | ⚠️ Media | ✅ Bassa | Solo browser | Remote Access clientless |

### WireGuard — La VPN moderna

WireGuard (2019) usa:
- **Crittografia**: ChaCha20 (dati), Poly1305 (autenticazione), Curve25519 (scambio chiavi)
- **Codice sorgente**: ~4000 righe vs ~100.000 di OpenVPN (superficie d'attacco minima)
- **Prestazioni**: più veloce di IPsec e OpenVPN grazie all'integrazione nel kernel

---

## 🔄 VPN e NAT: il problema NAT-Traversal

### Il problema

IPsec usa IP protocollo 50 (ESP) e 51 (AH), non TCP/UDP. Il NAT tradizionale lavora
su porte TCP/UDP, quindi **non può gestire pacchetti ESP/AH** — li butta via.

Scenario tipico: router di casa con NAT → router VPN aziendale.
Il pacchetto ESP viene modificato dal NAT (cambio IP sorgente) → il checksum IPsec fallisce!

### Soluzione: NAT-T (NAT Traversal)

- Incapsula i pacchetti ESP/AH in **UDP porta 4500**
- Il NAT può gestire pacchetti UDP normalmente
- Rilevamento automatico: se c'è NAT nel percorso, IKE lo rileva e attiva NAT-T
- Si attiva automaticamente su Cisco IOS con `crypto isakmp nat-traversal`

---

## ↔️ Split Tunneling

Con **full tunneling** (default): tutto il traffico del client va nella VPN.
Con **split tunneling**: solo il traffico verso reti aziendali usa la VPN.

```
FULL TUNNELING:
  YouTube → VPN → Rete aziendale → Internet → YouTube
  (inefficiente: tutto passa per il server VPN aziendale)

SPLIT TUNNELING:
  YouTube → Internet diretto (non nella VPN)
  Server aziendale → VPN → Rete aziendale → Server
  (efficiente: solo traffico aziendale nella VPN)
```

**Vantaggi split tunneling**:
- Riduce la banda consumata sul tunnel VPN
- Riduce il carico sul concentratore VPN aziendale
- Migliora le prestazioni per contenuti Internet non aziendali

**Rischi sicurezza split tunneling**:
- Il PC del dipendente è connesso sia a Internet (non protetto) che alla VPN aziendale
- Un malware sul PC può usare la connessione Internet per attaccare la rete aziendale
- Il traffico Internet del dipendente non passa dai sistemi di sicurezza aziendali (IDS/IPS, proxy)

> ⚠️ **Raccomandazione**: aziende con alta sensibilità dei dati (banche, sanità, difesa)
> dovrebbero disabilitare lo split tunneling e usare full tunneling.

---

## 📊 Schema visivo: topologia VPN completa

```
                    ╔══════════════════════════════╗
                    ║         INTERNET             ║
                    ║   (rete pubblica non sicura) ║
                    ╚══════════════════════════════╝
                           ↑              ↑
           Traffico cifrato│              │Traffico cifrato
           (ESP Tunnel Mode│              │ESP Tunnel Mode)
                           │              │
           ┌───────────────┴──┐       ┌───┴──────────────┐
           │  Router Milano   │       │  Router Roma     │
           │  (crypto map)    │       │  (crypto map)    │
           └───────────┬──────┘       └─────┬────────────┘
                       │                    │
              LAN Milano (privata)      LAN Roma (privata)
              192.168.1.0/24            192.168.2.0/24
              TRAFFICO IN CHIARO        TRAFFICO IN CHIARO
                 all'interno               all'interno

    Il tunnel cifra: IP_priv_src | TCP/UDP | payload applicativo
    L'ISP vede solo: IP_pub_src (203.0.113.2) → IP_pub_dst (203.0.113.6) | ESP cifrato
```
