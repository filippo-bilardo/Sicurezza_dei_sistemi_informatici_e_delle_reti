# 02 - Le VPN

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 02 — VPN e Accesso Remoto Sicuro**

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

## Excursus Storico: L'Evoluzione delle VPN

### Origini e Motivazioni (anni '90)

Le VPN nascono negli anni '90 come risposta a un problema aziendale concreto: **come connettere in modo sicuro sedi remote e dipendenti senza i costi proibitivi delle linee dedicate private?**

Prima delle VPN, le opzioni disponibili erano:
- **Linee dedicate punto-punto**: circuiti fisici affittati dai carrier (T1, E1, Frame Relay). Costosi (migliaia di euro/mese), limitati geograficamente, ma completamente privati
- **Modem dial-up diretti**: dipendenti chiamavano direttamente il centralino aziendale via modem. Lento, costoso (chiamate interurbane), scalabilità limitata
- **Reti MPLS**: gestite dai provider di telecomunicazioni, sicure ma costose e con vendor lock-in

L'esplosione di Internet negli anni '90 ha reso possibile una terza via: **usare Internet come backbone di trasporto**, ma **cifrando il traffico** per mantenere la privacy come in una rete privata.

### Timeline dei Protocolli VPN

```
1996 ┌─────────────────────────────────────────────────┐
     │ PPTP (Point-to-Point Tunneling Protocol)        │
     │ Microsoft + Ascend - Windows NT 4.0             │
     │ ✗ MS-CHAPv2 rotto (1998), MPPE debole          │
     └─────────────────────────────────────────────────┘

1998 ┌─────────────────────────────────────────────────┐
     │ L2TP (Layer 2 Tunneling Protocol) - RFC 2661    │
     │ Fusione di L2F (Cisco) e PPTP (Microsoft)       │
     │ Da solo non cifra → sempre abbinato a IPsec     │
     └─────────────────────────────────────────────────┘

1998 ┌─────────────────────────────────────────────────┐
     │ IPsec (Internet Protocol Security) - RFC 2401   │
     │ Standard IETF per IPv4, obbligatorio in IPv6    │
     │ Due modalità: Transport e Tunnel                │
     │ IKEv1 (RFC 2409) - negoziazione chiavi          │
     └─────────────────────────────────────────────────┘

2001 ┌─────────────────────────────────────────────────┐
     │ OpenVPN 1.0 - James Yonan                       │
     │ Basato su SSL/TLS, userspace, multipiattaforma  │
     │ Flessibile ma complesso (~70.000 righe codice)  │
     └─────────────────────────────────────────────────┘

2003 ┌─────────────────────────────────────────────────┐
     │ SSTP (Secure Socket Tunneling Protocol)         │
     │ Microsoft - Windows Vista/Server 2008           │
     │ Tunnel su HTTPS (porta 443), solo ecosistema MS │
     └─────────────────────────────────────────────────┘

2005 ┌─────────────────────────────────────────────────┐
     │ IKEv2 (RFC 4306) - evoluzione di IKEv1          │
     │ MOBIKE per roaming, riconnessione automatica    │
     │ Supporto nativo iOS/macOS, Windows, Android     │
     └─────────────────────────────────────────────────┘

2016 ┌─────────────────────────────────────────────────┐
     │ WireGuard - Jason A. Donenfeld                  │
     │ ~4.000 righe codice, kernel-space, moderne      │
     │ crypto primitives (Curve25519, ChaCha20)        │
     │ → Integrato in Linux kernel 5.6 (2020)          │
     └─────────────────────────────────────────────────┘
```

### Fasi Storiche delle VPN

#### **Prima Era: "Replacement delle Linee Dedicate" (1996-2003)**

**Contesto**: le aziende cercano di sostituire costose linee dedicate con soluzioni basate su Internet.

- **PPTP**: primo protocollo VPN largamente adottato grazie all'integrazione in Windows 95/NT. Facile da configurare, ma già nel 1998 emergono vulnerabilità crittografiche gravi in MS-CHAPv2
- **L2TP/IPsec**: risposta più solida che combina il tunneling L2TP con la sicurezza IPsec. Diventa lo standard per **site-to-site** VPN enterprise
- **IPsec standalone**: adottato pesantemente da router e firewall Cisco, Juniper, CheckPoint per interconnessioni datacenter

**Limiti**: configurazione complessa (soprattutto IPsec), problemi con NAT, performance limitate su CPU non dedicate.

#### **Seconda Era: "Remote Access e SSL VPN" (2003-2015)**

**Contesto**: crescita del telelavoro e necessità di accesso da dispositivi non aziendali.

- **OpenVPN**: diventa la soluzione open source di riferimento per remote access. Funziona su TCP/UDP, porta 443 per bypassare firewall restrittivi
- **SSL VPN (clientless)**: soluzioni proprietarie (Cisco, Juniper, Palo Alto) offrono accesso via browser senza installare software. Ideale per contractor/partner temporanei
- **Boom delle VPN consumer**: servizi come NordVPN, ExpressVPN nascono per aggirare censure e geoblocking. Business model basato su privacy marketing

**Innovazioni**: split tunneling intelligente, MFA integration, clientless access, miglior supporto mobile (iOS/Android).

#### **Terza Era: "Crisi della VPN Tradizionale e Zero Trust" (2015-oggi)**

**Contesto**: La migrazione al cloud, la pandemia di COVID-19 e la crescente minaccia di insider threat hanno reso il modello "castle and moat" (fortificazione perimetrale) completamente obsoleto. Le aziende si trovano a gestire:

- **Workforce distribuito globalmente**: accessi simultanei da decine di paesi, turni 24/7su fusi orari diversi. I gateway VPN centralizzati on-premise diventano colli di bottiglia geografici, causando latenza inaccettabile per utenti in Asia/Australia mentre il gateway risiede in Europa
- **Infrastruttura ibrida frammentata**: risorse distribuite tra datacenter on-premise, AWS, Azure, GCP, SaaS (Microsoft 365, Salesforce, Slack). Non esiste più un "perimetro" tradizionale — ogni risorsa ha un'identità e localizzazione diversa
- **Compromessi catastrofici di gateway VPN** (2019-2021): Pulse Secure (CVE-2019-11510), Citrix ADC (CVE-2019-19781), Fortinet SSL VPN (CVE-2018-13379) — attori avanzati ottengono accesso non autenticato, e una volta "dentro la VPN", l'attaccante ha accesso libero a tutta la rete interna senza ulteriori ostacoli
- **Rischio insider threat amplificato**: dipendenti negligenti o malintenzionati con credenziali VPN aziendali possono scaricare dataset interi in pochi minuti senza alcuna visibilità granulare da parte dei team di sicurezza
- **BYOD incontrollato**: dispositivi personali non gestiti (laptop personali, telefoni, tablet) configurati con VPN corporativa espongono dati sensibili se il dispositivo è compromesso — il traffico VPN è protetto, ma il dispositivo client è vulnerabile
- **Performance degradata per utenti globali**: un gateway centralizzato negli USA crea latenza di 300ms+ per utenti in Asia, rendendo inutilizzabili applicazioni interattive

**Caratteristiche di questa era:**

1. **Morte del modello "Castle and Moat"**
   - Vecchia logica: "tutto dentro il perimetro è trusted, tutto fuori è untrusted"
   - Nuova logica: "zero trust — verifica ogni richiesta, ogni volta, indipendentemente da dove viene"
   - Implicazione VPN: non è più sufficiente cifrare il canale. Serve verifica continua dell'identità, device posture, livello di trust del dispositivo

2. **Problemi di Scalabilità e Latenza**
   - Gateway centralizzato = collo di bottiglia geografico
   - Migliaia di utenti remoti connessi a singolo gateway causano degradazione performance
   - Latenza per utenti lontani rende applicazioni cloud interattive inutilizzabili
   - **Soluzione**: edge proxy distribuiti globalmente (ZTNA) vs gateway centralizzato

3. **Limitato Visibility Post-Autenticazione**
   - Una volta autenticato in VPN, utente ha accesso a *tutta* la subnet/VLAN
   - Nessuna visibilità su cosa sta effettivamente accedendo l'utente
   - Se credenziali compromesse → attaccante ha accesso libero
   - **Soluzione**: accesso per-application con application-aware proxy

4. **Crescente Complessità Infrastruttura**
   - On-premise + AWS + Azure + GCP + SaaS = impossibile gestire con singola VPN
   - Ogni cloud provider ha la sua VPN (AWS Site-to-Site, Azure VPN Gateway)
   - Configurazione manuale, error-prone, tunnel tra centinaia di risorse
   - **Soluzione**: identity-based access fabric che unifica l'intera infrastruttura ibrida

**Lezioni Apprese:**

```
❌ Non fare: 
   • Confidare che un gateway VPN sicuro = intera rete è sicura (perimetrale è morto)
   • Applicare "accesso a tutto" una volta autenticato
   • Deployment monolitico centralizzato

✅ Fare:
   • Zero trust: verifica ogni accesso, ogni volta
   • Visibilità granulare: quale utente accede quale app, quando, di che cosa
   • Device posture check: verificare que il dispositivo manca malware, è aggiornato
   • Segmentazione post-autenticazione: VLAN, ACL, firewall interno
   • Edge distribution: proxy distribuiti geograficamente, non gateway centralizzato
```

**Convergenza Attuale (2024):**

Le VPN non sono scomparse, ma si sono **riposizionate** in una strategia di sicurezza olistica:

- **VPN per site-to-site**: rimane rilevante per connettività tra datacenter / filiali (alta bandwidth, bassa latenza, protocolli proprietari)
- **ZTNA per remote access**: progressivamente sostituisce VPN per accesso utente da dispositivi personali
- **WireGuard come alternativa moderna**: dove VPN serve ancora, scegliere WireGuard per codice auditable, performance superiore, semplicità
- **Hybrid approach**: molte aziende corrono VPN + ZTNA in parallelo durante transizione


### Lezioni Apprese dalla Storia

```
✗ PPTP (MS-CHAPv2):      Cifratura debole deprecata → mai fidarsi di crypto proprietaria
✗ IKEv1 Aggressive Mode: Vulnerabile a dictionary attacks offline → sempre PSK sicure
✗ IPsec complessità:     Configurazione error-prone → preferire protocolli semplici verificabili
✓ OpenVPN flessibilità:  Open source + audit pubblici → fiducia della community
✓ WireGuard semplicità:  Codebase minima (~4K LOC vs 400K IPsec) → meno superficie d'attacco
✓ IKEv2 MOBIKE:          Roaming trasparente → user experience migliore = maggiore adozione
```

### VPN nel Contesto Moderno (2024-2026)

Oggi le VPN non sono più l'unica soluzione per l'accesso remoto sicuro, ma restano rilevanti in scenari specifici:

**Dove le VPN eccellono ancora:**
- Site-to-site tra datacenter (alta bandwidth, bassa latenza, protocolli non-HTTP)
- Accesso a risorse legacy che non supportano identity proxy
- Ambienti industriali/OT con protocolli proprietari (SCADA, Modbus)
- Developer access (SSH, RDP, database diretti)

**Dove le VPN perdono terreno:**
- SaaS/cloud applications → ZTNA più granulare
- BYOD workforce → device posture check integrato in ZTNA
- Global distributed teams → edge computing vs centralized gateway

### Il Futuro: Quantum-Resistant VPN

Con l'avvento dei computer quantistici, algoritmi come RSA-2048, ECDH P-256 diventeranno vulnerabili. Il NIST ha standardizzato nel 2024 algoritmi post-quantum (CRYSTALS-Kyber, CRYSTALS-Dilithium). Le VPN del futuro dovranno:
- Implementare **hybrid key exchange**: ECDH classico + Kyber per protezione immediata e futura
- Migrare da Curve25519 a curve post-quantum
- Supportare **Perfect Forward Secrecy (PFS) rafforzata** con rotazione chiavi frequente

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

### 3. Client-to-Site VPN (variante Remote Access)

Simile al Remote Access, ma con architettura più strutturata dove il client avvia sempre la connessione verso un concentratore VPN centrale dedicato.

```
[Client VPN] ──── Internet ──── [VPN Concentratore] ──── [Risorse Aziendali]
   Home/Mobile      (sempre initiator)    (sempre responder)   Server, DB, File
```

**Differenze principali da Remote Access generico:**
- **Topologia hub-and-spoke**: un singolo endpoint server (hub) centralizzato riceve connessioni da più client (spoke)
- **Gateway sempre attivo**: il concentratore funziona 24/7, sempre pronto ad accettare connessioni da client autorizzati
- **Autenticazione bidirezionale**: client autentica il server VPN (tramite certificato) e il server autentica il client
- **Assegnazione IP statica o dinamica**: il client riceve un IP da un pool gestito dal concentratore
- **Supporto split tunneling**: traffico verso risorse aziendali via VPN, traffico verso Internet pubblico direttamente (opzionale, controllabile)

**Uso tipico:** dipendenti remoti, contractor, partner che accedono a risorse aziendali specifiche (applicazioni interno, database, file server).

**Implementazioni comuni:**
- OpenVPN in modalità server/client
- WireGuard con configurazione server (usando wg-easy, pivpn)
- Cisco AnyConnect con ASA/ISE backend
- FortiClient verso Fortinet FortiGate

### 4. Personal VPN (Consumer VPN)

Servizio VPN commerciale rivolto a utenti finali (non aziendali) per proteggere la privacy su reti pubbliche e aggirare restrizioni geografiche.

```
[Dispositivo Utente] ──── Internet ──── [VPN Provider Server] ──── [Internet Pubblico]
   (home/caffè/hotel)                  (NordVPN, ExpressVPN,       (sito destinazione)
                               ProtonVPN, etc.)
```

**Caratteristiche:**
- **Semplice installation**: app consumer pre-configurata (zero-conf)
- **Uso occasionale**: non always-on, attivazione manuale
- **Nessuna autenticazione aziendale**: username/email + password, spesso MFA opzionale
- **IP condivisi tra utenti**: server VPN gestisce pool di IP estremamente grande, molti utenti condividono stessi IP pubblici
- **Enfasi privacy**: marketing su "nessun logging", "privacy garantita", anonimato
- **Geolocalizzazione**: utenti scelgono server VPN in Paese specifico per aggirare blocchi geografici o censure

**Protocolli comuni:** OpenVPN, WireGuard, Proprietary protocols (IKEv2-based), SSTP, L2TP/IPsec

**Modello di fiducia:**
- ⚠️ **Necessità completa di fiducia nel provider**: il provider VPN **vede tutto il traffico in chiaro** prima di cifrarlo. Se provider è malevolo o compromesso, privacy completamente violata
- ✅ Internet Service Provider (ISP) **non vede il traffico** — solo il tunnel VPN crittografato verso il server VPN
- ⚠️ Siti web destinazione **vedono l'IP del server VPN**, non l'IP reale dell'utente (potrebbe essere non authevole)

**Quando usare Personal VPN:**

✅ **Appropriato per...**
- Proteggere privacy su WiFi pubblico (caffè, hotel, aeroporto) da sniffing locale
- Evitare geoblocking (accedere Netflix di un Paese diverso da dove si è)
- Aggirare censura Internet (Cina, Iran, Russia)
- Protezione da ISP che fa logging del browsing

❌ **Non appropriato per...**
- Sicurezza completa: VPN provider rimane untrusted, potrebbe loggare traffico
- Anonimato totale: IP VPN rimane tracciabile, provider sa chi sei (account pagato con carta)
- Accesso a risorse aziendali: usare Remote Access VPN aziendale
- Bypass ToS di siti: potrebbe violare i terms of service

**Confronto: Personal VPN vs. Tor**

| Aspetto | Personal VPN | Tor |
|--------|-------------|-----|
| Provider accessibility | 1 hop | 3+ hop (onion routing) |
| Speed | Alto | Basso (multi-hop) |
| Anonimato | Parziale (provider sa chi sei) | Alto (nessuno sa chi sei) |
| Semplicità | Molto semplice | Complesso (Tor Browser) |
| Costo | €5-12/mese tipico | Gratuito |
| Trust model | Provider non-malicious | Rete decentralizzata |
| Bypassa firewall | Sì (con obfuscation) | Potenzialmente (Tor bridges) |

**Avvertenze di Sicurezza:**

```
⚠️ MITI sulla Personal VPN:

❌ "Personal VPN mi rende completamente anonimo"
   → Falso: Provider VPN conosce il tuo account (pagamento)
     Siti web vedono IP VPN (ovvero il provider), non il tuo, 
     ma pattern di traffico potrebbe essere correlato all'utente reale

❌ "Personal VPN mi protegge da virus/malware"
   → Falso: VPN protegge il trasporto, non il dispositivo.
     Malware sul tuo computer rimane accessibile anche con VPN.

❌ "Posso usare Personal VPN per attività illegale gratuitamente"
   → Rischioso: Polizia può ordinare al provider VPN il log degli utenti.
     Se provider ha policy "no-log" credibile, rimane come ultimo rifugio,
     ma lo stato di "no-log" è spesso non auditato.

✅ USO LEGITTIMO:
   • Privacy da ISP su rete pubblica (WiFi caffè)
   • Bypass geoblocco legittimi (accedere servizi da viaggio)
   • Privacy da tracciamento web (insieme a AdBlock, uBlock)
```

**Selezione Provider Affidabili (2024):**

| Provider | Giurisdizione | Policy No-Log | Open Source Audit | Prezzo |
|----------|--------------|---------------|------------------|--------|
| **Mullvad** | Svezia | Sì | Partial (OpenVPN) | €5/mese |
| **ProtonVPN** | Svizzera | Sì | Sì (WireGuard) | €5-8/mese |
| **IVPN** | Gibilterra | Sì | Sì (WireGuard) | €6/mese |
| **NordVPN** | Panama | Sì (recente audit) | No | €3-5/mese |
| ❌ **TunnelBear** | Canada | Sì | No | €10/mese |
| ❌ **ExpressVPN** | Isole Vergini | Questionato | No | €7/mese |

> ⚠️ Diffidare di provider in giurisdizioni Five Eyes (USA, UK, Australia, Canada, Nuova Zelanda) con mandatory data retention laws.

### 5. Cloud VPN

Connette reti on-premise o utenti alle risorse cloud (AWS, Azure, GCP).

```
[LAN Aziendale] ──── [VPN Gateway] ════════════ [AWS VPC / Azure VNet]
                           ↑
                     IPsec o WireGuard
```

### 6. MPLS VPN (Provider-Managed)

Soluzione di connettività WAN gestita completamente dall'operatore di telecomunicazione, basata su MPLS (Multi-Protocol Label Switching). A differenza delle VPN tradizionali su Internet pubblica, il traffico **non transita per Internet — rimane confinato dentro la rete privata del provider**.

```
[LAN Sede A] ──── [PE Router A] ═════════════════════ [PE Router B] ──── [LAN Sede B]
192.168.1.0/24      ↓                                      ↓           192.168.2.0/24
         Rete privata provider
         (MPLS backbone)
            ↓
        Garantie di QoS
        Isolamento garantito
        Nessun traffico Internet pubblico
```

**Caratteristiche distintive:**

- **Nessuna cifratura nativa**: MPLS affida la sicurezza all'**isolamento logico** tramite VRF (Virtual Routing and Forwarding), non alla crittografia. Il traffico è logicamente separato ma viaggia in chiaro sulla rete del provider
- **Garanzie di Quality of Service (QoS)**: il provider contratta SLA espliciti per latenza, perdita di pacchetti, larghezza di banda garantita, prioritizzazione
- **Always-on, trasparente all'utente**: il link rimane attivo 24/7, nessun client VPN da installare
- **Velocità di connessione garantite**: link dedicati logicamente, non contention con altri utenti finali
- **Supporto protocolli arbitrari**: MPLS non si limita a TCP/IP — supporta anche protocolli legacy (Novell IPX, AppleTalk, SNA) via VPLS

**Quando usare MPLS VPN:**

✅ **Preferibile quando...**
- Azienda ha budget consistente (~€10K+/mese per 10 sedi)
- Richiesti SLA rigidi con penali contrattuali
- Traffico mission-critical su link WAN (borse finanziarie, ospedali)
- Legacy enterprise con protocolli non-IP
- Rete aziendale fortemente distribuita con talmente tante sedi che mesh IP diventa ingestibile

❌ **Non adatto quando...**
- Budget limitato (SME) — Internet + IPsec è 10x più economico
- Azienda cloud-first: MPLS è irrilevante se tutto è in cloud
- Flessibilità richiesta: aggiungere sede cloud/remota è semplice con VPN, complicato con MPLS
- Workforce remoto: MPLS è site-to-site, non per utenti mobile

**Confronto: MPLS VPN vs. VPN su Internet**

| Aspetto | MPLS VPN | Internet VPN (IPsec/WireGuard) |
|--------|----------|------|
| Costo | €3K-10K per sede/mese | €0-500/mese (gateway dedicato) |
| QoS | Garantito (SLA) | Best-effort |
| Latenza (EU) | <10ms garantito | 20-50ms tipico |
| Cifratura | No (isolamento logico) | Sì (AES-256) |
| Scalabilità | Limitata (numero sedi) | Illimitata |
| Setup | 4-8 settimane | 1-2 giorni |
| Sicurezza | Fiducia provider | Algoritmi crittografici |
| Native remote access | No | Sì |

**Trend Moderno (2024):**

MPLS VPN è in declino tra le aziende moderne:
- Cloud migration riduce rilevanza: Amazon/Azure/GCP sostituiscono hub on-premise
- SD-WAN consente QoS su Internet pubblico, non richiede contratto provider
- Cost pressure: VPN su Internet + MFA è 20x più economico di MPLS
- Flessibilità: aggiungere sede cloud in pochi minuti vs. 6 settimane MPLS

Rimane rilevante per:
- Aziende finanze/assicurazioni con requisiti SLA rigidi legacy
- Fornitori di servizi che gestiscono rete MPLS già operativa
- Paesi con scadente qualità Internet pubblico (richiedono garanzie WAN)



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
Non è un singolo protocollo ma una categoria. Utilizza TLS/HTTPS sulla porta 443. Supporta tre modalità: clientless (browser), thin-client (port forwarding), full-tunnel (client VPN). Vedi guida dedicata [02 - SSL VPN](./02_ssl_vpn.md).

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

**SD-WAN** (Software Defined Wide Area Network) è un'architettura moderna per connettere sedi aziendali, ottimizzando il traffico su link multipli eterogenei (MPLS tradizionale + connessioni Internet pubbliche + LTE/5G). Sebbene includa cifratura dei tunnel, il suo focus primario differisce da quello di una VPN.

#### Differenze Fondamentali

| Aspetto | VPN | SD-WAN |
|--------|-----|--------|
| **Obiettivo primario** | Sicurezza + privacy del canale | Ottimizzazione performance WAN |
| **Focus tecnico** | Cifratura, autenticazione, riservatezza | Routing intelligente, QoS, failover |
| **Cifratura** | Elemento cruciale della sicurezza | Funzionalità inclusa, non prioritaria |
| **Decisioni di routing** | Gateway centralizzato, static | Dinamico basato su performance link |
| **Link supportati** | Qualsiasi (privato, pubblico) | MPLS + Internet + LTE + 5G simultanei |
| **Caso d'uso principale** | Accesso remoto individui + site-to-site | Connessione sempre-on tra filiali |
| **Latenza aggiunta** | Minima (solo cifratura) | Potenzialmente alta (analisi/ottimizzazione) |

#### Scenario Comparativo

**Azienda con 10 filiali distribuite in Italia:**

**Approccio VPN tradizionale:**
```
Filiale 1 → [VPN IPsec] → Sede Centrale
Filiale 2 → [VPN IPsec] → Sede Centrale
...
Filiale 10 → [VPN IPsec] → Sede Centrale

Problema: tutte le comunicazioni passano per la sede centrale (hub-and-spoke).
Se traffic Filiale 1 ↔ Filiale 2, deve fare: 1 → Sede → 2 (latenza aggiunta).
```

**Approccio SD-WAN:**
```
Filiale 1 ─→ Filiale 2
   ↓          ↓
  Link 1: Internet (100 Mbps, 25ms latenza)
  Link 2: MPLS (50 Mbps, 10ms latenza, garantito)
  Link 3: LTE backup (10 Mbps, 50ms latenza)

SD-WAN decide dinamicamente: "Trasmissione video conferencing → MPLS (QoS garantito)"
                      "Browsing → Internet (meno costoso)"
                      "Se MPLS down → failover automatico su Internet"

Traffic Filiale 1 ↔ Filiale 2 può fluire direttamente, ottimizzato per latenza.
```

#### Convergenza: SD-WAN Sicuro

Le soluzioni SD-WAN moderne (Cisco Catalyst, Fortinet SD-WAN, Palo Alto Prisma SD-WAN) integrano funzionalità di sicurezza avanzate:
- ✅ Crittografia dei tunnel (AES-256)
- ✅ URL filtering e malware detection
- ✅ Firewall integrato (next-gen)
- ✅ Segmentazione applicativa

**Risultato:** SD-WAN diventa una soluzione "all-in-one" che combina performance + sicurezza, potenzialmente rimpiazzando sia le VPN tradizionali che i firewall perimetrali.

#### Quando Scegliere

**Scegliere VPN quando:**
- ✅ Accesso remoto di utenti individuali
- ✅ Connessione semplice tra due sedi (costo/complessità ridotta)
- ✅ Ambienti con budget limitato
- ✅ Protocolli non-standard o legacy

**Scegliere SD-WAN quando:**
- ✅ 5+ sedi da connettere continuamente
- ✅ Mix di link: MPLS + Internet + LTE
- ✅ Video conferencing critica (richiede QoS dedicato)
- ✅ Failover automatico e resilienza richiesti
- ✅ Visibilità e controllo granulare del traffico WAN

**Scegliere entrambi quando:**
- ✅ SD-WAN per site-to-site (filiali)
- ✅ VPN remoto access per dipendenti mobili
- ✅ Complementari, non mutualmente esclusivi


### VPN vs Proxy / Tor

| Soluzione | Scopo principale | Anonimato | Performance | Caso d'uso |
|-----------|-----------------|-----------|-------------|------------|
| VPN | Accesso remoto sicuro / privacy | Parziale (fiducia nel provider) | Alta | Aziendale, smart working |
| Proxy HTTP/S | Bypass filtri web | Minimo | Alta | Accesso a contenuti |
| Tor | Anonimato forte | Alto (multihop) | Bassa | Privacy estrema, giornalismo |
| SSH Tunnel | Tunneling applicativo | No | Alta | Accesso specifico porta/servizio |
| SSH Tunnel | Per-application | Minimo | Alta | Dev access a server specifico |

### VPN vs SSH Tunneling

Per scenari semplici (accesso a un singolo server o servizio), un tunnel SSH può essere preferibile a una VPN completa:

```bash
# SSH Local Port Forwarding: accedere a DB interno sulla porta locale 5432
ssh -L 5432:db-interno.azienda.local:5432 utente@jumphost.azienda.com
# Da questo momento: localhost:5432 → tunneling cifrato → DB interno

# SSH Remote Port Forwarding: esporre servizio locale al jumphost
ssh -R 8080:localhost:3000 utente@jumphost.azienda.com
# Servizio su localhost:3000 → accessibile da jumphost:8080

# SSH Dynamic (SOCKS proxy): proxare tutto il browser
ssh -D 1080 utente@server.azienda.com
# Browser configurato con SOCKS proxy 127.0.0.1:1080 → tutto routato via SSH
```

**Vantaggi SSH tunnel:**
- ✅ Nessun software aggiuntivo (SSH è universale)
- ✅ Granularità per-porta/per-applicazione
- ✅ Autenticazione integrata (chiavi SSH)
- ✅ Cifratura AES integrata, collaudatissima

**Limiti SSH tunnel:**
- ❌ Non instrada tutto il traffico arbitrario (applicazioni non-proxy-aware falliscono)
- ❌ No split tunneling avanzato
- ❌ Richiede un jumphost SSH sempre raggiungibile e dedicato
- ❌ Scalabilità limitata (una connessione SSH per tunnel)
- ❌ Nessuna visibilità su traffico applicativo (è solo un tubo cifrato)
- ❌ Non supporta scenari multi-utente facilmente

**Quando usare SSH tunnel:**
- Developer che accede a database/cache interno da casa
- Accesso occasionale a un singolo servizio
- Debugging/troubleshooting di un servizio specifico
- Ambienti dove VPN non è installata ma SSH sì

**Quando usare VPN:**
- Accesso simultaneo a più servizi/subnet
- Utenti non-tecnici (non sanno configurare tunnel)
- Connessione always-on con auditing centralizzato
- Protocolli non-TCP/IP (DNS, DHCP, multicast)

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

**Indice**: [Indice](../README.md) 
**Prossima Sezione**: [SSL VPN](./02_ssl_vpn.md)
