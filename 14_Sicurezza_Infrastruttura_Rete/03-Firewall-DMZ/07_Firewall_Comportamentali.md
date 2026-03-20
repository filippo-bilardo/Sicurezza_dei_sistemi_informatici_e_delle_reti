# Firewall Comportamentali e Analisi del Traffico

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **Sezione 07 — Firewall con Analisi Comportamentale**

---

## Introduzione

I **firewall tradizionali** operano su regole statiche basate su indirizzi IP, porte e protocolli. I **firewall comportamentali** (o **behavioral firewalls**) analizzano invece il **comportamento del traffico** nel tempo per rilevare anomalie, minacce zero-day e attacchi sofisticati che bypassano le regole tradizionali.

Questi sistemi integrano tecniche di:
- **Behavioral analytics**: analisi statistica dei pattern di traffico
- **Machine Learning / AI**: rilevamento di anomalie tramite modelli addestrati
- **Threat Intelligence**: correlazione con IoC (Indicators of Compromise) globali
- **Application awareness**: ispezione deep packet fino al livello applicativo

### Obiettivi di Apprendimento

- Comprendere i limiti dei firewall tradizionali stateless/stateful
- Conoscere l'evoluzione verso NGFW e firewall comportamentali
- Analizzare le tecniche di behavioral analysis applicate alla sicurezza di rete
- Valutare soluzioni commerciali e open source per l'analisi comportamentale
- Implementare strategie di detection basate su anomalie

---

## Limiti dei Firewall Tradizionali

### Firewall Stateless (1a Generazione)

```
Regola: ALLOW tcp from 10.0.0.0/8 to 192.168.1.100:80
```

**Problemi:**
- ✗ Non tiene traccia delle connessioni (ogni pacchetto valutato indipendentemente)
- ✗ Vulnerabile a spoofing e session hijacking
- ✗ Nessuna comprensione del contesto applicativo

### Firewall Stateful (2a Generazione)

```
Connection tracking:
[SRC 10.0.0.5:45123] → [DST 192.168.1.100:80] STATE=ESTABLISHED
```

**Miglioramenti:** traccia le sessioni TCP/UDP, valida risposte in base allo stato

**Problemi residui:**
- ✗ Non ispeziona il payload applicativo
- ✗ Non rileva command & control (C2) su porte legittime (es. HTTPS:443)
- ✗ Non identifica malware che usa protocolli standard
- ✗ Non rileva data exfiltration lenta e graduale
- ✗ Non adatta le regole dinamicamente

### Esempio di Attacco Bypassa Firewall Stateful

```
Scenario: Malware che usa HTTPS (porta 443) per C2

Firewall stateful:
ALLOW tcp from LAN to ANY:443  ← regola legittima per navigazione

Attaccante:
[Host infetto] ──HTTPS:443──> [C2 Server malevolo]
               ↑ Traffico cifrato, indistinguibile da navigazione normale

Firewall stateful: ✓ ALLOW (porta 443, stato ESTABLISHED)
→ L'attacco passa inosservato
```

---

## Evoluzione: Next-Generation Firewall (NGFW)

I **NGFW** (3a generazione) aggiungono ai firewall stateful:

### 1. Deep Packet Inspection (DPI)

Ispezione del **payload completo** dei pacchetti, non solo degli header.

```
HTTP Request catturato da DPI:
POST /upload.php HTTP/1.1
Host: legitimate-site.com
Content-Type: multipart/form-data

[...binary data...]
  ↓ DPI analizza il contenuto:
  ✗ RILEVATO: file PE (Portable Executable) mascherato come immagine
  ✗ AZIONE: BLOCK + ALERT
```

**Tecniche DPI:**
- Pattern matching (signature-based): ricerca di byte sequences note (YARA rules)
- Protocol decoding: parsing di HTTP, DNS, SMB, FTP per estrarre metadati
- File type identification: analisi magic bytes, non estensione

### 2. Application Awareness

Riconoscimento delle applicazioni indipendentemente dalla porta.

```
Scenario: Skype su porta non standard

Traffico:  [Client] ──tcp:8080──> [Internet]
Firewall tradizionale: identifica solo "tcp:8080"
NGFW con App-ID:       identifica "Skype VoIP traffic"

Policy:
ALLOW tcp:8080 for HTTP     ← traffico HTTP permesso
BLOCK Skype                 ← Skype bloccato ovunque

Risultato: Skype bloccato anche se usa porta 8080
```

**Tecniche di identificazione applicazioni:**
- Behavioral fingerprinting: analisi pattern di handshake, timing, dimensione pacchetti
- SSL/TLS certificate inspection: estrazione CN/SAN dai certificati
- Heuristics: BitTorrent identificato da pattern di connessioni multiple P2P

### 3. Intrusion Prevention System (IPS) Integrato

Blocco attivo di exploit e attacchi noti.

```
Esempio: Rilevamento SQL Injection

HTTP Request:
GET /user.php?id=1' OR '1'='1 HTTP/1.1

IPS Signature:
alert tcp any any -> any 80 (
  msg:"SQL Injection attempt detected";
  content:"OR '1'='1";
  pcre:"/(\%27)|(\')|(\-\-)|(;)|(\%23)|(\#)/i";
  classtype:web-application-attack;
  sid:1000001;
)

AZIONE: DROP pacchetto + LOG + ALERT amministratore
```

### 4. User Identity Integration

Le regole non si basano più solo su IP, ma su **identità utente**.

```
Policy tradizionale (basata su IP):
ALLOW 192.168.1.50 to Internet:443

Policy NGFW (basata su identità):
ALLOW user:mario.rossi@azienda.it to Internet:443
      IF group:Marketing AND device:corporate-laptop

Vantaggi:
- Mobilità: l'utente ha lo stesso profilo ovunque si connetta
- BYOD: policy diverse per dispositivi personali vs aziendali
- Audit: log legati all'utente, non all'IP temporaneo
```

**Integrazione con:**
- Active Directory / LDAP
- SAML / OAuth identity provider
- 802.1X per autenticazione a livello rete
- Agenti endpoint per device fingerprinting

---

## Analisi Comportamentale: Tecniche e Algoritmi

### 1. Baseline del Comportamento Normale

Fase di **apprendimento** (tipicamente 2-4 settimane):

```
Esempio: Server web interno 192.168.1.100:80

Metriche raccolte:
┌─────────────────────────────────────────────────┐
│ Connessioni/ora:        150 ± 30                │
│ Bandwidth media:        5 Mbps                  │
│ Protocollo:             HTTP (GET 80%, POST 20%)│
│ Client tipici:          10.0.0.0/24 (LAN)       │
│ Orari attivi:           08:00-18:00 lun-ven     │
│ Geo-location client:    IT (100%)               │
│ User-Agent pattern:     Chrome/Firefox/Edge     │
└─────────────────────────────────────────────────┘

Baseline stabilita:
"Questo server riceve traffico HTTP da LAN in orario lavorativo"
```

### 2. Rilevamento Anomalie (Anomaly Detection)

Identificazione di deviazioni significative dal baseline.

```
Anomalia rilevata alle 03:00:

┌──────────────────────────────────────────────────────┐
│ ⚠️  ANOMALIA: Server web 192.168.1.100               │
├──────────────────────────────────────────────────────┤
│ • Connessioni/ora:    1200 (8x sopra baseline)       │
│ • Protocollo:         HTTP POST (95% vs 20% norm)    │
│ • Client source:      185.xxx.xxx.xxx (Russia)       │
│ • Orario:             03:00 (fuori orario lavoro)    │
│ • User-Agent:         python-requests/2.28.1         │
│                                                      │
│ SCORE ANOMALIA: 0.92 / 1.00 (HIGH)                   │
│ POSSIBILE CAUSA: Attacco automatizzato / web scraping│
└──────────────────────────────────────────────────────┘

AZIONE AUTOMATICA:
1. Rate limiting drastico per IP 185.xxx.xxx.xxx
2. Challenge CAPTCHA su endpoint sospetti
3. Alert team SOC (Security Operations Center)
```

**Algoritmi comuni per anomaly detection:**

#### Statistical Methods
- **Z-Score**: deviazione standard dalla media
  ```
  z = (x - μ) / σ
  Soglia tipica: |z| > 3 (99.7% confidenza)
  ```

- **Interquartile Range (IQR)**: identifica outlier
  ```
  Q1 = 25° percentile, Q3 = 75° percentile
  IQR = Q3 - Q1
  Outlier se: x < Q1 - 1.5*IQR  OR  x > Q3 + 1.5*IQR
  ```

#### Machine Learning

- **Isolation Forest**: isola anomalie con alberi di decisione
- **Autoencoders**: rete neurale che ricostruisce input normali, fallisce su anomalie
- **One-Class SVM**: addestra modello solo su dati "normali", rileva tutto il resto come anomalo
- **LSTM (Long Short-Term Memory)**: predice traffico futuro basandosi su serie temporali

### 3. Behavioral Signatures

Pattern comportamentali noti di attacchi specifici.

```
Behavioral Signature: Port Scanning

Pattern rilevato:
[Src IP: 203.0.113.50] in 60 secondi:
  → 192.168.1.1:22   (SYN)
  → 192.168.1.1:23   (SYN)
  → 192.168.1.1:80   (SYN)
  → 192.168.1.1:443  (SYN)
  → 192.168.1.1:3389 (SYN)
  [...100+ porte...]

Caratteristiche:
• ≥50 connessioni verso porte diverse dello stesso host
• ≥80% SYN senza ACK (connection refused)
• Durata: <120 secondi

DIAGNOSI: Port scan (nmap-like)
AZIONE: Block IP 203.0.113.50 per 24h + Alert
```

**Altri behavioral signatures:**

| Behavior | Indicatori | Possibile Attacco |
|----------|-----------|-------------------|
| **Beaconing** | Connessioni periodiche (ogni 60s ±5s) verso stesso IP esterno | C2 (Command & Control) malware |
| **DNS Tunneling** | Query DNS con subdomain lunghissimi (>50 char), alta frequenza | Data exfiltration via DNS |
| **Lateral Movement** | Host interno scansiona subnet interna con SMB/RDP | Post-exploitation, propagazione ransomware |
| **Data Exfiltration** | Upload massivo (GB) verso servizi cloud in breve periodo | Furto dati, insider threat |
| **Brute Force** | 100+ tentativi autenticazione SSH/RDP da stesso IP | Credential stuffing |
| **DGA (Domain Generation Algorithm)** | Query DNS verso domini randomici (.xyz, .top, nomi nonsense) | Malware cerca C2 server |

---

## Tecniche Avanzate di Analisi

### 1. User and Entity Behavior Analytics (UEBA)

Analisi comportamentale non solo del traffico di rete, ma anche delle **azioni degli utenti** nel sistema.

```
Profilo utente normale: mario.rossi@azienda.it

Comportamento tipico:
┌────────────────────────────────────────────────┐
│ • Login: 08:30-17:00 lun-ven da Milano         │
│ • Accessi: ERP, email, file server marketing   │
│ • Download: ~50MB/giorno (documenti Office)    │
│ • Geolocation: Italia (100%)                   │
│ • Device: laptop-mario-001 (Windows 11)        │
└────────────────────────────────────────────────┘

Anomalia rilevata:

⚠️  ALERT: mario.rossi@azienda.it
────────────────────────────────────────────────
• Login simultaneo da Milano (IT) e Bucarest (RO)
• Accesso a database HR (mai fatto prima)
• Download 5GB dati clienti in 10 minuti
• Tentativo accesso a server finanza (permission denied)
• Device: nuovo laptop non registrato

SCORE RISCHIO: 0.89 / 1.00 (CRITICAL)
POSSIBILE CAUSA: Account compromesso

AZIONE:
1. Sospensione automatica account
2. Richiesta MFA challenge su tutti i device
3. Alert CISO immediato
```

**Segnali UEBA critici:**
- Accesso a risorse mai usate prima (privilege escalation attempt)
- Orari anomali (3 AM quando l'utente normalmente non lavora)
- Impossible travel (login da continenti diversi in 2 ore)
- Deviazione da peer group (contabile accede a server development)

### 2. Network Traffic Analysis (NTA)

Analisi passiva del traffico di rete (senza inspection inline) tramite **SPAN/mirror ports** o **TAP**.

```
Architettura NTA:

[Switch Core]
      ↓ SPAN port (mirror tutto il traffico)
[NTA Sensor]
      ↓ analisi passiva (no latenza)
[SIEM / Analytics Platform]
      ↓ correlazione eventi
[SOC Dashboard]
```

**Vantaggi NTA:**
- No latency (non è inline, non rallenta il traffico)
- Visibilità completa del traffico east-west (tra server interni)
- Rilevamento di minacce già dentro la rete (post-breach detection)
- Analisi retrospettiva (storage PCAP fino a 90 giorni)

**Metriche analizzate da NTA:**

```python
# Esempio: rilevamento beaconing tramite NTA

import numpy as np

# Connessioni registrate verso IP esterno sospetto
timestamps = [
    1678900000, 1678900060, 1678900120, 1678900180, 
    1678900240, 1678900300  # ogni 60 secondi
]

# Calcola intervalli
intervals = np.diff(timestamps)
# [60, 60, 60, 60, 60]

mean_interval = np.mean(intervals)      # 60.0
std_interval = np.std(intervals)        # 0.0

# Beaconing detected se:
if std_interval < 5 and len(timestamps) > 10:
    print("⚠️  C2 Beaconing rilevato!")
    print(f"Intervallo: {mean_interval}s ± {std_interval}s")
```

### 3. Encrypted Traffic Analysis (ETA)

Analisi del traffico **cifrato** (TLS/SSL) senza decifrarlo.

**Problema:** il 95% del traffico web è HTTPS — impossibile fare DPI senza MITM.

**Soluzione:** analisi delle caratteristiche **esterne** della connessione:

```
Analisi TLS senza decifrare:

┌──────────────────────────────────────────────────┐
│ Features estratti da handshake TLS:              │
├──────────────────────────────────────────────────┤
│ • TLS version (1.2, 1.3)                         │
│ • Cipher suites proposte (ordine caratteristico)│
│ • Extensions (SNI, ALPN, ECH)                    │
│ • Certificate chain (CN, issuer, validity)       │
│ • Timing: durata handshake                       │
│ • Packet sizes: distribuzione lunghezze pacchetti│
│ • Inter-arrival times: timing tra pacchetti      │
└──────────────────────────────────────────────────┘

Machine Learning model:
Input: features sopra
Output: classificazione traffico
  → "benign web browsing"
  → "malware C2 over HTTPS"
  → "data exfiltration to cloud"
```

**Esempio: JA3 Fingerprinting**

```
JA3 hash di client TLS:

SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
  ↓ hash MD5
JA3: e7d705a3286e19ea42f587b344ee6865

Database:
e7d705a3286e19ea42f587b344ee6865 → Google Chrome 120.0
8e1ae5c8b3e1d8f5f1e8c8b3e1d8f5f1 → Trickbot malware C2

If (JA3 in malware_database):
    BLOCK + ALERT
```

---

## Soluzioni Commerciali e Open Source

### Soluzioni Enterprise (NGFW + Behavioral)

| Vendor | Prodotto | Caratteristiche Behavioral |
|--------|----------|----------------------------|
| **Palo Alto Networks** | PA-Series + Cortex XDR | WildFire (sandbox cloud), ML-powered threat prevention, AutoFocus threat intelligence |
| **Fortinet** | FortiGate | FortiGuard AI, behavioral IPS, botnet C2 detection |
| **Cisco** | Firepower NGFW | Snort 3 IPS, Talos threat intelligence, Secure Analytics (NTA) |
| **Check Point** | Quantum NGFW | ThreatCloud AI, SandBlast sandboxing, behavioral anomaly detection |
| **Sophos** | XG Firewall | Xstream architecture (DPI), Synchronized Security (endpoint + firewall correlation) |

### Soluzioni Open Source

#### 1. Suricata (IDS/IPS con Behavioral Rules)

```bash
# Installazione Suricata
sudo apt install suricata

# Esempio regola behavioral: rilevamento beaconing
alert tcp any any -> any any (
  msg:"Possible C2 beaconing detected";
  flow:established,to_server;
  threshold: type both, track by_src, count 10, seconds 600;
  detection_filter: track by_src, count 10, seconds 600;
  classtype:trojan-activity;
  sid:3000001;
)
```

**Features:**
- Protocol detection anche su porte non standard
- File extraction e MD5 hashing
- TLS/JA3 fingerprinting built-in
- Integration con ELK stack per analytics

#### 2. Zeek (già Bro) — Network Security Monitor

```bash
# Script Zeek custom per rilevamento DNS tunneling

@load base/protocols/dns

module DnsTunneling;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Detected
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Query DNS con subdomain > 50 caratteri (possibile tunneling)
    if ( |query| > 50 ) {
        NOTICE([
            $note=DNS_Tunneling_Detected,
            $msg=fmt("DNS query suspiciously long: %s", query),
            $conn=c
        ]);
    }
}
```

**Features:**
- Logging strutturato (JSON)
- Scripting language Turing-complete per custom detection
- Protocol analyzers per 50+ protocolli
- Integration con SIEM

#### 3. pfSense / OPNsense + Snort/Suricata

Firewall open source con IPS integrato.

```
Configurazione pfSense + Suricata:

1. Firewall > pfSense web GUI
2. System > Package Manager > Install Suricata
3. Services > Suricata > Interfaces > WAN Enable
4. Services > Suricata > Global Settings
   ☑ Enable Emerging Threats ruleset
   ☑ Enable Snort ruleset
   ☑ Enable custom behavioral rules
5. Alert output → Syslog → SIEM
```

#### 4. Security Onion — Distro Security Completa

Security Onion integra:
- **Suricata** (IDS)
- **Zeek** (NSM)
- **Wazuh** (HIDS)
- **Elasticsearch** (storage)
- **Kibana** (dashboard)
- **Stenographer** (PCAP)

```bash
# Installazione Security Onion
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/setup/so-setup-network
sudo bash so-setup-network

# Modalità deployment:
# - Standalone: tutto su un nodo (lab/small office)
# - Distributed: sensor + master node (enterprise)
```

---

## Machine Learning per Behavioral Firewall

### Pipeline ML Tipica

```
1. DATA COLLECTION
   ├─ NetFlow / IPFIX records
   ├─ Firewall logs
   ├─ IDS alerts
   └─ PCAP samples

2. FEATURE ENGINEERING
   ├─ Packet size distribution (mean, std, entropy)
   ├─ Inter-arrival time statistics
   ├─ Flow duration
   ├─ Bytes per packet ratio
   └─ Protocol-specific features (DNS query length, HTTP headers)

3. LABELING
   ├─ Normal traffic: labeled as "benign"
   └─ Attack traffic: labeled by attack type (C2, DDoS, exfiltration)

4. TRAINING
   └─ Algorithm: Random Forest / XGBoost / Neural Network

5. DEPLOYMENT
   ├─ Real-time inference on firewall
   └─ Prediction: benign / malicious (+ confidence score)

6. FEEDBACK LOOP
   └─ False positives → retrain model
```

### Esempio: Classificazione Traffico con Random Forest

```python
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Features estratti da connessioni di rete
X_train = np.array([
    # [duration, bytes_sent, bytes_recv, packets, dst_port, protocol_num]
    [5.2,  1024,  2048,  15, 443, 6],   # HTTPS normale
    [120,  500000, 1000, 1000, 443, 6], # possibile exfiltration
    [0.5,  64,    0,     1,  22,  6],   # SSH scan (SYN no reply)
    # ... migliaia di esempi
])

# Labels: 0 = benign, 1 = malicious
y_train = np.array([0, 1, 1, ...])

# Training
clf = RandomForestClassifier(n_estimators=100, max_depth=10)
clf.fit(X_train, y_train)

# Nuova connessione in tempo reale
new_connection = [[2.0, 5000, 3000, 20, 80, 6]]
prediction = clf.predict(new_connection)

if prediction[0] == 1:
    print("⚠️  Connessione sospetta rilevata!")
    # Azione firewall: rate limit / block / alert
```

### Sfide del ML nei Firewall

| Sfida | Problema | Soluzione |
|-------|----------|-----------|
| **False Positives** | Troppi alert falsi → alert fatigue | Tuning soglie, ensemble methods, human-in-the-loop |
| **Concept Drift** | Traffico "normale" cambia nel tempo | Retraining periodico (weekly), online learning |
| **Adversarial ML** | Attaccante manipola features per evadere | Adversarial training, model robustness testing |
| **Latency** | Inferenza ML aggiunge latenza | Model optimization (quantization), edge computing |
| **Explainability** | "Black box" — perché ha bloccato? | SHAP values, LIME, decision trees (interpretable) |

---

## Implementazione Pratica: Esempio con Suricata + ELK

### Architettura

```
Internet
   ↓
[Router]
   ↓ SPAN port
[Suricata Sensor] ← Analizza traffico in modalità IDS
   ↓ JSON logs
[Logstash] ← Parse e arricchisce log
   ↓
[Elasticsearch] ← Indicizza e conserva
   ↓
[Kibana] ← Dashboard per SOC
```

### 1. Configurazione Suricata

```yaml
# /etc/suricata/suricata.yaml

# Network interface per sniffing
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow

# Enable EVE JSON log
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
        - http:
            extended: yes
        - dns:
            enabled: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - flow

# Ruleset
rule-files:
  - /var/lib/suricata/rules/suricata.rules
  - /var/lib/suricata/rules/emerging-threats.rules
  - /etc/suricata/rules/custom-behavioral.rules  # nostre regole
```

### 2. Regola Behavioral Custom

```bash
# /etc/suricata/rules/custom-behavioral.rules

# Rilevamento beaconing C2
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"BEHAVIORAL Possible C2 beaconing";
  flow:established,to_server;
  content:"User-Agent|3a 20|"; # "User-Agent: "
  pcre:"/User-Agent\:\s+(curl|wget|python-requests)/i";
  threshold: type both, track by_src, count 10, seconds 600;
  classtype:trojan-activity;
  priority:1;
  sid:9000001;
  rev:1;
)

# Rilevamento DNS tunneling
alert dns any any -> any 53 (
  msg:"BEHAVIORAL DNS tunneling suspected";
  dns.query; content:"."; isdataat:50,relative;
  classtype:bad-unknown;
  priority:2;
  sid:9000002;
  rev:1;
)

# Rilevamento lateral movement (SMB scan interno)
alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"BEHAVIORAL Internal SMB scan detected";
  flow:to_server;
  flags:S;
  threshold: type both, track by_src, count 20, seconds 60;
  classtype:attempted-recon;
  priority:2;
  sid:9000003;
  rev:1;
)
```

### 3. Logstash Pipeline

```ruby
# /etc/logstash/conf.d/suricata.conf

input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
    type => "suricata"
  }
}

filter {
  if [type] == "suricata" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Arricchimento geolocation
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geo"
      }
    }
    
    # Arricchimento threat intelligence
    if [dest_ip] {
      # Lookup su threat feed (esempio)
      translate {
        field => "dest_ip"
        destination => "threat_intel"
        dictionary_path => "/etc/logstash/threat_intel.yml"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```

### 4. Kibana Dashboard

Query utili per analisi comportamentale:

```json
# Alert con confidence score alto
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "alert" } },
        { "range": { "alert.severity": { "lte": 2 } } }
      ]
    }
  }
}

# Top 10 source IP per numero alert
{
  "size": 0,
  "aggs": {
    "top_sources": {
      "terms": {
        "field": "src_ip",
        "size": 10,
        "order": { "_count": "desc" }
      }
    }
  }
}

# Timeline alert per categoria
{
  "size": 0,
  "aggs": {
    "timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "1h"
      },
      "aggs": {
        "by_category": {
          "terms": { "field": "alert.category" }
        }
      }
    }
  }
}
```

---

## Case Study: Rilevamento Ransomware con Analisi Comportamentale

### Scenario

Un laptop aziendale viene infettato da ransomware **Ryuk**. Il firewall comportamentale rileva l'attacco prima della cifratura completa.

### Timeline Attacco

```
T+0min:  Utente apre email phishing, esegue macro Word
         → Firewall non rileva nulla (traffico HTTPS legittimo)

T+5min:  Malware dropper scarica payload da C2
         Traffico: HTTPS verso cloudfront.net (CDN legittimo)
         → Firewall stateful: ALLOW (porta 443, certificate valido)

T+10min: Payload inizia beaconing verso C2 185.xxx.xxx.xxx
         Pattern: connessione ogni 60 secondi esatti
         ⚠️ BEHAVIORAL ALERT #1: "C2 beaconing detected"
         Score: 0.75 (Medium)

T+15min: Lateral movement: scansione SMB su subnet interna
         Pattern: 50 connessioni tcp:445 verso 192.168.1.0/24 in 30s
         ⚠️ BEHAVIORAL ALERT #2: "Internal SMB scan"
         Score: 0.85 (High)

T+20min: Tentativo connessione RDP ad altri 20 host
         Pattern: tcp:3389 verso host mai contattati prima
         ⚠️ BEHAVIORAL ALERT #3: "Lateral movement RDP"
         Score: 0.90 (Critical)

T+25min: NGFW correla i 3 alert + UEBA
         • Stesso src_ip (laptop compromesso)
         • Pattern coerente con ransomware TTPs (MITRE ATT&CK)
         • Utente non ha mai fatto SMB scan in passato

AZIONE AUTOMATICA (T+26min):
1. Isolamento host da rete (block src_ip su tutti i VLAN)
2. Kill connections attive
3. Alert SOC priority P1
4. Snapshot VM (se virtualizzato) per forensics
5. Email a utente: "Device isolato per sospetto malware"
```

### Confronto: Con e Senza Firewall Comportamentale

| Evento | Firewall Stateful | NGFW Comportamentale |
|--------|-------------------|----------------------|
| Beaconing C2 | ✗ Non rilevato (porta 443 legittima) | ✓ Rilevato (pattern periodico anomalo) |
| SMB scan interno | ✗ Non rilevato (traffico interno permesso) | ✓ Rilevato (scan comportamento anomalo) |
| Lateral movement | ✗ Non rilevato | ✓ Rilevato + correlato con altri alert |
| Tempo rilevamento | Mai (attacco completo) | **26 minuti** (prima della cifratura di massa) |
| Impatto | 100% file cifrati | <5% file cifrati (isolamento rapido) |

---

## Best Practice per Deployment

### 1. Tuning Iniziale

```
Fase 1: Learning Mode (2-4 settimane)
────────────────────────────────────────
☐ Deploy firewall in monitor-only mode
☐ Raccolta baseline traffico normale
☐ Identificazione false positive
☐ Tuning threshold e confidence score

Fase 2: Alert Mode (2 settimane)
────────────────────────────────────────
☐ Abilita alerting ma non blocking
☐ SOC valida alert, identifica FP
☐ Aggiusta regole comportamentali

Fase 3: Enforce Mode (ongoing)
────────────────────────────────────────
☐ Abilita blocking automatico
☐ Monitoring continuo
☐ Retraining ML model (mensile)
```

### 2. Regole d'Oro

```
✓ Inizia con detection, non prevention
✓ Prioritizza alert critici (C2, lateral movement, exfiltration)
✓ Integra con SIEM per correlazione multi-sorgente
✓ Whitelist applicazioni business-critical (evita blocchi accidentali)
✓ Mantieni logging esteso (PCAP per investigation)
✓ Threat intel feed aggiornato (< 24h)
✓ Response playbook automatizzato (SOAR integration)
✓ Review alert weekly: identifica nuovi pattern
```

### 3. Metriche di Successo

```
KPI da monitorare:

• Mean Time to Detect (MTTD): < 1 ora
• Mean Time to Respond (MTTR): < 4 ore
• False Positive Rate: < 5%
• True Positive Rate: > 90%
• Coverage: % traffico analizzato (target: 100% north-south, 80% east-west)
• Alert volume: 10-50 alert/giorno gestibili da SOC
```

---

## Limitazioni e Considerazioni

### Privacy e GDPR

L'analisi comportamentale può comportare profilazione utenti:

```
⚠️  GDPR Considerations:

• Art. 22: Profilazione automatizzata → richiede consenso esplicito
• Art. 35: DPIA (Data Protection Impact Assessment) obbligatoria
• Art. 32: Misure tecniche adeguate per pseudonimizzazione

Best practice compliance:
✓ Anonimizza IP utenti nei log dopo 90 giorni
✓ User notification su monitoring (policy aziendale)
✓ Limita analisi a traffico business-related (no social, personal)
✓ Audit trail su chi accede ai log comportamentali
✓ Data retention policy (default 1 anno max)
```

### Costi

```
Costi tipici NGFW enterprise:

Capex:
• Appliance hardware: €5.000 - €50.000 (dipende da throughput)
• Licenze iniziali: €10.000 - €100.000

Opex annuo:
• Subscription (threat intel + updates): €5.000 - €30.000
• Supporto vendor: 15-20% capex
• Staff SOC (analisti): €50.000 - €80.000/anno per FTE
• Cloud compute (se ML in cloud): €1.000 - €10.000/mese

ROI:
• Breach evitato: €500.000 - €5.000.000 (costo medio incident)
• Payback period tipico: 1-2 anni
```

### Limiti Tecnici

```
✗ Encrypted traffic (TLS 1.3): difficile analisi senza MITM
✗ High-speed networks (100G+): ML inference può aggiungere latenza
✗ Zero-day unknown: algoritmi si basano su comportamenti noti
✗ Adversarial attacks: attaccanti evadono detection variando timing
✗ Concept drift: modelli degradano se non retrainati regolarmente
```

---

## Domande di Verifica

1. **Spiega perché un firewall stateful tradizionale non riesce a bloccare malware che usa HTTPS per comunicare con un server C2. Come risolve il problema un firewall comportamentale?**

2. **Descrivi il concetto di "baseline comportamentale". Quali metriche useresti per creare un baseline per un web server interno?**

3. **Cosa si intende per "beaconing" nel contesto C2? Come può essere rilevato algoritmicamente senza ispezionare il payload cifrato?**

4. **Elenca 3 vantaggi e 3 svantaggi dell'uso di Machine Learning nei firewall comportamentali.**

5. **Nel caso study del ransomware Ryuk, quali sono stati i 3 alert comportamentali che hanno permesso il rilevamento? Perché un firewall tradizionale non li avrebbe identificati?**

6. **Cosa sono le "behavioral signatures"? Fornisci un esempio di signature per rilevare un port scan.**

---

## Riferimenti

### Standard e Framework
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Tactics, Techniques, and Procedures
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Identify, Protect, Detect, Respond, Recover
- [ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) - Information Security Management

### Tools Open Source
- [Suricata](https://suricata.io/) - IDS/IPS con behavioral rules
- [Zeek](https://zeek.org/) - Network Security Monitor
- [Security Onion](https://securityonionsolutions.com/) - Distro completa per NSM
- [SELKS](https://www.stamus-networks.com/selks) - Suricata + ELK stack preconfigurato

### Libri
- "Applied Network Security Monitoring" - Chris Sanders, Jason Smith
- "The Practice of Network Security Monitoring" - Richard Bejtlich
- "Machine Learning and Security" - Clarence Chio, David Freeman

### Research Papers
- "LSTM-based Network Traffic Analysis" - IEEE 2020
- "Detecting Encrypted Malware Traffic Without Decryption" - ACM CCS 2019
- "JA3/JA3S TLS Fingerprinting" - Salesforce Research

---

**Indice**: [README](../README.md)  
**Sezione Precedente**: [06 - nftables](./06_nftables.md)
