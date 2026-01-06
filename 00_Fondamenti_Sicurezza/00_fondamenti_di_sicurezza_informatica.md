# Capitolo 0 - Fondamenti di Sicurezza Informatica

> **Corso**: Sistemi e Reti 3  
> **Parte**: 0 - Fondamenti di Sicurezza Informatica  
> **Autore**: Prof. Filippo Bilardo  
> **Ultima modifica**: Dicembre 2025

---

## 📋 Indice

1. [Introduzione](#introduzione)
2. [Concetti Base di Sicurezza](#concetti-base)
3. [CIA Triad](#cia-triad)
4. [Panorama delle Minacce](#panorama-minacce)
5. [Vulnerabilità e Exploit](#vulnerabilita-exploit)
6. [Risk Management](#risk-management)
7. [Esempi Pratici](#esempi-pratici)
8. [Esercizi](#esercizi)

---

## 🎯 Introduzione

La **sicurezza informatica** è la pratica di proteggere sistemi, reti e dati da attacchi digitali, danni o accessi non autorizzati. È un campo multidisciplinare che comprende tecnologia, processi e persone.

### Perché è importante?

Nel mondo moderno, la sicurezza informatica è fondamentale perché:
- I dati sono diventati il "nuovo petrolio"
- Le minacce informatiche costano miliardi alle aziende
- La privacy è un diritto fondamentale
- Le infrastrutture critiche dipendono dalla sicurezza IT

---

## 🔐 Concetti Base di Sicurezza {#concetti-base}

### 0.1 Definizione di Sicurezza Informatica

La sicurezza informatica (o **cybersecurity**) è la protezione di:
- **Hardware**: dispositivi fisici
- **Software**: programmi e sistemi operativi
- **Dati**: informazioni in transito e a riposo
- **Reti**: comunicazioni e connessioni

### 0.2 Principi Fondamentali

I principi base della sicurezza informatica si possono riassumere nell'acronimo **CIA Triad**:

```
    Confidenzialità
         /\
        /  \
       /____\
      /      \
     / Integ- \
    /   rità   \
   /____________\
   Disponibilità
```

---

## 🛡️ CIA Triad {#cia-triad}

### 0.3.1 Confidenzialità (Confidentiality)

**Definizione**: Garantire che le informazioni siano accessibili solo a chi è autorizzato.

**Tecniche**:
- **Crittografia**: Cifrare i dati sensibili
- **Controllo accessi**: ACL, RBAC
- **Autenticazione**: Password, MFA, biometria

**Esempio pratico**:
```python
from cryptography.fernet import Fernet

# Genera una chiave per la crittografia
key = Fernet.generate_key()
cipher = Fernet(key)

# Dati sensibili
messaggio = b"Numero carta: 1234-5678-9012-3456"

# Cifratura per garantire la confidenzialità
cifrato = cipher.encrypt(messaggio)
print(f"Cifrato: {cifrato}")

# Decifratura (solo chi ha la chiave)
decifrato = cipher.decrypt(cifrato)
print(f"Decifrato: {decifrato}")
```

### 0.3.2 Integrità (Integrity)

**Definizione**: Assicurare che i dati non vengano modificati o corrotti in modo non autorizzato.

**Tecniche**:
- **Hash crittografici**: SHA-256, SHA-3
- **Firme digitali**: RSA, ECDSA
- **Checksum**: Verifica integrità file

**Esempio pratico**:
```python
import hashlib

# File da verificare
file_content = b"Documento importante"

# Calcola hash SHA-256
hash_originale = hashlib.sha256(file_content).hexdigest()
print(f"Hash originale: {hash_originale}")

# Simula modifica del file
file_modificato = b"Documento importante modificato"
hash_modificato = hashlib.sha256(file_modificato).hexdigest()

# Verifica integrità
if hash_originale == hash_modificato:
    print("✅ File integro")
else:
    print("⚠️ File modificato! Integrità compromessa")
```

### 0.3.3 Disponibilità (Availability)

**Definizione**: Garantire che sistemi e dati siano accessibili quando necessario.

**Tecniche**:
- **Ridondanza**: Backup, RAID, cluster
- **Bilanciamento carico**: Load balancer
- **Protezione DDoS**: Firewall, CDN
- **Piano di disaster recovery**

**Metriche**:
- **RTO** (Recovery Time Objective): Tempo massimo di inattività accettabile
- **RPO** (Recovery Point Objective): Perdita dati massima accettabile
- **Uptime**: Percentuale di disponibilità (es. 99.9% = 8.76 ore downtime/anno)

### 0.3.4 Autenticazione e Autorizzazione

**Autenticazione**: Verificare l'identità dell'utente
- **Qualcosa che conosci**: Password, PIN
- **Qualcosa che possiedi**: Token, smart card
- **Qualcosa che sei**: Biometria (impronta, face ID)

**Autorizzazione**: Determinare a cosa l'utente può accedere
- **DAC** (Discretionary Access Control)
- **MAC** (Mandatory Access Control)
- **RBAC** (Role-Based Access Control)
- **ABAC** (Attribute-Based Access Control)

### 0.3.5 Accountability e Non-Repudiation

**Accountability**: Tracciare le azioni degli utenti
- Log e audit trail
- SIEM (Security Information and Event Management)

**Non-Repudiation**: Impedire che qualcuno neghi di aver eseguito un'azione
- Firme digitali
- Timestamp crittografici
- Certificati digitali

---

## ⚠️ Panorama delle Minacce {#panorama-minacce}

### 0.4.1 Attori delle Minacce (Threat Actors)

| Tipo | Motivazione | Capacità | Esempi |
|------|-------------|----------|--------|
| **Script Kiddies** | Divertimento, reputazione | Bassa | Attacchi automatizzati |
| **Hacktivisti** | Ideologia, protesta | Media | Anonymous, LulzSec |
| **Cybercriminali** | Profitto finanziario | Alta | Ransomware gang |
| **Insider Threat** | Vendetta, denaro | Variabile | Dipendenti infedeli |
| **APT (Advanced Persistent Threat)** | Spionaggio, sabotaggio | Molto alta | Gruppi sponsorizzati da stati |

### 0.4.2 Motivazioni degli Attaccanti

1. **Finanziarie**: Furto dati, ransomware, frodi
2. **Politiche**: Spionaggio, sabotaggio infrastrutture
3. **Ideologiche**: Hacktivismo, proteste digitali
4. **Personali**: Vendetta, ego, sfida

### 0.4.3 Superfici di Attacco

Le aree vulnerabili di un sistema:

```
┌─────────────────────────────────────┐
│    Superficie di Attacco Digitale   │
├─────────────────────────────────────┤
│ • Applicazioni web                  │
│ • API e servizi                     │
│ • Rete e protocolli                 │
│ • Sistema operativo                 │
│ • Database                          │
│ • Dispositivi IoT                   │
└─────────────────────────────────────┘
         │
┌─────────────────────────────────────┐
│   Superficie di Attacco Fisica      │
├─────────────────────────────────────┤
│ • Server e workstation              │
│ • Dispositivi mobili                │
│ • USB e media rimovibili            │
│ • Reti wireless                     │
└─────────────────────────────────────┘
         │
┌─────────────────────────────────────┐
│   Superficie di Attacco Social      │
├─────────────────────────────────────┤
│ • Phishing e social engineering     │
│ • Pretexting                        │
│ • Tailgating                        │
└─────────────────────────────────────┘
```

### 0.4.4 Vettori di Attacco

- **Email**: Phishing, malware attachment
- **Web**: Drive-by download, XSS, SQL injection
- **Rete**: Man-in-the-Middle, packet sniffing
- **Fisico**: USB malware, shoulder surfing
- **Supply Chain**: Compromissione fornitori

---

## 🐛 Vulnerabilità e Exploit {#vulnerabilita-exploit}

### 0.5.1 CVE (Common Vulnerabilities and Exposures)

**CVE** è un dizionario pubblico di vulnerabilità di sicurezza note.

**Formato**: CVE-ANNO-NUMERO
- Esempio: `CVE-2021-44228` (Log4Shell)

**Struttura CVE**:
```
CVE-2021-44228
├── Descrizione: Remote code execution in Apache Log4j
├── Severity: CRITICAL (10.0 CVSS)
├── Affected: Apache Log4j 2.0-beta9 through 2.15.0
└── References: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

### 0.5.2 CWE (Common Weakness Enumeration)

**CWE** classifica i tipi di debolezze software.

**Top 10 CWE più pericolose (2023)**:
1. **CWE-787**: Out-of-bounds Write
2. **CWE-79**: Cross-site Scripting (XSS)
3. **CWE-89**: SQL Injection
4. **CWE-20**: Improper Input Validation
5. **CWE-125**: Out-of-bounds Read

### 0.5.3 CVSS (Common Vulnerability Scoring System)

**CVSS** fornisce un punteggio di gravità da 0.0 a 10.0.

**Scala CVSS v3**:
| Punteggio | Severità | Colore |
|-----------|----------|--------|
| 0.0 | None | 🟢 Verde |
| 0.1 - 3.9 | Low | 🟡 Giallo |
| 4.0 - 6.9 | Medium | 🟠 Arancione |
| 7.0 - 8.9 | High | 🔴 Rosso |
| 9.0 - 10.0 | Critical | ⚫ Nero |

**Esempio di calcolo CVSS**:
```python
# Metriche CVSS v3
metrics = {
    "Attack Vector": "Network",        # AV:N
    "Attack Complexity": "Low",        # AC:L
    "Privileges Required": "None",     # PR:N
    "User Interaction": "None",        # UI:N
    "Scope": "Changed",                # S:C
    "Confidentiality": "High",         # C:H
    "Integrity": "High",               # I:H
    "Availability": "High"             # A:H
}

# CVSS String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
# Score: 10.0 (CRITICAL)
```

### 0.5.4 Zero-Day Vulnerabilities

**Zero-Day**: Vulnerabilità scoperta e sfruttata prima che il vendor rilasci una patch.

**Ciclo di vita**:
1. **Scoperta** della vulnerabilità
2. **Exploit development**
3. **Attacco in-the-wild**
4. **Disclosure** pubblica o privata
5. **Patch release** dal vendor
6. **Patch deployment** dagli utenti

**Famosi Zero-Day**:
- **Stuxnet** (2010): 4 zero-day contro Siemens SCADA
- **EternalBlue** (2017): NSA exploit usato in WannaCry
- **Pegasus** (2021): Spyware iOS zero-click

---

## 📊 Risk Management {#risk-management}

### 0.6.1 Identificazione dei Rischi

**Risk = Threat × Vulnerability × Impact**

**Processo**:
1. **Asset Identification**: Cosa proteggere?
2. **Threat Modeling**: Quali minacce?
3. **Vulnerability Assessment**: Quali debolezze?
4. **Impact Analysis**: Quali conseguenze?

### 0.6.2 Valutazione dei Rischi

**Matrice Rischio**:

```
        │ ALTA │  M  │  H  │  C  │
Probabi-│──────┼─────┼─────┼─────┤
lità    │MEDIA │  L  │  M  │  H  │
        │──────┼─────┼─────┼─────┤
        │BASSA │  L  │  L  │  M  │
        └──────┴─────┴─────┴─────┘
               BASSO MEDIO ALTO
                   Impatto

L = Low Risk (Basso)
M = Medium Risk (Medio)
H = High Risk (Alto)
C = Critical Risk (Critico)
```

### 0.6.3 Mitigazione e Accettazione

**Strategie di risposta al rischio**:

1. **Mitigare**: Ridurre probabilità o impatto
   - Implementare controlli di sicurezza
   - Patch management
   - Training utenti

2. **Trasferire**: Spostare il rischio a terzi
   - Cyber insurance
   - Outsourcing

3. **Evitare**: Eliminare l'attività rischiosa
   - Disabilitare servizi non necessari

4. **Accettare**: Consapevolmente accettare il rischio
   - Documentare la decisione
   - Solo per rischi bassi

### 0.6.4 Monitoraggio Continuo

**Framework di monitoraggio**:
- **SIEM**: Security Information and Event Management
- **IDS/IPS**: Intrusion Detection/Prevention Systems
- **Vulnerability Scanning**: Scansioni periodiche
- **Penetration Testing**: Test annuali

---

## 💡 Esempi Pratici {#esempi-pratici}

### Esempio 1: Verifica Integrità File con SHA-256

```python
import hashlib
import sys

def calcola_hash_file(filename):
    """Calcola SHA-256 hash di un file"""
    sha256 = hashlib.sha256()
    
    try:
        with open(filename, 'rb') as f:
            # Leggi il file a blocchi per file grandi
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def verifica_integrita(file1, file2):
    """Verifica se due file sono identici"""
    hash1 = calcola_hash_file(file1)
    hash2 = calcola_hash_file(file2)
    
    if hash1 and hash2:
        if hash1 == hash2:
            print(f"✅ I file sono identici")
            print(f"Hash: {hash1}")
        else:
            print(f"⚠️ I file sono DIVERSI")
            print(f"Hash {file1}: {hash1}")
            print(f"Hash {file2}: {hash2}")
    else:
        print("❌ Errore nella lettura dei file")

# Esempio d'uso
if __name__ == "__main__":
    verifica_integrita("documento_originale.pdf", "documento_ricevuto.pdf")
```

### Esempio 2: Simulazione Risk Assessment

```python
class RiskAssessment:
    def __init__(self, asset_name):
        self.asset = asset_name
        self.threats = []
    
    def add_threat(self, name, probability, impact):
        """
        probability: 1-5 (1=molto bassa, 5=molto alta)
        impact: 1-5 (1=trascurabile, 5=catastrofico)
        """
        risk_score = probability * impact
        
        if risk_score <= 5:
            severity = "LOW"
        elif risk_score <= 15:
            severity = "MEDIUM"
        elif risk_score <= 20:
            severity = "HIGH"
        else:
            severity = "CRITICAL"
        
        self.threats.append({
            'name': name,
            'probability': probability,
            'impact': impact,
            'risk_score': risk_score,
            'severity': severity
        })
    
    def generate_report(self):
        print(f"\n{'='*60}")
        print(f"RISK ASSESSMENT REPORT: {self.asset}")
        print(f"{'='*60}\n")
        
        # Ordina per risk score decrescente
        sorted_threats = sorted(self.threats, 
                              key=lambda x: x['risk_score'], 
                              reverse=True)
        
        for threat in sorted_threats:
            print(f"Threat: {threat['name']}")
            print(f"  Probability: {threat['probability']}/5")
            print(f"  Impact: {threat['impact']}/5")
            print(f"  Risk Score: {threat['risk_score']}/25")
            print(f"  Severity: {threat['severity']}")
            print()

# Esempio d'uso
assessment = RiskAssessment("Server Web E-commerce")

assessment.add_threat("SQL Injection", probability=4, impact=5)
assessment.add_threat("DDoS Attack", probability=3, impact=4)
assessment.add_threat("Insider Threat", probability=2, impact=5)
assessment.add_threat("Phishing su admin", probability=3, impact=5)
assessment.add_threat("Furto fisico server", probability=1, impact=4)

assessment.generate_report()
```

**Output**:
```
============================================================
RISK ASSESSMENT REPORT: Server Web E-commerce
============================================================

Threat: SQL Injection
  Probability: 4/5
  Impact: 5/5
  Risk Score: 20/25
  Severity: HIGH

Threat: Phishing su admin
  Probability: 3/5
  Impact: 5/5
  Risk Score: 15/25
  Severity: MEDIUM

...
```

---

## 📝 Esercizi {#esercizi}

### Esercizio 1: CIA Triad (★☆☆)

Per ciascuno dei seguenti scenari, identifica quale principio della CIA Triad è compromesso:

1. Un database contiene record di pazienti accessibili pubblicamente su Internet
2. Un attacco DDoS rende un sito web inaccessibile per 4 ore
3. Un malware modifica subdolamente i saldi bancari nel database

**Soluzioni**:
<details>
<summary>Clicca per vedere le soluzioni</summary>

1. **Confidenzialità** - I dati sensibili sono esposti
2. **Disponibilità** - Il servizio è irraggiungibile
3. **Integrità** - I dati sono stati modificati senza autorizzazione
</details>

### Esercizio 2: CVSS Scoring (★★☆)

Data la seguente vulnerabilità, calcola il livello di severità:
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: Required
- Confidentiality Impact: High
- Integrity Impact: None
- Availability Impact: None

**Soluzione**:
<details>
<summary>Clicca per vedere la soluzione</summary>

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/C:H/I:N/A:N
Score: ~6.5 (MEDIUM)

La vulnerabilità richiede interazione utente (es. phishing), ma ha impatto alto sulla confidenzialità.
</details>

### Esercizio 3: Risk Management (★★★)

Sei il CISO di una media azienda. Hai identificato le seguenti minacce:

| Minaccia | Probabilità | Impatto | Costo Mitigazione |
|----------|-------------|---------|-------------------|
| Ransomware | Alta (4/5) | Critico (5/5) | 50.000€ |
| Furto laptop | Media (3/5) | Basso (2/5) | 5.000€ |
| SQL Injection | Media (3/5) | Alto (4/5) | 20.000€ |
| Incendio datacenter | Bassa (1/5) | Catastrofico (5/5) | 200.000€ |

Budget disponibile: 80.000€

Quali minacce mitighi e perché?

**Soluzione**:
<details>
<summary>Clicca per vedere una possibile soluzione</summary>

**Priorità di mitigazione**:
1. **Ransomware** (Risk Score: 20/25) - MITIGARE con 50.000€
   - Backup, training, segmentazione rete
2. **SQL Injection** (Risk Score: 12/25) - MITIGARE con 20.000€
   - WAF, code review, input validation
3. **Furto laptop** (Risk Score: 6/25) - MITIGARE con 5.000€
   - Full disk encryption, MDM
4. **Incendio datacenter** (Risk Score: 5/25) - TRASFERIRE
   - Assicurazione + cloud backup (già coperto)

Totale speso: 75.000€ (dentro budget)
Rischi residui: Accettati e documentati
</details>

---

## 🔗 Collegamenti

- **Prossimo**: [Capitolo 1 - Introduzione alla Crittografia](../01_Fondamenti_Crittografia/01_introduzione_alla_crittografia.md)
- **Indice**: [Torna all'indice principale](../00_INDICE.md)

---

## 📚 Risorse Aggiuntive

### Standard e Framework
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **ISO/IEC 27001**: Standard gestione sicurezza informazioni
- **CIS Controls**: https://www.cisecurity.org/controls

### Database Vulnerabilità
- **NVD** (National Vulnerability Database): https://nvd.nist.gov/
- **CVE**: https://cve.mitre.org/
- **CWE**: https://cwe.mitre.org/

### Tools
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

---

**Nota**: Questo è un capitolo introduttivo. Gli argomenti qui trattati saranno approfonditi nei capitoli successivi con focus specifico sulla crittografia e sicurezza di rete.
