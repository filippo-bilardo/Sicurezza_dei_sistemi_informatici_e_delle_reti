# Guida Completa a Nessus Essentials

## Indice
1. [Introduzione](#introduzione)
2. [Installazione](#installazione)
3. [Configurazione Iniziale](#configurazione)
4. [Creazione e Gestione Scan](#scan)
5. [Tipi di Scan](#tipi-scan)
6. [Interpretazione Risultati](#risultati)
7. [Gestione Vulnerabilità](#vulnerabilita)
8. [Report e Export](#report)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)
11. [Alternative a Nessus Essentials](#alternative)

---

## 1. Introduzione {#introduzione}

**Nessus Essentials** (ex Nessus Home) è uno scanner di vulnerabilità gratuito sviluppato da Tenable, leader nel settore della vulnerability assessment.

### Caratteristiche Principali

- **Gratuito per uso personale/educativo**: fino a 16 IP
- **Database vulnerabilità**: oltre 170.000 plugin
- **Aggiornamenti automatici**: plugin aggiornati quotidianamente
- **Web-based interface**: gestione via browser
- **Compliance checking**: verifiche di conformità
- **Credentialed scanning**: scan autenticati per analisi approfondite
- **Reporting avanzato**: report esportabili in vari formati

### Limitazioni Nessus Essentials vs Professional

| Feature | Essentials | Professional |
|---------|-----------|--------------|
| **Numero IP** | 16 max | Illimitati |
| **Uso commerciale** | ❌ No | ✅ Sì |
| **Advanced scanning** | Limitato | Completo |
| **Support** | Community | Commerciale |
| **Compliance auditing** | Basilare | Avanzato |
| **API access** | Limitato | Completo |

### Quando Usare Nessus Essentials

✅ **Home lab e testing personale**  
✅ **Formazione e apprendimento**  
✅ **Small network (< 16 dispositivi)**  
✅ **Vulnerability assessment preliminare**  

❌ **Ambiente enterprise**  
❌ **Uso commerciale/consulenza**  
❌ **Network di grandi dimensioni**  

---

## 2. Installazione {#installazione}

### Requisiti di Sistema

**Hardware Minimo:**
- CPU: 2 GHz dual-core
- RAM: 4 GB
- Disk: 30 GB liberi

**Hardware Raccomandato:**
- CPU: 4 core @ 2.5 GHz+
- RAM: 8 GB+
- Disk: SSD 50 GB+

**Sistemi Operativi Supportati:**
- Windows Server 2012+, Windows 10/11
- Red Hat Enterprise Linux 7/8/9
- Ubuntu 18.04/20.04/22.04
- Debian 9/10/11
- macOS 10.15+

### Download e Registrazione

1. **Registrazione:**
   - Vai su: https://www.tenable.com/products/nessus/nessus-essentials
   - Compila form registrazione
   - Ricevi **Activation Code** via email

2. **Download Installer:**
   ```bash
   # Linux (Ubuntu/Debian)
   wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/[version]/Nessus-[version]-ubuntu1404_amd64.deb
   
   # CentOS/RHEL
   wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/[version]/Nessus-[version]-es8.x86_64.rpm
   
   # macOS
   # Download .dmg dal sito
   
   # Windows
   # Download .msi dal sito
   ```

### Installazione Linux (Ubuntu/Debian)

```bash
# Installa pacchetto .deb
sudo dpkg -i Nessus-*-ubuntu*_amd64.deb

# Start Nessus service
sudo systemctl start nessusd
sudo systemctl enable nessusd

# Verifica stato
sudo systemctl status nessusd

# Nessus è ora disponibile su:
# https://localhost:8834
```

### Installazione CentOS/RHEL

```bash
# Installa pacchetto .rpm
sudo yum install Nessus-*-es8.x86_64.rpm

# Oppure con dnf
sudo dnf install Nessus-*-es8.x86_64.rpm

# Start service
sudo systemctl start nessusd
sudo systemctl enable nessusd

# Firewall (se necessario)
sudo firewall-cmd --permanent --add-port=8834/tcp
sudo firewall-cmd --reload

# Access via browser
# https://localhost:8834
```

### Installazione Windows

```powershell
# Esegui installer MSI come Administrator
.\Nessus-[version]-x64.msi

# Nessus service viene installato automaticamente
# Access via:
# https://localhost:8834

# Verifica service
Get-Service "Tenable Nessus"
```

### Installazione macOS

```bash
# Monta DMG e trascina in Applications
# Oppure via terminale:
sudo installer -pkg /Volumes/Nessus/Install\ Nessus.pkg -target /

# Start service
sudo launchctl load /Library/LaunchDaemons/com.tenablesecurity.nessusd.plist

# Access
# https://localhost:8834
```

---

## 3. Configurazione Iniziale {#configurazione}

### Setup Wizard

1. **Accesso Web Interface:**
   - Browser: `https://localhost:8834`
   - Accetta certificato self-signed (warning normale)

2. **Welcome Screen:**
   - Seleziona: **"Nessus Essentials"**
   - Click: **"Continue"**

3. **Activation:**
   - Inserisci **Activation Code** ricevuto via email
   - Click: **"Continue"**
   - Attendi download plugin (~10-20 minuti)

4. **Create User Account:**
   ```
   Username: admin
   Password: [strong password - min 12 caratteri]
   ```
   - Click: **"Submit"**

5. **Plugin Compilation:**
   - Attendi compilazione plugin
   - Può richiedere 15-30 minuti

### Post-Installation Configuration

**Settings → Advanced:**

```yaml
# Performance tuning
Max concurrent checks per host: 5
Max concurrent hosts: 10
Reduce parallel connections on congestion: Yes

# Network settings
Allow unsafe SSL/TLS renegotiation: No
Use kernel congestion detection: Yes

# Scanner settings
Stop scanning after host becomes unreachable: Yes
Enable safe checks: Yes (per scan meno invasivi)
```

**Settings → Software Updates:**
```yaml
# Plugin updates
Update plugins automatically: Yes
Update frequency: Daily

# Software updates
Check for updates automatically: Yes
```

---

## 4. Creazione e Gestione Scan {#scan}

### Creazione Nuovo Scan

1. **New Scan:**
   - Click: **"New Scan"**
   - Seleziona template appropriato

2. **Basic Network Scan Template:**
   ```yaml
   Name: "Network Vulnerability Scan"
   Description: "Comprehensive vulnerability assessment"
   Folder: My Scans
   
   Targets: 
     - Single IP: 192.168.1.10
     - Range: 192.168.1.1-50
     - CIDR: 192.168.1.0/24
     - Hostname: server.example.com
     - Import file: targets.txt
   
   Schedule:
     - Enabled: No (manual scan)
     - Frequency: Once
     - Start time: --
   ```

3. **Discovery Settings:**
   ```yaml
   # Host Discovery
   Ping methods:
     - TCP
     - ICMP
     - ARP
   
   # Port Scanning
   Port scan range: default
   Consider unscanned ports as closed: No
   ```

4. **Assessment Settings:**
   ```yaml
   # General
   Scan Type: 
     - Full scan (più lento, completo)
     - Light scan (più veloce, meno invasivo)
   
   # Web Applications
   Scan web applications: Yes
   
   # Brute Force
   Enable brute force: No (evita lockout account)
   ```

5. **Credentials (Optional):**
   ```yaml
   # Per scan autenticati più approfonditi
   
   # SSH
   Authentication method: Password
   Username: scanuser
   Password: ********
   Elevate privileges: sudo
   
   # Windows
   Authentication method: Password
   Username: Administrator
   Password: ********
   Domain: WORKGROUP
   
   # SNMP
   Community string: public
   ```

### Tipi di Template Pre-configurati

**1. Basic Network Scan:**
- Scan generale per vulnerabilità comuni
- Discovery porte e servizi
- Non invasivo

**2. Advanced Scan:**
- Configurazione personalizzabile completa
- Controllo granulare su ogni aspetto

**3. Web Application Tests:**
- Focus su vulnerabilità web
- SQL injection, XSS, CSRF
- Crawling e testing applicazioni

**4. Malware Scan:**
- Ricerca backdoor e malware
- Botnet detection
- Suspicious file identification

**5. Internal PCI Network Scan:**
- Compliance PCI DSS
- Verifica requisiti standard pagamenti

**6. SCADA and ICS Audit:**
- Sistemi industriali
- Protocolli SCADA
- Safety-first approach

---

## 5. Tipi di Scan {#tipi-scan}

### Credentialed vs Non-Credentialed Scan

**Non-Credentialed (External) Scan:**
```yaml
Caratteristiche:
  - Simula attaccante esterno
  - Nessuna autenticazione
  - Solo vulnerabilità visibili dall'esterno
  - Più veloce ma meno completo

Rileva:
  - Porte aperte
  - Servizi esposti
  - Vulnerabilità remote
  - Banner e version info
```

**Credentialed (Authenticated) Scan:**
```yaml
Caratteristiche:
  - Accesso con credenziali
  - Analisi approfondita sistema
  - Patch level verification
  - Configuration audit

Rileva:
  - Missing patches
  - Malware e rootkit
  - Configuration errors
  - Local vulnerabilities
  - Compliance issues
```

### Discovery Scan

```yaml
Obiettivo: Identificare host attivi

Settings:
  Port scan: Yes
  Service detection: Yes
  OS identification: Yes
  
Output:
  - Host inventory
  - Open ports list
  - Services/versions
  - OS fingerprint
```

### Vulnerability Scan

```yaml
Obiettivo: Identificare vulnerabilità note

Checks:
  - CVE database
  - Exploit availability
  - Patch status
  - Default credentials
  - Misconfigurations

Severity levels:
  - Critical (CVSS 9.0-10.0)
  - High (CVSS 7.0-8.9)
  - Medium (CVSS 4.0-6.9)
  - Low (CVSS 0.1-3.9)
  - Info (CVSS 0.0)
```

### Compliance Audit Scan

```yaml
Standards supportati:
  - PCI DSS
  - HIPAA
  - CIS Benchmarks
  - NIST
  - ISO 27001

Verifica:
  - Configuration baselines
  - Security policies
  - Access controls
  - Audit logging
```

---

## 6. Interpretazione Risultati {#risultati}

### Dashboard Overview

```
┌─────────────────────────────────────────┐
│  Scan Results Summary                   │
├─────────────────────────────────────────┤
│  Hosts Scanned:         10              │
│  Vulnerabilities:       47              │
│  ├─ Critical:           3               │
│  ├─ High:               12              │
│  ├─ Medium:             18              │
│  ├─ Low:                14              │
│  └─ Info:               156             │
├─────────────────────────────────────────┤
│  Remediation Priority:  View →          │
│  Host Details:          View →          │
│  Vulnerabilities:       View →          │
└─────────────────────────────────────────┘
```

### Vulnerabilities View

**Per Severità:**
```yaml
Critical (CVSS 9.0+):
  - Remote Code Execution
  - Authentication Bypass
  - Privilege Escalation
  → Richiede azione immediata

High (CVSS 7.0-8.9):
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Insecure Deserialization
  → Pianificare remediation urgente

Medium (CVSS 4.0-6.9):
  - Information Disclosure
  - CSRF
  - Weak Encryption
  → Remediation in breve termine

Low (CVSS 0.1-3.9):
  - Directory Listing
  - Verbose Errors
  - Missing Security Headers
  → Remediation quando possibile
```

### Analisi Singola Vulnerabilità

```yaml
Title: Apache HTTP Server CVE-2021-41773 Path Traversal

Synopsis:
  "Remote attacker can read arbitrary files via path traversal"

Description:
  "Apache HTTP Server 2.4.49 is affected by a path traversal
   vulnerability that allows attackers to read files outside
   web root directory..."

Solution:
  "Upgrade to Apache 2.4.51 or later"

See Also:
  - CVE-2021-41773
  - https://httpd.apache.org/security/vulnerabilities_24.html

Risk Information:
  CVSS Base Score: 9.8 (Critical)
  CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  CVSSv2: 7.5

Vulnerability Information:
  Exploit Available: Yes
  Exploitability: Easy
  Patch Publication Date: 2021-10-04
  Vulnerability Publication Date: 2021-10-05

Plugin Information:
  Plugin ID: 154238
  Family: Web Servers
  
References:
  - CVE: CVE-2021-41773
  - BID: 112021
```

### Host Details

```yaml
Host: 192.168.1.10 (web-server-01)

Operating System:
  - Ubuntu Linux 20.04
  - Kernel: 5.4.0-42-generic

Network Information:
  - IP: 192.168.1.10
  - MAC: 00:0C:29:XX:XX:XX
  - NetBIOS: WEB-SERVER-01
  
Open Ports:
  22/tcp    SSH       OpenSSH 8.2p1
  80/tcp    HTTP      Apache 2.4.49
  443/tcp   HTTPS     Apache 2.4.49
  3306/tcp  MySQL     MySQL 5.7.35

Vulnerabilities:
  Critical: 1
  High: 5
  Medium: 8
  Low: 3

Top Vulnerabilities:
  1. Apache Path Traversal (CVE-2021-41773) - Critical
  2. MySQL Authentication Bypass - High
  3. OpenSSH User Enumeration - Medium
```

---

## 7. Gestione Vulnerabilità {#vulnerabilita}

### Prioritizzazione Remediation

**Framework CVSS (Common Vulnerability Scoring System):**

```
CVSS = Base Score × Temporal × Environmental

Base Score Metrics:
  - Attack Vector (AV): Network/Adjacent/Local/Physical
  - Attack Complexity (AC): Low/High
  - Privileges Required (PR): None/Low/High
  - User Interaction (UI): None/Required
  - Scope (S): Unchanged/Changed
  - Impact: Confidentiality/Integrity/Availability

Temporal Score:
  - Exploit Code Maturity
  - Remediation Level
  - Report Confidence

Environmental Score:
  - Modified Base Metrics
  - Confidentiality/Integrity/Availability Requirements
```

### Action Plan Template

```yaml
Vulnerability: Apache CVE-2021-41773
Severity: Critical (CVSS 9.8)
Affected Hosts: 
  - web-server-01 (192.168.1.10)
  - web-server-02 (192.168.1.11)

Immediate Actions:
  1. Isolate affected servers (if possible)
  2. Apply temporary mitigations:
     - Disable directory traversal in Apache config
     - Add WAF rules
  
Short-term (24-48h):
  3. Test patch in staging environment
  4. Schedule maintenance window
  5. Apply Apache update to 2.4.51
  6. Rescan to verify remediation

Long-term:
  7. Implement patch management policy
  8. Enable auto-updates for critical components
  9. Schedule regular vulnerability scans

Verification:
  - Rescan after remediation
  - Verify plugin no longer triggers
  - Document in change log
```

### Remediation Tracking

```python
# Script per tracking remediation
import csv
from datetime import datetime

vulnerabilities = []

def add_vulnerability(host, vuln_id, severity, status):
    """Track vulnerabilità"""
    vuln = {
        'host': host,
        'vuln_id': vuln_id,
        'severity': severity,
        'status': status,
        'discovered': datetime.now(),
        'remediated': None
    }
    vulnerabilities.append(vuln)

def mark_remediated(vuln_id):
    """Marca come risolto"""
    for v in vulnerabilities:
        if v['vuln_id'] == vuln_id:
            v['status'] = 'Remediated'
            v['remediated'] = datetime.now()

def export_report(filename):
    """Export CSV report"""
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
        writer.writeheader()
        writer.writerows(vulnerabilities)

# Usage
add_vulnerability('192.168.1.10', 'CVE-2021-41773', 'Critical', 'Open')
mark_remediated('CVE-2021-41773')
export_report('vuln_tracking.csv')
```

---

## 8. Report e Export {#report}

### Tipi di Report

**1. Executive Summary:**
```yaml
Target Audience: Management, non-technical

Contents:
  - Overall risk score
  - High-level statistics
  - Business impact
  - Remediation timeline
  - Compliance status

Format: PDF, PowerPoint
```

**2. Technical Report:**
```yaml
Target Audience: IT team, Security engineers

Contents:
  - Detailed vulnerability listings
  - CVE references
  - Proof of concept
  - Remediation steps
  - Configuration issues

Format: PDF, HTML
```

**3. Compliance Report:**
```yaml
Target Audience: Auditors, Compliance officers

Contents:
  - Standards compliance status
  - Pass/Fail per requirement
  - Gap analysis
  - Remediation roadmap

Standards:
  - PCI DSS
  - HIPAA
  - ISO 27001
  - CIS Benchmarks
```

### Export Formats

```yaml
Supported Formats:
  - PDF (full report)
  - HTML (interactive)
  - CSV (data export)
  - Nessus (native format)
  - NessusDB (database)

API Export:
  - JSON
  - XML
```

### Generazione Report

**Via Web Interface:**
```
1. Seleziona scan completato
2. Click "Report" → "Generate Report"
3. Seleziona formato (PDF/HTML/CSV)
4. Scegli template:
   - Executive Summary
   - Technical Report
   - Custom Report
5. Configura opzioni:
   - Include host details: Yes
   - Include plugin details: Yes
   - Show progress: Yes
6. Click "Generate"
7. Download quando pronto
```

**Custom Report Configuration:**
```yaml
Sections to include:
  ☑ Table of Contents
  ☑ Executive Summary
  ☑ Scan Information
  ☑ Host Summary
  ☑ Vulnerabilities by Host
  ☑ Vulnerabilities by Plugin
  ☑ Compliance Results
  ☑ Remediations
  ☐ Plugin Details (troppo verbose)

Filters:
  Severity: Critical, High, Medium
  Hosts: All
  Plugin families: All
  
Output options:
  Include charts: Yes
  Include graphs: Yes
  Color coding: By severity
```

---

## 9. Best Practices {#best-practices}

### 1. Scheduling Scans

```yaml
Frequency Recommendations:

Critical Infrastructure:
  - Weekly full scans
  - Daily discovery scans
  - Post-change verification scans

Production Servers:
  - Bi-weekly vulnerability scans
  - Monthly compliance audits
  - Quarterly deep-dive audits

Development/Testing:
  - Monthly vulnerability scans
  - Pre-deployment scans

Workstations:
  - Monthly scans
  - Quarterly compliance checks

Timing:
  - Off-peak hours (night/weekend)
  - Avoid business-critical periods
  - Coordinate with change windows
```

### 2. Scan Configuration

```yaml
Performance Tuning:

Network Considerations:
  - Max concurrent hosts: 5-10 (adjust by network capacity)
  - Max checks per host: 5
  - Scan slow down on congestion: Yes
  
Invasiveness:
  - Enable safe checks: Yes (production)
  - Disable safe checks: No (unless authorized)
  - Stop on denial of service: Yes

Credentials:
  - Use dedicated scan accounts
  - Minimal necessary privileges
  - Rotate credentials regularly
  - Log all credentialed access
```

### 3. False Positive Management

```yaml
Verification Process:
  1. Review vulnerability details
  2. Check affected systems manually
  3. Reproduce if possible
  4. Verify with multiple tools
  
If False Positive:
  1. Document reasoning
  2. Create exception rule
  3. Retest with updated config
  4. Report to Tenable (improve plugin)

Common False Positives:
  - Version detection errors
  - Filtered ports misidentified as open
  - SSL/TLS false alarms
  - Web app scanner misinterpretations
```

### 4. Continuous Monitoring

```yaml
Integration Points:
  - SIEM integration (Splunk, ELK)
  - Ticketing systems (Jira, ServiceNow)
  - Configuration management (Ansible, Puppet)
  - Asset management (CMDB)

Automation:
  - Scheduled scans
  - Automatic report generation
  - Alert on critical findings
  - Compliance deviation alerts

Metrics to Track:
  - Mean Time to Detect (MTTD)
  - Mean Time to Remediate (MTTR)
  - Vulnerability density (vulns/asset)
  - Patch compliance rate
  - Risk score trend
```

### 5. Security Hardening

```bash
# Nessus Server Hardening

# Change default port
sudo systemctl stop nessusd
sudo vi /opt/nessus/etc/nessus/nessus-service.conf
# port = 8834 → 8443 (custom port)
sudo systemctl start nessusd

# SSL/TLS certificate
# Replace self-signed with valid certificate
sudo /opt/nessus/sbin/nessuscli fetch --certificate-path=/path/to/cert.pem --private-key-path=/path/to/key.pem

# Firewall rules
sudo ufw allow from 192.168.1.0/24 to any port 8443
sudo ufw deny 8443

# Strong password policy
# Enforce via Settings → Users → Password Settings
# - Min length: 14 characters
# - Complexity: Yes
# - Expiration: 90 days
# - 2FA: Enable

# Regular updates
sudo /opt/nessus/sbin/nessuscli update --all

# Backup configuration
sudo /opt/nessus/sbin/nessuscli backup --create /backup/nessus-$(date +%F).tar.gz
```

---

## 10. Troubleshooting {#troubleshooting}

### Common Issues

**Issue 1: Plugin Update Failed**
```yaml
Symptoms:
  - "Plugin update failed" error
  - Outdated plugin set

Solutions:
  1. Check internet connectivity
  2. Verify firewall allows outbound HTTPS
  3. Manual update:
     sudo /opt/nessus/sbin/nessuscli update --all
  4. Check disk space (requires ~1GB)
  5. Restart service:
     sudo systemctl restart nessusd
```

**Issue 2: Scan Stuck/Hanging**
```yaml
Symptoms:
  - Scan progress frozen
  - No results returned

Solutions:
  1. Check target reachability:
     ping <target-ip>
  2. Verify no firewall blocking
  3. Reduce concurrent checks
  4. Enable "Stop scan on unreachable host"
  5. Check Nessus logs:
     tail -f /opt/nessus/var/nessus/logs/nessusd.messages
  6. Kill stuck scan:
     - Via UI: Scan → Actions → Stop
     - Or restart service
```

**Issue 3: High Memory Usage**
```yaml
Symptoms:
  - Nessus consuming 4GB+ RAM
  - System slowdown

Solutions:
  1. Reduce concurrent scans
  2. Decrease scan scope
  3. Increase system RAM (8GB+ recommended)
  4. Tune performance settings:
     Settings → Advanced → Performance
  5. Schedule scans during off-hours
```

**Issue 4: Authentication Failures**
```yaml
Symptoms:
  - Credentialed scan fails
  - "Authentication failed" errors

Solutions:
  SSH:
    - Verify credentials manually: ssh user@target
    - Check sudo/su privileges
    - Verify SSH key permissions
    - Check ~/.ssh/authorized_keys
  
  Windows:
    - Verify SMB access: smbclient -L //target -U user
    - Check admin shares: \\target\C$
    - Enable RemoteRegistry service
    - Check Windows firewall rules
  
  SNMP:
    - Verify community string: snmpwalk -v2c -c public target
    - Check SNMP service running
    - Verify ACLs on SNMP agent
```

**Issue 5: Certificate Errors**
```yaml
Symptoms:
  - Browser SSL/TLS warnings
  - "Unable to connect securely"

Solutions:
  1. Accept self-signed certificate (expected behavior)
  2. Add exception in browser
  3. Install custom certificate:
     sudo /opt/nessus/sbin/nessuscli fetch --custom-certificate
  4. Or access via: https://localhost:8834
     (instead of IP address)
```

### Logs Location

```bash
# Linux
Main logs: /opt/nessus/var/nessus/logs/
  - nessusd.messages (main log)
  - nessusd.dump (debug)
  - www_server.log (web interface)

Scan logs: /opt/nessus/var/nessus/logs/[scan-id]/

# Windows
C:\ProgramData\Tenable\Nessus\nessus\logs\

# macOS
/Library/Nessus/run/logs/
```

### Debug Mode

```bash
# Enable debug logging
sudo /opt/nessus/sbin/nessuscli fix --set log_whole_attack=yes
sudo systemctl restart nessusd

# View debug output
tail -f /opt/nessus/var/nessus/logs/nessusd.dump

# Disable after troubleshooting
sudo /opt/nessus/sbin/nessuscli fix --set log_whole_attack=no
```

---

## 11. Alternative a Nessus Essentials {#alternative}

### Confronto Alternative

| Tool | Licenza | Costo | Target IP | Punti di Forza | Limitazioni |
|------|---------|-------|-----------|----------------|-------------|
| **OpenVAS** | GPL | Free | Unlimited | Open source, completo | Setup complesso |
| **Qualys Community** | Freemium | Free tier | 16-20 | Cloud-based, facile | Limite IP free |
| **Rapid7 InsightVM** | Commercial | Trial | Limited | Integration, automation | Costoso |
| **Acunetix** | Commercial | Trial | Limited | Web app focus | Specializzato web |
| **Nikto** | GPL | Free | Unlimited | Web server focus | Solo web, limitato |
| **Lynis** | GPL | Free | Unlimited | System audit | Solo Linux/Unix |
| **Nuclei** | MIT | Free | Unlimited | Fast, modern | Template-based |

---

### 1. OpenVAS (Open Vulnerability Assessment System)

**Descrizione:**  
Fork open source di Nessus (pre-2005), ora parte di Greenbone Vulnerability Management (GVM).

**Caratteristiche:**
- ✅ Completamente gratuito e open source
- ✅ Nessun limite numero IP
- ✅ Database vulnerabilità ampio (70,000+ NVT)
- ✅ Aggiornamenti quotidiani feed
- ✅ Web interface (Greenbone Security Assistant)
- ❌ Setup più complesso di Nessus
- ❌ Performance inferiori
- ❌ UI meno intuitiva

**Installazione Ubuntu:**
```bash
# Install via Docker (metodo più semplice)
docker run -d -p 443:443 --name openvas greenbone/openvas

# Oppure installazione nativa
sudo add-apt-repository ppa:mrazavi/gvm
sudo apt update
sudo apt install gvm

# Setup
sudo gvm-setup

# Access
https://localhost:9392
# Default: admin / admin (da cambiare)
```

**Quando Usare OpenVAS:**
- ✅ Uso commerciale senza costi licensing
- ✅ Network grandi (>16 IP)
- ✅ Customizzazione completa
- ✅ Compliance con requisiti open source
- ❌ Se serve supporto commerciale
- ❌ Se UI intuitiva è prioritaria

---

### 2. Qualys Community Edition

**Descrizione:**  
Cloud-based vulnerability scanner con tier gratuito limitato.

**Caratteristiche:**
- ✅ Zero installation (cloud)
- ✅ Sempre aggiornato
- ✅ Dashboard professionale
- ✅ Integration con altri tool Qualys
- ❌ Limite IP (tier free: 16-20)
- ❌ Requires account registration
- ❌ Data in cloud (privacy concerns)

**Setup:**
```
1. Registrazione: https://www.qualys.com/community-edition/
2. Deploy Cloud Agent o Scan Appliance
3. Configure scan via web portal
4. No local installation required
```

**Quando Usare Qualys:**
- ✅ Infrastruttura cloud (AWS, Azure, GCP)
- ✅ Zero maintenance preference
- ✅ Professional reporting necessario
- ❌ Concerns su data privacy
- ❌ Network air-gapped

---

### 3. Nuclei (ProjectDiscovery)

**Descrizione:**  
Scanner moderno, veloce, template-based per vulnerability detection.

**Caratteristiche:**
- ✅ Estremamente veloce
- ✅ Template YAML semplici
- ✅ Community templates (3000+)
- ✅ CI/CD integration
- ✅ Modern CLI interface
- ❌ Meno comprehensive di Nessus
- ❌ Focus su web/network

**Installazione:**
```bash
# Install via Go
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Or download binary
wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.0/nuclei_2.9.0_linux_amd64.zip
unzip nuclei*.zip
sudo mv nuclei /usr/local/bin/

# Update templates
nuclei -update-templates

# Basic scan
nuclei -u https://example.com

# Scan multiple targets
nuclei -l targets.txt -t cves/

# Custom template
nuclei -u https://example.com -t custom-template.yaml
```

**Template Example:**
```yaml
# custom-cve-scan.yaml
id: CVE-2021-41773

info:
  name: Apache HTTP Server 2.4.49 - Path Traversal
  author: pdteam
  severity: critical
  description: Apache 2.4.49 path traversal vulnerability
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-41773

requests:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
    
    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
      - type: status
        status:
          - 200
```

**Quando Usare Nuclei:**
- ✅ CI/CD pipeline integration
- ✅ Bug bounty hunting
- ✅ Fast scanning requirements
- ✅ Custom check development
- ❌ Comprehensive full-stack scanning
- ❌ Compliance auditing

---

### 4. Nikto

**Descrizione:**  
Web server scanner open source, specializzato in vulnerabilità web.

**Caratteristiche:**
- ✅ Gratuito e open source
- ✅ Focus web server vulnerabilities
- ✅ 6700+ potential dangerous files/programs
- ✅ Outdated server detection
- ❌ Solo web scanning
- ❌ Molto rumoroso (generate molti log)
- ❌ Facilmente rilevabile da IDS

**Installazione e Uso:**
```bash
# Install
sudo apt install nikto

# Basic scan
nikto -h http://target.com

# Full scan with options
nikto -h http://target.com \
      -ssl \
      -port 80,443,8080 \
      -output report.html \
      -Format html

# Scan with authentication
nikto -h http://target.com -id admin:password

# Tune scan (reduce false positives)
nikto -h http://target.com -Tuning x
# Tuning options:
# 1 - Interesting File
# 2 - Misconfiguration
# 3 - Information Disclosure
# x - Reverse Tuning (exclude)
```

**Quando Usare Nikto:**
- ✅ Quick web server assessment
- ✅ Initial reconnaissance
- ✅ Testing web misconfigurations
- ❌ Stealth scanning (very noisy)
- ❌ Comprehensive infrastructure scan

---

### 5. Lynis

**Descrizione:**  
Security auditing tool per Linux/Unix, compliance and hardening.

**Caratteristiche:**
- ✅ Open source
- ✅ System configuration audit
- ✅ Compliance checking (PCI-DSS, HIPAA)
- ✅ Hardening recommendations
- ✅ No installation (single script)
- ❌ Solo Linux/Unix
- ❌ No network scanning
- ❌ No remote scanning

**Installazione e Uso:**
```bash
# Download
git clone https://github.com/CISOfy/lynis
cd lynis

# Run audit
sudo ./lynis audit system

# Output
Report saved: /var/log/lynis-report.dat

# View suggestions
cat /var/log/lynis-report.dat | grep suggestion

# Automated scan con cron
# /etc/cron.daily/lynis
#!/bin/bash
cd /opt/lynis && ./lynis audit system --cronjob
```

**Sample Output:**
```
================================================================================
  Lynis 3.0.8 - Security Auditing and Hardening Tool
================================================================================

[+] Initializing program
  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

[+] System Information
  - Operating system:     Ubuntu
  - OS version:           22.04
  - Kernel version:       5.15.0

[+] Performing tests
  [V] Vulnerability scan
  [V] Compliance tests
  [V] Security hardening

Hardening index: 72/100

Suggestions:
  - Install package apt-show-versions [KRNL-5622]
  - Configure minimum password length [AUTH-9286]
  - Enable process accounting [ACCT-9622]
  - Install and configure auditd [ACCT-9628]
```

**Quando Usare Lynis:**
- ✅ Linux/Unix hardening
- ✅ Compliance verification
- ✅ Configuration audit
- ✅ CI/CD security checks
- ❌ Network vulnerability scanning
- ❌ Windows environments

---

### 6. OWASP ZAP (Zed Attack Proxy)

**Descrizione:**  
Web application security scanner open source da OWASP.

**Caratteristiche:**
- ✅ Gratuito e open source
- ✅ Web app penetration testing
- ✅ Intercepting proxy
- ✅ Automated scanner
- ✅ API testing
- ❌ Solo web applications
- ❌ Learning curve steep

**Installazione:**
```bash
# Linux
wget https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2.12.0_Linux.tar.gz
tar -xvf ZAP*.tar.gz
cd ZAP*
./zap.sh

# Docker
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap-webswing.sh

# Automated scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://target.com
```

**API Scanning:**
```bash
# Import OpenAPI/Swagger definition
zap-cli -p 8080 open-url https://target.com/swagger.json

# Spider API
zap-cli spider https://target.com/api

# Active scan
zap-cli active-scan https://target.com/api

# Generate report
zap-cli report -o zap-report.html -f html
```

**Quando Usare ZAP:**
- ✅ Web application testing
- ✅ API security testing
- ✅ DevSecOps integration
- ✅ Manual pentesting
- ❌ Infrastructure scanning
- ❌ Network-level vulnerabilities

---

### 7. Trivy (Aqua Security)

**Descrizione:**  
Container, IaC, and code vulnerability scanner.

**Caratteristiche:**
- ✅ Container image scanning
- ✅ IaC scanning (Terraform, CloudFormation)
- ✅ Code dependencies
- ✅ Kubernetes manifests
- ✅ Fast and accurate
- ❌ Non general-purpose
- ❌ Focus DevOps/Container

**Installazione e Uso:**
```bash
# Install
sudo apt install trivy

# Scan container image
trivy image nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan IaC
trivy config terraform/

# Scan Kubernetes
trivy k8s --report summary cluster

# Output to JSON
trivy image --format json nginx:latest > results.json

# Only critical/high
trivy image --severity CRITICAL,HIGH nginx:latest
```

**CI/CD Integration:**
```yaml
# GitHub Actions
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:latest'
    format: 'sarif'
    output: 'trivy-results.sarif'
    
- name: Upload results to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'
```

**Quando Usare Trivy:**
- ✅ Container security
- ✅ DevOps pipeline
- ✅ IaC security
- ✅ Dependency scanning
- ❌ Traditional infrastructure
- ❌ Web application testing

---

## Conclusioni

### Scelta Tool Appropriato

**Per Uso Personale/Educativo:**
1. **Nessus Essentials** - Best overall, user-friendly
2. **OpenVAS** - Se serve unlimited IP
3. **Nuclei** - Per testing veloce

**Per Enterprise:**
1. **Nessus Professional** - Industry standard
2. **Qualys VMDR** - Cloud-first organization
3. **Rapid7 InsightVM** - DevSecOps integration

**Per Web Applications:**
1. **OWASP ZAP** - Comprehensive, free
2. **Burp Suite** - Professional pentesting
3. **Acunetix** - Automated, enterprise

**Per DevOps/Containers:**
1. **Trivy** - Container scanning
2. **Anchore** - Policy-based
3. **Snyk** - Developer-friendly

**Per Compliance:**
1. **Nessus Professional** - Multiple standards
2. **Qualys** - Continuous compliance
3. **Tenable.sc** - Enterprise compliance

### Approccio Multi-Tool

**Best Practice: Utilizzare combinazione di tool**

```yaml
Vulnerability Management Stack:

1. Network/Infrastructure:
   - Nessus Professional (quarterly deep scan)
   - OpenVAS (continuous monitoring)

2. Web Applications:
   - OWASP ZAP (development)
   - Burp Suite (pentesting)

3. Containers/Cloud:
   - Trivy (CI/CD pipeline)
   - Aqua Security (runtime protection)

4. Configuration/Hardening:
   - Lynis (Linux systems)
   - CIS-CAT (compliance)

5. Code Security:
   - SonarQube (SAST)
   - Snyk (dependencies)
```

### Risorse Aggiuntive

**Documentazione:**
- [Nessus Documentation](https://docs.tenable.com/nessus/)
- [OpenVAS Documentation](https://www.openvas.org/documentation.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

**Community:**
- [Tenable Community](https://community.tenable.com/)
- [r/netsec](https://reddit.com/r/netsec)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

**Training:**
- [Tenable University](https://university.tenable.com/)
- [SANS SEC460: Enterprise Vulnerability Assessment](https://www.sans.org/cyber-security-courses/enterprise-vulnerability-assessment/)
- [Offensive Security - PWK](https://www.offensive-security.com/pwk-oscp/)

---

**Data ultima revisione:** Gennaio 2026  
**Versione Nessus:** 10.6.x  
**Autore:** Corso Sicurezza dei Sistemi Informatici e delle Reti
