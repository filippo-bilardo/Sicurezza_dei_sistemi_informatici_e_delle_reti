# 04 — IDS, IPS e Monitoraggio della DMZ

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: IDS, IPS, SIEM, monitoraggio, honeypot, incident response

---

## 1. IDS — Intrusion Detection System

### 1.1 Cos'è un IDS

Un **IDS (Intrusion Detection System)** è un sistema che monitora il traffico di rete o le attività di sistema alla ricerca di **attività sospette o malevole** e genera **alert** (notifiche) quando le rileva.

⚠️ **Importante**: L'IDS **non blocca** il traffico — lo osserva passivamente e avvisa. È come un sistema di allarme: suona, ma non chiude la porta.

```
                   ┌─────┐
         ─────────►│     ├─────────►   (traffico passa liberamente)
         Traffico  │SPAN │
                   │port │
                   └──┬──┘
                      │ (copia del traffico)
                      ▼
                   ┌─────┐
                   │ IDS │ → ALERT! → Admin/SIEM
                   └─────┘
                (analizza in modalità
                 passiva/promiscua)
```

La porta **SPAN** (Switched Port ANalyzer) è una funzione dello switch che copia tutto il traffico di una o più porte verso la porta dove è collegato l'IDS. In alternativa si usa un **TAP** (Test Access Point) hardware.

### 1.2 Tipi di IDS

#### IDS Basato su Signature (Signature-Based)

Confronta il traffico con un **database di firme** (pattern) di attacchi noti. Simile a un antivirus.

```
Traffico → [Confronto con DB firme] → Match? → ALERT!
```

**Pro**: Molto accurato per attacchi noti, pochi falsi positivi  
**Contro**: Non rileva attacchi sconosciuti (zero-day), richiede aggiornamenti costanti del DB

#### IDS Basato su Anomalia (Anomaly-Based / Behavioral)

Stabilisce un **profilo del traffico normale** e segnala deviazioni significative.

```
Fase 1 (apprendimento): Analizza traffico normale → crea baseline
Fase 2 (rilevamento): Traffico attuale vs baseline → deviazioni? → ALERT!
```

**Pro**: Può rilevare attacchi sconosciuti  
**Contro**: Molti falsi positivi (traffico legittimo insolito = alert), richiede tempo di apprendimento

#### IDS di Rete (NIDS) vs IDS di Host (HIDS)

| | NIDS | HIDS |
|--|------|------|
| Dove gira | Sulla rete (analizza pacchetti) | Sul singolo host/server |
| Cosa monitora | Traffico di rete | Log di sistema, file, processi |
| Visibilità | Tutta la rete | Solo il singolo host |
| Cifratura | ❌ Non vede traffico cifrato | ✅ Vede attività prima/dopo cifratura |
| Esempio | Snort, Suricata | OSSEC, Wazuh, Tripwire |

---

## 2. IPS — Intrusion Prevention System

### 2.1 Cos'è un IPS

Un **IPS (Intrusion Prevention System)** è come un IDS, ma con la capacità di **bloccare il traffico malevolo in tempo reale**. Viene posizionato **inline** nel flusso di rete, non in modalità passiva.

```
                ┌──────────────────────────────────────────┐
   Traffico ───►│              IPS (inline)                │──► Traffico pulito
   in entrata   │  ┌─────────────────────────┐             │    (o bloccato)
                │  │  Analisi traffico       │             │
                │  │  ↓                      │             │
                │  │  Match firma/anomalia?  │             │
                │  │  ├─ No  → forward       │             │
                │  │  └─ Sì  → DROP + ALERT  │             │
                │  └─────────────────────────┘             │
                └──────────────────────────────────────────┘
```

### 2.2 IDS vs IPS — Confronto

| Caratteristica | IDS | IPS |
|----------------|-----|-----|
| Posizione | Fuori banda (SPAN port) | In linea (inline) |
| Blocca traffico | ❌ No | ✅ Sì |
| Impatto sul traffico | Nessuno (passivo) | Può aggiungere latenza |
| Rischio falsi positivi | Produce alert inutili | **Blocca traffico legittimo!** |
| Resilienza | ❌ Punto di failure se guasto | ❌ Blocca tutto se guasto (fail-open/fail-close) |
| Uso tipico | Monitoring, audit, forensics | Produzione, blocco attacchi in tempo reale |

### 2.3 Il Problema dei Falsi Positivi nell'IPS

Un **falso positivo** è quando il sistema classifica traffico legittimo come malevolo. In un IDS, questo significa solo un alert indesiderato. In un **IPS**, significa **bloccare traffico legittimo** — un disastro in produzione!

Esempio: una regola IPS che blocca "tentativi SQL injection" potrebbe bloccare query SQL legittime di un'applicazione se scritte in un certo modo.

**Soluzione**: Configurare l'IPS inizialmente in modalità **detection-only** (come un IDS), analizzare i falsi positivi per settimane, e solo poi passare alla modalità **prevention**.

---

## 3. Posizionamento IDS/IPS nella Rete con DMZ

Il posizionamento è cruciale. Ecco le posizioni tipiche:

```
                         Internet
                             │
                    ┌────────┴────────┐
                    │                 │
               ┌────┴────┐      [IDS/IPS 1]
               │Firewall │       pre-firewall
               │Esterno  │       (vede tutto, anche
               └────┬────┘        traffico bloccato)
                    │
               ┌────┴────┐
               │  [DMZ]  │◄─── [IDS/IPS 2] in DMZ
               │         │       (vede traffico che ha
               └────┬────┘        superato FW esterno)
                    │
               ┌────┴────┐
               │Firewall │
               │Interno  │
               └────┬────┘
                    │
               ┌────┴────┐
               │  [LAN]  │◄─── [IDS/IPS 3] nella LAN
               └─────────┘       (rileva lateral movement)
```

### 3.1 IDS/IPS Esterno (Pre-Firewall)

**Posizione**: tra Internet e il firewall esterno.

**Vantaggio**: Vede **tutto** il traffico proveniente da Internet, incluso quello già bloccato dal firewall.  
**Utilizzo**: Analisi threat intelligence, monitoraggio attacchi DDoS, studio dei pattern di attacco.  
**Tipo raccomandato**: IDS passivo (non ha senso un IPS qui — il firewall già blocca).

### 3.2 IDS/IPS in DMZ

**Posizione**: nella rete DMZ, monitorando il traffico verso/dai server.

**Vantaggio**: Rileva attacchi che hanno superato il firewall, attività anomale dei server (es. web server compromesso che scansiona la rete).  
**Utilizzo**: Rilevamento attacchi a livello applicativo (SQL injection, XSS, directory traversal).  
**Tipo raccomandato**: NIDS/NIPS, integrato spesso nel WAF (Web Application Firewall).

### 3.3 IDS/IPS nella LAN Interna

**Posizione**: sulla rete interna, vicino ai server critici o core switch.

**Vantaggio**: Rileva **lateral movement** (un attaccante che si sposta da un sistema all'altro nella LAN).  
**Utilizzo**: Rilevamento insider threat, ransomware che si diffonde, post-compromise detection.  
**Tipo raccomandato**: HIDS su server critici + NIDS sul core switch.

---

## 4. SIEM — Security Information and Event Management

### 4.1 Cos'è un SIEM

Un **SIEM** è una piattaforma centralizzata che:
1. **Raccoglie** log da tutti i dispositivi di rete (firewall, IDS/IPS, server, switch...)
2. **Correla** gli eventi tra fonti diverse
3. **Analizza** in tempo reale cercando pattern sospetti
4. **Genera alert** aggregati e contestualizzati
5. **Archivia** i log per compliance e analisi forensica

```
Firewall logs  ─────┐
IDS/IPS alerts ─────┤
Server logs    ─────┼──► [SIEM] ──► Dashboard + Alerts ──► SOC
Switch logs    ─────┤            ──► Correlazione eventi
DNS logs       ─────┤            ──► Archiviazione compliance
Antivirus logs ─────┘
```

### 4.2 Correlazione degli Eventi

Il vero valore del SIEM è la **correlazione**: un singolo evento può sembrare innocuo, ma la combinazione di eventi rivela un attacco.

**Esempio di correlazione**:
- Alle 02:00: IDS rileva 1000 tentativi di login falliti su Web Server DMZ
- Alle 02:05: Login riuscito sul Web Server
- Alle 02:07: Il Web Server inizia a scansionare la rete interna (anomalia!)
- Alle 02:08: Firewall interno blocca connessione da Web Server verso DB Server

**Il SIEM correla questi 4 eventi** e genera un alert critico: "Possibile compromissione Web Server DMZ seguito da tentativo di lateral movement".

### 4.3 Strumenti SIEM Open Source

| Strumento | Note |
|-----------|------|
| **Wazuh** | SIEM/HIDS open source, molto completo, basato su OSSEC |
| **Graylog** | Gestione log centralizzata, buona scalabilità |
| **ELK Stack** | Elasticsearch + Logstash + Kibana — potente ma complesso |
| **Security Onion** | Distribuzione Linux all-in-one con Snort, Zeek, Kibana |

---

## 5. Cosa Loggare in una DMZ

### 5.1 Log Fondamentali

In una DMZ è essenziale registrare i seguenti eventi:

| Categoria | Evento | Perché è Importante |
|-----------|--------|---------------------|
| **Connessioni accettate** | Ogni connessione TCP/UDP accettata dal firewall | Audit trail, baseline traffico |
| **Connessioni rifiutate** | Ogni pacchetto bloccato da ACL/firewall | Rilevamento scansioni, attacchi |
| **Port Scanning** | Tentativi di connessione su molte porte | Ricognizione pre-attacco |
| **Login falliti** | Su tutti i server DMZ | Brute force, credential stuffing |
| **Login riusciti** | Su tutti i server DMZ | Verifica accessi legittimi |
| **Modifiche configurazione** | Router, firewall, switch | Rilevamento cambiamenti non autorizzati |
| **Traffico anomalo** | Volume insolito, protocolli inusuali | DDoS, esfiltrazione dati |
| **DNS queries insolite** | Query DNS verso domini sospetti | DNS tunneling, C2 communication |
| **Orari insoliti** | Attività fuori orario lavorativo | Accessi non autorizzati |

### 5.2 Formato dei Log

I log devono contenere **almeno** questi campi:

```
[Timestamp] [Severity] [Source IP] [Dest IP] [Protocol] [Port] [Action] [Reason]

Esempio:
2024-03-15 14:23:07 WARN  8.8.8.8    192.168.100.10  TCP  22   DENIED  "ACL_WAN_IN rule 99"
2024-03-15 14:23:09 INFO  10.0.0.5   192.168.100.10  TCP  80   ALLOWED "ACL_LAN_IN rule 10"
```

### 5.3 Configurazione Logging su Cisco IOS

```cisco
! Abilita logging con timestamp
service timestamps log datetime msec

! Configura livello di log
logging on
logging buffered 64000 informational

! Invia log a server Syslog esterno
logging host 10.0.0.50

! Aggiungi logging alle ACL (aggiunge "log" alla fine delle regole)
ip access-list extended ACL_WAN_IN
 99 deny ip any any log

! Visualizza log in buffer
show logging
```

---

## 6. Honeypot

### 6.1 Cos'è un Honeypot

Un **honeypot** è un sistema deliberatamente vulnerabile e privo di dati reali, posizionato nella rete come **trappola per gli attaccanti**. Il suo scopo è attirare, rilevare e studiare l'attività malevola.

```
INTERNET
    │
    ├──► Web Server (reale) → risponde legittimamente
    │
    ├──► DNS Server (reale) → risponde legittimamente
    │
    └──► HoneyPot ← qualsiasi connessione qui è SOSPETTA!
         (sembra un server, ma non ha traffico legittimo)
```

**Principio chiave**: Nessun utente legittimo dovrebbe mai connettersi a un honeypot. Qualsiasi traffico verso di esso è quindi **per definizione sospetto**.

### 6.2 Tipi di Honeypot

| Tipo | Descrizione | Interazione con attaccante |
|------|-------------|---------------------------|
| **Low Interaction** | Emula servizi di rete (porte aperte) | Limitata — solo i banner |
| **Medium Interaction** | Emula servizi più complessi | Media — risponde a comandi base |
| **High Interaction** | Sistema reale (es. VM) | Alta — attaccante crede di aver compromesso un sistema vero |

### 6.3 Posizionamento in DMZ

Il posizionamento più comune è **nella DMZ**, dove simula un server pubblico:

```
DMZ:
  192.168.100.10  → Web Server (reale)
  192.168.100.11  → DNS Server (reale)
  192.168.100.12  → Mail Server (reale)
  192.168.100.20  → HoneyPot (simula un server non documentato)
```

Quando un attaccante fa una scansione della rete DMZ e trova `192.168.100.20`, tenta di connettersi. L'honeypot registra tutto: IP sorgente, porte testate, payloads inviati, tools usati.

### 6.4 Strumenti Honeypot Open Source

| Strumento | Tipo | Note |
|-----------|------|------|
| **Honeyd** | Low interaction | Simula interi sistemi di rete |
| **Kippo/Cowrie** | Medium interaction | Honeypot SSH specifico |
| **Glastopf** | Medium interaction | Honeypot web application |
| **T-Pot** | Multi-honeypot | Suite completa con dashboard |

---

## 7. Incident Response per DMZ Compromessa

### 7.1 Le 5 Fasi dell'Incident Response

Quando si rileva che un server in DMZ è stato compromesso, si seguono 5 fasi standard (NIST SP 800-61):

#### Fase 1 — RILEVAZIONE (Detection)

**Obiettivo**: Confermare che sia effettivamente avvenuta una compromissione.

Indicatori di compromissione (IoC) tipici:
- Log IDS/IPS con alert critici
- Traffico insolito dal server DMZ verso la LAN
- Processi anomali in esecuzione sul server
- File modificati o aggiunti di recente
- Account creati o modificati

```bash
# Comandi di triage sul server Linux sospetto
netstat -antup          # connessioni di rete attive
ps aux --forest         # processi in esecuzione
who                     # chi è loggato
last                    # ultimi accessi
find / -newer /etc/passwd -type f  # file recenti
```

#### Fase 2 — CONTENIMENTO (Containment)

**Obiettivo**: Limitare il danno, impedire la diffusione.

**Azioni immediate**:
1. **Isolare il server compromesso** — disconnetterlo dalla rete (o applicare ACL più restrittive)
2. **Non spegnere subito** — la memoria RAM potrebbe contenere prove utili
3. **Bloccare IP sorgente** dell'attaccante sul firewall
4. **Notificare il management** e il team di sicurezza

```cisco
! Blocco emergenza: isola il server compromesso sul firewall
ip access-list extended ACL_EMERGENCY_ISOLATE
 10 deny ip 192.168.100.10 0.0.0.0 any
 10 deny ip any 192.168.100.10 0.0.0.0
 20 permit ip any any

interface GigabitEthernet0/1
 ip access-group ACL_EMERGENCY_ISOLATE in
```

#### Fase 3 — ERADICAZIONE (Eradication)

**Obiettivo**: Rimuovere la causa dell'incidente.

- Identificare il vettore di attacco (come è entrato?)
- Rimuovere backdoor, malware, account creati dall'attaccante
- Applicare patch alla vulnerabilità sfruttata
- Cambiare tutte le credenziali potenzialmente compromesse

#### Fase 4 — RIPRISTINO (Recovery)

**Obiettivo**: Ripristinare il servizio in modo sicuro.

- Ripristinare il server da un **backup pulito** (non dal disco corrente!)
- Applicare configurazione hardened (non quella originale, che era vulnerabile)
- Monitoraggio intensivo nelle ore/giorni successivi
- Riconnettere il server alla rete solo dopo verifica

#### Fase 5 — LESSON LEARNED (Post-Incident)

**Obiettivo**: Imparare dall'incidente per prevenire il prossimo.

- Riunione post-mortem con tutto il team
- Documentazione dell'incidente (timeline, vettore, impatto)
- Aggiornamento delle policy di sicurezza
- Aggiornamento regole IDS/IPS
- Formazione del personale (se l'attacco era basato su social engineering)

---

## 8. Checklist Monitoraggio DMZ

Usa questa checklist per verificare che il monitoraggio della DMZ sia adeguato:

### Monitoraggio Infrastruttura
- [ ] Tutti i dispositivi inviano log a un server Syslog centralizzato
- [ ] Il SIEM è configurato e operativo
- [ ] Le ACL del firewall hanno l'opzione `log` per le regole deny
- [ ] Il firewall registra tutte le connessioni accettate e rifiutate
- [ ] I log sono conservati per almeno 6 mesi (12 mesi per compliance PCI-DSS)

### IDS/IPS
- [ ] IDS/IPS presente in DMZ con signature aggiornate
- [ ] Alert IDS/IPS arrivano al SIEM entro 60 secondi
- [ ] Sono definite procedure di risposta per ogni tipo di alert
- [ ] Falsi positivi documentati e regole affinate

### Verifica Periodica
- [ ] Review settimanale dei log di accesso
- [ ] Review mensile delle regole ACL (regole non più necessarie?)
- [ ] Scansione vulnerabilità trimestrale dei server DMZ
- [ ] Penetration test annuale dell'intera infrastruttura perimetrale

### Incident Response
- [ ] Piano di Incident Response documentato e aggiornato
- [ ] Contatti di emergenza del team sicurezza definiti
- [ ] Backup recenti e testati dei server DMZ
- [ ] Procedura di isolamento rapido documentata e testata

---

## 9. Strumenti Open Source per la DMZ

| Strumento | Categoria | Funzione principale |
|-----------|-----------|---------------------|
| **Snort** | IDS/IPS | Analisi traffico in tempo reale con signature |
| **Suricata** | IDS/IPS | Come Snort, ma multi-threaded e più performante |
| **Zeek (ex Bro)** | Network monitoring | Analisi comportamentale del traffico |
| **pfSense** | Firewall/UTM | Firewall open source con IDS integrato |
| **OPNsense** | Firewall/UTM | Alternativa a pfSense, più aggiornata |
| **Wazuh** | HIDS/SIEM | Monitoraggio integrità file, log analysis |
| **Graylog** | Log management | Raccolta e analisi log centralizzata |
| **T-Pot** | Honeypot | Suite multi-honeypot con dashboard |

> 💡 **Nota**: Questi strumenti sono citati a scopo informativo. In Packet Tracer non è possibile simularli, ma è importante conoscerli per la teoria e per il mondo del lavoro reale.

---

## 10. Riepilogo Concetti Chiave

| Termine | Definizione rapida |
|---------|-------------------|
| **IDS** | Rileva intrusioni, non le blocca (passivo) |
| **IPS** | Rileva E blocca intrusioni (inline) |
| **Signature-based** | Confronta con DB di attacchi noti |
| **Anomaly-based** | Rileva deviazioni dalla baseline normale |
| **NIDS** | IDS di rete — monitora il traffico |
| **HIDS** | IDS di host — monitora il sistema locale |
| **SIEM** | Raccoglie e correla log da tutta l'infrastruttura |
| **Falso positivo** | Traffico legittimo classificato come attacco |
| **Falso negativo** | Attacco reale non rilevato (il peggio!) |
| **Honeypot** | Sistema trappola per attirare e studiare gli attaccanti |
| **IoC** | Indicator of Compromise — segnale di una compromissione |
| **Lateral Movement** | Attaccante che si sposta da sistema a sistema nella rete |

---

*Guida 04/04 — ES06 — Sistemi e Reti 3*
