# 02 — Hardening della DMZ: OS, Server, Bastion Host e Patch Management

> 📚 **Guida teorica** | Livello: 4ª–5ª superiore
> 🔗 Prerequisiti: Linux base, concetti di servizi di rete
> ⏱️ Tempo di lettura: ~30 minuti

---

## 🎯 Cos'è l'Hardening?

L'**hardening** (indurimento) è il processo di riduzione della superficie d'attacco di un sistema rimuovendo funzionalità non necessarie, configurando correttamente i componenti e applicando misure di sicurezza proattive.

Il principio guida è la **riduzione dell'attack surface**:

```
Sistema appena installato:
Attack Surface = [servizi default] + [porte aperte] + [software installato] + [account predefiniti]
              = MOLTO GRANDE

Dopo hardening:
Attack Surface = [solo ciò che serve] × [configurato in modo sicuro]
              = MOLTO PIÙ PICCOLO
```

> 🔒 **Regola d'oro**: "Se non ti serve, non installarla. Se è installata, disabilitala. Se è abilitata, configurala in modo sicuro."

---

## 🖥️ Hardening del Sistema Operativo

### 1. Minimal Install

Il primo passo è partire da un'installazione **minimale**: solo il sistema operativo base, senza pacchetti opzionali.

**Linux (Ubuntu/Debian)**:
```bash
# Verifica i pacchetti installati e cerca quelli non necessari
dpkg --get-selections | grep -v deinstall

# Rimuovi i pacchetti non necessari (esempio)
apt-get purge --auto-remove \
    telnet \           # usa SSH invece
    ftp \              # usa SFTP invece
    rsh-client \       # uso storico, non sicuro
    finger \           # informazioni utenti, privacy risk
    nis \              # NIS è obsoleto e insicuro
    talk              # non necessario su server

# Aggiorna l'indice e applica aggiornamenti di sicurezza
apt-get update && apt-get upgrade -y
```

**Windows Server (Server Core)**:
```powershell
# Usa Server Core (senza GUI) per ridurre attack surface
# Verifica e rimuovi ruoli non necessari
Get-WindowsFeature | Where-Object {$_.Installed -eq $True} | Format-Table
Remove-WindowsFeature [nome-feature-non-necessaria]
```

### 2. Disabilitare Servizi Inutili

Ogni servizio in esecuzione è un potenziale vettore di attacco.

**Linux — Verifica e disabilita servizi**:
```bash
# Visualizza tutti i servizi attivi
systemctl list-units --type=service --state=running

# Verifica un servizio specifico
systemctl status avahi-daemon   # mDNS discovery — non serve su server DMZ

# Disabilita e ferma servizi non necessari
systemctl stop avahi-daemon
systemctl disable avahi-daemon

# Altri servizi tipicamente non necessari su server DMZ:
systemctl disable bluetooth        # fisicamente assente su server, ma può essere attivo
systemctl disable cups             # printing service
systemctl disable rpcbind          # solo se non serve NFS
systemctl disable postfix          # se non è un mail server
systemctl disable NetworkManager   # usa systemd-networkd invece su server

# Verifica le porte in ascolto dopo il hardening
ss -tlnp        # TCP listening
ss -ulnp        # UDP listening
```

**Windows Server**:
```powershell
# Elenca servizi in esecuzione
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName

# Disabilita servizi non necessari (esempi)
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Set-Service -Name "Spooler" -StartupType Disabled          # se non è un print server
Set-Service -Name "WinRM" -StartupType Disabled            # se non usi PowerShell Remoting
Stop-Service -Name "RemoteRegistry" -Force
```

### 3. Gestione Account e Autenticazione

```bash
# Linux: disabilita account di default inutili
passwd -l daemon
passwd -l bin
passwd -l sys
passwd -l games
passwd -l news
passwd -l uucp
passwd -l proxy
passwd -l www-data  # il web server avrà il suo account dedicato

# Verifica account con shell di login (non dovrebbero esserci molti)
grep -v '/sbin/nologin\|/bin/false' /etc/passwd

# Configura password policy in /etc/login.defs
# PASS_MAX_DAYS   90    ← scadenza password ogni 90 giorni
# PASS_MIN_DAYS   1     ← minimo 1 giorno tra i cambi
# PASS_WARN_AGE   14    ← avviso 14 giorni prima della scadenza

# Configura PAM per password complesse
# /etc/pam.d/common-password
# password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
```

### 4. Filesystem Permissions e Least Privilege

```bash
# Il processo del web server deve girare con un utente dedicato senza privilegi
# Verifica con quale utente gira nginx/apache
ps aux | grep nginx
# Output atteso: www-data  1234  0.0  0.1  ...  nginx: worker process

# I file web devono essere di proprietà di root, leggibili da www-data
# NON devono essere scrivibili da www-data (eccetto upload directory)
chown -R root:www-data /var/www/html
chmod -R 750 /var/www/html          # root rwx, www-data r-x, altri ---
chmod -R 770 /var/www/html/uploads  # solo la directory upload è scrivibile

# Monta partizioni sensibili con opzioni restrittive (/etc/fstab)
# /tmp: noexec, nosuid, nodev
# UUID=xxx /tmp ext4 defaults,noexec,nosuid,nodev 0 2
```

### 5. Logging e Audit

> 🎯 **Principio**: I log devono essere generati **e inviati fuori dalla DMZ**. Se l'attaccante compromette il server, non deve poter cancellare i log locali.

```bash
# Configura rsyslog per inviare log al SIEM esterno (fuori dalla DMZ)
# /etc/rsyslog.conf
# *.* @@192.168.100.50:514    ← invia TUTTO al SIEM (TCP)
# auth,authpriv.* @@192.168.100.50:514  ← autenticazione

# Abilita auditd per audit di sistema
apt-get install auditd
systemctl enable auditd
systemctl start auditd

# Regole di audit rilevanti per DMZ:
# /etc/audit/rules.d/audit.rules
# -a always,exit -F arch=b64 -S execve    # ogni exec di processo
# -w /etc/passwd -p wa                    # modifica file passwd
# -w /etc/shadow -p wa                    # modifica file shadow  
# -w /var/www/html -p wa                  # modifica file web
# -a always,exit -F arch=b64 -S connect   # ogni connessione di rete

# Verifica che i log non siano modificabili localmente
chattr +a /var/log/auth.log    # append-only: non possono essere cancellati
```

---

## 🌐 Hardening del Web Server

### Nascondere Informazioni di Versione

Gli attaccanti usano le versioni dei software per trovare CVE specifici. Non dargli queste informazioni.

**Nginx**:
```nginx
# /etc/nginx/nginx.conf
http {
    server_tokens off;    # nasconde versione Nginx negli header e pagine errore

    # Rimuovi header che rivelano il backend
    # proxy_hide_header X-Powered-By;
    # proxy_hide_header X-AspNet-Version;
    
    # Aggiungi security header
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

**Apache**:
```apache
# /etc/apache2/conf-available/security.conf
ServerTokens Prod              # mostra solo "Apache" senza versione
ServerSignature Off            # rimuove firma dalle pagine di errore

# /etc/apache2/apache2.conf
TraceEnable Off                # disabilita metodo TRACE (informativo, usato in XST)
```

### Disabilitare Metodi HTTP Pericolosi

```nginx
# Nginx: blocca metodi non necessari
server {
    location / {
        limit_except GET POST HEAD {
            deny all;          # permetti solo GET, POST, HEAD
        }
    }
}
```

```apache
# Apache: blocca TRACE, PUT, DELETE
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|PUT|DELETE|PATCH)
RewriteRule .* - [F]
```

### Rate Limiting

```nginx
# Nginx: rate limiting per prevenire brute force e DDoS applicativo
http {
    # Definisci zone di rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;   # 5 req/min per /login
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;    # 100 req/min per /api

    server {
        location /login {
            limit_req zone=login burst=3 nodelay;
            limit_req_status 429;                  # 429 Too Many Requests
        }
        location /api/ {
            limit_req zone=api burst=20;
        }
    }
}
```

### Configurare Timeout

```nginx
# Nginx: timeout per prevenire Slowloris e connessioni zombie
http {
    client_body_timeout 10s;       # timeout per ricevere il body della richiesta
    client_header_timeout 10s;     # timeout per ricevere gli header
    keepalive_timeout 5s;          # tempo massimo keep-alive
    send_timeout 10s;              # timeout per inviare la risposta
    client_max_body_size 10m;      # dimensione massima upload
}
```

---

## 🔍 Hardening DNS in DMZ

Il server DNS in DMZ deve essere configurato come **autoritative-only**: risponde solo per le zone di cui è responsabile, **non esegue ricorsione** per conto di client esterni.

### Configurazione BIND 9 — Autoritative-Only

```bind
// /etc/bind/named.conf.options
options {
    directory "/var/cache/bind";

    // ── SICUREZZA FONDAMENTALE ──
    recursion no;                   // NO ricorsione: previene DNS amplification
    allow-recursion { none; };      // nessuno può fare query ricorsive
    allow-query { any; };           // risponde a query per le sue zone a chiunque

    // Versione nascosta (information disclosure)
    version "not disclosed";

    // Disabilita zone transfer non autorizzati
    allow-transfer { none; };       // di default, nessuno può fare zone transfer

    // Response Rate Limiting (RRL) — anti amplification
    rate-limit {
        responses-per-second 10;    // max 10 risposte/sec per IP sorgente
        window 5;
    };
};

// Zona autoritative per il dominio aziendale
zone "azienda.it" {
    type master;
    file "/etc/bind/zones/db.azienda.it";
    allow-transfer { key tsig-replica; };  // solo replica autorizzata con TSIG
};
```

### TSIG per Zone Transfer Autenticati

```bash
# Genera chiave TSIG per autenticare il zone transfer con il DNS secondario
tsig-keygen -a hmac-sha256 tsig-replica > /etc/bind/tsig-replica.key

# Contenuto del file generato (esempio):
# key "tsig-replica" {
#     algorithm hmac-sha256;
#     secret "base64encodedkey==";
# };
```

### Split-Horizon DNS (DNS Vista)

```bind
// DNS pubblica (in DMZ): risponde con IP pubblici
// DNS interna (in LAN): risponde con IP interni privati

// named.conf — split-horizon
acl "lan-network" { 172.16.20.0/24; };

view "interna" {
    match-clients { lan-network; };
    zone "azienda.it" {
        type master;
        file "/etc/bind/zones/db.azienda.it.interno";  // IP privati
    };
};

view "esterna" {
    match-clients { any; };
    zone "azienda.it" {
        type master;
        file "/etc/bind/zones/db.azienda.it.esterno";  // IP pubblici DMZ
    };
};
```

---

## 📧 Hardening Mail Server in DMZ

### Prevenire Open Relay

Un **open relay** è un mail server che accetta e inoltra email per qualsiasi mittente e destinatario, anche non suoi. È uno dei problemi più seri: viene usato per spam e può portare alla blacklist dell'IP aziendale.

**Postfix — Configurazione Anti-Relay**:
```
# /etc/postfix/main.cf

# Accetta email solo per i domini configurati
mydestination = azienda.it, mail.azienda.it, localhost

# Relay permesso solo dalla LAN interna (per invio email dei dipendenti)
mynetworks = 127.0.0.0/8, 172.16.20.0/24

# Blocca relay per tutti gli altri
smtpd_relay_restrictions =
    permit_mynetworks,          # permetti la LAN
    permit_sasl_authenticated,  # permetti utenti autenticati
    reject_unauth_destination   # rifiuta tutto il resto

# Restrizioni mittente
smtpd_sender_restrictions =
    reject_non_fqdn_sender,     # rifiuta mittenti senza FQDN
    reject_unknown_sender_domain # rifiuta domini mittente inesistenti
```

### SPF, DKIM, DMARC

```
# Record DNS SPF (TXT record in zona DNS):
# Indica quali server possono inviare email per @azienda.it
azienda.it. IN TXT "v=spf1 mx ip4:203.0.113.10 -all"
# "v=spf1": versione SPF
# "mx": i mail server MX sono autorizzati
# "ip4:...": questo IP specifico è autorizzato
# "-all": tutti gli altri sono rifiutati (hard fail)

# DKIM: firma crittografica delle email
# Genera chiave DKIM
opendkim-genkey -t -s mail -d azienda.it
# Pubblica la chiave pubblica come record DNS TXT:
mail._domainkey.azienda.it. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

# DMARC: policy per email che falliscono SPF/DKIM
_dmarc.azienda.it. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@azienda.it; pct=100"
# "p=quarantine": metti in quarantena email che falliscono (p=reject per massima protezione)
# "rua=mailto:": invia report aggregati a questo indirizzo
```

### TLS Obbligatorio

```
# /etc/postfix/main.cf — TLS per SMTP
smtpd_tls_security_level = may           # accetta TLS se offerto
smtp_tls_security_level = encrypt        # forza TLS nell'invio (livello più sicuro)
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1  # solo TLS 1.2+
smtpd_tls_cert_file = /etc/ssl/certs/mail.azienda.it.pem
smtpd_tls_key_file = /etc/ssl/private/mail.azienda.it.key
```

---

## 🛡️ Bastion Host e Jump Server

### Cos'è un Bastion Host?

Un **bastion host** (o jump server) è un server specializzato, altamente protetto, che funge da **unico punto di accesso** per la gestione amministrativa dei sistemi in DMZ e LAN.

```
RETE LAN INTERNA
        │
        │ SSH o RDP
        ▼
  [BASTION HOST]     ← unico punto di ingresso per gli admin
  172.16.20.100
        │
        ├──── SSH ──▶ Web Server DMZ (172.16.10.10)
        ├──── SSH ──▶ DNS Server DMZ (172.16.10.11)
        ├──── SSH ──▶ Mail Server DMZ (172.16.10.12)
        └──── SSH ──▶ Server DB LAN (172.16.20.20)

REGOLA: Nessun altro host può fare SSH direttamente ai server DMZ.
        Gli amministratori si connettono al bastion host, poi da lì ai server.
```

**Vantaggi**:
- Un singolo punto da monitorare per tutto l'accesso amministrativo
- Le sessioni possono essere registrate (session recording)
- MFA applicato in un unico punto
- Se un admin ha credenziali compromesse, il bastion host limita il danno

### SSH Hardening sul Bastion Host

```bash
# /etc/ssh/sshd_config — configurazione SSH hardened

# Disabilita autenticazione password: solo chiavi SSH
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Disabilita login root via SSH
PermitRootLogin no

# Consenti solo utenti specifici
AllowUsers admin-alice admin-bob

# Forza SSH versione 2 (v1 è insicuro)
Protocol 2

# Timeout autenticazione ridotto
LoginGraceTime 30s

# Limita tentativi di login
MaxAuthTries 3

# Disabilita funzionalità non necessarie
X11Forwarding no
AllowTcpForwarding yes    # necessario per il tunneling verso server DMZ
AllowAgentForwarding no

# Banner legale (deterrenza)
Banner /etc/ssh/banner.txt

# Algoritmi crittografici forti
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
```

### Session Recording

```bash
# Installa asciinema o usa script per registrare le sessioni admin
# Oppure usa PAM per reindirizzare tput

# Con tlog (RHEL/CentOS — session recording PAM)
# /etc/tlog/tlog-rec-session.conf
# - tutte le sessioni SSH vengono registrate automaticamente
# - i log vanno al syslog e poi al SIEM

# Configurazione semplice con script:
# /etc/profile.d/session-record.sh
# script -f -q -t2 /var/log/sessions/$(date +%Y%m%d-%H%M%S)-$USER.log
```

---

## 🔄 Patch Management per Server DMZ

### Perché i Server DMZ sono Prioritari

```
Esposizione dei server:

Internet  ──▶  [DMZ Server] ──▶ LAN
           ↑
     Direttamente raggiungibili
     da miliardi di dispositivi
     
VS.

Internet  ──[FW]──  LAN  ──▶ [Server interni]
                              ↑
                     Raggiungi solo se l'attaccante
                     ha già superato il firewall
```

I server DMZ sono i **primi a essere testati** da scanner automatici come Shodan, Censys e bot malware. Una vulnerabilità non patchata su un server DMZ viene trovata in **ore o giorni**.

### Ciclo di Patch Management

```
        ┌─────────────────────────────────┐
        │                                 │
        ▼                                 │
   [1. SCAN]                              │
   Vulnerability scanner                  │
   (Nessus, OpenVAS, Qualys)             │
        │                                 │
        ▼                                 │
   [2. TRIAGE]                            │
   Prioritizza per CVSS score             │
   CVSSv3 ≥ 7.0 = patch urgente           │
        │                                 │
        ▼                                 │
   [3. TEST]                              │
   Applica patch in staging               │
   Verifica che il servizio funzioni      │
        │                                 │
        ▼                                 │
   [4. DEPLOY]                            │
   Applica in produzione                  │
   Manutenzione programmata               │
        │                                 │
        ▼                                 │
   [5. VERIFICA]                          │
   Re-scan per confermare                 │
   patch applicata correttamente          │
        │                                 │
        └─────────────────────────────────┘
```

**Frequenza raccomandata**:

| Tipo | Frequenza |
|------|-----------|
| Patch critiche (CVSSv3 ≥ 9.0) | Entro 24–72 ore |
| Patch alte (CVSSv3 7.0–8.9) | Entro 7 giorni |
| Patch medie (CVSSv3 4.0–6.9) | Entro 30 giorni |
| Patch basse (CVSSv3 < 4.0) | Entro 90 giorni |
| Aggiornamenti OS di sistema | Mensile (patch Tuesday) |

---

## ✅ Checklist Hardening DMZ — Formato di Audit

| # | Misura | Priorità | Strumento di Verifica | Applicata? |
|---|--------|----------|-----------------------|-----------|
| 1 | Minimal install (solo pacchetti necessari) | 🔴 CRITICA | `dpkg --list` / `rpm -qa` | ☐ |
| 2 | Tutti i servizi inutili disabilitati | 🔴 CRITICA | `systemctl list-units` / `ss -tlnp` | ☐ |
| 3 | Aggiornamenti OS e software applicati | 🔴 CRITICA | `apt-get update && apt list --upgradable` | ☐ |
| 4 | Account di default disabilitati/rimossi | 🔴 CRITICA | `cat /etc/passwd` | ☐ |
| 5 | Login root SSH disabilitato | 🔴 CRITICA | `grep PermitRootLogin /etc/ssh/sshd_config` | ☐ |
| 6 | Autenticazione SSH solo con chiave | 🔴 CRITICA | `grep PasswordAuthentication /etc/ssh/sshd_config` | ☐ |
| 7 | Firewall locale (iptables/ufw) attivo | 🔴 CRITICA | `ufw status` / `iptables -L` | ☐ |
| 8 | Solo porte necessarie aperte | 🔴 CRITICA | `ss -tlnp` — verifica ogni porta | ☐ |
| 9 | Versione software nascosta (web server) | 🟡 ALTA | `curl -I http://server` | ☐ |
| 10 | Security header HTTP configurati | 🟡 ALTA | `curl -I https://server` — verifica header | ☐ |
| 11 | Metodi HTTP non necessari disabilitati | 🟡 ALTA | `curl -X TRACE http://server` | ☐ |
| 12 | Rate limiting attivo | 🟡 ALTA | Test con Apache Bench / ab | ☐ |
| 13 | DNS: ricorsione disabilitata | 🔴 CRITICA | `dig @dns-server google.com` — deve fallire | ☐ |
| 14 | DNS: RRL configurato | 🟡 ALTA | `named -V` — verifica supporto RRL | ☐ |
| 15 | Mail: no open relay | 🔴 CRITICA | `swaks --to test@gmail.com --from fake@extern.com` | ☐ |
| 16 | SPF/DKIM/DMARC configurati | 🟡 ALTA | `dig TXT azienda.it` — verifica record | ☐ |
| 17 | Log inviati a SIEM esterno | 🔴 CRITICA | Verifica ricezione log su SIEM | ☐ |
| 18 | Filesystem: permessi corretti su file web | 🟡 ALTA | `ls -la /var/www/html` | ☐ |
| 19 | Vulnerability scan regolare programmato | 🟡 ALTA | Nessus/OpenVAS job schedulato | ☐ |
| 20 | Accesso admin solo via bastion host | 🔴 CRITICA | ACL firewall verificata | ☐ |

---

## 🧪 Punti di Riflessione

> 💬 **Domanda 1**: Un web server gira come root perché "così si evitano problemi di permessi". Quali sono i rischi concreti? Come si risolve correttamente il problema dei permessi?

> 💬 **Domanda 2**: L'amministratore configura SSH sul bastion host con `PermitRootLogin yes` "perché è più comodo". Quali sono le conseguenze in caso di compromissione del bastion host?

> 💬 **Domanda 3**: Il DMARC è configurato con `p=none` invece di `p=quarantine` o `p=reject`. Qual è l'impatto pratico sulla sicurezza email dell'azienda?

---

*02 — Hardening della DMZ | Guida Teorica ES07 | SISTEMI E RETI*
