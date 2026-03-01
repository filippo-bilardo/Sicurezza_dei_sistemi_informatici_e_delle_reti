# Capitolo 19 - SSH (Secure Shell)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 6 - Protocolli Crittografici  
> **Autore**: Prof. Filippo Bilardo  
> **Capitolo Precedente**: [Capitolo 18 - SSL/TLS](18_ssltls.md)  
> **Prossimo Capitolo**: [Capitolo 20 - IPsec](20_ipsec.md)

---

## Introduzione

**SSH** (Secure Shell) fornisce accesso remoto sicuro a sistemi Unix/Linux.

### Versioni

- **SSH-1**: ❌ Insicuro (deprecato)
- **SSH-2**: ✅ Standard attuale (RFC 4251-4254)

## Porta

```
TCP 22 (default)
```

## Architettura

```
┌─────────────────────────────┐
│  SSH Connection Layer       │  (canali multipli)
├─────────────────────────────┤
│  SSH Authentication Layer   │  (login utente)
├─────────────────────────────┤
│  SSH Transport Layer        │  (cifratura, integrità)
└─────────────────────────────┘
         ↓
    TCP/IP
```

## Handshake SSH

Il processo di connessione avviene in 4 fasi:

```
Client                                    Server
──────                                    ──────
TCP SYN                          ──────>
                                 <──────  TCP SYN-ACK
TCP ACK                          ──────>

SSH-2.0-OpenSSH_9.x              ──────>  (banner)
                                 <──────  SSH-2.0-OpenSSH_9.x

1. KEY EXCHANGE
─────────────────────────────────────────────────
SSH_MSG_KEXINIT                  ──────>
(algoritmi supportati)
                                 <──────  SSH_MSG_KEXINIT
                                          (selezione algoritmo)

SSH_MSG_KEX_ECDH_INIT            ──────>
(chiave pubblica effimera Curve25519)
                                 <──────  SSH_MSG_KEX_ECDH_REPLY
                                          (host key pubblica,
                                           chiave effimera server,
                                           firma host key)

  → Client verifica firma con host key (known_hosts)
  → ECDH: shared secret → session key (AES/ChaCha20)

2. NEWKEYS
─────────────────────────────────────────────────
SSH_MSG_NEWKEYS                  ──────>
                                 <──────  SSH_MSG_NEWKEYS
  → Da qui tutto è cifrato

3. AUTHENTICATION
─────────────────────────────────────────────────
SSH_MSG_SERVICE_REQUEST          ──────>
(ssh-userauth)
                                 <──────  SSH_MSG_SERVICE_ACCEPT

SSH_MSG_USERAUTH_REQUEST         ──────>
(user, metodo: publickey/password)
                                 <──────  SSH_MSG_USERAUTH_SUCCESS

4. CONNECTION (canali multipli)
─────────────────────────────────────────────────
SSH_MSG_CHANNEL_OPEN             ──────>
(session)
                                 <──────  SSH_MSG_CHANNEL_OPEN_CONFIRMATION

SSH_MSG_CHANNEL_REQUEST          ──────>
(exec / shell / subsystem)
                                 <──────  SSH_MSG_CHANNEL_DATA
                                          (stdout)
```

### Proprietà di sicurezza garantite

| Proprietà | Meccanismo |
|-----------|-----------|
| **Confidenzialità** | AES-256-GCM o ChaCha20-Poly1305 |
| **Integrità** | HMAC-SHA2 o AEAD (integrato) |
| **Autenticità server** | Firma con host key (ECDSA/Ed25519) |
| **Autenticità client** | Chiave pubblica o password |
| **Perfect Forward Secrecy** | ECDH con chiavi effimere |

---

## Autenticazione

### 1. Password

```bash
ssh user@hostname
# Inserisce password
```

⚠️ Vulnerabile a brute force

### 2. Chiave Pubblica (raccomandato)

```bash
# Genera coppia chiavi
ssh-keygen -t ed25519 -C "user@email.com"

# Output:
# ~/.ssh/id_ed25519 (privata)
# ~/.ssh/id_ed25519.pub (pubblica)

# Copia chiave su server
ssh-copy-id user@server

# Login senza password
ssh user@server
```

### 3. Tipi Chiave

| Algoritmo | Dimensione | Sicurezza | Velocità |
|-----------|-----------|-----------|----------|
| **Ed25519** | 256 bit | ✅ Ottima | ⚡ Veloce |
| **ECDSA** | 256/384/521 | ✅ Buona | ⚡ Veloce |
| **RSA** | 2048/4096 | ✅ Buona | 🐌 Lenta |
| **DSA** | 1024 | ❌ Debole | ⚠️ Deprecato |

**Raccomandazione**: Ed25519

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

## Gestione known_hosts

### Trust On First Use (TOFU)

La prima volta che ci si connette a un server, SSH mostra l'impronta della host key:

```
The authenticity of host 'server.example.com (192.168.1.100)' can't be established.
ED25519 key fingerprint is SHA256:abc123XYZ...
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'server.example.com' to the list of known hosts.
```

L'impronta viene salvata in `~/.ssh/known_hosts`. Le connessioni successive verificano che la chiave non sia cambiata (protezione da MITM).

### Formato known_hosts

```
# ~/.ssh/known_hosts
server.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
192.168.1.100 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...

# Hash (più sicuro: nasconde i nomi host)
|1|abc123...|def456... ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
```

### Comandi utili

```bash
# Verifica fingerprint del server (prima di connettersi)
ssh-keyscan -t ed25519 server.example.com | ssh-keygen -lf -

# Aggiunge manualmente la chiave a known_hosts
ssh-keyscan server.example.com >> ~/.ssh/known_hosts

# Elimina una voce (server cambiato chiave)
ssh-keygen -R server.example.com

# Abilita hashing dei nomi host (sicurezza)
ssh-keygen -H -f ~/.ssh/known_hosts

# Controlla se un host è già in known_hosts
ssh-keygen -F server.example.com
```

⚠️ Se appare il messaggio **"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED"**  
→ possibile attacco MITM oppure il server ha rigenerato le chiavi.  
Verificare **out-of-band** prima di accettare.

---

## SSH Certificates (SSH CA)

La gestione individuale delle chiavi `authorized_keys` non scala. Con una **SSH Certificate Authority (CA)** il server accetta qualsiasi chiave firmata dalla CA.

### Vantaggi rispetto alle chiavi tradizionali

| Aspetto | Chiavi pubbliche | Certificati SSH |
|---------|-----------------|-----------------|
| Scadenza | No | ✅ Sì (built-in) |
| Revoca | Rimozione manuale | CRL / principals |
| Scalabilità | Bassa | Alta |
| Audit | Difficile | Semplice (ID nel cert) |

### Setup CA e firma chiavi utente

```bash
# 1. Crea la CA (fatta UNA sola volta dall'amministratore)
ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca -C "SSH CA aziendale"
# Output: ssh_ca (privata) + ssh_ca.pub (pubblica)

# 2. Configura il server per fidarsi della CA
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ssh_ca.pub

# 3. Firma la chiave pubblica dell'utente
ssh-keygen -s /etc/ssh/ssh_ca \
    -I "mario.rossi@azienda.it" \
    -n mario,admin \
    -V +30d \
    ~/.ssh/id_ed25519.pub

# Output: ~/.ssh/id_ed25519-cert.pub
# -I: identity (log)
# -n: principals (username validi su server)
# -V: validità (30 giorni)

# 4. L'utente si connette normalmente (SSH usa auto il certificato)
ssh mario@server
```

### Firma chiavi host (elimina warning TOFU)

```bash
# Firma la host key del server
ssh-keygen -s /etc/ssh/ssh_ca \
    -I "server.example.com" \
    -h \
    -n server.example.com,192.168.1.100 \
    /etc/ssh/ssh_host_ed25519_key.pub

# Configura sshd per presentare il certificato host
# /etc/ssh/sshd_config
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub

# Il client si fida di qualsiasi server firmato dalla CA
# ~/.ssh/known_hosts
@cert-authority *.example.com ssh-ed25519 AAAAC3Nz... (chiave ssh_ca.pub)
```

---

## Configurazione Client

File: `~/.ssh/config`

```bash
# Server produzione
Host prod
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_prod_ed25519
    
# Server sviluppo
Host dev
    HostName dev.example.com
    User developer
    IdentityFile ~/.ssh/id_dev_ed25519
    ForwardAgent yes

# Bastion host (jump server)
Host internal
    HostName 10.0.0.50
    User admin
    ProxyJump bastion
```

Uso:
```bash
ssh prod  # invece di ssh admin@192.168.1.100 -p 2222
```

## Configurazione Server

File: `/etc/ssh/sshd_config`

### ✅ Configurazione Sicura

```bash
# Porta non standard
Port 2222

# Solo SSH-2
Protocol 2

# Disabilita root login
PermitRootLogin no

# Solo chiave pubblica
PasswordAuthentication no
PubkeyAuthentication yes

# Disabilita metodi deboli
ChallengeResponseAuthentication no
KerberosAuthentication no

# Limita utenti
AllowUsers user1 user2

# Timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Algoritmi moderni
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

Riavvia servizio:
```bash
sudo systemctl restart sshd
```

## Port Forwarding

### Local Forward

```bash
# Redirige localhost:8080 → remote:80
ssh -L 8080:remote:80 user@server

# Accedi a DB remoto
ssh -L 3306:localhost:3306 user@dbserver
mysql -h 127.0.0.1 -P 3306
```

### Remote Forward

```bash
# Server può accedere a tua porta locale
ssh -R 8080:localhost:80 user@server

# Server accede a localhost:80 via sua porta 8080
```

### Dynamic Forward (SOCKS Proxy)

```bash
# Crea proxy SOCKS su porta 1080
ssh -D 1080 user@server

# Configura browser per usare localhost:1080 come proxy
```

## SCP: Copia File

```bash
# Locale → Remoto
scp file.txt user@server:/path/to/destination/

# Remoto → Locale
scp user@server:/path/file.txt ./

# Directory ricorsiva
scp -r folder/ user@server:/path/

# Via bastion
scp -o "ProxyJump=bastion" file.txt user@internal:/path/
```

## SFTP: File Transfer

```bash
sftp user@server

# Comandi SFTP
put local.txt          # Upload
get remote.txt         # Download
ls                     # Lista remota
lls                    # Lista locale
cd /path              # Change dir remoto
lcd /path             # Change dir locale
```

## rsync over SSH

`rsync` è più efficiente di SCP per trasferimenti incrementali: copia solo le **differenze**.

```bash
# Sincronizza directory locale → remota
rsync -avz --progress \
    /local/dir/ \
    user@server:/remote/dir/

# Con eliminazione file rimossi in locale
rsync -avz --delete \
    /local/dir/ \
    user@server:/remote/dir/

# Porta SSH personalizzata
rsync -avz -e "ssh -p 2222" \
    /local/dir/ user@server:/remote/dir/

# Dry run (mostra cosa verrebbe trasferito)
rsync -avzn /local/dir/ user@server:/remote/dir/

# Esclude file/dir
rsync -avz --exclude='*.log' --exclude='tmp/' \
    /local/dir/ user@server:/remote/dir/
```

### Confronto metodi di trasferimento

| Metodo | I casi d'uso | Differenziale | Efficienza |
|--------|-------------|---------------|------------|
| **SCP** | Copia singola | No | Media |
| **SFTP** | Interattivo / scripting | No | Media |
| **rsync** | Backup, sincronizzazione | ✅ Sì | Alta |

---

## SSH Agent

Gestisce chiavi private in memoria:

```bash
# Avvia agent
eval $(ssh-agent)

# Aggiungi chiave
ssh-add ~/.ssh/id_ed25519

# Lista chiavi caricate
ssh-add -l

# Agent forwarding
ssh -A user@server
```

## SSH Multiplexing (ControlMaster)

Riutilizza una singola connessione TCP per più sessioni SSH verso lo stesso host.  
Velocizza drasticamente comandi ripetuti (es. deploy, Ansible, Git over SSH).

```bash
# ~/.ssh/config
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
```

```bash
# Crea la directory dei socket
mkdir -p ~/.ssh/sockets

# Prima connessione: crea il master
ssh user@server

# Connessioni successive: istantanee (no handshake)
ssh user@server "uptime"
ssh user@server "df -h"
scp file.txt user@server:/tmp/

# Controlla lo stato del master
ssh -O check user@server

# Chiudi il master
ssh -O exit user@server
```

### Vantaggi

- Handshake solo alla prima connessione
- Ideale per script che aprono molte connessioni
- Riduce carico del server

---

## SSH in Python

```python
import paramiko

def ssh_execute(hostname, username, key_file, command):
    """Esegui comando via SSH"""
    
    # Client SSH
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connetti con chiave privata
        client.connect(
            hostname,
            username=username,
            key_filename=key_file
        )
        
        # Esegui comando
        stdin, stdout, stderr = client.exec_command(command)
        
        # Output
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if output:
            print(f"Output:\n{output}")
        if error:
            print(f"Error:\n{error}")
            
    finally:
        client.close()

# Uso
ssh_execute(
    "server.example.com",
    "admin",
    "/home/user/.ssh/id_ed25519",
    "uptime"
)
```

## SFTP in Python

```python
import paramiko

def sftp_upload(hostname, username, key_file, local_path, remote_path):
    """Upload file via SFTP"""
    
    transport = paramiko.Transport((hostname, 22))
    
    try:
        # Autenticazione
        key = paramiko.Ed25519Key.from_private_key_file(key_file)
        transport.connect(username=username, pkey=key)
        
        # SFTP client
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        # Upload
        sftp.put(local_path, remote_path)
        print(f"✅ Uploaded: {local_path} → {remote_path}")
        
        sftp.close()
        
    finally:
        transport.close()

# Uso
sftp_upload(
    "server.example.com",
    "admin",
    "/home/user/.ssh/id_ed25519",
    "local_file.txt",
    "/remote/path/file.txt"
)
```

## Hardening SSH

### 1. Fail2Ban

Blocca brute force:

```bash
sudo apt install fail2ban

# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

### 2. Autenticazione 2FA

```bash
sudo apt install libpam-google-authenticator

# Configura per utente
google-authenticator

# /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

### 3. Chroot SFTP

```bash
# /etc/ssh/sshd_config
Match User sftpuser
    ChrootDirectory /var/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
```

## Escape Sequences

Durante una sessione SSH interattiva, il carattere `~` (tilde) seguito da un tasto permette comandi speciali:

| Sequenza | Azione |
|----------|--------|
| `~.` | Disconnetti la sessione |
| `~C` | Apri prompt per port forwarding on-the-fly |
| `~R` | Richiedi rekeying |
| `~#` | Lista connessioni forwarded |
| `~?` | Mostra help |
| `~~` | Invia `~` letterale |

```bash
# Esempio: aggiungere un tunnel locale DOPO la connessione
~C
ssh> -L 8080:internal-host:80
Forwarding port.
```

---

## Git over SSH

Git utilizza SSH come protocollo di trasporto sicuro per i repository remoti.

```bash
# Clona via SSH (invece di HTTPS)
git clone git@github.com:utente/repo.git

# Cambia remote da HTTPS a SSH
git remote set-url origin git@github.com:utente/repo.git

# Test connessione GitHub
ssh -T git@github.com
# Hi username! You've successfully authenticated...

# Più chiavi SSH (es. lavoro + personale)
# ~/.ssh/config
Host github-lavoro
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_lavoro

Host github-personale
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_personale

# Usa con alias
git clone github-lavoro:azienda/repo.git
```

---

## Vulnerabilità Notevoli

| CVE | Anno | Descrizione | Impatto |
|-----|------|-------------|---------|
| **CVE-2023-38408** | 2023 | Remote code execution tramite ssh-agent forwarding e librerie PKCS#11 | Critico |
| **CVE-2023-51385** | 2023 | OS command injection via nomi host con metacaratteri in `ssh_config` | Alto |
| **CVE-2024-6387** (regreSSHion) | 2024 | Race condition nel gestore SIGALRM di OpenSSH → RCE unauthenticated su glibc Linux | Critico |
| **CVE-2016-0777** | 2016 | Memory leak chiave privata via roaming feature | Alto |
| **CVE-2008-0166** | 2008 | PRNG debole in Debian/Ubuntu → chiavi predicibili | Critico |

### Misure di mitigazione generali

```bash
# Mantieni OpenSSH aggiornato
sudo apt update && sudo apt upgrade openssh-server

# Controlla la versione
ssh -V
# OpenSSH_9.x, OpenSSL 3.x

# Disabilita agent forwarding quando non necessario
# ~/.ssh/config
Host *
    ForwardAgent no

# Limita il tempo di autenticazione (riduce esposizione a regreSSHion)
# /etc/ssh/sshd_config
LoginGraceTime 30
```

---

## Debugging

```bash
# Client verbose
ssh -vvv user@server

# Server debug
sudo /usr/sbin/sshd -d -p 2222

# Test chiave
ssh-keygen -y -f ~/.ssh/id_ed25519

# Controlla permessi
ls -la ~/.ssh/
# id_ed25519: 600
# id_ed25519.pub: 644
# authorized_keys: 600
```

### Checklist permessi

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/config
```

---

## Riepilogo

### Comandi principali

| Comando | Scopo |
|---------|-------|
| `ssh user@host` | Connessione remota |
| `ssh-keygen -t ed25519` | Genera coppia di chiavi |
| `ssh-copy-id user@host` | Copia chiave pubblica sul server |
| `scp src user@host:dst` | Copia file |
| `rsync -avz src/ user@host:dst/` | Sincronizzazione incrementale |
| `sftp user@host` | Shell FTP sicura |
| `ssh -L port:host:port user@srv` | Tunnel locale |
| `ssh -R port:host:port user@srv` | Tunnel remoto |
| `ssh -D 1080 user@server` | Proxy SOCKS |
| `ssh -J bastion user@internal` | Jump / bastion host |

### Checklist sicurezza

| ✅ | Misura | Priorità |
|----|--------|----------|
| ✅ | Usa Ed25519 o ECDSA (no DSA, no RSA < 2048) | Alta |
| ✅ | Disabilita autenticazione con password | Alta |
| ✅ | Disabilita login diretto come root | Alta |
| ✅ | Usa porta non standard (es. 2222) | Media |
| ✅ | Installa e configura fail2ban | Alta |
| ✅ | Limita gli utenti abilitati con `AllowUsers` | Alta |
| ✅ | Usa solo algoritmi moderni (cipher, kex, mac) | Media |
| ✅ | Configura timeout sessioni (`ClientAliveInterval`) | Media |
| ✅ | Aggiorna OpenSSH regolarmente | Alta |
| ✅ | Considera SSH CA per ambienti con molti server | Media |

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 18 - SSL/TLS](18_ssltls.md)
- **Successivo**: [Capitolo 20 - IPsec](20_ipsec.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 4251-4254: SSH Protocol
- OpenSSH: https://www.openssh.com

**Best Practice**: Ed25519, no password auth, no root login, porta non standard, fail2ban, aggiornare OpenSSH, usare SSH CA in ambienti enterprise.
