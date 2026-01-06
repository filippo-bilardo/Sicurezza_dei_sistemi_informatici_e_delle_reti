# Capitolo 19 - SSH (Secure Shell)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 6 - Protocolli Crittografici  
> **Autore**: Prof. Filippo Bilardo

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

## SSH Agent

Gestisce chiavi private in memoria:

```bash
# Avvia agent
eval $(ssh-agent)

# Aggiungi chiave
ssh-add ~/.ssh/id_ed25519

# Lista chiavi caricate
ssh-agent -l

# Agent forwarding
ssh -A user@server
```

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

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 18 - SSL/TLS](18_ssltls.md)
- **Successivo**: [Capitolo 20 - IPsec](20_ipsec.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 4251-4254: SSH Protocol
- OpenSSH: https://www.openssh.com

**Best Practice**: Ed25519, no password, no root login, porta non standard, fail2ban.
