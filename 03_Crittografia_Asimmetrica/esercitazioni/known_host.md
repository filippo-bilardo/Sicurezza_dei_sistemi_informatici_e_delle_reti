# Guida alla Sicurezza SSH: Chiavi Host e Autenticazione

## Indice
1. [File known_hosts](#file-known_hosts)
2. [Host Key Fingerprint](#host-key-fingerprint)
3. [Modificare la Chiave Pubblica del Server](#modificare-la-chiave-pubblica-del-server)
4. [Chiavi in /etc/ssh](#chiavi-in-etcssh)
5. [Negoziazione dell'Algoritmo](#negoziazione-dellalgoritmo)
6. [Funzioni di Hash](#funzioni-di-hash)
7. [Comandi Utili](#comandi-utili)

---

## File known_hosts

### Cos'è
Il file `~/.ssh/known_hosts` (o `/etc/ssh/ssh_known_hosts` per configurazioni globali) memorizza le chiavi pubbliche dei server SSH a cui ci si è già connessi in precedenza.

### Scopo
- **Protezione contro attacchi Man-in-the-Middle (MITM)**: quando ti connetti a un server SSH per la prima volta, il client memorizza la sua chiave pubblica
- **Verifica dell'identità**: nelle connessioni successive, il client verifica che la chiave del server corrisponda a quella memorizzata

### Formato del file
```
hostname algorithm public-key [comment]
```

**Esempio:**
```
192.168.1.100 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... 
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm...
[192.168.1.50]: 2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI...
```

### Formato con hash (più sicuro)
```
|1|base64-salt|base64-hash algorithm public-key
```

**Esempio:**
```
|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= ssh-rsa AAAAB3... 
```

### Prima connessione
Quando ti connetti per la prima volta a un server: 
```bash
$ ssh user@server. example.com
The authenticity of host 'server. example.com (192.168.1.100)' can't be established.
ED25519 key fingerprint is SHA256:7KMZvJhM8fHrHIj8D5qYzN8Xp+dW4xQ9z8B2K3pLMwE.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Rispondendo "yes", la chiave viene aggiunta a `known_hosts`.

### Problemi comuni
**Warning di chiave cambiata:**
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
```

**Cause legittime:**
- Reinstallazione del server
- Rigenerazione delle chiavi host
- Indirizzo IP riassegnato a un altro server

---

## Host Key Fingerprint

### Definizione
L'**Host Key Fingerprint** è un'impronta digitale (hash) della chiave pubblica del server SSH, più breve e facile da verificare rispetto alla chiave completa.

### Formati

#### SHA256 (predefinito moderno)
```
SHA256:7KMZvJhM8fHrHIj8D5qYzN8Xp+dW4xQ9z8B2K3pLMwE
```

#### MD5 (legacy, meno sicuro)
```
MD5:43: 51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73: a8
```

### Come ottenere il fingerprint

**Sul server:**
```bash
# Per tutte le chiavi
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub

# Output esempio: 
256 SHA256:7KMZvJhM8fHrHIj8D5qYzN8Xp+dW4xQ9z8B2K3pLMwE root@server (ED25519)
```

**Con formato MD5:**
```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E md5
```

### Verifica manuale
Prima di connetterti, puoi verificare il fingerprint tramite un canale sicuro (telefono, email firmata, console fisica) e confrontarlo durante la prima connessione.

### Visual Host Key (ASCII art)
```bash
ssh-keygen -lv -f /etc/ssh/ssh_host_ed25519_key.pub
```
Produce un'immagine ASCII "randomart" visivamente riconoscibile: 
```
+--[ED25519 256]--+
|        .o+*=o   |
|       .  o.oE    |
|      . . o. o    |
|       o = = o   |
|      .  S = B .   |
|       o = O *   |
|        + = X .   |
|         o B o   |
|          . o.   |
+----[SHA256]-----+
```

---

## Modificare la Chiave Pubblica del Server

### Quando è necessario
- Compromissione della chiave privata del server
- Migrazione a algoritmi più sicuri (es. da RSA a ED25519)
- Best practice di rotazione periodica delle chiavi
- Dopo reinstallazione del sistema

### Procedura sul server

#### 1. Backup delle vecchie chiavi
```bash
sudo mkdir /root/ssh_backup_$(date +%Y%m%d)
sudo cp /etc/ssh/ssh_host_* /root/ssh_backup_$(date +%Y%m%d)/
```

#### 2. Eliminare le vecchie chiavi
```bash
sudo rm /etc/ssh/ssh_host_*
```

#### 3. Generare nuove chiavi

**Su Debian/Ubuntu:**
```bash
sudo dpkg-reconfigure openssh-server
```

**Manualmente:**
```bash
# ED25519 (consigliato)
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# RSA (4096 bit)
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# ECDSA
sudo ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
```

#### 4. Impostare i permessi corretti
```bash
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chmod 644 /etc/ssh/ssh_host_*_key.pub
sudo chown root:root /etc/ssh/ssh_host_*
```

#### 5. Riavviare il servizio SSH
```bash
sudo systemctl restart sshd
# oppure
sudo service ssh restart
```

### Procedura sul client

I client devono rimuovere la vecchia chiave dal file `known_hosts`:

**Rimuovere una specifica chiave:**
```bash
ssh-keygen -R hostname
ssh-keygen -R 192.168.1.100
ssh-keygen -R [192.168.1.100]:2222  # per porte non standard
```

**Manualmente:**
```bash
# Modificare il file
nano ~/.ssh/known_hosts
# Eliminare la riga corrispondente all'host
```

### Distribuzione sicura delle nuove chiavi

1. **Comunicare i fingerprint** tramite canale sicuro
2. Alla prossima connessione, **verificare il fingerprint** visualizzato
3. Confermare la connessione solo se il fingerprint corrisponde

---

## Chiavi in /etc/ssh

### Panoramica delle chiavi host

Il server SSH mantiene diverse coppie di chiavi per supportare vari algoritmi crittografici:

```
/etc/ssh/
├── ssh_host_dsa_key          # DSA (obsoleto, non usare)
├── ssh_host_dsa_key.pub
├── ssh_host_ecdsa_key        # ECDSA (elliptic curve)
├── ssh_host_ecdsa_key. pub
├── ssh_host_ed25519_key      # ED25519 (consigliato)
├── ssh_host_ed25519_key.pub
├── ssh_host_rsa_key          # RSA
├── ssh_host_rsa_key.pub
├── sshd_config               # Configurazione server
└── ssh_config                # Configurazione client
```

### Tipi di chiavi

#### 1. **ED25519** (Consigliato) ⭐
```bash
# Generazione
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
```
- **Dimensione**: 256 bit
- **Vantaggi**: veloce, sicuro, chiavi piccole
- **Supporto**: OpenSSH 6.5+ (2014)

#### 2. **RSA**
```bash
# Generazione
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
```
- **Dimensione**: 2048-4096 bit (minimo 2048)
- **Vantaggi**: compatibilità universale
- **Svantaggi**: prestazioni inferiori con chiavi grandi

#### 3. **ECDSA**
```bash
# Generazione
ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
```
- **Dimensione**: 256, 384, o 521 bit
- **Vantaggi**: veloce, chiavi più piccole di RSA
- **Svantaggi**: controversie su NIST curves

#### 4. **DSA** (DEPRECATO ❌)
- **NON USARE**:  vulnerabilità crittografiche
- **Disabilitato** in OpenSSH 7.0+ di default

### Configurazione in sshd_config

```bash
# Specifica quali chiavi host utilizzare
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

# NON includere DSA
# HostKey /etc/ssh/ssh_host_dsa_key
```

### File di configurazione

#### `/etc/ssh/sshd_config` (Server)
Configurazione del demone SSH (server):
```bash
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
HostKey /etc/ssh/ssh_host_ed25519_key
```

#### `/etc/ssh/ssh_config` (Client)
Configurazione predefinita per tutti i client:
```bash
Host *
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
```

#### `~/.ssh/config` (Client personale)
Configurazione per utente specifico:
```bash
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    HostKeyAlgorithms ssh-ed25519
```

---

## Negoziazione dell'Algoritmo

### Processo di negoziazione

Quando client e server stabiliscono una connessione SSH, negoziano automaticamente: 

1. **Algoritmo di scambio chiavi** (Key Exchange - KEX)
2. **Algoritmo di cifratura** (Cipher)
3. **Algoritmo MAC** (Message Authentication Code)
4. **Algoritmo di compressione**

### Fasi della negoziazione

```
CLIENT                                SERVER
  |                                      |
  |  1. Invio lista algoritmi supportati |
  |------------------------------------->|
  |                                      |
  |  2. Risposta con lista algoritmi     |
  |<-------------------------------------|
  |                                      |
  |  3. Selezione algoritmi comuni       |
  |      (priorità del client)           |
  |                                      |
  |  4. Scambio chiavi con KEX           |
  |<------------------------------------>|
  |                                      |
  |  5. Verifica Host Key                |
  |<-------------------------------------|
  |                                      |
  |  6. Connessione cifrata stabilita    |
  |======================================|
```

### Key Exchange (KEX) Algorithms

Algoritmi per lo scambio sicuro delle chiavi di sessione:

#### Consigliati
```
curve25519-sha256               # Veloce e sicuro
curve25519-sha256@libssh.org    # Variant
diffie-hellman-group-exchange-sha256
diffie-hellman-group16-sha512
diffie-hellman-group18-sha512
```

#### Da evitare
```
diffie-hellman-group1-sha1      # Obsoleto, debole
diffie-hellman-group14-sha1     # SHA1 vulnerabile
```

### Host Key Algorithms

Algoritmi per le chiavi del server:

```
ssh-ed25519                     # Consigliato
rsa-sha2-512                    # RSA con SHA-2
rsa-sha2-256
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
ssh-rsa                         # Legacy (SHA-1)
ssh-dss                         # Obsoleto
```

### Cipher (Algoritmi di cifratura)

```
chacha20-poly1305@openssh.com   # Consigliato
aes256-gcm@openssh.com          # AES-GCM
aes128-gcm@openssh.com
aes256-ctr                      # AES Counter Mode
aes192-ctr
aes128-ctr
```

### MAC Algorithms

Garantiscono l'integrità dei messaggi:

```
hmac-sha2-512-etm@openssh.com   # Encrypt-then-MAC
hmac-sha2-256-etm@openssh.com
umac-128-etm@openssh.com
hmac-sha2-512
hmac-sha2-256
```

### Configurazione avanzata

**Client (`~/.ssh/config`):**
```bash
Host secure-server
    HostName server.example.com
    # Solo algoritmi moderni e sicuri
    KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
    Ciphers chacha20-poly1305@openssh. com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

**Server (`/etc/ssh/sshd_config`):**
```bash
# Solo algoritmi sicuri
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
```

### Verificare la negoziazione

```bash
# Modalità verbose per vedere gli algoritmi negoziati
ssh -vv user@server 2>&1 | grep -i "kex\|cipher\|mac\|host key"
```

---

## Funzioni di Hash

### Cosa sono

Le **funzioni di hash crittografiche** trasformano dati di qualsiasi dimensione in un output di dimensione fissa (digest) in modo unidirezionale e deterministico.

### Proprietà essenziali

1. **Deterministico**: stesso input → stesso output
2. **Veloce da calcolare**
3. **Unidirezionale**: impossibile risalire all'input dall'hash
4. **Resistente alle collisioni**:  difficile trovare due input con stesso hash
5. **Effetto valanga**: piccola modifica input → hash completamente diverso

### Algoritmi di hash in SSH

#### SHA-2 Family (Sicuri) ✅

**SHA-256** (256 bit / 32 bytes)
```
SHA256:7KMZvJhM8fHrHIj8D5qYzN8Xp+dW4xQ9z8B2K3pLMwE
```

**SHA-512** (512 bit / 64 bytes)
```
SHA512:jZB8PqMm7eoQHg...  (più lungo)
```

**Utilizzo:**
- Fingerprint delle chiavi host
- HMAC per integrità messaggi
- Key derivation functions

#### MD5 (Obsoleto) ⚠️

```
MD5:43:51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73:a8
```

- **128 bit** (16 bytes)
- **Vulnerabile** a collisioni
- **Solo per compatibilità** con sistemi legacy

#### SHA-1 (Deprecato) ⚠️

```
SHA1:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
```

- **160 bit** (20 bytes)
- **Vulnerabilità dimostrate** (2017)
- **In fase di dismissione** in SSH

### Hash in diversi contesti SSH

#### 1. Host Key Fingerprint
```bash
# Calcola fingerprint (SHA-256)
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# Output:
# 256 SHA256:7KMZvJhM8fHrHIj8D5qYzN8Xp+dW4xQ9z8B2K3pLMwE root@server (ED25519)
```

#### 2. HMAC (Hash-based Message Authentication Code)
Garantisce integrità e autenticità dei pacchetti SSH:
```
hmac-sha2-256
hmac-sha2-512
```

Formula:  `HMAC = H(K ⊕ opad || H(K ⊕ ipad || message))`

#### 3. Key Derivation
SSH usa hash per derivare chiavi di sessione dalla chiave condivisa:
```
HASH(K || H || session_id || "A" || session_id) → IV client-to-server
HASH(K || H || session_id || "B" || session_id) → IV server-to-client
HASH(K || H || session_id || "C" || session_id) → encryption key C→S
HASH(K || H || session_id || "D" || session_id) → encryption key S→C
```

#### 4. Known Hosts (hashing)
```bash
# Hashare hostname nel known_hosts
ssh-keygen -H -f ~/.ssh/known_hosts
```

Prima: 
```
github.com ssh-rsa AAAAB3NzaC1yc2EA...
```

Dopo:
```
|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= ssh-rsa AAAAB3... 
```

**Vantaggi:**
- Privacy: nasconde gli host a cui ti connetti
- Sicurezza: attaccante non può enumerare i tuoi server

### Esempi pratici

#### Calcolare hash manualmente

```bash
# SHA-256 di un file
sha256sum /etc/ssh/ssh_host_ed25519_key.pub

# SHA-256 di una stringa
echo -n "hello" | sha256sum

# MD5 (solo test, non usare in produzione)
md5sum file.txt
```

#### Confrontare fingerprint

```bash
# Sul server
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key. pub -E sha256

# Sul client (da known_hosts)
ssh-keygen -lf ~/.ssh/known_hosts -E sha256 | grep server-hostname
```

#### Verificare integrità connessione

```bash
# Connessione con debug per vedere MAC usato
ssh -vv user@server 2>&1 | grep "MAC"
# Output esempio:
# debug1: MAC client to server: hmac-sha2-256-etm@openssh. com
# debug1: MAC server to client: hmac-sha2-256-etm@openssh.com
```

---

## Comandi Utili

### Gestione Chiavi Host

#### Visualizzare fingerprint
```bash
# Tutte le chiavi del server
for key in /etc/ssh/ssh_host_*_key. pub; do
    ssh-keygen -lf "$key"
done

# Con visual ASCII art
ssh-keygen -lvf /etc/ssh/ssh_host_ed25519_key.pub

# Formato MD5 (legacy)
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub -E md5
```

#### Generare nuove chiavi host
```bash
# ED25519 (consigliato)
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -C "$(hostname)-$(date +%Y%m%d)"

# RSA 4096 bit
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# ECDSA 521 bit
sudo ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
```

#### Testare configurazione server
```bash
# Verifica sintassi configurazione
sudo sshd -t

# Verifica estesa con output
sudo sshd -T

# Verifica per un utente specifico
sudo sshd -T -C user=filippo
```

### Gestione known_hosts

#### Rimuovere entry
```bash
# Per hostname
ssh-keygen -R server.example.com

# Per IP
ssh-keygen -R 192.168.1.100

# Per porta non standard
ssh-keygen -R [192.168.1.100]:2222

# Rimuovere tutte le entry di un host (anche con alias)
ssh-keygen -R server.example.com -f ~/.ssh/known_hosts
ssh-keygen -R 192.168.1.100 -f ~/.ssh/known_hosts
```

#### Hashare known_hosts
```bash
# Hashare tutti gli hostname (privacy)
ssh-keygen -H -f ~/.ssh/known_hosts

# Backup creato automaticamente
# ~/.ssh/known_hosts.old
```

#### Cercare nel known_hosts
```bash
# Trovare una chiave specifica
ssh-keygen -F server.example.com

# Con numero di riga
grep -n "server.example.com" ~/.ssh/known_hosts
```

#### Aggiungere manualmente una chiave
```bash
# Ottenere la chiave pubblica da un server
ssh-keyscan server.example.com >> ~/.ssh/known_hosts

# Per una porta specifica
ssh-keyscan -p 2222 server. example.com >> ~/.ssh/known_hosts

# Solo ED25519
ssh-keyscan -t ed25519 server. example.com >> ~/.ssh/known_hosts

# Più host contemporaneamente
ssh-keyscan server1.com server2.com server3.com >> ~/.ssh/known_hosts
```

### Debug e Diagnostica

#### Connessione verbose
```bash
# Livello 1 (base)
ssh -v user@server

# Livello 2 (dettagliato)
ssh -vv user@server

# Livello 3 (molto dettagliato)
ssh -vvv user@server

# Salvare output debug
ssh -vvv user@server 2>&1 | tee ssh_debug.log
```

#### Analizzare la negoziazione
```bash
# Vedere algoritmi supportati dal client
ssh -Q kex          # Key exchange
ssh -Q cipher       # Cifratura
ssh -Q mac          # MAC
ssh -Q key          # Host key types

# Vedere cosa viene negoziato
ssh -vv user@server 2>&1 | grep -E "kex:|cipher:|MAC:|host key"
```

#### Testare connessione senza autenticazione
```bash
# Solo handshake e scambio chiavi
ssh -v -o BatchMode=yes -o ConnectTimeout=5 user@server exit
```

#### Forzare algoritmi specifici
```bash
# Solo ED25519 per host key
ssh -o HostKeyAlgorithms=ssh-ed25519 user@server

# Cipher specifico
ssh -c aes256-gcm@openssh.com user@server

# KEX specifico
ssh -o KexAlgorithms=curve25519-sha256 user@server

# Combinazione
ssh -o HostKeyAlgorithms=ssh-ed25519 \
    -o KexAlgorithms=curve25519-sha256 \
    -o Ciphers=chacha20-poly1305@openssh.com \
    user@server
```

### Gestione File di Configurazione

#### Validare ssh_config
```bash
# Sintassi client config
ssh -G user@server | head -20

# Vedere configurazione effettiva per un host
ssh -G myserver
```

#### Backup e restore
```bash
# Backup completo directory SSH
sudo tar -czf ssh_backup_$(date +%Y%m%d).tar.gz /etc/ssh/

# Backup known_hosts
cp ~/.ssh/known_hosts ~/.ssh/known_hosts.backup. $(date +%Y%m%d)

# Restore
sudo tar -xzf ssh_backup_20260109.tar.gz -C /
```

### Monitoraggio e Log

#### Visualizzare log SSH
```bash
# Systemd
sudo journalctl -u sshd -f

# Log tradizionali
sudo tail -f /var/log/auth.log      # Debian/Ubuntu
sudo tail -f /var/log/secure        # RedHat/CentOS

# Filtrare solo SSH
sudo grep sshd /var/log/auth.log
```

#### Connessioni attive
```bash
# Utenti connessi via SSH
who
w

# Dettagli connessioni
ss -tnp | grep : 22
netstat -tnp | grep :22

# Processo sshd
ps aux | grep sshd
```

#### Tentativi di accesso falliti
```bash
# Ultimi tentativi falliti
sudo grep "Failed password" /var/log/auth.log | tail -20

# IP con più tentativi
sudo grep "Failed password" /var/log/auth.log | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

### Performance e Benchmark

#### Misurare velocità cifratura
```bash
# Trasferire file con algoritmo specifico
time ssh -c aes128-ctr user@server "cat /dev/zero | head -c 100M" > /dev/null

# Confrontare diversi cipher
for cipher in aes128-ctr aes256-ctr chacha20-poly1305@openssh.com; do
    echo "Testing $cipher"
    time ssh -c $cipher user@server "cat /dev/zero | head -c 100M" > /dev/null
done
```

### Sicurezza Avanzata

#### Scansione configurazione sicurezza
```bash
# Algoritmi deboli abilitati
sudo sshd -T | grep -E "ciphers|macs|kexalgorithms" | \
    grep -E "sha1|md5|dss|rc4"
```

#### Hardening rapido
```bash
# Aggiungere a /etc/ssh/sshd_config
cat <<EOF | sudo tee -a /etc/ssh/sshd_config

# Security hardening
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Strong algorithms only
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

# Verificare e riavviare
sudo sshd -t && sudo systemctl restart sshd
```

#### Rotazione chiavi automatica (script)
```bash
#!/bin/bash
# Script:  rotate_ssh_keys.sh

BACKUP_DIR="/root/ssh_keys_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup
cp /etc/ssh/ssh_host_* "$BACKUP_DIR/"

# Rigenerazione
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q

# Permessi
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

# Fingerprint
echo "Nuovi fingerprint:"
for key in /etc/ssh/ssh_host_*_key.pub; do
    ssh-keygen -lf "$key"
done

# Riavvio
systemctl restart sshd

echo "Chiavi rotate.  Backup in: $BACKUP_DIR"
```

### Utilities Extra

#### Convertire formati chiavi
```bash
# PEM to OpenSSH
ssh-keygen -i -f key.pem > key.pub

# OpenSSH to PEM
ssh-keygen -e -f key.pub > key. pem

# PKCS#8 to OpenSSH
ssh-keygen -p -m PEM -f ~/. ssh/id_rsa
```

#### Copiare chiave pubblica su server
```bash
# Metodo automatico
ssh-copy-id user@server

# Porta specifica
ssh-copy-id -p 2222 user@server

# Chiave specifica
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
```

#### Testare chiave pubblica
```bash
# Verificare se la tua chiave funziona
ssh -i ~/.ssh/id_ed25519 -o PreferredAuthentications=publickey user@server

# Vedere quale chiave viene usata
ssh -v user@server 2>&1 | grep "Offering public key"
```

---

## Best Practices

### Per Amministratori di Server

1. **Usare solo algoritmi moderni**: 
   - ED25519 per host keys
   - Disabilitare DSA e SHA-1
   
2. **Disabilitare password authentication**:
   ```bash
   PasswordAuthentication no
   ChallengeResponseAuthentication no
   ```

3. **Rigenerare chiavi periodicamente** (es. annualmente)

4. **Pubblicare fingerprint** su canale sicuro (website HTTPS, DNS SSHFP records)

5. **Monitorare log** per tentativi di accesso sospetti

6. **Fail2ban** o rate limiting per proteggere da brute force

### Per Utenti

1. **Verificare sempre fingerprint** alla prima connessione

2. **Usare `~/.ssh/config`** per configurazioni host-specific

3. **Mantenere known_hosts pulito**:  rimuovere host obsoleti

4. **Backup** di `~/.ssh/known_hosts` prima di modifiche massive

5. **Usare chiavi SSH** invece di password

6. **Proteggere chiavi private** con passphrase

---

## Risorse Utili

### Documentazione
```bash
man ssh
man sshd
man sshd_config
man ssh_config
man ssh-keygen
```

### Tool online
- **ssh-audit**: https://github.com/jtesta/ssh-audit
  ```bash
  ssh-audit server.example.com
  ```

### RFC e Standard
- RFC 4253: SSH Transport Layer Protocol
- RFC 4254: SSH Connection Protocol  
- RFC 4716: SSH Public Key File Format
- RFC 8709: Ed25519 and Ed448 Public Key Algorithms

---

## Conclusione

La sicurezza SSH si basa su: 
1. **Crittografia forte**:  algoritmi moderni (ED25519, ChaCha20)
2. **Verifica dell'identità**: fingerprint e known_hosts
3. **Autenticazione robusta**: chiavi pubbliche invece di password
4. **Configurazione corretta**: disabilitare algoritmi deboli

Mantenere aggiornato OpenSSH e seguire le best practices è fondamentale per una sicurezza efficace. 

---

**Autore**: Guida SSH Security  
**Data**: 2026-01-09  
**Versione**: 1.0