# Autenticazione SSH con Chiave Pubblica/Privata

SSH (Secure Shell) è un protocollo crittografico utilizzato per comunicare in modo sicuro con server remoti. In questa guida imparerai come configurare l'autenticazione basata su chiavi crittografiche, un metodo più sicuro rispetto all'autenticazione con password.

## Indice
1. [Introduzione teorica](#introduzione-teorica)
2. [Prerequisiti](#prerequisiti)
3. [Esercitazione Pratica 1](#esercitazione-pratica-1---ssh-con-chiave-pubblica-privata)
4. [Esercitazione Pratica 2](#esercitazione-pratica-2---config-per-semplificare-la-connessione-ssh)
5. [Verifica e Troubleshooting](#verifica-e-troubleshooting)
6. [Esercizi](#esercizi)


## Obiettivi della Lezione
- Comprendere il funzionamento della crittografia asimmetrica
- Generare una coppia di chiavi SSH (pubblica/privata)
- Configurare l'accesso al server senza password
- Collegare al server `cognome.nome@w4s.filippobilardo.it -p 2222`

## Introduzione teorica

### Cos'è SSH?

**SSH (Secure Shell)** è un protocollo di rete che permette di:
- Accedere in modo sicuro a server remoti
- Eseguire comandi su macchine remote
- Trasferire file in modo sicuro (SCP, SFTP)
- Creare tunnel crittografati

**Caratteristiche principali**:
- **Crittografia**: tutti i dati sono cifrati
- **Autenticazione**: verifica dell'identità di client e server
- **Integrità**: protezione contro alterazioni dei dati
- **Porta predefinita**: 22

**Componenti SSH**:
- **Client SSH**: programma che inizia la connessione (es. `ssh`, PuTTY)
- **Server SSH**: programma che accetta le connessioni (es. `sshd`, OpenSSH)
- **Chiave pubblica**: condivisa liberamente
- **Chiave privata**: mantenuta segreta

#### Sintassi del comando SSH:
```bash
ssh [opzioni] [utente@]hostname [comando]
```

#### Esempi di connessione:

##### Connessione semplice:
```bash
# Connessione con l'utente corrente
ssh 192.168.1.100

# Connessione con un utente specifico
ssh mario@192.168.1.100
ssh mario@server.example.com
```

##### Specificare una porta diversa:
```bash
ssh -p 2222 mario@192.168.1.100
```

##### Eseguire un comando remoto:
```bash
# Eseguire un singolo comando
ssh mario@192.168.1.100 ls -la

# Eseguire più comandi
ssh mario@192.168.1.100 "cd /var/log && tail -n 20 syslog"

# Eseguire un comando con sudo
ssh mario@192.168.1.100 "sudo systemctl restart apache2"
```

##### Connessione in modalità verbose (per debugging):
```bash
ssh -v mario@192.168.1.100
ssh -vv mario@192.168.1.100  # più dettagli
ssh -vvv mario@192.168.1.100 # massimo dettaglio
```

### Crittografia Asimmetrica

L'autenticazione SSH con chiavi utilizza la **crittografia asimmetrica**, che si basa su due chiavi matematicamente correlate:

#### 1. **Chiave Privata** (Private Key)
- Deve rimanere **segreta** e conservata solo sul tuo computer
- Non deve mai essere condivisa o trasmessa
- Utilizzata per **decifrare** messaggi e **firmare** digitalmente
- Generalmente memorizzata in `~/.ssh/id_rsa` o `~/.ssh/id_ed25519` o `~/.ssh/id_ed25519_rossi.marco.key`

#### 2. **Chiave Pubblica** (Public Key)
- Può essere **condivisa liberamente**
- Viene copiata sul server remoto
- Utilizzata per **cifrare** messaggi destinati al possessore della chiave privata
- Generalmente memorizzata in `~/.ssh/id_rsa.pub` o `~/.ssh/id_ed25519.pub` o `~/.ssh/id_ed25519_rossi.marco.key.pub`

#### Come Funziona l'Autenticazione?

```
┌─────────────┐                           ┌─────────────┐
│   CLIENT    │                           │   SERVER    │
│             │                           │             │
│  ┌────────┐ │                           │  ┌────────┐ │
│  │ Chiave │ │   1. Richiesta connessione│  │ Chiave │ │
│  │Privata │ │──────────────────────────>│  │Pubblica│ │
│  └────────┘ │                           │  └────────┘ │
│             │   2. Challenge cifrato    │             │
│             │<──────────────────────────│             │
│             │                           │             │
│  Decifrare  │   3. Risposta firmata     │  Verifica   │
│  challenge  │──────────────────────────>│  firma      │
│             │                           │             │
│             │   4. Accesso consentito   │             │
│             │<──────────────────────────│             │
└─────────────┘                           └─────────────┘
```

**Processo passo-passo:**

1. Il client invia una richiesta di connessione al server usando il proprio nome utente 
2. Il server controlla se esiste la chiave pubblica del client in `~/.ssh/authorized_keys`
3. Il server genera un **challenge** (messaggio casuale) e lo cifra con la chiave pubblica del client
4. Il client decifra il challenge con la sua chiave privata
5. Il client firma il challenge e lo rispedisce al server usando la sua chiave privata
6. Il server verifica la firma con la chiave pubblica
7. Se la verifica ha successo, l'accesso viene concesso, altrimenti negato

**Attenzione**: Se volete utilizzare solo l'autenticazione con chiavi, è possibile disabilitare l'autenticazione con password nel file di configurazione del server SSH (`/etc/ssh/sshd_config`), impostando `PasswordAuthentication no`.

#### Vantaggi dell'Autenticazione con Chiavi

✅ **Sicurezza maggiore**: Le chiavi sono molto più lunghe e complesse delle password  
✅ **Nessuna trasmissione di credenziali**: La chiave privata non lascia mai il client  
✅ **Protezione da attacchi brute-force**: Impossibile indovinare una chiave di 2048+ bit  
✅ **Automazione**: Permette script e connessioni automatiche senza inserire password  
✅ **Gestione centralizzata**: Facile revocare l'accesso rimuovendo la chiave pubblica dal server  

#### Tipi di Algoritmi per Chiavi SSH

| Algoritmo | Lunghezza | Sicurezza | Velocità | Raccomandato |
|-----------|-----------|-----------|----------|--------------|
| RSA | 2048-4096 bit | Buona | Media | ✅ Sì |
| DSA | 1024 bit | Obsoleto | - | ❌ No |
| ECDSA | 256-521 bit | Buona | Alta | ⚠️ Dipende |
| Ed25519 | 256 bit | Ottima | Molto alta | ✅ Sì (moderno) |

**Raccomandazione**: Utilizzare **Ed25519** per nuove chiavi (più veloce e sicuro), o **RSA 4096** per compatibilità con sistemi più vecchi.
L'algoritmo Ed25519
- Basato su curve ellittiche
- Offre alta sicurezza con chiavi più corte
- Efficiente in termini di prestazioni
- Supportato dalla maggior parte dei client/server SSH moderni
- Consigliato per la maggior parte degli usi
- Non supportato su sistemi molto vecchi (prima del 2015)

---

### Autenticazione solo con Password

SSH supporta anche l'autenticazione tramite password, ma è meno sicura rispetto all'uso delle chiavi. In questo metodo, il client invia la password al server per verificare l'identità dell'utente. 
Con l'autenticazione con password:
- La password viene trasmessa (anche se cifrata)
- È vulnerabile ad attacchi di forza bruta e intercettazioni
- Non è adatta per l'automazione senza intervento umano
- Può essere disabilitata per aumentare la sicurezza, quando si utilizza l'autenticazione con chiavi
- Può essere usata come metodo di fallback se le chiavi non sono disponibili

#### Prima connessione:

Alla prima connessione, SSH chiederà di verificare la fingerprint del server:

```
The authenticity of host '192.168.1.100 (192.168.1.100)' can't be established.
ECDSA key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

- Digitare `yes` per accettare e salvare la chiave nel file `~/.ssh/known_hosts`
- Successivamente, il sistema verificherà automaticamente l'identità del server

fingerprint significa "impronta digitale" ed è un hash univoco della chiave pubblica del server.


#### File known_hosts:

Il file `~/.ssh/known_hosts` memorizza le chiavi pubbliche dei server a cui ti sei connesso in precedenza. Serve a prevenire attacchi di tipo "man-in-the-middle".

#### Comandi utili per gestire known_hosts:
```bash
# Visualizzare le chiavi salvate
cat ~/.ssh/known_hosts

# Rimuovere una chiave specifica
ssh-keygen -R 192.168.1.100

# Rimuovere tutte le chiavi di un host
ssh-keygen -R server.example.com
```

## Prerequisiti

### Software Necessario

#### Windows
- **Git Bash** (consigliato) - installato con Git for Windows
- **PuTTY** + **PuTTYgen** (alternativa)
- **Windows Terminal** + OpenSSH (Windows 10/11)

#### Linux/macOS
- OpenSSH client (pre-installato nella maggior parte delle distribuzioni)

### Verifica Installazione

Apri un terminale e verifica che SSH sia installato:

```bash
ssh -V
```

Output atteso (esempio):
```
OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022
```

---

## Esercitazione Pratica 1 - SSH con Chiave Pubblica-Privata 

### Step 1: Generare la Coppia di Chiavi

Apri un terminale (Git Bash su Windows, Terminal su Linux/macOS).

#### Opzione A: Chiave Ed25519 (Raccomandato)

```bash
ssh-keygen -t ed25519 -C "tuo.nome@esempio.it"
```

#### Opzione B: Chiave RSA (Compatibilità)

```bash
ssh-keygen -t rsa -b 4096 -C "tuo.nome@esempio.it"
```

**Parametri:**
- `-t`: tipo di algoritmo (ed25519 o rsa). ed25519 è un algoritmo moderno e sicuro per chiavi a curva ellittica, raccomandato per la sua velocità e resistenza agli attacchi. Altri tipi comuni includono rsa o ecdsa.
- `-b`: lunghezza della chiave in bit (solo per RSA)
- `-C`: commento (solitamente la tua email), spesso usato per identificare il proprietario (ad esempio, un indirizzo email). Questo commento appare nella chiave pubblica e aiuta a organizzare più chiavi.

#### Processo Interattivo

```
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/user/.ssh/id_ed25519):
```

**Premi INVIO** per accettare il percorso predefinito.

```
Enter passphrase (empty for no passphrase):
```

**Importante**: Inserisci una **passphrase sicura** per proteggere la chiave privata.
- Usa almeno 12 caratteri
- Combina lettere, numeri e simboli
- Questa password NON viene inviata al server, protegge solo la tua chiave locale

La passphrase aggiunge un ulteriore livello di sicurezza, sebbene non sia obbligatoria. In caso di furto del file della chiave privata, la passphrase impedisce l'uso non autorizzato della chiave.

```
Enter same passphrase again:
```

Ripeti la passphrase.

```
Your identification has been saved in /home/user/.ssh/id_ed25519
Your public key has been saved in /home/user/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx tuo.nome@esempio.it
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|     . .         |
|    . + .        |
|   . = o         |
|    = o S        |
|   o + o .       |
|  . * + o        |
| . * = o         |
|  + + .          |
+----[SHA256]-----+
```

✅ **Chiavi generate con successo!**

### Step 2: Verificare le Chiavi Create

```bash
ls -la ~/.ssh/
```

Dovresti vedere:
```
-rw-------  1 user user  411 Dec 17 10:00 id_ed25519      # Chiave PRIVATA
-rw-r--r--  1 user user  103 Dec 17 10:00 id_ed25519.pub  # Chiave PUBBLICA
```

**Nota i permessi:**
- Chiave privata: `-rw-------` (600) - leggibile/scrivibile solo dal proprietario
- Chiave pubblica: `-rw-r--r--` (644) - leggibile da tutti

### Step 3: Visualizzare la Chiave Pubblica

```bash
cat ~/.ssh/id_ed25519.pub
```

Output esempio:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx... tuo.nome@esempio.it
```

Questa è la chiave che dovrai copiare sul server.

### Step 4: Copiare la Chiave Pubblica sul Server

Copiare la chiave pubblica sul server `w4s.filippobilardo.it` nella file `~/.ssh/authorized_keys`.
nella cartella home dell'utente `cognome.nome`.

#### Metodo A: Copia Manuale

1. Visualizza e copia la chiave pubblica:
```bash
cat ~/.ssh/id_ed25519.pub
```

2. Connettiti al server con password:
```bash
ssh -p 2222 cognome.nome@w4s.filippobilardo.it
```

3. Sul server, crea la directory `.ssh` se non esiste:
```bash
mkdir -p ~/.ssh     # -p crea la cartella se non esiste
chmod 700 ~/.ssh    # solo il proprietario può accedere
```

4. Aggiungi la chiave al file `authorized_keys`:
```bash
echo "ssh-ed25519 AAAAC3NzaC1... tuo.nome@esempio.it" >> ~/.ssh/authorized_keys
```

5. Imposta i permessi corretti:
```bash
chmod 600 ~/.ssh/authorized_keys
```

6. Esci dal server:
```bash
exit
```
#### Metodo B (alternativo): Usare il comando `ssh` con `cat` e redirezione
Metodo alternativo: uso di `scp` per copiare il file:
```bash
# Copiare la chiave sul server
scp -P 2222 ~/.ssh/id_ed25519.pub cognome.nome@w4s.filippobilardo.it:~/id_ed25519.pub

# Connettersi al server
ssh -p 2222 cognome.nome@w4s.filippobilardo.it

# Sul server: aggiungere la chiave al file authorized_keys
mkdir -p ~/.ssh   # -p crea la cartella se non esiste
chmod 700 ~/.ssh  # solo il proprietario può accedere
cat ~/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
rm ~/id_ed25519.pub
exit
```

#### Metodo C (alternativo): Usare il comando `ssh` con `cat` e pipe
Metodo alternativo: Copia manuale con cat e pipe:
```bash
# In un solo comando
cat ~/.ssh/id_ed25519.pub | ssh utente@server "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"    
```

### Step 5: Testare la Connessione

Prova a connetterti senza password:

```bash
ssh -p 2222 cognome.nome@w4s.filippobilardo.it
# oppure
ssh -i ~/.ssh/id_ed25519 -p 2222 cognome.nome@w4s.filippobilardo.it
```

Se hai impostato una passphrase, ti verrà chiesta (solo la prima volta per sessione):
```
Enter passphrase for key '/home/user/.ssh/id_ed25519':
```

✅ Se riesci ad accedere senza inserire la password del server, l'autenticazione con chiavi funziona correttamente!


## Esercitazione Pratica 2 - config per semplificare la connessione SSH 

### Configurare il file config
Dal prompt dei comandi di windows (Git Bash, PowerShell) o terminale Linux/macOS:
Crea (o modifica se già esiste) il file `~/.ssh/config`:
```bash
nano ~/.ssh/config
```

Aggiungi questa configurazione:
```
Host w4s
    HostName w4s.filippobilardo.it
    Port 2222
    User cognome.nome
    IdentityFile ~/.ssh/id_ed25519
```

Salva (CTRL+O, INVIO, CTRL+X in nano).

Imposta i permessi corretti:
```bash
chmod 600 ~/.ssh/config
```

Ora puoi connetterti semplicemente con:
```bash
ssh w4s
```

##### Esempio di configurazione base:
```
# Server di sviluppo
Host dev
    HostName 192.168.1.100
    User mario
    Port 22
    IdentityFile ~/.ssh/id_ed25519

# Server di produzione
Host prod
    HostName server.example.com
    User admin
    Port 2222
    IdentityFile ~/.ssh/chiave_produzione

# Server con jump host
Host interno
    HostName 10.0.1.50
    User utente
    ProxyJump bastion

Host bastion
    HostName bastion.example.com
    User gateway
    Port 22
```

##### Utilizzo degli alias:

```bash
# Invece di: ssh mario@192.168.1.100
ssh dev

# Invece di: ssh -p 2222 admin@server.example.com
ssh prod

# Connessione attraverso jump host
ssh interno
```


## Esercitazione Pratica 3 (OPZIONALE) - salvataggio della passphrase con SSH Agent

Per non dover inserire la passphrase ad ogni connessione, Configurare l'SSH Agent, un programma che memorizza le chiavi in memoria crittografata.:

#### Linux/macOS:

```bash
# Avvia l'agent
eval "$(ssh-agent -s)"

# Aggiungi la chiave
ssh-add ~/.ssh/id_ed25519
```

#### Windows (Git Bash):

```bash
# Avvia l'agent automaticamente
eval $(ssh-agent -s)

# Aggiungi la chiave
ssh-add ~/.ssh/id_ed25519
```

#### Windows (PowerShell):

```powershell
# Avvia il servizio
Start-Service ssh-agent

# Aggiungi la chiave
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```


##### Opzioni utili per il config:
```
# Configurazione globale per tutti gli host
Host *
    # Mantieni la connessione attiva
    ServerAliveInterval 60
    ServerAliveCountMax 3
    
    # Riutilizza le connessioni esistenti
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
    
    # Forwarding dell'agent SSH
    ForwardAgent yes
    
    # Compressione dei dati
    Compression yes
    
    # Tentativi di autenticazione
    ConnectionAttempts 3

# Server specifico con tutte le opzioni
Host myserver
    HostName server.example.com
    User myuser
    Port 22
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    LogLevel INFO
    StrictHostKeyChecking ask
    UserKnownHostsFile ~/.ssh/known_hosts
    PasswordAuthentication no
    PubkeyAuthentication yes
```


## Esercitazione Pratica 4 (OPZIONALE) - Configurare il Server SSH

Il file di configurazione del server SSH si trova in `/etc/ssh/sshd_config`.
e consente di personalizzare le impostazioni di sicurezza e accesso.
Solo l'amministratore di sistema (root) può modificare questo file.

#### File di configurazione SSH server (/etc/ssh/sshd_config)

**IMPORTANTE**: Fare sempre un backup prima di modificare:
```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
```

#### Configurazioni di sicurezza consigliate:

```bash
sudo nano /etc/ssh/sshd_config
```

```
# Porta SSH (cambiare per maggiore sicurezza)
Port 22

# Protocollo SSH (solo versione 2)
Protocol 2

# Permettere solo autenticazione con chiave
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no

# Disabilitare il login come root
PermitRootLogin no

# Limite di autenticazioni
MaxAuthTries 3
MaxSessions 10

# Timeout per login
LoginGraceTime 60

# Permettere solo utenti specifici
AllowUsers mario luigi
# Oppure permettere solo gruppi specifici
AllowGroups sshusers

# Disabilitare X11 forwarding se non necessario
X11Forwarding no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Host key files
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Disabilitare file .rhosts
IgnoreRhosts yes

# Verificare i permessi dei file
StrictModes yes

# Keepalive
ClientAliveInterval 300
ClientAliveCountMax 2
```

##### Applicare le modifiche:

```bash
# Verificare la configurazione
sudo sshd -t

# Se tutto è OK, riavviare il servizio
sudo systemctl restart ssh
```

---

## Esercitazione Pratica 5 - Utilizzo di VS Code con SSH

Visual Studio Code offre un'eccellente integrazione con SSH tramite l'estensione **Remote - SSH**, che permette di sviluppare direttamente su server remoti come se fossero in locale.

### Vantaggi di VS Code Remote - SSH

✅ **Sviluppo remoto**: Modifica file direttamente sul server  
✅ **Terminale integrato**: Esegui comandi sul server  
✅ **Debug remoto**: Debug applicazioni sul server  
✅ **Estensioni**: Usa le tue estensioni VS Code sul server  
✅ **Sincronizzazione automatica**: Nessun bisogno di FTP/SCP manuale  
✅ **Performance**: Il codice viene eseguito sul server, solo l'interfaccia è locale  

### Step 1: Installare l'Estensione Remote - SSH

1. Apri **VS Code**
2. Vai su **Extensions** (Ctrl+Shift+X o Cmd+Shift+X)
3. Cerca **"Remote - SSH"**
4. Installa l'estensione pubblicata da **Microsoft**

**Estensioni consigliate:**
- `ms-vscode-remote.remote-ssh` - Remote - SSH (principale)
- `ms-vscode-remote.remote-ssh-edit` - Remote - SSH: Editing Configuration Files
- `ms-vscode.remote-explorer` - Remote Explorer

![Remote SSH Extension](https://code.visualstudio.com/assets/docs/remote/ssh/ssh-extension.png)

### Step 2: Configurare la Connessione SSH

#### Metodo A: Usando il file SSH config (Raccomandato)

1. Apri il Command Palette (Ctrl+Shift+P o Cmd+Shift+P)
2. Digita: `Remote-SSH: Open SSH Configuration File...`
3. Seleziona il file di configurazione (solitamente `~/.ssh/config`)
4. Aggiungi la configurazione del server:

```bash
Host w4s
    HostName w4s.filippobilardo.it
    Port 2222
    User cognome.nome
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes
```

**Spiegazione parametri:**
- `Host`: nome alias per la connessione (puoi usare qualsiasi nome)
- `HostName`: indirizzo IP o hostname del server
- `Port`: porta SSH (default 22)
- `User`: username sul server remoto
- `IdentityFile`: percorso alla chiave privata SSH
- `ForwardAgent`: permette di usare le chiavi SSH locali sul server remoto

**Configurazione avanzata con più server:**
```bash
# Server di produzione
Host prod-server
    HostName w4s.filippobilardo.it
    Port 2222
    User cognome.nome
    IdentityFile ~/.ssh/id_ed25519

# Server di sviluppo
Host dev-server
    HostName dev.example.com
    Port 22
    User developer
    IdentityFile ~/.ssh/id_rsa_dev

# Raspberry Pi locale
Host raspberry
    HostName 192.168.1.50
    Port 22
    User pi
```

#### Metodo B: Connessione diretta

1. Clicca sull'icona **Remote Explorer** nella sidebar (o premi F1)
2. Seleziona **Remote-SSH: Connect to Host...**
3. Digita: `ssh cognome.nome@w4s.filippobilardo.it -p 2222`
4. Premi Invio

---

### Step 3: Connettersi al Server

1. Apri il Command Palette (Ctrl+Shift+P)
2. Digita: `Remote-SSH: Connect to Host...`
3. Seleziona il tuo host dalla lista (es. `w4s`)
4. Si aprirà una nuova finestra VS Code
5. Se richiesto, inserisci la passphrase della chiave SSH
6. Attendi il completamento della connessione

**Indicatori di connessione:**
- Angolo in basso a sinistra: vedrai `SSH: w4s` (colore verde)
- Barra del titolo: mostra `[SSH: w4s]`

### Step 4: Lavorare sul Server Remoto

#### Aprire una cartella remota

1. File → Open Folder (Ctrl+K Ctrl+O)
2. Naviga alla cartella desiderata sul server
3. Clicca **OK**

Ora puoi:
- ✅ Modificare file direttamente sul server
- ✅ Creare/eliminare file e cartelle
- ✅ Usare il terminale integrato (Terminal → New Terminal)
- ✅ Installare estensioni sul server remoto
- ✅ Eseguire debug di applicazioni

#### Aprire un terminale remoto

1. Terminal → New Terminal (Ctrl+` o Ctrl+J)
2. Il terminale è già connesso al server!
3. Esegui comandi come se fossi in SSH:

```bash
# Verifica dove sei
pwd

# Lista file
ls -la

# Installa pacchetti
npm install
pip install -r requirements.txt

# Avvia applicazioni
node server.js
python app.py
```

#### Trasferire file

**Upload file locale → server:**
- Drag & drop file dall'Explorer nel pannello VS Code
- Oppure: Tasto destro su cartella → Upload files

**Download file server → locale:**
- Tasto destro su file → Download
- I file vengono salvati nella cartella locale che scegli

### Step 5: Configurazioni Avanzate

#### Installare estensioni sul server remoto

Alcune estensioni devono essere installate anche sul server:

1. Vai su Extensions (Ctrl+Shift+X)
2. Vedrai due sezioni:
   - **Local - Installed**: estensioni locali
   - **SSH: w4s - Installed**: estensioni sul server
3. Installa le estensioni necessarie nella sezione remota

**Estensioni consigliate per il server:**
- Python
- Node.js Extension Pack
- Docker
- GitLens

#### Port Forwarding

Per accedere a servizi web in esecuzione sul server:

1. Terminal → New Terminal
2. Avvia l'applicazione (es. `node server.js` sulla porta 3000)
3. VS Code rileva automaticamente la porta e chiede se fare forwarding
4. Clicca **Forward Port**
5. Apri `localhost:3000` nel browser locale

**Port Forwarding manuale:**
1. Command Palette → `Forward a Port`
2. Inserisci il numero di porta (es. `3000`)
3. La porta è ora accessibile localmente

**Visualizzare porte forward:**
- Pannello PORTS (accanto al terminale)
- Mostra tutte le porte forward attive

#### SSH Agent Forwarding

Per usare le tue chiavi SSH locali sul server remoto (es. per git push):

Nel file `~/.ssh/config`:
```bash
Host w4s
    HostName w4s.filippobilardo.it
    Port 2222
    User cognome.nome
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes    # ← Importante!
```

Ora puoi fare git push dal server usando le tue chiavi locali!

### Troubleshooting VS Code SSH

#### Problema: "Could not establish connection"

**Soluzione 1**: Verifica connessione SSH manuale
```bash
ssh cognome.nome@w4s.filippobilardo.it -p 2222
```

**Soluzione 2**: Controlla i log
1. Command Palette → `Remote-SSH: Show Log`
2. Cerca errori nel log

**Soluzione 3**: Rimuovi server dai noti
```bash
ssh-keygen -R w4s.filippobilardo.it
```

#### Problema: "Permission denied (publickey)"

**Causa**: Chiave SSH non configurata correttamente

**Soluzione**:
1. Verifica che la chiave pubblica sia sul server:
   ```bash
   ssh cognome.nome@w4s.filippobilardo.it -p 2222 "cat ~/.ssh/authorized_keys"
   ```
2. Verifica il percorso della chiave in `~/.ssh/config`:
   ```bash
   IdentityFile ~/.ssh/id_ed25519
   ```
3. Verifica permessi chiave:
   ```bash
   chmod 600 ~/.ssh/id_ed25519
   ```

#### Problema: "VS Code Server failed to start"

**Soluzione**: Rimuovi la cache del server
```bash
ssh cognome.nome@w4s.filippobilardo.it -p 2222 "rm -rf ~/.vscode-server"
```
Poi riconnetti da VS Code.

#### Problema: Connessione lenta

**Causa**: Estensioni pesanti installate sul server

**Soluzione**:
1. Disabilita estensioni non necessarie sul server
2. Usa il parametro `remote.SSH.useLocalServer: false` nelle impostazioni

#### Problema: "Bad owner or permissions on config file"

**Causa**: Permessi errati sul file `~/.ssh/config`

**Soluzione**:
```bash
chmod 600 ~/.ssh/config
```

### Best Practices VS Code + SSH

✅ **Usa il file config**: Più comodo di ricordare comandi lunghi  
✅ **Forward Agent**: Abilita `ForwardAgent yes` per usare chiavi locali  
✅ **Estensioni minime**: Installa solo le estensioni necessarie sul server  
✅ **Salva automaticamente**: Abilita Auto Save (File → Auto Save)  
✅ **Multiple workspace**: Usa workspace per progetti diversi  
✅ **Git integrato**: Usa il source control integrato di VS Code  

### Shortcuts Utili

| Comando | Shortcut | Descrizione |
|---------|----------|-------------|
| Command Palette | Ctrl+Shift+P | Apre il menu comandi |
| Open Folder | Ctrl+K Ctrl+O | Apre cartella remota |
| New Terminal | Ctrl+` | Nuovo terminale SSH |
| Toggle Sidebar | Ctrl+B | Mostra/nascondi sidebar |
| Quick Open | Ctrl+P | Cerca file velocemente |
| Go to Line | Ctrl+G | Vai a linea specifica |
| Search | Ctrl+Shift+F | Cerca nel progetto |
| Save All | Ctrl+K S | Salva tutti i file |

### Workflow Completo: Esempio Pratico

**Scenario**: Sviluppare un'applicazione Node.js sul server remoto

#### 1. Connetti al server
```
Command Palette → Remote-SSH: Connect to Host → w4s
```

#### 2. Apri cartella progetto
```
File → Open Folder → /home/cognome.nome/progetti/mio-app
```

#### 3. Installa estensioni sul server
- Installa "JavaScript and TypeScript" extension sul server

#### 4. Apri terminale integrato
```
Terminal → New Terminal
```

#### 5. Inizializza progetto
```bash
npm init -y
npm install express
```

#### 6. Crea file server.js
```javascript
const express = require('express');
const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
    res.send('Hello from remote server!');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

#### 7. Avvia applicazione
```bash
node server.js
```

#### 8. VS Code rileva porta 3000
- Clicca **Forward Port** quando richiesto

#### 9. Testa nel browser locale
```
http://localhost:3000
```

#### 10. Commit e push
```bash
git add .
git commit -m "Initial commit"
git push origin main
```

Tutto fatto direttamente da VS Code! 🚀

---

## Approfondimenti sulla Sicurezza SSH

### Opzioni importanti:

```bash
# Specificare il nome del file
ssh-keygen -t ed25519 -f ~/.ssh/chiave_server_web

# Cambiare la passphrase di una chiave esistente
ssh-keygen -p -f ~/.ssh/id_ed25519

# Generare senza passphrase (sconsigliato per chiavi importanti)
ssh-keygen -t ed25519 -N "" -f ~/.ssh/chiave_automatica
```

### Struttura dei file:

```bash
~/.ssh/
├── id_ed25519          # Chiave privata (NEVER share!)
├── id_ed25519.pub      # Chiave pubblica (può essere condivisa)
├── known_hosts         # Chiavi dei server fidati
├── authorized_keys     # Chiavi pubbliche autorizzate (sul server)
└── config              # File di configurazione (opzionale)
```

### Permessi corretti:

```bash
# Impostare i permessi corretti
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 644 ~/.ssh/authorized_keys
chmod 644 ~/.ssh/known_hosts
chmod 600 ~/.ssh/config
```

---

## Verifica e Troubleshooting

### Verificare la Connessione in Modalità Verbose

Per diagnosticare problemi:

```bash
ssh -v -p 2222 cognome.nome@w4s.filippobilardo.it
```

Per maggiori dettagli:
```bash
ssh -vvv -p 2222 cognome.nome@w4s.filippobilardo.it
```

### Problemi Comuni

#### 1. "Permission denied (publickey)"

**Causa**: La chiave pubblica non è stata copiata correttamente o i permessi sono errati.

**Soluzione:**
```bash
# Verifica i permessi sul server
ls -la ~/.ssh/
# authorized_keys deve essere 600
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

#### 2. "WARNING: UNPROTECTED PRIVATE KEY FILE!"

**Causa**: La chiave privata ha permessi troppo aperti.

**Soluzione:**
```bash
chmod 600 ~/.ssh/id_ed25519
```

#### 3. "Connection refused"

**Causa**: Porta errata o server non raggiungibile.

**Soluzione:**
```bash
# Verifica la connessione
ping w4s.filippobilardo.it

# Verifica la porta
nmap -p 2222 w4s.filippobilardo.it
```

#### 4. La passphrase viene richiesta ad ogni connessione

**Causa**: SSH agent non è configurato.

**Soluzione:** Segui lo Step 7 per configurare l'SSH agent.

### Comandi Utili per Diagnostica

```bash
# Visualizza le chiavi caricate nell'agent
ssh-add -l

# Rimuovi tutte le chiavi dall'agent
ssh-add -D

# Testa la connessione con output dettagliato
ssh -vT -p 2222 cognome.nome@w4s.filippobilardo.it
```

---


## Esercizi

### Esercizio 1: Generazione Base (★☆☆)

1. Genera una nuova coppia di chiavi SSH con algoritmo Ed25519
2. Visualizza il contenuto della chiave pubblica
3. Verifica i permessi dei file generati

**Domande:**
- Qual è la differenza tra la chiave pubblica e quella privata?
- Perché la chiave privata ha permessi 600?

### Esercizio 2: Connessione al Server (★★☆)

1. Copia la tua chiave pubblica sul server usando `ssh-copy-id`
2. Connettiti al server senza utilizzare la password
3. Verifica che il tuo file `~/.ssh/authorized_keys` sul server contenga la chiave corretta

**Domande:**
- Cosa succede se qualcuno ottiene la tua chiave pubblica?
- Cosa succede se qualcuno ottiene la tua chiave privata?

### Esercizio 3: Configurazione Avanzata (★★★)

1. Crea un file di configurazione SSH (`~/.ssh/config`)
2. Aggiungi un alias "w4s" per il server
3. Configura l'SSH agent per memorizzare la passphrase
4. Testa la connessione usando solo `ssh w4s`

**Domande:**
- Quali vantaggi offre il file config?
- Come funziona l'SSH agent?

### Esercizio 4: Sicurezza (★★★)

1. Genera una seconda coppia di chiavi con algoritmo RSA 4096
2. Rinominala in `id_rsa_backup`
3. Configura il sistema per usare chiavi diverse per server diversi
4. Documenta le differenze tra Ed25519 e RSA

**Domande:**
- Quando è preferibile usare RSA invece di Ed25519?
- Come si può revocare l'accesso di una specifica chiave?

### Esercizio 5: Troubleshooting (★★☆)

Simula questi problemi e risolvili:

1. Modifica i permessi della chiave privata a 644 e prova a connetterti
2. Rimuovi la chiave pubblica dal server e prova a connetterti
3. Usa il comando `ssh -v` per diagnosticare un problema di connessione

**Domande:**
- Cosa significa ogni livello di verbosità (-v, -vv, -vvv)?
- Come si interpreta l'output di debug?

---

## Riferimenti e Approfondimenti

### Documentazione Ufficiale
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [RFC 4253 - SSH Protocol](https://tools.ietf.org/html/rfc4253)

### Best Practices di Sicurezza
- Usa sempre una passphrase per proteggere le chiavi private
- Non condividere mai la chiave privata
- Genera chiavi separate per dispositivi diversi
- Ruota le chiavi periodicamente (ogni 1-2 anni)
- Usa Ed25519 o RSA ≥ 2048 bit
- Mantieni aggiornato il client SSH

### Comandi di Riferimento Rapido

```bash
# Generare chiavi
ssh-keygen -t ed25519 -C "commento"
ssh-keygen -t rsa -b 4096 -C "commento"

# Copiare chiave sul server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host -p PORT

# Connessione
ssh user@host -p PORT

# SSH Agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add -l  # Lista chiavi

# Diagnostica
ssh -v user@host
ssh -vvv user@host  # Molto verbose

# Permessi corretti
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/authorized_keys  # sul server
```

---

## Conclusioni

Hai imparato a:
✅ Comprendere la crittografia asimmetrica  
✅ Generare coppie di chiavi SSH  
✅ Configurare l'autenticazione senza password  
✅ Risolvere problemi comuni  
✅ Implementare best practices di sicurezza  

L'autenticazione con chiavi SSH è uno strumento fondamentale per ogni sistemista e sviluppatore. Pratica regolarmente e mantieni sempre le tue chiavi private al sicuro!

---

**Autore**: Prof. Filippo Bilardo  
**Corso**: Sistemi e Reti 3  
**Data**: Dicembre 2025