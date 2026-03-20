# Nginx Proxy Manager - Guida Studente

## 📌 Cosa Contiene Questo Progetto

Container Docker con **Nginx Proxy Manager**: interfaccia web per gestire reverse proxy senza dover editare file di configurazione manualmente.

**Vantaggi:**
- ✅ GUI web user-friendly (no CLI)
- ✅ Certificati SSL automatici (Let's Encrypt, 1 click)
- ✅ Load balancing visuale
- ✅ Access Lists (protezione con password)
- ✅ Log integrati nell'interfaccia

---

## 🚀 Quick Start (3 minuti)

### 1. Copia file .env

```bash
cp .env.example .env
# Modifica email per Let's Encrypt
nano .env
```

### 2. Avvia il container

```bash
docker-compose up -d
```

### 3. Verifica container attivo

```bash
docker-compose ps
# Stato: Up

docker-compose logs -f
# Aspetta: "Nginx Proxy Manager is running"
```

### 4. Accedi all'interfaccia

**URL:** http://localhost:81

**Credenziali default:**
- Email: `admin@example.com`
- Password: `changeme`

⚠️ **Al primo accesso ti chiederà di cambiare email e password!**

---

## 📂 Struttura Directory

```
nginx-proxy-manager-project/
│
├── docker-compose.yml         ← Config stack Docker
├── .env.example               ← Template variabili ambiente
├── .env                       ← Tue variabili (CREA!)
├── README.md                  ← Questa guida
├── npm-manage.sh              ← Script helper (opzionale)
│
└── data/                      ← Volume persistente (creato automaticamente)
    ├── nginx/                 ← Config Nginx generate da NPM
    │   ├── proxy_host/        ← Config per ogni proxy host
    │   ├── redirection_host/
    │   ├── stream/
    │   └── dead_host/
    │
    ├── letsencrypt/           ← Certificati SSL
    │   ├── live/
    │   ├── archive/
    │   └── renewal/
    │
    ├── logs/                  ← Log accessi/errori
    │   ├── proxy-host-1_access.log
    │   ├── proxy-host-1_error.log
    │   └── fallback_access.log
    │
    └── database.sqlite        ← Database SQLite
```

---

## 🎯 Come Creare un Reverse Proxy

### Scenario: Proxy per App Backend su porta 8080

Supponiamo di avere un'applicazione che gira su `http://192.168.1.100:8080`

#### Passo 1: Accedi alla Dashboard

http://localhost:81 → Login

#### Passo 2: Aggiungi Proxy Host

1. Menu laterale: **Hosts** → **Proxy Hosts**
2. Click **Add Proxy Host**

#### Passo 3: Compila Tab "Details"

```
Domain Names:       myapp.example.com
                    (oppure myapp.localhost per test locale)

Scheme:             http ▼
Forward Hostname:   192.168.1.100
Forward Port:       8080

☑ Cache Assets
☑ Block Common Exploits
☑ Websockets Support (se necessario per WebSocket/Socket.io)
```

#### Passo 4: (Opzionale) SSL Certificate

**Tab "SSL":**

```
SSL Certificate:    Request a new SSL Certificate ▼

Email:              tuo@email.com

☑ Force SSL (redirect HTTP → HTTPS)
☑ HTTP/2 Support
☑ HSTS Enabled (Strict-Transport-Security header)
☑ I Agree to the Let's Encrypt Terms of Service
```

**Requisiti per Let's Encrypt:**
- Dominio reale (non .localhost)
- DNS punta al server pubblico
- Porte 80/443 accessibili da Internet

#### Passo 5: Save

Click **Save** → Proxy attivo! 🎉

---

## 🧪 Test del Reverse Proxy

### Test con dominio locale (.localhost)

**1. Aggiungi entry a /etc/hosts:**

```bash
echo "127.0.0.1 myapp.localhost" | sudo tee -a /etc/hosts
```

**2. Testa con browser:**

```
http://myapp.localhost
```

**3. Oppure con curl:**

```bash
curl http://myapp.localhost
```

### Test con Header Host (senza /etc/hosts)

```bash
curl -H "Host: myapp.localhost" http://localhost
```

---

## 🛡️ Protezione con Access List (Autenticazione)

### Crea Access List

1. Menu: **Access Lists** → **Add Access List**

```
Name:               Rete Scolastica
Satisfy Any:        ☑ (almeno 1 condizione soddisfatta)
Pass Authentication: ☐ (non abilitare se vuoi autenticazione obbligatoria)
```

2. **Tab "Authorization"** → **Add Username**

```
Username:   studente1
Password:   Password123!
```

3. Aggiungi altri utenti se necessario
4. **Save**

### Applica Access List a Proxy Host

1. Vai a **Hosts** → **Proxy Hosts**
2. Modifica il proxy host desiderato
3. **Tab "Details"** → **Access List:** seleziona `Rete Scolastica`
4. **Save**

### Test Autenticazione

```bash
# Senza credenziali → 401 Unauthorized
curl http://myapp.localhost

# Con credenziali → 200 OK
curl -u studente1:Password123! http://myapp.localhost
```

---

## 📊 Visualizzazione Log

### Log da Interfaccia Web

1. **Hosts** → **Proxy Hosts**
2. Click **...** (tre puntini) sul proxy host
3. **View Logs**

Visualizza in tempo reale access.log e error.log!

### Log da Terminale

```bash
# Access log
tail -f data/logs/proxy-host-1_access.log

# Error log
tail -f data/logs/proxy-host-1_error.log

# Conta richieste GET
grep "GET" data/logs/proxy-host-1_access.log | wc -l

# Top 10 IP client
awk '{print $1}' data/logs/proxy-host-1_access.log | sort | uniq -c | sort -rn | head -10
```

---

## 🔧 Comandi Utili

### Gestione Container

```bash
# Avvio
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# Log real-time
docker-compose logs -f nginx-proxy-manager

# Stato container
docker-compose ps

# Entra nel container (debug)
docker exec -it nginx-proxy-manager /bin/bash
```

### Backup e Restore

**Backup via GUI:**
1. **Settings** → **Backups** → **Create Backup**
2. Download file `.json`

**Backup completo (manuale):**

```bash
# Stop container
docker-compose down

# Backup dati
tar -czf npm-backup-$(date +%Y%m%d).tar.gz data/

# Riavvia
docker-compose up -d
```

**Restore:**

```bash
# Estrai backup
tar -xzf npm-backup-20260320.tar.gz

# Riavvia container
docker-compose up -d
```

**Restore da GUI:**
1. **Settings** → **Backups** → **Upload** → Seleziona `.json`

---

## 🌐 Certificati SSL Let's Encrypt

### Requisiti

- ✅ Dominio reale (es. `myapp.example.com`)
- ✅ DNS punta al tuo server pubblico
- ✅ Porte 80 e 443 accessibili da Internet
- ✅ Email valida

### Procedura

1. Crea/Modifica Proxy Host
2. **Tab "SSL"**
3. ☑ **Request a new SSL Certificate**
4. Email: `tuo@email.com`
5. ☑ **Force SSL** (redirect HTTP → HTTPS)
6. ☑ **I Agree to the Let's Encrypt Terms**
7. **Save**

Nginx Proxy Manager:
- Richiede certificato a Let's Encrypt automaticamente
- Certificato valido 90 giorni
- **Rinnovo automatico** prima della scadenza

### Certificati Self-Signed (Test Locale)

Per test senza dominio reale:

1. **SSL Certificates** → **Add SSL Certificate** → **Custom**

```
Name:               Localhost Test
Certificate Key:    [incolla .key]
Certificate:        [incolla .crt]
```

2. Genera certificato:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout localhost.key \
  -out localhost.crt \
  -subj "/CN=*.localhost/O=Test/C=IT"
```

3. Copia contenuto e incolla in NPM
4. Applica a proxy host

---

## 🔍 Troubleshooting

### ❌ Problema: Container non si avvia

**Causa:** Porte 80/443/81 già in uso

```bash
# Verifica cosa usa le porte
sudo lsof -i :80
sudo lsof -i :443
sudo lsof -i :81

# Ferma servizi conflittuali
sudo systemctl stop apache2
sudo systemctl stop nginx
```

**Alternativa:** Cambia porte in `docker-compose.yml`:

```yaml
ports:
  - '8080:80'   # HTTP
  - '8443:443'  # HTTPS
  - '8181:81'   # Admin
```

### ❌ Problema: 502 Bad Gateway

**Causa:** Backend non raggiungibile

**Debug:**

```bash
# Verifica backend attivo
curl http://192.168.1.100:8080

# Da container NPM
docker exec nginx-proxy-manager curl http://192.168.1.100:8080

# Controlla log errori
docker-compose logs nginx-proxy-manager | grep -i error
```

**Soluzioni:**
- Verifica IP backend corretto
- Verifica porta backend corretta
- Verifica firewall non blocca connessione

### ❌ Problema: Let's Encrypt fallisce

**Causa:** DNS non configurato o porte non aperte

**Verifica:**

```bash
# Testa DNS
nslookup myapp.example.com

# Testa raggiungibilità esterna (da altro PC)
curl http://myapp.example.com
```

**Requisiti:**
- DNS A record punta al tuo server pubblico
- Router forwarding porta 80 e 443 → server NPM
- Firewall permette porte 80/443

### ❌ Problema: Access List non funziona

**Causa:** Browser ha salvato credenziali vecchie

**Soluzione:**
- Apri finestra incognito
- Oppure clear cache/cookies
- Oppure `curl -u user:pass` per test

---

## 📚 Risorse Utili

- [Nginx Proxy Manager Docs](https://nginxproxymanager.com/guide/)
- [GitHub Repository](https://github.com/NginxProxyManager/nginx-proxy-manager)
- [Docker Hub](https://hub.docker.com/r/jc21/nginx-proxy-manager)
- [Forum Discussioni](https://github.com/NginxProxyManager/nginx-proxy-manager/discussions)

---

## ✅ Checklist Progetto

Prima di consegnare il progetto, verifica:

- [ ] Container NPM funzionante (docker-compose ps → Up)
- [ ] Login funzionante (password cambiata)
- [ ] Almeno 3 proxy host configurati
- [ ] 1 proxy con SSL (Let's Encrypt o self-signed)
- [ ] 1 proxy con Access List attiva
- [ ] Screenshot dashboard e proxy host
- [ ] Export backup configurazione (Settings → Backup)
- [ ] Analisi log (top 10 IP, richieste totali)
- [ ] Relazione tecnica (2-3 pagine PDF)

---

## 🎓 Domande di Verifica

1. **Quali sono i vantaggi di NPM rispetto alla configurazione manuale di Nginx?**

2. **Cosa contiene la directory `data/` e perché è importante?**

3. **Spiega il processo per ottenere un certificato SSL con Let's Encrypt tramite NPM.**

4. **Come funziona una Access List? In quale scenario la useresti?**

5. **Cosa succede se elimini la cartella `data/`?**

---

**Creato per:** ES04 — Reverse Proxy | Sistemi e Reti 3  
**Versione:** 1.0 | Marzo 2026
