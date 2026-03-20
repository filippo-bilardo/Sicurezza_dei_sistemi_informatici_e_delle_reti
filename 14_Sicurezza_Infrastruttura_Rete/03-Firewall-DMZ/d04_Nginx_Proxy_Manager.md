# Nginx Proxy Manager: Gestione Reverse Proxy con Interfaccia Web

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES04 — Reverse Proxy**

---

## Introduzione

**Nginx Proxy Manager** (NPM) è un'interfaccia web per gestire reverse proxy Nginx senza dover modificare manualmente i file di configurazione. Ideale per:

- **Gestione visuale** di host proxy
- **Certificati SSL automatici** con Let's Encrypt (un click)
- **Access Lists** per protezione con username/password
- **Logs in tempo reale** nell'interfaccia
- **No Linux CLI necessaria** (perfetto per studenti)

```
Senza NPM:
[Admin] → SSH → nano nginx.conf → nginx -t → nginx -s reload
        ↑ Complesso, error-prone

Con NPM:
[Admin] → Web GUI → Add Proxy Host → Save
        ↑ Click & Save, GUI friendly
```

---

## Prerequisiti

- Docker e Docker Compose installati
- Porta 80, 81, 443 disponibili
- (Opzionale) Dominio per certificati SSL reali

---

## Architettura Progetto

```
nginx-proxy-manager/
│
├── README.md                   ← Guida per studenti
├── docker-compose.yml          ← Configurazione stack
├── .env                        ← Variabili ambiente (opzionale)
│
├── data/                       ← Volume persistente Docker
│   ├── nginx/                  ← Config Nginx generate da NPM
│   ├── letsencrypt/            ← Certificati SSL
│   └── logs/                   ← Log accessi
│
└── backend-apps/               ← App di esempio
    ├── app1/
    │   └── docker-compose.yml
    ├── app2/
    │   └── docker-compose.yml
    └── app3/
        └── docker-compose.yml
```

---

## STEP 1 — Preparazione Directory

```bash
# Crea struttura progetto
mkdir -p ~/nginx-proxy-manager/{data,backend-apps}
cd ~/nginx-proxy-manager

# Crea cartelle volume
mkdir -p data/{nginx,letsencrypt,logs}

# Verifica struttura
tree -L 2
```

---

## STEP 2 — File docker-compose.yml

Crea il file principale:

```bash
nano docker-compose.yml
```

Contenuto:

```yaml
version: '3.8'

services:
  # Nginx Proxy Manager
  nginx-proxy-manager:
    image: 'jc21/nginx-proxy-manager:latest'
    container_name: nginx-proxy-manager
    restart: unless-stopped
    ports:
      # HTTP
      - '80:80'
      # HTTPS
      - '443:443'
      # Admin Web Interface
      - '81:81'
    environment:
      # Database connection (usa SQLite interno)
      DB_SQLITE_FILE: "/data/database.sqlite"
      
      # Opzionale: MySQL esterno per production
      # DB_MYSQL_HOST: "db"
      # DB_MYSQL_PORT: 3306
      # DB_MYSQL_USER: "npm"
      # DB_MYSQL_PASSWORD: "npm_password"
      # DB_MYSQL_NAME: "npm"
      
      # Timezone
      TZ: "Europe/Rome"
    
    volumes:
      # Dati persistenti
      - ./data/nginx:/data
      - ./data/letsencrypt:/etc/letsencrypt
      
      # Log accessibili dall'host
      - ./data/logs:/data/logs
    
    networks:
      - proxy-network
    
    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:81"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # MySQL (opzionale, per production)
  # db:
  #   image: mariadb:latest
  #   container_name: npm-db
  #   restart: unless-stopped
  #   environment:
  #     MYSQL_ROOT_PASSWORD: "root_password"
  #     MYSQL_DATABASE: "npm"
  #     MYSQL_USER: "npm"
  #     MYSQL_PASSWORD: "npm_password"
  #   volumes:
  #     - ./data/mysql:/var/lib/mysql
  #   networks:
  #     - proxy-network

networks:
  proxy-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

---

## STEP 3 — File .env (Opzionale)

Per gestire variabili sensibili:

```bash
nano .env
```

Contenuto:

```bash
# Nginx Proxy Manager Configuration
NPM_VERSION=latest
HTTP_PORT=80
HTTPS_PORT=443
ADMIN_PORT=81

# Database (se usi MySQL esterno)
# DB_ROOT_PASSWORD=SecureRootPass123!
# DB_PASSWORD=NpmDbPass456!

# Timezone
TZ=Europe/Rome

# Email per Let's Encrypt
LETSENCRYPT_EMAIL=admin@example.com
```

Aggiorna docker-compose.yml:

```yaml
services:
  nginx-proxy-manager:
    image: 'jc21/nginx-proxy-manager:${NPM_VERSION}'
    ports:
      - '${HTTP_PORT}:80'
      - '${HTTPS_PORT}:443'
      - '${ADMIN_PORT}:81'
    environment:
      TZ: "${TZ}"
```

---

## STEP 4 — README.md per Studenti

```bash
nano README.md
```

Contenuto:

```markdown
# Nginx Proxy Manager - Guida Studente

## 📌 Cosa fa questo container?

Nginx Proxy Manager ti permette di creare reverse proxy tramite interfaccia web,
senza dover modificare manualmente i file di configurazione Nginx.

## 🚀 Avvio Rapido

### 1. Avvia il container

\`\`\`bash
docker-compose up -d
\`\`\`

### 2. Verifica che sia attivo

\`\`\`bash
docker-compose ps
# Stato deve essere "Up"

docker-compose logs -f nginx-proxy-manager
# Aspetta: "Database migrations completed successfully"
\`\`\`

### 3. Accedi all'interfaccia web

Apri browser: **http://localhost:81**

**Credenziali default:**
- Email: `admin@example.com`
- Password: `changeme`

⚠️ **Cambia subito la password al primo accesso!**

---

## 📖 Come Creare un Reverse Proxy

### Esempio: Proxy per Applicazione su porta 8080

1. **Dashboard** → **Hosts** → **Proxy Hosts** → **Add Proxy Host**

2. **Tab "Details":**
   - Domain Names: `app1.localhost` (o tuo dominio)
   - Scheme: `http`
   - Forward Hostname / IP: `172.30.0.11` (IP container backend)
   - Forward Port: `8080`
   - ☑ Cache Assets
   - ☑ Block Common Exploits
   - ☑ Websockets Support (se necessario)

3. **Tab "SSL"** (opzionale):
   - ☑ Request a new SSL Certificate
   - Email: tuo@email.com
   - ☑ Force SSL
   - ☑ HTTP/2 Support

4. **Save** → Proxy attivo!

---

## 🧪 Test del Proxy

### Opzione 1: File /etc/hosts (locale)

\`\`\`bash
# Aggiungi entry
echo "127.0.0.1 app1.localhost" | sudo tee -a /etc/hosts

# Testa
curl http://app1.localhost
\`\`\`

### Opzione 2: Header Host (per test)

\`\`\`bash
curl -H "Host: app1.localhost" http://localhost
\`\`\`

---

## 📂 Struttura Volumi

\`\`\`
data/
├── nginx/              ← Configurazioni Nginx generate automaticamente
│   ├── proxy_host/     ← Config per ogni proxy host
│   ├── redirection_host/
│   └── stream/
│
├── letsencrypt/        ← Certificati SSL
│   ├── live/
│   └── archive/
│
└── logs/               ← Log accessi
    ├── proxy-host-1_access.log
    ├── proxy-host-1_error.log
    └── fallback_access.log
\`\`\`

**Accesso log:**
\`\`\`bash
tail -f data/logs/proxy-host-1_access.log
\`\`\`

---

## 🔧 Comandi Utili

### Gestione Container

\`\`\`bash
# Avvio
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# Log real-time
docker-compose logs -f

# Entra nel container (debug)
docker exec -it nginx-proxy-manager /bin/bash
\`\`\`

### Backup Dati

\`\`\`bash
# Backup completo
tar -czf npm-backup-$(date +%Y%m%d).tar.gz data/

# Restore
tar -xzf npm-backup-20260320.tar.gz
\`\`\`

### Reset Completo

⚠️ **ATTENZIONE: Cancella tutti i dati!**

\`\`\`bash
docker-compose down -v
rm -rf data/nginx/* data/letsencrypt/*
docker-compose up -d
# Login con credenziali default
\`\`\`

---

## 🛡️ Sicurezza

### Cambio Password Admin

1. Login → **Users** → Click su **admin@example.com**
2. **Edit** → Cambia email e password
3. **Save**

### Access Lists (Protezione con Password)

Per proteggere un proxy host:

1. **Access Lists** → **Add Access List**
2. Nome: `Rete Scolastica`
3. **Authorization** → **Add User**
   - Username: `studente`
   - Password: `password123`
4. **Save**
5. Vai al **Proxy Host** → Tab **Details**
6. Access List: seleziona `Rete Scolastica`
7. **Save**

Ora il sito richiede username/password!

---

## 🌐 Certificati SSL con Let's Encrypt

### Requisiti

- Dominio reale (non .localhost)
- DNS punta al tuo server pubblico
- Porte 80/443 accessibili da Internet

### Procedura

1. **Proxy Host** → Tab **SSL**
2. ☑ **Request a new SSL Certificate**
3. Email: tua@email.com
4. ☑ **I Agree to the Let's Encrypt Terms of Service**
5. **Save**

Certificato valido 90 giorni, rinnovo automatico!

---

## 🔍 Troubleshooting

### Problema: 502 Bad Gateway

**Causa:** Backend non raggiungibile

\`\`\`bash
# Verifica backend attivo
docker ps

# Testa connessione interna
docker exec nginx-proxy-manager curl http://172.30.0.11:8080
\`\`\`

### Problema: Porta 80/443 già in uso

\`\`\`bash
# Verifica cosa usa le porte
sudo lsof -i :80
sudo lsof -i :443

# Ferma servizio conflittante
sudo systemctl stop apache2
# oppure
sudo systemctl stop nginx
\`\`\`

### Problema: Cannot connect to Docker daemon

\`\`\`bash
# Verifica Docker attivo
sudo systemctl status docker

# Avvia Docker
sudo systemctl start docker

# Aggiungi user a gruppo docker (no sudo)
sudo usermod -aG docker $USER
# Logout e login
\`\`\`

---

## 📚 Risorse

- [Documentazione ufficiale](https://nginxproxymanager.com/guide/)
- [GitHub Repository](https://github.com/NginxProxyManager/nginx-proxy-manager)
- [Forum Community](https://github.com/NginxProxyManager/nginx-proxy-manager/discussions)

---

## ✅ Checklist Consegna Progetto

- [ ] Container NPM funzionante
- [ ] Almeno 3 proxy host configurati
- [ ] 1 proxy con SSL (Let's Encrypt o self-signed)
- [ ] 1 proxy con Access List (autenticazione)
- [ ] Screenshot dashboard NPM
- [ ] Export configurazione (Settings → Backup)
- [ ] Relazione tecnica (2-3 pagine)
\`\`\`

---

## STEP 5 — Applicazioni Backend di Esempio

Crea 3 applicazioni backend semplici per testare NPM:

### App 1: Web Server Nginx Statico

```bash
mkdir -p backend-apps/app1
nano backend-apps/app1/docker-compose.yml
```

```yaml
version: '3.8'
services:
  app1:
    image: nginx:alpine
    container_name: backend-app1
    ports:
      - "8081:80"
    volumes:
      - ./html:/usr/share/nginx/html
    networks:
      nginx-proxy-manager_proxy-network:
        ipv4_address: 172.30.0.11

networks:
  nginx-proxy-manager_proxy-network:
    external: true
```

```bash
mkdir backend-apps/app1/html
echo "<h1>Backend App 1</h1><p>Server statico Nginx</p>" > backend-apps/app1/html/index.html
```

### App 2: Apache Web Server

```bash
mkdir -p backend-apps/app2
nano backend-apps/app2/docker-compose.yml
```

```yaml
version: '3.8'
services:
  app2:
    image: httpd:alpine
    container_name: backend-app2
    ports:
      - "8082:80"
    volumes:
      - ./html:/usr/local/apache2/htdocs/
    networks:
      nginx-proxy-manager_proxy-network:
        ipv4_address: 172.30.0.12

networks:
  nginx-proxy-manager_proxy-network:
    external: true
```

```bash
mkdir backend-apps/app2/html
echo "<h1>Backend App 2</h1><p>Server Apache</p>" > backend-apps/app2/html/index.html
```

### App 3: Node.js Express

```bash
mkdir -p backend-apps/app3
nano backend-apps/app3/docker-compose.yml
```

```yaml
version: '3.8'
services:
  app3:
    image: node:18-alpine
    container_name: backend-app3
    working_dir: /app
    command: node server.js
    ports:
      - "8083:3000"
    volumes:
      - ./:/app
    networks:
      nginx-proxy-manager_proxy-network:
        ipv4_address: 172.30.0.13

networks:
  nginx-proxy-manager_proxy-network:
    external: true
```

```bash
# Crea app Node.js semplice
cat > backend-apps/app3/server.js << 'EOF'
const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/html'});
  res.end(`
    <h1>Backend App 3</h1>
    <p>Node.js Express Server</p>
    <p>Request URL: ${req.url}</p>
    <p>Timestamp: ${new Date().toISOString()}</p>
  `);
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});
EOF

cat > backend-apps/app3/package.json << 'EOF'
{
  "name": "backend-app3",
  "version": "1.0.0",
  "description": "Simple Node.js backend",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  }
}
EOF
```

---

## STEP 6 — Avvio Completo

### 6.1 Avvia NPM

```bash
cd ~/nginx-proxy-manager
docker-compose up -d

# Verifica
docker-compose ps
docker-compose logs -f nginx-proxy-manager
```

### 6.2 Avvia Backend Apps

```bash
# App 1
cd backend-apps/app1
docker-compose up -d

# App 2
cd ../app2
docker-compose up -d

# App 3
cd ../app3
docker-compose up -d

# Verifica tutti i container
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 6.3 Test Backend Diretti

```bash
# Test porte dirette
curl http://localhost:8081  # App 1
curl http://localhost:8082  # App 2
curl http://localhost:8083  # App 3
```

---

## STEP 7 — Configurazione NPM GUI

### 7.1 Login Iniziale

1. Browser: `http://localhost:81`
2. Login:
   - Email: `admin@example.com`
   - Password: `changeme`
3. Cambia email e password al primo accesso

### 7.2 Crea Proxy Host per App1

1. **Hosts** → **Proxy Hosts** → **Add Proxy Host**

**Tab Details:**
```
Domain Names: app1.localhost
Scheme: http
Forward Hostname/IP: 172.30.0.11
Forward Port: 80
☑ Cache Assets
☑ Block Common Exploits
```

2. **Save**

### 7.3 Test Proxy

```bash
# Aggiungi a /etc/hosts
echo "127.0.0.1 app1.localhost" | sudo tee -a /etc/hosts

# Test
curl http://app1.localhost
# Output: <h1>Backend App 1</h1>...
```

### 7.4 Ripeti per App2 e App3

- App2: `app2.localhost` → `172.30.0.12:80`
- App3: `app3.localhost` → `172.30.0.13:3000`

---

## STEP 8 — Configurazione SSL Self-Signed

Per test locale senza dominio reale:

### 8.1 Genera Certificato

```bash
# Crea certificato self-signed
docker exec nginx-proxy-manager sh -c "
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /data/custom_ssl/npm-selfsigned.key \
  -out /data/custom_ssl/npm-selfsigned.crt \
  -subj '/CN=*.localhost/O=Test Org/C=IT'
"
```

### 8.2 Aggiungi Certificato in NPM

1. **SSL Certificates** → **Add SSL Certificate** → **Custom**

```
Name: Localhost Self-Signed
Certificate Key: [copia da npm-selfsigned.key]
Certificate: [copia da npm-selfsigned.crt]
```

2. **Save**

### 8.3 Applica a Proxy Host

1. Modifica **app1.localhost**
2. Tab **SSL**
3. SSL Certificate: seleziona `Localhost Self-Signed`
4. ☑ Force SSL
5. ☑ HTTP/2 Support
6. **Save**

### 8.4 Test HTTPS

```bash
curl -k https://app1.localhost
# -k ignora certificato self-signed
```

---

## STEP 9 — Access List (Autenticazione)

### 9.1 Crea Access List

1. **Access Lists** → **Add Access List**

```
Name: Studenti
☑ Satisfy Any
```

2. **Authorization** → **Add Username**

```
Username: studente1
Password: Pass123!
```

3. Aggiungi altri utenti: `studente2`, `studente3`
4. **Save**

### 9.2 Applica ad App2

1. Modifica proxy **app2.localhost**
2. Tab **Details**
3. Access List: `Studenti`
4. **Save**

### 9.3 Test Autenticazione

```bash
# Senza credenziali: 401 Unauthorized
curl http://app2.localhost

# Con credenziali: 200 OK
curl -u studente1:Pass123! http://app2.localhost
```

---

## STEP 10 — Monitoring e Log

### 10.1 Visualizza Log GUI

NPM Dashboard → Proxy Host → **...** (menu) → **View Logs**

### 10.2 Log da Terminale

```bash
# Log real-time
tail -f ~/nginx-proxy-manager/data/logs/proxy-host-1_access.log

# Analisi log
cat data/logs/proxy-host-1_access.log | grep "GET" | wc -l
# Conta richieste GET

# Top 10 IP
cat data/logs/proxy-host-1_access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### 10.3 Statistiche Nginx

```bash
# Entra nel container
docker exec -it nginx-proxy-manager /bin/bash

# Verifica config generate
cat /data/nginx/proxy_host/1.conf

# Testa config
nginx -t

# Statistiche connessioni
netstat -an | grep :80 | wc -l
```

---

## STEP 11 — Backup e Restore

### 11.1 Backup via GUI

NPM → **Settings** → **Backups** → **Create Backup**

Download file `.json` con tutta la configurazione.

### 11.2 Backup Manuale Completo

```bash
# Stop container
docker-compose down

# Backup dati
cd ~/nginx-proxy-manager
tar -czf npm-backup-$(date +%Y%m%d-%H%M%S).tar.gz data/

# Lista backup
ls -lh npm-backup-*.tar.gz
```

### 11.3 Restore

```bash
# Extract backup
tar -xzf npm-backup-20260320-150000.tar.gz

# Restart container
docker-compose up -d

# Oppure restore via GUI:
# Settings → Backups → Upload .json
```

---

## STEP 12 — Script di Automazione

Crea script helper:

```bash
nano npm-manage.sh
chmod +x npm-manage.sh
```

Contenuto:

```bash
#!/bin/bash

PROJECT_DIR="$HOME/nginx-proxy-manager"
cd "$PROJECT_DIR" || exit

case "$1" in
  start)
    echo "🚀 Avvio Nginx Proxy Manager..."
    docker-compose up -d
    echo "✅ NPM attivo su http://localhost:81"
    ;;
  stop)
    echo "🛑 Stop Nginx Proxy Manager..."
    docker-compose down
    ;;
  restart)
    echo "🔄 Restart..."
    docker-compose restart
    ;;
  logs)
    docker-compose logs -f nginx-proxy-manager
    ;;
  status)
    docker-compose ps
    ;;
  backup)
    echo "💾 Backup in corso..."
    tar -czf "npm-backup-$(date +%Y%m%d-%H%M%S).tar.gz" data/
    echo "✅ Backup completato"
    ls -lh npm-backup-*.tar.gz | tail -1
    ;;
  reset)
    echo "⚠️  ATTENZIONE: Reset completo!"
    read -p "Confermi? (yes/no): " confirm
    if [ "$confirm" == "yes" ]; then
      docker-compose down -v
      rm -rf data/nginx/* data/letsencrypt/*
      echo "✅ Reset completato"
    fi
    ;;
  *)
    echo "Uso: $0 {start|stop|restart|logs|status|backup|reset}"
    exit 1
    ;;
esac
```

**Utilizzo:**

```bash
./npm-manage.sh start    # Avvia
./npm-manage.sh logs     # Visualizza log
./npm-manage.sh backup   # Backup
./npm-manage.sh status   # Stato container
```

---

## STEP 13 — Consegna Esercitazione

### File da Consegnare

```
consegna-npm/
├── docker-compose.yml
├── .env
├── README.md
├── npm-manage.sh
├── screenshots/
│   ├── 01-dashboard.png
│   ├── 02-proxy-hosts.png
│   ├── 03-ssl-certificates.png
│   ├── 04-access-lists.png
│   └── 05-logs.png
├── backup/
│   └── npm-backup-YYYYMMDD.json
└── relazione.pdf (3-5 pagine)
```

### Contenuto Relazione

1. **Introduzione**: cos'è NPM, perché usarlo
2. **Architettura**: diagramma rete, container, volumi
3. **Configurazione**:
   - 3 proxy host creati
   - Certificati SSL (tipo, procedura)
   - Access Lists configurate
4. **Test**:
   - Screenshot funzionamento
   - Test performance (ab, curl)
   - Test autenticazione
5. **Log Analysis**:
   - Top 10 richieste
   - Error rate
   - Response time medio
6. **Conclusioni**: vantaggi NPM vs config manuale

---

## Domande di Verifica

1. **Quali sono i vantaggi di NPM rispetto a configurare Nginx manualmente?**

2. **Spiega il ruolo dei volumi Docker in questo progetto. Cosa succederebbe senza volumi?**

3. **Come funziona Let's Encrypt in NPM? Quali sono i requisiti per ottenere certificati SSL reali?**

4. **Descrivi il flusso di una richiesta HTTP attraverso NPM fino al backend.**

5. **Quando useresti una Access List in NPM? Fornisci 2 scenari reali.**

---

## Riferimenti

- [Nginx Proxy Manager Official Docs](https://nginxproxymanager.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

---

**Sezione Precedente**: [03 - Load Balancing](./03_Load_Balancing.md)
