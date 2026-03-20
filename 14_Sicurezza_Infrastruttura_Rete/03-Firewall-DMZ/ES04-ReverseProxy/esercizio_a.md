# A — Laboratorio Guidato: Nginx Reverse Proxy Base con Load Balancing

🔬 **Tipo**: Laboratorio guidato  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumento**: Ubuntu Server 22.04 + Nginx + Docker (opzionale)  
📁 **File da consegnare**: `nginx.conf`, screenshot, relazione tecnica

---

## 📸 Riepilogo Screenshot Richiesti

| # | Step | Cosa mostrare |
|---|------|---------------|
| 📸1 | STEP 2 | Output di `nginx -v` con versione installata |
| 📸2 | STEP 3 | File `/etc/nginx/nginx.conf` con upstream configurato |
| 📸3 | STEP 4 | Browser che mostra risposta da Server 1 |
| 📸4 | STEP 4 | Browser che mostra risposta da Server 2 (dopo refresh) |
| 📸5 | STEP 5 | Test con un server backend spento (failover) |
| 📸6 | STEP 6 | Output di `tail -f /var/log/nginx/access.log` |
| 📸7 | STEP 7 | Statistiche Nginx con `nginx -T` o status page |
| 📸8 | STEP 8 | Test load balancing con script (10 richieste) |

---

## 🏢 Scenario

L'azienda **WebScale S.r.l.** gestisce un sito e-commerce con picchi di traffico durante le promozioni. Il server singolo non riesce a gestire il carico. Il team IT deve implementare un **reverse proxy Nginx** con **load balancing** su 3 server backend per:

1. Distribuire il traffico equamente
2. Garantire alta disponibilità (failover automatico)
3. Migliorare le performance con caching
4. Proteggere i server backend dall'esposizione diretta

---

## 🗺️ Topologia di Rete

```
                    INTERNET
                        │
                   [Router/FW]
                        │ 192.168.1.1
                        │
                 ┌──────┴──────┐
                 │             │
          [Reverse Proxy]      │
          192.168.1.50:80      │
          Nginx                │
                 │             │
        ┌────────┼────────┐    │
        │        │        │    │
   [Backend 1] [Backend 2] [Backend 3]
   192.168.1.11 .12       .13
   Apache/Node  Apache/Node Apache/Node
   Port 8080    Port 8080   Port 8080
```

---

## 📋 STEP 1 — Preparazione Ambiente

### 1.1 Requisiti VM

Serviranno **4 VM** (o 1 VM + 3 container Docker):

| VM/Container | IP | Software | Porta | Ruolo |
|--------------|----|----|------|-------|
| nginx-proxy | 192.168.1.50 | Nginx | 80 | Reverse Proxy |
| backend-1 | 192.168.1.11 | Apache/Nginx | 8080 | Web Server |
| backend-2 | 192.168.1.12 | Apache/Nginx | 8080 | Web Server |
| backend-3 | 192.168.1.13 | Apache/Nginx | 8080 | Web Server |

### 1.2 Opzione Docker (Semplificata)

```bash
# Crea docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  backend1:
    image: nginx:alpine
    container_name: backend1
    ports:
      - "8081:80"
    volumes:
      - ./backend1:/usr/share/nginx/html
    networks:
      webnet:
        ipv4_address: 172.20.0.11

  backend2:
    image: nginx:alpine
    container_name: backend2
    ports:
      - "8082:80"
    volumes:
      - ./backend2:/usr/share/nginx/html
    networks:
      webnet:
        ipv4_address: 172.20.0.12

  backend3:
    image: nginx:alpine
    container_name: backend3
    ports:
      - "8083:80"
    volumes:
      - ./backend3:/usr/share/nginx/html
    networks:
      webnet:
        ipv4_address: 172.20.0.13

networks:
  webnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
EOF

# Crea pagine diverse per ogni backend
mkdir -p backend{1,2,3}
echo "<h1>Backend Server 1</h1><p>Hostname: backend1</p>" > backend1/index.html
echo "<h1>Backend Server 2</h1><p>Hostname: backend2</p>" > backend2/index.html
echo "<h1>Backend Server 3</h1><p>Hostname: backend3</p>" > backend3/index.html

# Avvia container
docker-compose up -d

# Verifica
curl http://localhost:8081  # Backend 1
curl http://localhost:8082  # Backend 2
curl http://localhost:8083  # Backend 3
```

### 1.3 Verifica Connettività

```bash
# Dal reverse proxy, testa i backend
curl http://192.168.1.11:8080
curl http://192.168.1.12:8080
curl http://192.168.1.13:8080

# Output atteso: HTML di ciascun server
```

---

## 📋 STEP 2 — Installazione Nginx

### 2.1 Installazione su Ubuntu

```bash
# Update repository
sudo apt update

# Installa Nginx
sudo apt install nginx -y

# Verifica versione
nginx -v
# Output: nginx version: nginx/1.18.0 (Ubuntu)

# Verifica servizio
sudo systemctl status nginx

# Abilita avvio automatico
sudo systemctl enable nginx
```

### 2.2 Verifica Installazione

```bash
# Accedi a http://192.168.1.50
curl http://localhost

# Output atteso: "Welcome to nginx!"
```

📸 **SCREENSHOT 1**: Output di `nginx -v`

---

## 📋 STEP 3 — Configurazione Reverse Proxy Base

### 3.1 Backup Configurazione Originale

```bash
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup
```

### 3.2 Configurazione Upstream (Backend Servers)

```bash
sudo nano /etc/nginx/conf.d/upstream.conf
```

Inserisci:

```nginx
# Definizione upstream: gruppo di server backend
upstream backend_servers {
    # Algoritmo: round-robin (default)
    # Distribuisce richieste circolarmente

    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
    server 192.168.1.13:8080;
}
```

### 3.3 Configurazione Virtual Host

```bash
sudo nano /etc/nginx/sites-available/reverse-proxy
```

Contenuto:

```nginx
server {
    listen 80;
    server_name webscale.local;  # Sostituisci con il tuo dominio

    # Log specifici per questo virtual host
    access_log /var/log/nginx/reverse-proxy-access.log;
    error_log /var/log/nginx/reverse-proxy-error.log;

    # Location principale: reverse proxy a backend
    location / {
        # Proxy pass verso upstream
        proxy_pass http://backend_servers;

        # Header per passare info client ai backend
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    # Location per file statici (opzionale)
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        proxy_pass http://backend_servers;
        proxy_cache_valid 200 1h;
        expires 1h;
    }
}
```

### 3.4 Attivazione Configurazione

```bash
# Crea symlink in sites-enabled
sudo ln -s /etc/nginx/sites-available/reverse-proxy /etc/nginx/sites-enabled/

# Disabilita default site (opzionale)
sudo rm /etc/nginx/sites-enabled/default

# Verifica sintassi
sudo nginx -t

# Output atteso:
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Riavvia Nginx
sudo systemctl restart nginx

# Verifica status
sudo systemctl status nginx
```

📸 **SCREENSHOT 2**: File configurazione con upstream

---

## 📋 STEP 4 — Test Load Balancing

### 4.1 Test Manuale con Browser

```bash
# Aggiungi entry /etc/hosts (sul PC client)
echo "192.168.1.50 webscale.local" | sudo tee -a /etc/hosts

# Accedi con browser
http://webscale.local
```

**Cosa osservare:**
- Prima richiesta: mostra "Backend Server 1"
- Refresh (F5): mostra "Backend Server 2"
- Refresh: mostra "Backend Server 3"
- Refresh: torna a "Backend Server 1" (round-robin)

📸 **SCREENSHOT 3**: Risposta Backend 1  
📸 **SCREENSHOT 4**: Risposta Backend 2 (dopo refresh)

### 4.2 Test con curl

```bash
# 10 richieste consecutive
for i in {1..10}; do
  curl -s http://webscale.local | grep -oP '(?<=Backend Server )[0-9]'
done

# Output atteso (round-robin):
# 1
# 2
# 3
# 1
# 2
# 3
# 1
# 2
# 3
# 1
```

---

## 📋 STEP 5 — Test Failover (High Availability)

### 5.1 Simulazione Guasto Server

```bash
# Ferma backend-2
# Se Docker:
docker stop backend2

# Se VM:
ssh backend2
sudo systemctl stop nginx  # o apache2
```

### 5.2 Test Continuità Servizio

```bash
# Continua a fare richieste
for i in {1..10}; do
  curl -s http://webscale.local | grep -oP '(?<=Backend Server )[0-9]'
  sleep 1
done

# Output atteso (backend-2 escluso automaticamente):
# 1
# 3
# 1
# 3
# 1
# 3
```

**Nginx automaticamente esclude backend non disponibili!**

### 5.3 Ripristino Server

```bash
# Riavvia backend-2
docker start backend2

# Dopo 5-10 secondi, Nginx lo reinclude automaticamente
# Test:
for i in {1..6}; do
  curl -s http://webscale.local | grep -oP '(?<=Backend Server )[0-9]'
done

# Output: 1, 2, 3, 1, 2, 3 ✓
```

📸 **SCREENSHOT 5**: Test con server spento (solo 1 e 3)

---

## 📋 STEP 6 — Analisi Log

### 6.1 Formato Log Nginx

```bash
# Visualizza log in tempo reale
sudo tail -f /var/log/nginx/reverse-proxy-access.log

# Formato log:
# IP - - [timestamp] "GET / HTTP/1.1" status bytes "referer" "user-agent"
```

**Esempio:**
```
192.168.1.100 - - [20/Mar/2026:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [20/Mar/2026:10:30:46 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

### 6.2 Analisi Statistiche

```bash
# Richieste totali
wc -l /var/log/nginx/reverse-proxy-access.log

# Top 10 IP client
awk '{print $1}' /var/log/nginx/reverse-proxy-access.log | sort | uniq -c | sort -rn | head -10

# Status code distribution
awk '{print $9}' /var/log/nginx/reverse-proxy-access.log | sort | uniq -c | sort -rn

# Bandwidth totale (bytes)
awk '{sum+=$10} END {print sum/1024/1024 " MB"}' /var/log/nginx/reverse-proxy-access.log
```

📸 **SCREENSHOT 6**: Log Nginx in tempo reale

---

## 📋 STEP 7 — Health Checks Avanzati

### 7.1 Configurazione Health Checks

```bash
sudo nano /etc/nginx/conf.d/upstream.conf
```

Modifica upstream:

```nginx
upstream backend_servers {
    # Health check passivo (default)
    # max_fails: tentativi falliti prima di marcare down
    # fail_timeout: tempo di attesa prima di riprovare

    server 192.168.1.11:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.13:8080 max_fails=3 fail_timeout=30s;

    # Backup server (usato solo se tutti i principali falliscono)
    # server 192.168.1.20:8080 backup;

    # Keepalive connections per performance
    keepalive 32;
}
```

### 7.2 Test Health Check

```bash
# Ricarica Nginx
sudo nginx -s reload

# Simula server lento (risponde dopo 15 secondi)
# Backend-1: aggiungi sleep
ssh backend1
# Aggiungi delay artificiale nella risposta

# Nginx lo marca come down dopo 3 fail
# Traffico va solo a backend-2 e backend-3
```

---

## 📋 STEP 8 — Algoritmi di Load Balancing

### 8.1 Round Robin (Default)

Già configurato. Distribuzione circolare.

### 8.2 Least Connections

```nginx
upstream backend_servers {
    least_conn;  # Invia richieste al server con meno connessioni attive

    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
    server 192.168.1.13:8080;
}
```

**Use case:** carico non uniforme (richieste lunghe vs corte)

### 8.3 IP Hash

```nginx
upstream backend_servers {
    ip_hash;  # Stesso client IP → sempre stesso backend (session affinity)

    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
    server 192.168.1.13:8080;
}
```

**Use case:** applicazioni con sessioni server-side (no cookie-based session)

### 8.4 Weighted Load Balancing

```nginx
upstream backend_servers {
    server 192.168.1.11:8080 weight=3;  # Riceve 3x traffico
    server 192.168.1.12:8080 weight=2;  # Riceve 2x traffico
    server 192.168.1.13:8080 weight=1;  # Riceve 1x traffico
}
```

**Use case:** server con hardware diverso (potente vs debole)

### 8.5 Test Algoritmi

```bash
# Test con curl + counter
for i in {1..30}; do
  curl -s http://webscale.local | grep -oP '(?<=Backend Server )[0-9]'
done | sort | uniq -c

# Con weight=3,2,1 output:
# 15 1  (50%)
# 10 2  (33%)
#  5 3  (17%)
```

📸 **SCREENSHOT 8**: Test 10 richieste con distribuzione

---

## 📋 STEP 9 — Monitoring e Status Page

### 9.1 Stub Status Module

```bash
sudo nano /etc/nginx/sites-available/reverse-proxy
```

Aggiungi location:

```nginx
# Status page (solo da localhost per sicurezza)
location /nginx_status {
    stub_status on;
    access_log off;
    allow 127.0.0.1;
    allow 192.168.1.0/24;  # Aggiungi subnet ammessa
    deny all;
}
```

### 9.2 Accesso Status

```bash
# Ricarica Nginx
sudo nginx -s reload

# Accedi a status
curl http://localhost/nginx_status

# Output:
# Active connections: 2
# server accepts handled requests
#  1234 1234 5678
# Reading: 0 Writing: 1 Waiting: 1
```

**Metriche:**
- **Active connections**: connessioni attive totali
- **accepts**: connessioni accettate totali
- **handled**: connessioni gestite (dovrebbe = accepts)
- **requests**: richieste HTTP totali
- **Reading**: Nginx legge header richiesta
- **Writing**: Nginx scrive risposta al client
- **Waiting**: connessioni idle (keepalive)

📸 **SCREENSHOT 7**: Status page Nginx

---

## 📋 STEP 10 — Consegna

### 10.1 File da Consegnare

1. **nginx.conf** e **upstream.conf** finali
2. **8 screenshot** richiesti
3. **Relazione tecnica** (2-3 pagine) con:
   - Topologia di rete implementata
   - Spiegazione upstream e algoritmo LB usato
   - Test failover: cosa è successo quando server spento
   - Analisi log: top 5 IP, status codes, bandwidth
   - Confronto 3 algoritmi LB (round-robin, least_conn, ip_hash)

### 10.2 Criteri di Valutazione

| Criterio | Peso | Note |
|----------|------|------|
| Reverse proxy funzionante | 30% | Client accede ai backend tramite proxy |
| Load balancing corretto | 25% | Traffico distribuito equamente |
| Failover testato | 20% | Servizio continua con server down |
| Log analisi | 10% | Interpretazione corretta metriche |
| Relazione tecnica | 15% | Completa e professionale |

---

## 🔧 Troubleshooting

### Problema: 502 Bad Gateway

```bash
# Verifica backend raggiungibili
curl http://192.168.1.11:8080

# Verifica firewall
sudo ufw status
sudo ufw allow from 192.168.1.50 to any port 8080

# Controlla log errori
sudo tail -f /var/log/nginx/reverse-proxy-error.log
```

### Problema: Load balancing non funziona

```bash
# Verifica upstream definito
sudo nginx -T | grep -A 5 "upstream backend_servers"

# Controlla proxy_pass usa upstream name corretto
sudo nginx -T | grep "proxy_pass"
# Deve essere: proxy_pass http://backend_servers;
```

### Problema: Timeout

```bash
# Aumenta timeout in server block
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;
```

---

## 📚 Domande di Verifica

1. **Qual è la differenza tra reverse proxy e forward proxy?**
2. **Spiega come funziona l'algoritmo round-robin nel load balancing.**
3. **Cosa succede quando un backend server va down durante il traffic? Come Nginx gestisce il failover?**
4. **Quando useresti `ip_hash` invece di `least_conn`?**
5. **Cosa indica "Active connections: 50" nella status page di Nginx?**

---

*Esercizio A — ES04 Reverse Proxy | Sistemi e Reti 3*
