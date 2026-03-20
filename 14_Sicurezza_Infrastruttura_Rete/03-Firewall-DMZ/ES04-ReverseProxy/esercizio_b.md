# B — Progetto Autonomo: High-Availability Reverse Proxy con SSL

🏗️ **Tipo**: Progetto autonomo  
⭐ **Difficoltà**: ⭐⭐⭐⭐ (Avanzato)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumento**: Ubuntu + Nginx + Let's Encrypt + Docker  
📁 **File da consegnare**: Progetto completo + documentazione

---

## 🏢 Scenario

L'azienda **CloudBank S.p.A.** richiede un'infrastruttura reverse proxy enterprise con:

### Requisiti Funzionali
1. **HTTPS obbligatorio** con certificati SSL/TLS (Let's Encrypt)
2. **Load balancing** su 4 backend servers
3. **Session persistence** con cookie
4. **Caching aggressivo** per contenuti statici (immagini, CSS, JS)
5. **Rate limiting** per protezione DDoS (max 10 req/s per IP)
6. **Health monitoring** attivo con endpoint `/health`
7. **Security headers** (HSTS, CSP, X-Frame-Options)
8. **Logging avanzato** con formato JSON per SIEM
9. **WebSocket support** per applicazioni real-time
10. **Failover automatico** con backup server

---

## 🗺️ Topologia

```
                    INTERNET (HTTPS:443)
                            │
                    [Reverse Proxy]
                    nginx-proxy
                    SSL Termination
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    [Backend 1]         [Backend 2]         [Backend 3]
    Node.js:8080        Node.js:8080        Node.js:8080
    Primary             Primary             Primary
                                                │
                                          [Backend 4]
                                          Node.js:8080
                                          Backup
```

---

## 📋 STEP 1–5: Installazione e Configurazione Base

(Segui STEP 1-5 dell'Esercizio A per setup iniziale)

---

## 📋 STEP 6 — Configurazione SSL/TLS con Let's Encrypt

### 6.1 Installazione Certbot

```bash
sudo apt install certbot python3-certbot-nginx -y
```

### 6.2 Ottenimento Certificato

```bash
# Con dominio reale
sudo certbot --nginx -d cloudbank.example.com

# Per test (self-signed)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx.key \
  -out /etc/nginx/ssl/nginx.crt
```

### 6.3 Configurazione HTTPS

```nginx
upstream backend_app {
    least_conn;
    
    server 192.168.1.11:8080 max_fails=2 fail_timeout=10s;
    server 192.168.1.12:8080 max_fails=2 fail_timeout=10s;
    server 192.168.1.13:8080 max_fails=2 fail_timeout=10s;
    server 192.168.1.14:8080 backup;
    
    keepalive 32;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name cloudbank.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name cloudbank.example.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/cloudbank.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloudbank.example.com/privkey.pem;

    # SSL configuration (Mozilla Modern)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=app_limit:10m rate=10r/s;
    limit_req zone=app_limit burst=20 nodelay;

    # Logging
    access_log /var/log/nginx/cloudbank-access.log combined;
    error_log /var/log/nginx/cloudbank-error.log warn;

    # Session persistence (cookie-based)
    upstream_hash $cookie_backend_route consistent;

    location / {
        proxy_pass http://backend_app;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf)$ {
        proxy_pass http://backend_app;
        proxy_cache static_cache;
        proxy_cache_valid 200 7d;
        proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;
        add_header X-Cache-Status $upstream_cache_status;
        expires 7d;
    }

    # Health check endpoint
    location /nginx-health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

---

## 📋 STEP 7 — Configurazione Cache

```nginx
# In http block di nginx.conf
proxy_cache_path /var/cache/nginx/static levels=1:2 keys_zone=static_cache:10m max_size=1g inactive=7d;
proxy_cache_path /var/cache/nginx/api levels=1:2 keys_zone=api_cache:10m max_size=100m inactive=1h;

# Crea directory
sudo mkdir -p /var/cache/nginx/{static,api}
sudo chown -R www-data:www-data /var/cache/nginx
```

---

## 📋 STEP 8 — Rate Limiting Avanzato

```nginx
# Multiple rate limit zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

# Apply different limits
location /api/ {
    limit_req zone=api burst=10 nodelay;
    proxy_pass http://backend_app;
}

location /login {
    limit_req zone=login burst=3 nodelay;
    proxy_pass http://backend_app;
}
```

---

## 📋 STEP 9 — Monitoring con Prometheus

```nginx
# Installa nginx-prometheus-exporter
wget https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v0.11.0/nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz
tar -xzf nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz
sudo mv nginx-prometheus-exporter /usr/local/bin/

# Run exporter
/usr/local/bin/nginx-prometheus-exporter -nginx.scrape-uri=http://localhost/nginx_status

# Metriche disponibili su: http://localhost:9113/metrics
```

---

## 📋 STEP 10 — Test e Validazione

### Test SSL
```bash
# Test SSL configuration
curl -I https://cloudbank.example.com

# Test SSL grade
ssllabs.com/ssltest/analyze.html?d=cloudbank.example.com
```

### Test Load Balancing
```bash
# 1000 richieste con Apache Bench
ab -n 1000 -c 10 https://cloudbank.example.com/
```

### Test Rate Limiting
```bash
# Supera limite (deve ricevere 503)
for i in {1..20}; do curl -s -o /dev/null -w "%{http_code}\n" https://cloudbank.example.com/; done
```

### Test Failover
```bash
# Spegni 2 backend, verifica servizio continua
docker stop backend1 backend2
curl https://cloudbank.example.com/  # Deve funzionare
```

---

## 📋 STEP 11 — Consegna

### Documentazione Richiesta (8-10 pagine)

1. **Architettura**: diagramma, componenti, IP plan
2. **Configurazione SSL**: certificati, cipher suites, security headers
3. **Load balancing**: algoritmo, weight, failover strategy
4. **Caching**: hit ratio target, policy, invalidation
5. **Security**: rate limiting, WAF rules, OWASP compliance
6. **Monitoring**: dashboard Prometheus/Grafana
7. **Test results**: performance (req/s), failover time, SSL grade
8. **Troubleshooting guide**: problemi comuni e soluzioni

### Criteri Valutazione

| Criterio | Peso |
|----------|------|
| SSL/TLS configurato correttamente | 20% |
| Load balancing + failover | 20% |
| Caching funzionante (hit >30%) | 15% |
| Rate limiting attivo | 10% |
| Security headers completi | 10% |
| Monitoring implementato | 10% |
| Documentazione | 15% |

---

*Esercizio B — ES04 Reverse Proxy | Sistemi e Reti 3*
