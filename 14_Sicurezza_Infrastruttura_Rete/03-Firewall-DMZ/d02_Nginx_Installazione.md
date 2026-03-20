# Nginx: Installazione e Architettura

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES04 — Reverse Proxy**

---

## Introduzione a Nginx

**Nginx** (engine-x) è un web server, reverse proxy e load balancer ad alte performance, creato da Igor Sysoev nel 2004.

**Caratteristiche:**
- Architettura event-driven asincrona (non thread-based)
- Gestisce 10.000+ connessioni simultanee con poca RAM
- Usato da 40% dei siti top 1000 (Netflix, Dropbox, WordPress.com)
- Open source + versione commerciale (Nginx Plus)

---

## Installazione

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nginx -y
nginx -v  # Verifica versione
```

### Da Sorgente (ultima versione)
```bash
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --with-http_ssl_module --with-stream
make
sudo make install
```

---

## Struttura File

```
/etc/nginx/
├── nginx.conf              # Configurazione principale
├── sites-available/        # Virtual host disponibili
├── sites-enabled/          # Virtual host attivi (symlink)
├── conf.d/                 # Include modulari
└── snippets/               # Frammenti riusabili

/var/log/nginx/
├── access.log              # Log accessi
└── error.log               # Log errori

/var/www/html/              # Document root default
```

---

## Configurazione Base

```nginx
# /etc/nginx/nginx.conf

user www-data;
worker_processes auto;  # CPU cores

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Performance
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    
    # Virtual hosts
    include /etc/nginx/sites-enabled/*;
}
```

---

## Comandi Utili

```bash
# Test configurazione
sudo nginx -t

# Reload (no downtime)
sudo nginx -s reload

# Restart
sudo systemctl restart nginx

# Stop
sudo nginx -s stop

# Status
sudo systemctl status nginx
```

---

**Prossima Sezione**: [03 - Load Balancing](./03_Load_Balancing.md)
