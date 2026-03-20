# Load Balancing con Nginx

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES04 — Reverse Proxy**

---

## Algoritmi di Load Balancing

### 1. Round Robin (Default)
Distribuzione circolare: server 1 → 2 → 3 → 1 → 2 → 3...

```nginx
upstream backend {
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
    server 10.0.0.3:8080;
}
```

### 2. Least Connections
Invia richieste al server con meno connessioni attive.

```nginx
upstream backend {
    least_conn;
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
}
```

**Use case**: richieste con durata variabile (upload file, long-polling)

### 3. IP Hash
Stesso client IP → sempre stesso server (session affinity).

```nginx
upstream backend {
    ip_hash;
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
}
```

**Use case**: applicazioni con sessioni server-side

### 4. Weighted
Distribuisce traffico proporzionalmente ai pesi.

```nginx
upstream backend {
    server 10.0.0.1:8080 weight=3;  # 60% traffico
    server 10.0.0.2:8080 weight=2;  # 40% traffico
}
```

**Use case**: server con capacità diverse

---

## Health Checks

### Passive Health Checks (Default)

```nginx
upstream backend {
    server 10.0.0.1:8080 max_fails=3 fail_timeout=30s;
    server 10.0.0.2:8080 max_fails=3 fail_timeout=30s;
}
```

- **max_fails**: tentativi falliti prima di marcare server "down"
- **fail_timeout**: tempo di attesa prima di riprovare

### Active Health Checks (Nginx Plus)

```nginx
upstream backend {
    zone backend 64k;
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
}

server {
    location / {
        proxy_pass http://backend;
        health_check interval=5s fails=3 passes=2 uri=/health;
    }
}
```

---

## Session Persistence

### Cookie-based

```nginx
upstream backend {
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
    
    sticky cookie srv_id expires=1h domain=.example.com path=/;
}
```

### Route parameter

```nginx
map $cookie_route $route_cookie {
    ~.(?P<route>\w+)$ $route;
}

upstream backend {
    server 10.0.0.1:8080 route=a;
    server 10.0.0.2:8080 route=b;
    
    sticky route $route_cookie;
}
```

---

## Backup Server

```nginx
upstream backend {
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
    server 10.0.0.3:8080 backup;  # Usato solo se altri down
}
```

---

## Domande di Verifica

1. **Quando useresti "least_conn" invece di "round-robin"?**
2. **Cosa succede dopo 3 max_fails in un server?**
3. **Perché ip_hash è utile per applicazioni con sessioni?**

---

**Prossima Sezione**: [04 - SSL Termination](./04_SSL_Termination.md)
