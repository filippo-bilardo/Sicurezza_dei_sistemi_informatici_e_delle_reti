# C — Verifica Scritta: Reverse Proxy e Load Balancing

📝 **Tipo**: Verifica scritta  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 1 ora  
📄 **Modalità**: Carta e penna / Computer  

---

## Sezione 1: Concetti Fondamentali (5 domande)

### Domanda 1
**Spiega la differenza tra forward proxy e reverse proxy. Per ciascuno, fornisci un esempio di scenario d'uso reale.**

### Domanda 2
**Elenca 5 vantaggi di usare un reverse proxy davanti ai server web in produzione.**

### Domanda 3
**Cosa si intende per "SSL termination"? Perché un'azienda potrebbe scegliere di gestire SSL sul reverse proxy invece che sui server backend?**

### Domanda 4
**Descrivi il flusso di una richiesta HTTP che passa attraverso un reverse proxy Nginx fino al server backend.**

### Domanda 5
**Cosa significa "high availability" nel contesto di un reverse proxy? Come viene implementata?**

---

## Sezione 2: Load Balancing (5 domande)

### Domanda 6
**Spiega come funziona l'algoritmo di load balancing "round-robin". Fornisci un esempio con 3 server backend e 6 richieste.**

### Domanda 7
**Qual è la differenza tra "least connections" e "ip_hash" come algoritmi di load balancing? Quando useresti uno invece dell'altro?**

### Domanda 8
**In questo upstream Nginx:**
```nginx
upstream backend {
    server 10.0.0.1:8080 weight=3;
    server 10.0.0.2:8080 weight=1;
    server 10.0.0.3:8080 backup;
}
```
**Come viene distribuito il traffico tra i 3 server? Quando viene usato il server backup?**

### Domanda 9
**Cosa significa "session persistence" (o session affinity)? Come si implementa in Nginx?**

### Domanda 10
**Descrivi cosa sono i "health checks" nel load balancing. Spiega la differenza tra passive e active health checks.**

---

## Sezione 3: Configurazione Nginx (5 domande)

### Domanda 11
**Spiega il significato di ciascuna direttiva:**
```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

### Domanda 12
**In questa configurazione:**
```nginx
upstream web {
    server 10.0.0.1:8080 max_fails=3 fail_timeout=30s;
}
```
**Cosa succede dopo che un server fallisce 3 richieste consecutive?**

### Domanda 13
**Come si configura Nginx per reindirizzare automaticamente HTTP a HTTPS? Scrivi il blocco server necessario.**

### Domanda 14
**Interpreta questa configurazione cache:**
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=1g;
proxy_cache_valid 200 1h;
```
**Cosa significano "levels", "keys_zone", "max_size" e "proxy_cache_valid"?**

### Domanda 15
**Come si abilita il supporto WebSocket in Nginx reverse proxy? Scrivi le direttive necessarie.**

---

## Sezione 4: Sicurezza (5 domande)

### Domanda 16
**Cosa sono i "security headers" HTTP? Elenca e spiega 4 header di sicurezza importanti (es. HSTS, X-Frame-Options).**

### Domanda 17
**Cos'è il rate limiting e come protegge da attacchi DDoS? Fornisci un esempio di configurazione Nginx.**

### Domanda 18
**Spiega cos'è un attacco "Slowloris" e come un reverse proxy può mitigarlo.**

### Domanda 19
**Perché è importante nascondere la versione di Nginx nei response headers? Come si fa?**

### Domanda 20
**Scenario:** Nei log del reverse proxy noti 10.000 richieste in 10 secondi da 50 IP diversi verso `/login`. Cosa potrebbe indicare? Quali contromisure immediate implementeresti?

---

## Griglia di Valutazione

| Punteggio | Voto | Valutazione |
|-----------|------|-------------|
| 19-20 | 10 | Eccellente |
| 17-18 | 9 | Ottimo |
| 15-16 | 8 | Distinto |
| 13-14 | 7 | Buono |
| 12 | 6 | Sufficiente |
| < 12 | < 6 | Insufficiente |

---

*Esercizio C — ES04 Reverse Proxy | Sistemi e Reti 3*
