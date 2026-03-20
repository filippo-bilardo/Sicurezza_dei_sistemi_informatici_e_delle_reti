# Reverse Proxy: Concetti Fondamentali

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 03 — Firewall e DMZ**  
> **ES04 — Reverse Proxy**

---

## Introduzione

Un **reverse proxy** è un server che si posiziona davanti ai server web backend, ricevendo richieste dai client e inoltrandole ai server appropriati.

```
Forward Proxy (protegge CLIENT):
[Client] → [Proxy] → Internet

Reverse Proxy (protegge SERVER):
Internet → [Proxy] → [Server Backend]
```

---

## Use Cases Principali

### 1. Load Balancing
Distribuzione traffico su più server per performance e affidabilità.

### 2. SSL/TLS Termination
Gestione HTTPS centralizzata, server backend in HTTP.

### 3. Caching
Memorizzazione contenuti statici per ridurre carico server.

### 4. Security
- Nasconde IP e architettura server backend
- WAF (Web Application Firewall)
- Rate limiting anti-DDoS
- Security headers injection

### 5. Compression
Gzip/Brotli trasparente per ridurre banda.

### 6. High Availability
Failover automatico se server cade.

---

## Vantaggi

✓ **Performance**: caching, compressione, connection pooling
✓ **Scalabilità**: aggiunta server senza downtime
✓ **Sicurezza**: layer protettivo, WAF, hiding details
✓ **Manutenzione**: deploy zero-downtime con rolling updates
✓ **Flessibilità**: routing intelligente per A/B testing, canary deployment

---

## Soluzioni Popolari

| Software | Tipo | Use Case |
|----------|------|----------|
| **Nginx** | Web server + RP | General purpose, alta performance |
| **HAProxy** | Load balancer | Layer 4/7 LB specializzato |
| **Apache mod_proxy** | Web server + RP | Integrazione con Apache esistente |
| **Traefik** | Cloud-native RP | Kubernetes, Docker, microservices |
| **Envoy** | Service mesh | Istio, microservices avanzati |

---

## Domande di Verifica

1. **Qual è la differenza principale tra forward e reverse proxy?**
2. **Perché un'azienda userebbe reverse proxy invece di esporre direttamente i server?**
3. **Cosa significa "SSL termination" e quali sono i vantaggi?**

---

**Prossima Sezione**: [02 - Nginx Installazione](./02_Nginx_Installazione.md)
