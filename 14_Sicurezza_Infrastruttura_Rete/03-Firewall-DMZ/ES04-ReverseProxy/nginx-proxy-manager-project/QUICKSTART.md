# 🚀 Quick Start - Nginx Proxy Manager

Guida rapida per avviare Nginx Proxy Manager in 5 minuti.

---

## Requisiti

- Docker e Docker Compose installati
- Porte 80, 81, 443 disponibili
- 2GB RAM libera

**Verifica prerequisiti:**
```bash
docker --version
docker-compose --version
```

---

## Setup in 4 Step

### 1️⃣ Clone/Download Progetto

```bash
# Se hai il progetto locale
cd nginx-proxy-manager-project

# Oppure scarica da GitHub (esempio)
# git clone <repo-url>
# cd nginx-proxy-manager-project
```

### 2️⃣ Configura Ambiente

```bash
# Copia file esempio
cp .env.example .env

# (Opzionale) Modifica email per Let's Encrypt
nano .env
```

### 3️⃣ Avvia Container

```bash
# Avvia NPM
docker-compose up -d

# Verifica
docker-compose ps
# Deve mostrare: Up (healthy)
```

### 4️⃣ Login

**URL:** http://localhost:81

**Credenziali default:**
- Email: `admin@example.com`
- Password: `changeme`

⚠️ **Cambia subito la password!**

---

## Crea il Tuo Primo Proxy

### Scenario: Proxy per app su localhost:8080

1. **Dashboard NPM** → **Hosts** → **Proxy Hosts** → **Add Proxy Host**

2. **Tab "Details":**
   ```
   Domain Names:       myapp.localhost
   Scheme:             http
   Forward Hostname:   host.docker.internal  (per app su host)
   Forward Port:       8080
   ☑ Cache Assets
   ☑ Block Common Exploits
   ```

3. **Save**

4. **Test:**
   ```bash
   # Aggiungi a /etc/hosts
   echo "127.0.0.1 myapp.localhost" | sudo tee -a /etc/hosts
   
   # Accedi
   curl http://myapp.localhost
   ```

✅ **Done!**

---

## Test con Backend di Esempio

Se non hai un backend, usa le app di esempio:

```bash
# Vai nella directory example-backend
cd example-backend

# Crea file HTML (vedi README.md nella cartella)
# Oppure usa il comando rapido:
./create-apps.sh  # (se esiste)

# Avvia backend
docker-compose up -d

# Test porte dirette
curl http://localhost:8081  # App1
curl http://localhost:8082  # App2
curl http://localhost:8083  # App3
```

**Configura in NPM:**
- **app1.localhost** → `172.30.0.11:80`
- **app2.localhost** → `172.30.0.12:80`
- **app3.localhost** → `172.30.0.13:3000`

---

## Script Helper (Opzionale)

Usa lo script per gestire NPM:

```bash
# Rendi eseguibile (prima volta)
chmod +x npm-manage.sh

# Comandi disponibili
./npm-manage.sh start        # Avvia
./npm-manage.sh stop         # Stop
./npm-manage.sh status       # Stato + statistiche
./npm-manage.sh logs         # Log real-time
./npm-manage.sh backup       # Backup completo
./npm-manage.sh logs-analyze # Analisi log

# Help
./npm-manage.sh help
```

---

## SSL Certificato (Let's Encrypt)

### Requisiti
- Dominio reale (es. `myapp.example.com`)
- DNS punta al tuo server
- Porte 80/443 aperte su Internet

### Procedura
1. Modifica/Crea Proxy Host
2. **Tab "SSL"**
3. ☑ Request a new SSL Certificate
4. Email: `tuo@email.com`
5. ☑ Force SSL
6. ☑ I Agree to Let's Encrypt Terms
7. **Save**

Certificato valido 90 giorni, **rinnovo automatico**!

---

## Troubleshooting

### ❌ Porta già in uso

```bash
# Verifica cosa usa porta 80/81/443
sudo lsof -i :80
sudo lsof -i :81
sudo lsof -i :443

# Ferma servizio conflittuale
sudo systemctl stop nginx
sudo systemctl stop apache2
```

### ❌ Container non parte

```bash
# Visualizza errori
docker-compose logs nginx-proxy-manager

# Ricrea container
docker-compose down
docker-compose up -d
```

### ❌ 502 Bad Gateway

- Verifica backend raggiungibile: `curl http://backend-ip:porta`
- Controlla IP e porta corretti in NPM
- Per app su host Docker: usa `host.docker.internal` invece di `localhost`

---

## Comandi Utili

```bash
# Status
docker-compose ps

# Log real-time
docker-compose logs -f

# Stop
docker-compose down

# Restart
docker-compose restart

# Backup dati
tar -czf npm-backup.tar.gz data/

# Reset completo (ATTENZIONE!)
docker-compose down -v
rm -rf data/*
docker-compose up -d
```

---

## 📚 Risorse

- 📖 [README completo](README.md) - Guida dettagliata
- 📖 [Guida teorica NPM](../docs/04_Nginx_Proxy_Manager.md) - Concetti approfonditi
- 🌐 [NPM Official Docs](https://nginxproxymanager.com/)
- 🐙 [GitHub Repo](https://github.com/NginxProxyManager/nginx-proxy-manager)

---

## ✅ Checklist Progetto Studente

Prima di consegnare:

- [ ] Container NPM funzionante (`docker-compose ps` → Up)
- [ ] Password admin cambiata
- [ ] Almeno 3 proxy host configurati
- [ ] 1 proxy con SSL (Let's Encrypt o self-signed)
- [ ] 1 proxy con Access List
- [ ] Screenshot dashboard NPM
- [ ] Backup configurazione esportato
- [ ] Relazione PDF (2-3 pagine)

---

**Pronto in 5 minuti! 🎉**

Per domande o problemi, consulta il [README completo](README.md).
