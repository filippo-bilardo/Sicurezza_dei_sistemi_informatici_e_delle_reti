# Backend Apps di Esempio

Tre applicazioni backend per testare Nginx Proxy Manager.

## Setup

### 1. Crea file HTML per App1 e App2

```bash
# App1 (Nginx)
mkdir app1-html
cat > app1-html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Backend App 1</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #f0f0f0; }
        h1 { color: #2c3e50; }
        .info { background: white; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
    </style>
</head>
<body>
    <h1>🚀 Backend App 1</h1>
    <div class="info">
        <p><strong>Server:</strong> Nginx (Alpine)</p>
        <p><strong>IP Container:</strong> 172.30.0.11</p>
        <p><strong>Porta diretta:</strong> 8081</p>
        <p><strong>Via Proxy:</strong> app1.localhost</p>
    </div>
</body>
</html>
EOF

# App2 (Apache)
mkdir app2-html
cat > app2-html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Backend App 2</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #e8f4f8; }
        h1 { color: #2980b9; }
        .info { background: white; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
    </style>
</head>
<body>
    <h1>⚡ Backend App 2</h1>
    <div class="info">
        <p><strong>Server:</strong> Apache HTTPD (Alpine)</p>
        <p><strong>IP Container:</strong> 172.30.0.12</p>
        <p><strong>Porta diretta:</strong> 8082</p>
        <p><strong>Via Proxy:</strong> app2.localhost</p>
    </div>
</body>
</html>
EOF
```

### 2. Crea App3 Node.js

```bash
mkdir app3-node
cat > app3-node/server.js << 'EOF'
const http = require('http');

const server = http.createServer((req, res) => {
  const timestamp = new Date().toISOString();
  
  res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
  res.end(`
<!DOCTYPE html>
<html>
<head>
    <title>Backend App 3</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #e8f5e9; }
        h1 { color: #27ae60; }
        .info { background: white; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
    </style>
</head>
<body>
    <h1>🟢 Backend App 3</h1>
    <div class="info">
        <p><strong>Server:</strong> Node.js ${process.version}</p>
        <p><strong>IP Container:</strong> 172.30.0.13</p>
        <p><strong>Porta diretta:</strong> 8083</p>
        <p><strong>Via Proxy:</strong> app3.localhost</p>
        <p><strong>Request URL:</strong> ${req.url}</p>
        <p><strong>Timestamp:</strong> ${timestamp}</p>
    </div>
</body>
</html>
  `);
});

server.listen(3000, () => {
  console.log('✅ Node.js server running on port 3000');
});
EOF

cat > app3-node/package.json << 'EOF'
{
  "name": "backend-app3",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  }
}
EOF
```

### 3. Avvia Backend Apps

```bash
# Avvia tutte le app
docker-compose up -d

# Verifica
docker-compose ps
```

### 4. Test Porte Dirette

```bash
curl http://localhost:8081  # App1
curl http://localhost:8082  # App2
curl http://localhost:8083  # App3
```

### 5. Configura in NPM

**App1:**
- Domain: `app1.localhost`
- Forward: `172.30.0.11:80`

**App2:**
- Domain: `app2.localhost`
- Forward: `172.30.0.12:80`

**App3:**
- Domain: `app3.localhost`
- Forward: `172.30.0.13:3000`

### 6. Test via Proxy

```bash
# Aggiungi a /etc/hosts
echo "127.0.0.1 app1.localhost app2.localhost app3.localhost" | sudo tee -a /etc/hosts

# Test
curl http://app1.localhost
curl http://app2.localhost
curl http://app3.localhost
```

## Stop

```bash
docker-compose down
```
