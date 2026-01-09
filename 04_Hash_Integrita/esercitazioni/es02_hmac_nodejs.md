# Esercitazione 2 - HMAC con Node.js

## 📋 Obiettivo

Imparare a utilizzare HMAC (Hash-based Message Authentication Code) per:
- Autenticare messaggi
- Verificare integrità con chiave segreta
- Implementare API authentication
- Creare token sicuri

**Difficoltà**: ⭐⭐⭐ Avanzato  
**Tempo**: 60-75 minuti  
**Tecnologie**: Node.js, crypto module, Express.js

---

## 📁 Struttura Progetto

```
es02-hmac-nodejs/
├── README.md
├── package.json
├── esempi/
│   ├── 01-hmac-base.js
│   ├── 02-verifica-hmac.js
│   └── 03-timing-attack.js
├── progetti/
│   ├── api-auth/
│   │   ├── server.js
│   │   ├── client.js
│   │   └── .env.example
│   └── jwt-simple/
│       ├── jwt.js
│       └── test.js
└── esercizi/
    └── secure-messaging.js
```

---

## 🚀 Setup Iniziale

```bash
mkdir es02-hmac-nodejs
cd es02-hmac-nodejs
npm init -y
npm install express dotenv
mkdir esempi progetti esercizi
```

---

## 📝 Esempi Base

### Esempio 1: HMAC Base (`esempi/01-hmac-base.js`)

```javascript
const crypto = require('crypto');

console.log('=== ESEMPIO 1: HMAC Base ===\n');

// Chiave segreta condivisa tra client e server
const chiaveSegreta = 'supersecretkey123!@#';

// Messaggio da autenticare
const messaggio = 'Trasferimento: 1000 EUR a Bob';

// Calcola HMAC-SHA256
const hmac = crypto.createHmac('sha256', chiaveSegreta);
hmac.update(messaggio);
const tag = hmac.digest('hex');

console.log('Messaggio:', messaggio);
console.log('Chiave:', chiaveSegreta);
console.log('HMAC-SHA256:', tag);
console.log('Lunghezza:', tag.length, 'caratteri\n');

// Verifica HMAC
function verificaHMAC(messaggio, tagRicevuto, chiave) {
    const hmacVerifica = crypto.createHmac('sha256', chiave);
    hmacVerifica.update(messaggio);
    const tagCalcolato = hmacVerifica.digest('hex');
    
    // ⚠️ NON usare === per confrontare (timing attack!)
    // ✅ Usa crypto.timingSafeEqual
    
    const bufferRicevuto = Buffer.from(tagRicevuto, 'hex');
    const bufferCalcolato = Buffer.from(tagCalcolato, 'hex');
    
    try {
        return crypto.timingSafeEqual(bufferRicevuto, bufferCalcolato);
    } catch (e) {
        return false;
    }
}

// Test verifica
console.log('--- VERIFICA HMAC ---');
console.log('Messaggio originale:', verificaHMAC(messaggio, tag, chiaveSegreta) ? '✅ Autentico' : '❌ Falso');

// Modifica il messaggio
const messaggioModificato = 'Trasferimento: 9999 EUR a Bob';
console.log('Messaggio modificato:', verificaHMAC(messaggioModificato, tag, chiaveSegreta) ? '✅ Autentico' : '❌ Falso');

// Chiave errata
const chiaveErrata = 'wrongkey';
console.log('Chiave errata:', verificaHMAC(messaggio, tag, chiaveErrata) ? '✅ Autentico' : '❌ Falso');
```

**Eseguilo:**
```bash
node esempi/01-hmac-base.js
```

---

### Esempio 2: Verifica HMAC Sicura (`esempi/02-verifica-hmac.js`)

```javascript
const crypto = require('crypto');

console.log('=== ESEMPIO 2: Verifica HMAC Sicura ===\n');

/**
 * Genera HMAC per un messaggio
 */
function generaHMAC(messaggio, chiave, algoritmo = 'sha256') {
    return crypto.createHmac(algoritmo, chiave)
        .update(messaggio)
        .digest('hex');
}

/**
 * Verifica HMAC in modo sicuro (timing-safe)
 */
function verificaHMAC(messaggio, tagRicevuto, chiave, algoritmo = 'sha256') {
    const tagAtteso = generaHMAC(messaggio, chiave, algoritmo);
    
    // Converti in Buffer
    const bufA = Buffer.from(tagRicevuto, 'hex');
    const bufB = Buffer.from(tagAtteso, 'hex');
    
    // Confronto timing-safe
    try {
        return crypto.timingSafeEqual(bufA, bufB);
    } catch (e) {
        // Lunghezze diverse = falso
        return false;
    }
}

/**
 * Crea messaggio autenticato
 */
function creaMessaggioAutenticato(contenuto, chiave) {
    const timestamp = Date.now();
    const payload = JSON.stringify({
        contenuto,
        timestamp
    });
    
    const hmac = generaHMAC(payload, chiave);
    
    return {
        payload,
        hmac,
        timestamp
    };
}

/**
 * Verifica messaggio autenticato
 */
function verificaMessaggioAutenticato(messaggio, chiave, ttl = 300000) {
    const { payload, hmac, timestamp } = messaggio;
    
    // 1. Verifica HMAC
    if (!verificaHMAC(payload, hmac, chiave)) {
        return { valido: false, errore: 'HMAC non valido' };
    }
    
    // 2. Verifica timestamp (TTL = 5 minuti default)
    const now = Date.now();
    if (now - timestamp > ttl) {
        return { valido: false, errore: 'Messaggio scaduto' };
    }
    
    // 3. Parse payload
    const dati = JSON.parse(payload);
    
    return { valido: true, dati };
}

// TEST
const chiave = 'shared_secret_key_12345';

console.log('--- CREAZIONE MESSAGGIO ---');
const msg = creaMessaggioAutenticato('Ordine #12345 confermato', chiave);
console.log('Payload:', msg.payload);
console.log('HMAC:', msg.hmac);
console.log('Timestamp:', new Date(msg.timestamp).toISOString());

console.log('\n--- VERIFICA MESSAGGIO ---');
const verifica1 = verificaMessaggioAutenticato(msg, chiave);
console.log('Risultato:', verifica1.valido ? '✅ VALIDO' : '❌ NON VALIDO');
if (verifica1.valido) {
    console.log('Contenuto:', verifica1.dati.contenuto);
}

// Test con HMAC manomesso
console.log('\n--- TEST HMAC MANOMESSO ---');
const msgManomesso = { ...msg, hmac: 'aabbccdd' };
const verifica2 = verificaMessaggioAutenticato(msgManomesso, chiave);
console.log('Risultato:', verifica2.valido ? '✅ VALIDO' : '❌ NON VALIDO');
if (!verifica2.valido) {
    console.log('Errore:', verifica2.errore);
}

// Test con messaggio scaduto
console.log('\n--- TEST MESSAGGIO SCADUTO ---');
const msgVecchio = creaMessaggioAutenticato('Vecchio ordine', chiave);
msgVecchio.timestamp = Date.now() - 400000; // 6 minuti fa
const verifica3 = verificaMessaggioAutenticato(msgVecchio, chiave);
console.log('Risultato:', verifica3.valido ? '✅ VALIDO' : '❌ NON VALIDO');
if (!verifica3.valido) {
    console.log('Errore:', verifica3.errore);
}
```

**Eseguilo:**
```bash
node esempi/02-verifica-hmac.js
```

---

### Esempio 3: Timing Attack Demo (`esempi/03-timing-attack.js`)

```javascript
const crypto = require('crypto');
const { performance } = require('perf_hooks');

console.log('=== ESEMPIO 3: Dimostrazione Timing Attack ===\n');

const chiave = 'secret';
const messaggio = 'test message';
const hmacCorretto = crypto.createHmac('sha256', chiave)
    .update(messaggio)
    .digest('hex');

/**
 * ❌ VULNERABILE: Confronto non timing-safe
 */
function verificaUnsafe(tag1, tag2) {
    if (tag1.length !== tag2.length) return false;
    
    for (let i = 0; i < tag1.length; i++) {
        if (tag1[i] !== tag2[i]) {
            return false; // Esce subito = timing diverso!
        }
    }
    return true;
}

/**
 * ✅ SICURO: Confronto timing-safe
 */
function verificaSafe(tag1, tag2) {
    try {
        const buf1 = Buffer.from(tag1, 'hex');
        const buf2 = Buffer.from(tag2, 'hex');
        return crypto.timingSafeEqual(buf1, buf2);
    } catch (e) {
        return false;
    }
}

// Test timing
const tentativi = 1000;

console.log('Test con', tentativi, 'iterazioni\n');

// Test 1: Primo carattere errato
console.log('--- PRIMO CARATTERE ERRATO ---');
let tagErrato1 = 'X' + hmacCorretto.substring(1);
let tempoUnsafe1 = 0;

for (let i = 0; i < tentativi; i++) {
    const start = performance.now();
    verificaUnsafe(tagErrato1, hmacCorretto);
    tempoUnsafe1 += performance.now() - start;
}
console.log('Tempo medio (unsafe):', (tempoUnsafe1 / tentativi).toFixed(6), 'ms');

// Test 2: Ultimo carattere errato
console.log('\n--- ULTIMO CARATTERE ERRATO ---');
let tagErrato2 = hmacCorretto.substring(0, hmacCorretto.length - 1) + 'X';
let tempoUnsafe2 = 0;

for (let i = 0; i < tentativi; i++) {
    const start = performance.now();
    verificaUnsafe(tagErrato2, hmacCorretto);
    tempoUnsafe2 += performance.now() - start;
}
console.log('Tempo medio (unsafe):', (tempoUnsafe2 / tentativi).toFixed(6), 'ms');

console.log('\n📊 Differenza tempo:', 
    Math.abs(tempoUnsafe1 - tempoUnsafe2).toFixed(6), 'ms');
console.log('⚠️  Un attaccante può sfruttare questa differenza!\n');

// Test metodo sicuro
console.log('--- METODO SICURO ---');
let tempoSafe1 = 0;
let tempoSafe2 = 0;

for (let i = 0; i < tentativi; i++) {
    let start = performance.now();
    verificaSafe(tagErrato1, hmacCorretto);
    tempoSafe1 += performance.now() - start;
    
    start = performance.now();
    verificaSafe(tagErrato2, hmacCorretto);
    tempoSafe2 += performance.now() - start;
}

console.log('Tempo primo char errato:', (tempoSafe1 / tentativi).toFixed(6), 'ms');
console.log('Tempo ultimo char errato:', (tempoSafe2 / tentativi).toFixed(6), 'ms');
console.log('📊 Differenza tempo:', 
    Math.abs(tempoSafe1 - tempoSafe2).toFixed(6), 'ms');
console.log('✅ Tempi costanti = Sicuro!\n');

console.log('💡 Lezione: Usa sempre crypto.timingSafeEqual()');
```

**Eseguilo:**
```bash
node esempi/03-timing-attack.js
```

---

## 🚀 Progetti Completi

### Progetto 1: API Authentication (`progetti/api-auth/`)

Sistema di autenticazione API usando HMAC.

#### `progetti/api-auth/.env.example`

```env
PORT=3000
API_SECRET=your-secret-key-here-change-this
```

#### `progetti/api-auth/server.js`

```javascript
const express = require('express');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

const API_SECRET = process.env.API_SECRET || 'default-secret-change-this';
const PORT = process.env.PORT || 3000;

// Database utenti fittizio
const utenti = {
    'user1': { id: 1, name: 'Alice', apiKey: 'key_alice_123' },
    'user2': { id: 2, name: 'Bob', apiKey: 'key_bob_456' }
};

/**
 * Genera HMAC per autenticazione
 */
function generaHMAC(data, secret) {
    return crypto.createHmac('sha256', secret)
        .update(data)
        .digest('hex');
}

/**
 * Verifica HMAC in modo sicuro
 */
function verificaHMAC(data, hmacRicevuto, secret) {
    const hmacAtteso = generaHMAC(data, secret);
    
    try {
        const buf1 = Buffer.from(hmacRicevuto, 'hex');
        const buf2 = Buffer.from(hmacAtteso, 'hex');
        return crypto.timingSafeEqual(buf1, buf2);
    } catch (e) {
        return false;
    }
}

/**
 * Middleware: Verifica HMAC signature
 */
function verificaSignature(req, res, next) {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const apiKey = req.headers['x-api-key'];
    
    // Verifica presenza headers
    if (!signature || !timestamp || !apiKey) {
        return res.status(401).json({ error: 'Headers mancanti' });
    }
    
    // Verifica timestamp (max 5 minuti)
    const now = Date.now();
    if (Math.abs(now - parseInt(timestamp)) > 300000) {
        return res.status(401).json({ error: 'Request scaduta' });
    }
    
    // Trova utente
    const user = Object.values(utenti).find(u => u.apiKey === apiKey);
    if (!user) {
        return res.status(401).json({ error: 'API key non valida' });
    }
    
    // Crea payload da firmare
    const method = req.method;
    const path = req.path;
    const body = req.body ? JSON.stringify(req.body) : '';
    const payload = `${method}:${path}:${timestamp}:${body}`;
    
    // Verifica HMAC
    if (!verificaHMAC(payload, signature, API_SECRET)) {
        return res.status(401).json({ error: 'Signature non valida' });
    }
    
    // Autenticazione riuscita
    req.user = user;
    next();
}

// Routes

app.get('/', (req, res) => {
    res.json({
        message: 'API Server con HMAC Authentication',
        endpoints: {
            '/api/data': 'GET - Richiede autenticazione HMAC',
            '/api/update': 'POST - Richiede autenticazione HMAC'
        }
    });
});

app.get('/api/data', verificaSignature, (req, res) => {
    res.json({
        message: 'Dati riservati',
        user: req.user.name,
        data: {
            balance: 1000,
            transactions: [
                { id: 1, amount: 100, date: '2026-01-01' },
                { id: 2, amount: -50, date: '2026-01-02' }
            ]
        }
    });
});

app.post('/api/update', verificaSignature, (req, res) => {
    res.json({
        message: 'Dati aggiornati',
        user: req.user.name,
        received: req.body
    });
});

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   🔐 API Server con HMAC Auth         ║
╠════════════════════════════════════════╣
║  URL: http://localhost:${PORT}         ║
║  Secret: ${API_SECRET.substring(0, 10)}...  ║
╠════════════════════════════════════════╣
║  Test utenti:                          ║
║  - Alice: key_alice_123                ║
║  - Bob: key_bob_456                    ║
╚════════════════════════════════════════╝
    `);
});
```

#### `progetti/api-auth/client.js`

```javascript
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2

const API_URL = 'http://localhost:3000';
const API_SECRET = 'your-secret-key-here-change-this';
const API_KEY = 'key_alice_123';

/**
 * Genera signature HMAC per la richiesta
 */
function generaSignature(method, path, body, timestamp, secret) {
    const bodyStr = body ? JSON.stringify(body) : '';
    const payload = `${method}:${path}:${timestamp}:${bodyStr}`;
    
    return crypto.createHmac('sha256', secret)
        .update(payload)
        .digest('hex');
}

/**
 * Esegue richiesta autenticata
 */
async function richiestaAutenticata(method, path, body = null) {
    const timestamp = Date.now().toString();
    const signature = generaSignature(method, path, body, timestamp, API_SECRET);
    
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY,
            'X-Timestamp': timestamp,
            'X-Signature': signature
        }
    };
    
    if (body) {
        options.body = JSON.stringify(body);
    }
    
    const response = await fetch(API_URL + path, options);
    return response.json();
}

// Test
(async () => {
    console.log('=== TEST CLIENT HMAC ===\n');
    
    // Test 1: GET /api/data
    console.log('--- GET /api/data ---');
    const data = await richiestaAutenticata('GET', '/api/data');
    console.log('Risposta:', JSON.stringify(data, null, 2));
    
    // Test 2: POST /api/update
    console.log('\n--- POST /api/update ---');
    const update = await richiestaAutenticata('POST', '/api/update', {
        field: 'name',
        value: 'Nuovo Nome'
    });
    console.log('Risposta:', JSON.stringify(update, null, 2));
})();
```

**Avvio:**
```bash
cd progetti/api-auth
cp .env.example .env
npm install node-fetch@2

# Terminale 1: Server
node server.js

# Terminale 2: Client
node client.js
```

---

### Progetto 2: JWT Semplificato (`progetti/jwt-simple/`)

Implementazione minimale di JWT usando HMAC.

#### `progetti/jwt-simple/jwt.js`

```javascript
const crypto = require('crypto');

class SimpleJWT {
    constructor(secret) {
        this.secret = secret;
    }
    
    /**
     * Codifica in Base64URL
     */
    base64urlEncode(str) {
        return Buffer.from(str)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    /**
     * Decodifica da Base64URL
     */
    base64urlDecode(str) {
        str += '='.repeat((4 - str.length % 4) % 4);
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        return Buffer.from(str, 'base64').toString();
    }
    
    /**
     * Genera signature HMAC
     */
    sign(data) {
        return crypto.createHmac('sha256', this.secret)
            .update(data)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    /**
     * Crea JWT
     */
    create(payload, expiresIn = 3600) {
        // Header
        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };
        
        // Payload con exp
        const payloadWithExp = {
            ...payload,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + expiresIn
        };
        
        // Encode
        const headerEncoded = this.base64urlEncode(JSON.stringify(header));
        const payloadEncoded = this.base64urlEncode(JSON.stringify(payloadWithExp));
        
        // Signature
        const data = `${headerEncoded}.${payloadEncoded}`;
        const signature = this.sign(data);
        
        return `${data}.${signature}`;
    }
    
    /**
     * Verifica e decodifica JWT
     */
    verify(token) {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Token non valido');
        }
        
        const [headerEncoded, payloadEncoded, signature] = parts;
        
        // Verifica signature
        const data = `${headerEncoded}.${payloadEncoded}`;
        const expectedSignature = this.sign(data);
        
        const buf1 = Buffer.from(signature, 'base64');
        const buf2 = Buffer.from(expectedSignature, 'base64');
        
        if (!crypto.timingSafeEqual(buf1, buf2)) {
            throw new Error('Signature non valida');
        }
        
        // Decodifica payload
        const payload = JSON.parse(this.base64urlDecode(payloadEncoded));
        
        // Verifica expiration
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            throw new Error('Token scaduto');
        }
        
        return payload;
    }
}

module.exports = SimpleJWT;
```

#### `progetti/jwt-simple/test.js`

```javascript
const SimpleJWT = require('./jwt');

console.log('=== TEST JWT SEMPLIFICATO ===\n');

const jwt = new SimpleJWT('my-secret-key');

// Crea token
console.log('--- CREAZIONE TOKEN ---');
const payload = {
    userId: 123,
    username: 'alice',
    role: 'admin'
};

const token = jwt.create(payload, 60); // Scade in 60 secondi
console.log('Payload:', payload);
console.log('Token:', token);

// Verifica token
console.log('\n--- VERIFICA TOKEN ---');
try {
    const decoded = jwt.verify(token);
    console.log('✅ Token valido!');
    console.log('Payload decodificato:', decoded);
    console.log('Scade tra:', decoded.exp - Math.floor(Date.now() / 1000), 'secondi');
} catch (error) {
    console.log('❌ Errore:', error.message);
}

// Test con token modificato
console.log('\n--- TOKEN MODIFICATO ---');
const tokenModificato = token.substring(0, token.length - 5) + 'XXXXX';
try {
    jwt.verify(tokenModificato);
    console.log('❌ ERRORE: Token modificato accettato!');
} catch (error) {
    console.log('✅ Token rifiutato:', error.message);
}

// Test con token scaduto
console.log('\n--- TOKEN SCADUTO ---');
const tokenScaduto = jwt.create(payload, -1); // Già scaduto
try {
    jwt.verify(tokenScaduto);
    console.log('❌ ERRORE: Token scaduto accettato!');
} catch (error) {
    console.log('✅ Token rifiutato:', error.message);
}
```

**Eseguilo:**
```bash
node progetti/jwt-simple/test.js
```

---

## 💪 Esercizi

### Esercizio: Secure Messaging (`esercizi/secure-messaging.js`)

Implementa un sistema di messaggistica con autenticazione HMAC.

**Requisiti:**
1. Ogni messaggio include: contenuto, mittente, timestamp, HMAC
2. Verifica HMAC prima di accettare il messaggio
3. Rifiuta messaggi più vecchi di 10 minuti
4. Log di tutti i messaggi ricevuti (validi e invalidi)

**Scheletro:**

```javascript
const crypto = require('crypto');

class SecureMessaging {
    constructor(secret) {
        this.secret = secret;
        this.messaggi = [];
    }
    
    creaMessaggio(mittente, contenuto) {
        // TODO: Implementa
        // 1. Crea payload con mittente, contenuto, timestamp
        // 2. Genera HMAC del payload
        // 3. Restituisci oggetto messaggio
    }
    
    verificaMessaggio(messaggio) {
        // TODO: Implementa
        // 1. Verifica HMAC
        // 2. Verifica timestamp (< 10 min)
        // 3. Se valido, aggiungi a this.messaggi
        // 4. Restituisci {valido: bool, errore: string}
    }
    
    leggiMessaggi(mittente = null) {
        // TODO: Filtra messaggi per mittente (opzionale)
    }
}

// TEST
const messaging = new SecureMessaging('shared-secret');

// Invia messaggi
const msg1 = messaging.creaMessaggio('Alice', 'Ciao Bob!');
const msg2 = messaging.creaMessaggio('Bob', 'Ciao Alice!');

console.log('Messaggio 1:', messaging.verificaMessaggio(msg1));
console.log('Messaggio 2:', messaging.verificaMessaggio(msg2));

// Test manomissione
msg1.contenuto = 'Messaggio modificato';
console.log('Messaggio manomesso:', messaging.verificaMessaggio(msg1));

// Leggi tutti i messaggi
console.log('\nMessaggi validi:', messaging.leggiMessaggi());
```

---

## 📚 Concetti Appresi

✅ HMAC per autenticazione messaggi  
✅ Timing-safe comparison  
✅ API authentication con HMAC  
✅ JWT semplificato  
✅ Protezione da timing attacks  
✅ Gestione timestamp e TTL  

---

**Autore**: Prof. Filippo Bilardo  
**Corso**: Sistemi e Reti 3  
**Capitolo**: 04 - Hash e Integrità
