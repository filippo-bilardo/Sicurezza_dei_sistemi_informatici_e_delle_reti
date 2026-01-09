# Esercitazione 1 - Funzioni Hash con Node.js

## 📋 Obiettivo

Imparare a utilizzare le funzioni hash crittografiche in Node.js per:
- Calcolare hash di stringhe e file
- Verificare l'integrità dei dati
- Comparare diversi algoritmi hash
- Implementare un sistema di verifica file

**Difficoltà**: ⭐⭐ Intermedio  
**Tempo**: 45-60 minuti  
**Tecnologie**: Node.js, crypto module

---

## 📁 Struttura Progetto

```
es01-hash-nodejs/
├── README.md
├── package.json
├── esempi/
│   ├── 01-hash-base.js
│   ├── 02-hash-file.js
│   ├── 03-verifica-integrita.js
│   └── 04-confronto-algoritmi.js
├── esercizi/
│   ├── file-checker.js
│   └── password-hash.js
└── test-files/
    ├── documento.txt
    ├── immagine.jpg
    └── checksums.txt
```

---

## 🚀 Setup Iniziale

### 1. Crea la cartella del progetto

```bash
mkdir es01-hash-nodejs
cd es01-hash-nodejs
```

### 2. Inizializza progetto Node.js

```bash
npm init -y
```

### 3. Struttura cartelle

```bash
mkdir esempi esercizi test-files
```

**Note**: Il modulo `crypto` è nativo di Node.js, non servono dipendenze esterne!

---

## 📝 Esempi Base

### Esempio 1: Hash di Stringhe (`esempi/01-hash-base.js`)

```javascript
const crypto = require('crypto');

console.log('=== ESEMPIO 1: Hash di Stringhe ===\n');

// Messaggio da hashare
const messaggio = 'Hello, Sicurezza!';

// SHA-256
const sha256 = crypto.createHash('sha256')
    .update(messaggio)
    .digest('hex');

console.log('Messaggio:', messaggio);
console.log('SHA-256:', sha256);
console.log('Lunghezza:', sha256.length, 'caratteri\n');

// SHA-512
const sha512 = crypto.createHash('sha512')
    .update(messaggio)
    .digest('hex');

console.log('SHA-512:', sha512);
console.log('Lunghezza:', sha512.length, 'caratteri\n');

// MD5 (deprecato, solo a scopo educativo)
const md5 = crypto.createHash('md5')
    .update(messaggio)
    .digest('hex');

console.log('MD5 (deprecato):', md5);
console.log('Lunghezza:', md5.length, 'caratteri\n');

// Avalanche effect - piccola modifica, hash completamente diverso
const messaggio2 = 'Hello, Sicurezza.'; // Cambiato ! in .
const sha256_2 = crypto.createHash('sha256')
    .update(messaggio2)
    .digest('hex');

console.log('--- AVALANCHE EFFECT ---');
console.log('Messaggio 1:', messaggio);
console.log('SHA-256:    ', sha256);
console.log('\nMessaggio 2:', messaggio2);
console.log('SHA-256:    ', sha256_2);
console.log('\nDiversi?', sha256 !== sha256_2);
```

**Eseguilo:**
```bash
node esempi/01-hash-base.js
```

**Output atteso:**
```
=== ESEMPIO 1: Hash di Stringhe ===

Messaggio: Hello, Sicurezza!
SHA-256: 7a8c5c... (64 caratteri)
Lunghezza: 64 caratteri

SHA-512: 3f9d8b... (128 caratteri)
...
```

---

### Esempio 2: Hash di File (`esempi/02-hash-file.js`)

```javascript
const crypto = require('crypto');
const fs = require('fs');

console.log('=== ESEMPIO 2: Hash di File ===\n');

/**
 * Calcola hash di un file
 * @param {string} filePath - Percorso del file
 * @param {string} algorithm - Algoritmo hash (default: sha256)
 * @returns {Promise<string>} Hash del file
 */
function hashFile(filePath, algorithm = 'sha256') {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash(algorithm);
        const stream = fs.createReadStream(filePath);
        
        stream.on('error', reject);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
    });
}

// Crea un file di test
const testFile = 'test-files/documento.txt';
const content = 'Questo è un documento importante.\nNon deve essere modificato!';

// Crea la cartella se non esiste
if (!fs.existsSync('test-files')) {
    fs.mkdirSync('test-files');
}

fs.writeFileSync(testFile, content);

// Calcola hash del file
hashFile(testFile)
    .then(hash => {
        console.log('File:', testFile);
        console.log('SHA-256:', hash);
        console.log('\n✅ Hash calcolato con successo!');
        
        // Salva l'hash per verifica futura
        fs.writeFileSync('test-files/documento.txt.sha256', hash);
        console.log('💾 Hash salvato in: documento.txt.sha256');
    })
    .catch(error => {
        console.error('❌ Errore:', error.message);
    });
```

**Eseguilo:**
```bash
node esempi/02-hash-file.js
```

---

### Esempio 3: Verifica Integrità (`esempi/03-verifica-integrita.js`)

```javascript
const crypto = require('crypto');
const fs = require('fs');

console.log('=== ESEMPIO 3: Verifica Integrità File ===\n');

/**
 * Calcola hash di un file
 */
function hashFile(filePath, algorithm = 'sha256') {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash(algorithm);
        const stream = fs.createReadStream(filePath);
        
        stream.on('error', reject);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
    });
}

/**
 * Verifica integrità di un file
 * @param {string} filePath - File da verificare
 * @param {string} expectedHash - Hash atteso
 * @returns {Promise<boolean>} True se integro
 */
async function verificaIntegrita(filePath, expectedHash) {
    try {
        const actualHash = await hashFile(filePath);
        return actualHash === expectedHash.toLowerCase();
    } catch (error) {
        console.error('Errore nella verifica:', error.message);
        return false;
    }
}

// Test: crea file e calcola hash
const testFile = 'test-files/documento.txt';
const content = 'Documento originale importante';

if (!fs.existsSync('test-files')) {
    fs.mkdirSync('test-files');
}

fs.writeFileSync(testFile, content);

(async () => {
    // Calcola hash originale
    const hashOriginale = await hashFile(testFile);
    console.log('📄 File originale:', testFile);
    console.log('🔐 Hash originale:', hashOriginale);
    
    // Test 1: Verifica file non modificato
    console.log('\n--- TEST 1: File non modificato ---');
    const verifica1 = await verificaIntegrita(testFile, hashOriginale);
    console.log(verifica1 ? '✅ File integro!' : '❌ File corrotto!');
    
    // Test 2: Modifica il file
    console.log('\n--- TEST 2: File modificato ---');
    fs.appendFileSync(testFile, '\n[MODIFICATO]');
    const verifica2 = await verificaIntegrita(testFile, hashOriginale);
    console.log(verifica2 ? '✅ File integro!' : '❌ File corrotto!');
    
    // Test 3: Ripristina file
    console.log('\n--- TEST 3: File ripristinato ---');
    fs.writeFileSync(testFile, content);
    const verifica3 = await verificaIntegrita(testFile, hashOriginale);
    console.log(verifica3 ? '✅ File integro!' : '❌ File corrotto!');
})();
```

**Eseguilo:**
```bash
node esempi/03-verifica-integrita.js
```

**Output atteso:**
```
📄 File originale: test-files/documento.txt
🔐 Hash originale: a8f3e7...

--- TEST 1: File non modificato ---
✅ File integro!

--- TEST 2: File modificato ---
❌ File corrotto!

--- TEST 3: File ripristinato ---
✅ File integro!
```

---

### Esempio 4: Confronto Algoritmi (`esempi/04-confronto-algoritmi.js`)

```javascript
const crypto = require('crypto');
const { performance } = require('perf_hooks');

console.log('=== ESEMPIO 4: Confronto Algoritmi Hash ===\n');

const messaggio = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(100);
const algoritmi = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];

console.log('Messaggio:', messaggio.length, 'bytes\n');
console.log('Algoritmo'.padEnd(12), 'Hash Length', 'Tempo (ms)', 'Stato');
console.log('-'.repeat(70));

algoritmi.forEach(algo => {
    const start = performance.now();
    
    const hash = crypto.createHash(algo)
        .update(messaggio)
        .digest('hex');
    
    const end = performance.now();
    const tempo = (end - start).toFixed(4);
    
    let stato = '';
    if (algo === 'md5') stato = '❌ ROTTO';
    else if (algo === 'sha1') stato = '⚠️  DEPRECATO';
    else stato = '✅ SICURO';
    
    console.log(
        algo.padEnd(12),
        (hash.length + ' chars').padEnd(11),
        tempo.padStart(10),
        stato
    );
});

console.log('\n💡 Raccomandazione: Usa SHA-256 o superiore');
```

**Eseguilo:**
```bash
node esempi/04-confronto-algoritmi.js
```

---

## 💪 Esercizi Pratici

### Esercizio 1: File Integrity Checker (`esercizi/file-checker.js`)

Crea un programma che:
1. Prende un file come argomento
2. Calcola SHA-256 del file
3. Salva l'hash in `filename.sha256`
4. Permette di verificare l'integrità in seguito

**Scheletro:**

```javascript
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Calcola e salva hash di un file
 */
function calculateAndSaveHash(filePath) {
    // TODO: Implementa
    // 1. Controlla se file esiste
    // 2. Calcola SHA-256
    // 3. Salva in filePath.sha256
    // 4. Stampa risultato
}

/**
 * Verifica hash di un file
 */
function verifyFileHash(filePath) {
    // TODO: Implementa
    // 1. Leggi hash da filePath.sha256
    // 2. Calcola hash attuale del file
    // 3. Confronta
    // 4. Stampa risultato
}

// Parse argomenti command line
const args = process.argv.slice(2);
const comando = args[0];
const filePath = args[1];

if (!comando || !filePath) {
    console.log('Uso:');
    console.log('  node file-checker.js hash <file>    - Calcola hash');
    console.log('  node file-checker.js verify <file>  - Verifica hash');
    process.exit(1);
}

if (comando === 'hash') {
    calculateAndSaveHash(filePath);
} else if (comando === 'verify') {
    verifyFileHash(filePath);
} else {
    console.error('Comando non valido:', comando);
}
```

**Test:**
```bash
# Crea un file test
echo "Documento importante" > test.txt

# Calcola hash
node esercizi/file-checker.js hash test.txt

# Verifica (dovrebbe passare)
node esercizi/file-checker.js verify test.txt

# Modifica file
echo "MODIFICATO" >> test.txt

# Verifica (dovrebbe fallire)
node esercizi/file-checker.js verify test.txt
```

---

### Esercizio 2: Password Hashing (`esercizi/password-hash.js`)

**Obiettivo**: Implementa un sistema di hash per password usando algoritmi appropriati.

**Nota importante**: Per password NON usare hash semplici! Usa algoritmi come bcrypt, scrypt o argon2.

Questo esercizio mostra perché:

```javascript
const crypto = require('crypto');

console.log('=== Password Hashing - ESEMPIO ERRATO vs CORRETTO ===\n');

// ❌ METODO ERRATO: Hash semplice
function hashPasswordWRONG(password) {
    return crypto.createHash('sha256')
        .update(password)
        .digest('hex');
}

// ✅ METODO CORRETTO: Hash + Salt
function hashPasswordCorrect(password) {
    // Genera salt casuale (16 bytes = 128 bit)
    const salt = crypto.randomBytes(16).toString('hex');
    
    // Hash password con salt usando PBKDF2
    const hash = crypto.pbkdf2Sync(
        password,
        salt,
        100000,  // Iterazioni (più alto = più sicuro ma più lento)
        64,      // Lunghezza output
        'sha512' // Algoritmo
    ).toString('hex');
    
    // Restituisci salt + hash
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    const [salt, originalHash] = storedHash.split(':');
    
    // Ricalcola hash con stesso salt
    const hash = crypto.pbkdf2Sync(
        password,
        salt,
        100000,
        64,
        'sha512'
    ).toString('hex');
    
    return hash === originalHash;
}

// TEST
const password = 'MySecretPassword123!';

// Metodo errato
console.log('--- METODO ERRATO (SHA-256 semplice) ---');
const hashErrato = hashPasswordWRONG(password);
console.log('Password:', password);
console.log('Hash:', hashErrato);
console.log('❌ Problema: Stesso hash per stessa password (rainbow table attack!)');
console.log('❌ Problema: Veloce da calcolare (brute force facile)');

// Metodo corretto
console.log('\n--- METODO CORRETTO (PBKDF2 + Salt) ---');
const hashCorretto1 = hashPasswordCorrect(password);
const hashCorretto2 = hashPasswordCorrect(password);

console.log('Password:', password);
console.log('Hash 1:', hashCorretto1);
console.log('Hash 2:', hashCorretto2);
console.log('✅ Stesso password, hash diversi (grazie al salt)!');

// Verifica
console.log('\n--- VERIFICA PASSWORD ---');
console.log('Password corretta?', verifyPassword(password, hashCorretto1));
console.log('Password errata?', verifyPassword('WrongPassword', hashCorretto1));
```

**Eseguilo:**
```bash
node esercizi/password-hash.js
```

---

## 🎯 Compiti per Casa

1. **Completa `file-checker.js`**: Implementa le funzioni mancanti
2. **Estendi il checker**: Aggiungi supporto per multipli file (checksum di una cartella)
3. **Download verifier**: Crea script che scarica un file e verifica l'hash (come fa apt, npm, etc.)
4. **Performance test**: Confronta prestazioni di diversi algoritmi su file grandi (>100MB)

---

## 📚 Concetti Appresi

✅ Calcolare hash con il modulo `crypto` di Node.js  
✅ Hashare file usando streams  
✅ Verificare integrità dei dati  
✅ Confrontare algoritmi hash  
✅ Differenza tra hash semplici e salted hash  
✅ PBKDF2 per password  

---

## 🔗 Risorse

- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [PBKDF2 Specification](https://tools.ietf.org/html/rfc2898)
- [NIST Hash Functions](https://csrc.nist.gov/projects/hash-functions)

---

**Autore**: Prof. Filippo Bilardo  
**Corso**: Sistemi e Reti 3  
**Capitolo**: 04 - Hash e Integrità
