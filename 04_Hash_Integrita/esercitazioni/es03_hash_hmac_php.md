# Esercitazione 3 - Hash e HMAC con PHP


## 📋 Obiettivo

Imparare a utilizzare funzioni hash e HMAC in PHP per:
- Calcolare hash con diversi algoritmi
- Hashare password in modo sicuro
- Implementare HMAC per autenticazione
- Creare un sistema di login sicuro

**Difficoltà**: ⭐⭐ Intermedio  
**Tempo**: 60-75 minuti  
**Tecnologie**: PHP 8+, password_hash, hash_hmac

[ACN-GPDP Linee Guida Conservazione Password.pdf](https://www.garanteprivacy.it/web/guest/home/docweb/-/docweb-display/docweb/9962384)
---

## 📁 Struttura Progetto

```
es03-hash-hmac-php/
├── README.md
├── esempi/
│   ├── 01-hash-base.php
│   ├── 02-password-hash.php
│   ├── 03-hmac-base.php
│   └── 04-file-hash.php
├── progetti/
│   ├── login-system/
│   │   ├── index.php
│   │   ├── register.php
│   │   ├── login.php
│   │   ├── dashboard.php
│   │   ├── logout.php
│   │   └── db.php
│   └── api-auth/
│       ├── server.php
│       └── client.php
└── esercizi/
    └── session-token.php
```

---

## 🚀 Setup Iniziale

```bash
mkdir es03-hash-hmac-php
cd es03-hash-hmac-php
mkdir esempi progetti esercizi
```

**Requisiti:**
- PHP 8.0 o superiore
- Estensione `hash` (inclusa di default)
- Estensione `password` (inclusa di default)

**Verifica installazione:**
```bash
php -v
php -m | grep hash
```

---

## 📝 Esempi Base

### Esempio 1: Hash Base (`esempi/01-hash-base.php`)

```php
<?php
/**
 * Esempio 1: Funzioni Hash Base
 * Dimostra l'uso di diversi algoritmi hash
 */

echo "=== ESEMPIO 1: Hash di Stringhe ===\n\n";

$messaggio = "Hello, Sicurezza!";

// SHA-256
$sha256 = hash('sha256', $messaggio);
echo "Messaggio: $messaggio\n";
echo "SHA-256: $sha256\n";
echo "Lunghezza: " . strlen($sha256) . " caratteri\n\n";

// SHA-512
$sha512 = hash('sha512', $messaggio);
echo "SHA-512: $sha512\n";
echo "Lunghezza: " . strlen($sha512) . " caratteri\n\n";

// MD5 (deprecato, solo educativo)
$md5 = md5($messaggio);
echo "MD5 (deprecato): $md5\n";
echo "Lunghezza: " . strlen($md5) . " caratteri\n\n";

// Avalanche Effect
echo "--- AVALANCHE EFFECT ---\n";
$messaggio1 = "Hello, Sicurezza!";
$messaggio2 = "Hello, Sicurezza."; // Cambiato ! in .

$hash1 = hash('sha256', $messaggio1);
$hash2 = hash('sha256', $messaggio2);

echo "Messaggio 1: $messaggio1\n";
echo "SHA-256:     $hash1\n\n";
echo "Messaggio 2: $messaggio2\n";
echo "SHA-256:     $hash2\n\n";
echo "Hash diversi? " . ($hash1 !== $hash2 ? "✅ Sì" : "❌ No") . "\n\n";

// Lista algoritmi disponibili
echo "--- ALGORITMI DISPONIBILI ---\n";
$algoritmi = hash_algos();
echo "Totale: " . count($algoritmi) . " algoritmi\n";
echo "Alcuni esempi: " . implode(', ', array_slice($algoritmi, 0, 10)) . "...\n\n";

// Confronto prestazioni
echo "--- CONFRONTO PRESTAZIONI ---\n";
$dati = str_repeat("Lorem ipsum dolor sit amet. ", 1000);
$algoritmi_test = ['md5', 'sha1', 'sha256', 'sha512'];

foreach ($algoritmi_test as $algo) {
    $start = microtime(true);
    hash($algo, $dati);
    $tempo = (microtime(true) - $start) * 1000;
    
    $stato = match($algo) {
        'md5' => '❌ ROTTO',
        'sha1' => '⚠️  DEPRECATO',
        default => '✅ SICURO'
    };
    
    printf("%-10s: %6.4f ms - %s\n", strtoupper($algo), $tempo, $stato);
}

echo "\n💡 Raccomandazione: Usa SHA-256 o superiore\n";
?>
```

**Eseguilo:**
```bash
php esempi/01-hash-base.php
```

---

### Esempio 2: Password Hashing (`esempi/02-password-hash.php`)

```php
<?php
/**
 * Esempio 2: Password Hashing Sicuro
 * Mostra il modo CORRETTO di hashare password
 */

echo "=== ESEMPIO 2: Password Hashing ===\n\n";

$password = "MySecurePassword123!";

// ❌ METODO ERRATO: Hash semplice
echo "--- METODO ERRATO (SHA-256 semplice) ---\n";
$hashErrato = hash('sha256', $password);
echo "Password: $password\n";
echo "Hash SHA-256: $hashErrato\n";
echo "❌ Problema 1: Stesso hash per stessa password (rainbow table!)\n";
echo "❌ Problema 2: Veloce da calcolare (brute force facile)\n";
echo "❌ Problema 3: Nessun salt automatico\n\n";

// ✅ METODO CORRETTO: password_hash()
echo "--- METODO CORRETTO (password_hash con bcrypt) ---\n";
$hashCorretto = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
echo "Password: $password\n";
echo "Hash bcrypt: $hashCorretto\n";
echo "Lunghezza: " . strlen($hashCorretto) . " caratteri\n";
echo "✅ Salt automatico incluso nel hash\n";
echo "✅ Cost factor regolabile (12 = 2^12 iterazioni)\n";
echo "✅ Algoritmo resistente a brute force\n\n";

// Dimostra che lo stesso password genera hash diversi (grazie al salt)
echo "--- STESSO PASSWORD, HASH DIVERSI ---\n";
$hash1 = password_hash($password, PASSWORD_BCRYPT);
$hash2 = password_hash($password, PASSWORD_BCRYPT);
echo "Hash 1: $hash1\n";
echo "Hash 2: $hash2\n";
echo "Diversi? " . ($hash1 !== $hash2 ? "✅ Sì (grazie al salt!)" : "❌ No") . "\n\n";

// Verifica password
echo "--- VERIFICA PASSWORD ---\n";
$hashMemorizzato = password_hash($password, PASSWORD_BCRYPT);

// Password corretta
$passwordInput = "MySecurePassword123!";
$verifica1 = password_verify($passwordInput, $hashMemorizzato);
echo "Password corretta ('$passwordInput'): ";
echo $verifica1 ? "✅ VALIDA" : "❌ INVALIDA";
echo "\n";

// Password errata
$passwordInput2 = "WrongPassword";
$verifica2 = password_verify($passwordInput2, $hashMemorizzato);
echo "Password errata ('$passwordInput2'): ";
echo $verifica2 ? "✅ VALIDA" : "❌ INVALIDA";
echo "\n\n";

// Controllo se rehash necessario
echo "--- REHASH PASSWORD ---\n";
echo "L'hash necessita di essere rigenerato? ";
$needsRehash = password_needs_rehash($hashMemorizzato, PASSWORD_BCRYPT, ['cost' => 12]);
echo $needsRehash ? "⚠️  Sì, rigenera!" : "✅ No, ok";
echo "\n\n";

// Algoritmi disponibili
echo "--- ALGORITMI PASSWORD DISPONIBILI ---\n";
echo "PASSWORD_DEFAULT: " . PASSWORD_DEFAULT . " (attualmente bcrypt)\n";
echo "PASSWORD_BCRYPT: " . PASSWORD_BCRYPT . "\n";
if (defined('PASSWORD_ARGON2I')) {
    echo "PASSWORD_ARGON2I: " . PASSWORD_ARGON2I . " (PHP 7.2+)\n";
}
if (defined('PASSWORD_ARGON2ID')) {
    echo "PASSWORD_ARGON2ID: " . PASSWORD_ARGON2ID . " (PHP 7.3+)\n";
}

echo "\n💡 Usa sempre password_hash() e password_verify()!\n";
?>
```

**Eseguilo:**
```bash
php esempi/02-password-hash.php
```

---

### Esempio 3: HMAC Base (`esempi/03-hmac-base.php`)

```php
<?php
/**
 * Esempio 3: HMAC (Hash-based Message Authentication Code)
 * Autenticazione e integrità dei messaggi
 */

echo "=== ESEMPIO 3: HMAC Base ===\n\n";

// Chiave segreta condivisa
$chiaveSegreta = "supersecretkey123!@#";

// Messaggio da autenticare
$messaggio = "Trasferimento: 1000 EUR a Bob";

// Calcola HMAC-SHA256
$hmac = hash_hmac('sha256', $messaggio, $chiaveSegreta);

echo "Messaggio: $messaggio\n";
echo "Chiave: $chiaveSegreta\n";
echo "HMAC-SHA256: $hmac\n";
echo "Lunghezza: " . strlen($hmac) . " caratteri\n\n";

/**
 * Verifica HMAC in modo sicuro (timing-safe)
 */
function verificaHMAC($messaggio, $hmacRicevuto, $chiave) {
    $hmacCalcolato = hash_hmac('sha256', $messaggio, $chiave);
    
    // ✅ METODO SICURO: hash_equals() è timing-safe
    return hash_equals($hmacCalcolato, $hmacRicevuto);
}

echo "--- VERIFICA HMAC ---\n";

// Test 1: Messaggio originale
$verifica1 = verificaHMAC($messaggio, $hmac, $chiaveSegreta);
echo "Messaggio originale: " . ($verifica1 ? "✅ Autentico" : "❌ Falso") . "\n";

// Test 2: Messaggio modificato
$messaggioModificato = "Trasferimento: 9999 EUR a Bob";
$verifica2 = verificaHMAC($messaggioModificato, $hmac, $chiaveSegreta);
echo "Messaggio modificato: " . ($verifica2 ? "✅ Autentico" : "❌ Falso") . "\n";

// Test 3: Chiave errata
$chiaveErrata = "wrongkey";
$verifica3 = verificaHMAC($messaggio, $hmac, $chiaveErrata);
echo "Chiave errata: " . ($verifica3 ? "✅ Autentico" : "❌ Falso") . "\n\n";

// Dimostrazione timing attack
echo "--- TIMING ATTACK DEMO ---\n";

function verificaUnsafe($hmac1, $hmac2) {
    // ❌ VULNERABILE: Confronto NON timing-safe
    return $hmac1 === $hmac2; // Esce appena trova differenza!
}

function verificaSafe($hmac1, $hmac2) {
    // ✅ SICURO: Confronto timing-safe
    return hash_equals($hmac1, $hmac2); // Tempo costante
}

echo "⚠️  NON usare === per confrontare HMAC!\n";
echo "✅ USA hash_equals() per prevenire timing attacks\n\n";

// Esempio messaggio autenticato
echo "--- MESSAGGIO AUTENTICATO COMPLETO ---\n";

function creaMessaggioAutenticato($contenuto, $chiave) {
    $timestamp = time();
    $payload = json_encode([
        'contenuto' => $contenuto,
        'timestamp' => $timestamp
    ]);
    
    $hmac = hash_hmac('sha256', $payload, $chiave);
    
    return [
        'payload' => $payload,
        'hmac' => $hmac,
        'timestamp' => $timestamp
    ];
}

function verificaMessaggioAutenticato($messaggio, $chiave, $ttl = 300) {
    // 1. Verifica HMAC
    $hmacCalcolato = hash_hmac('sha256', $messaggio['payload'], $chiave);
    if (!hash_equals($hmacCalcolato, $messaggio['hmac'])) {
        return ['valido' => false, 'errore' => 'HMAC non valido'];
    }
    
    // 2. Verifica timestamp (TTL = 5 minuti default)
    $now = time();
    if ($now - $messaggio['timestamp'] > $ttl) {
        return ['valido' => false, 'errore' => 'Messaggio scaduto'];
    }
    
    // 3. Decodifica payload
    $dati = json_decode($messaggio['payload'], true);
    
    return ['valido' => true, 'dati' => $dati];
}

$msg = creaMessaggioAutenticato("Ordine #12345 confermato", $chiaveSegreta);
echo "Payload: {$msg['payload']}\n";
echo "HMAC: {$msg['hmac']}\n";
echo "Timestamp: " . date('Y-m-d H:i:s', $msg['timestamp']) . "\n\n";

$verifica = verificaMessaggioAutenticato($msg, $chiaveSegreta);
echo "Verifica: " . ($verifica['valido'] ? "✅ VALIDO" : "❌ NON VALIDO") . "\n";
if ($verifica['valido']) {
    echo "Contenuto: {$verifica['dati']['contenuto']}\n";
}
?>
```

**Eseguilo:**
```bash
php esempi/03-hmac-base.php
```

---

### Esempio 4: Hash di File (`esempi/04-file-hash.php`)

```php
<?php
/**
 * Esempio 4: Hash di File
 * Calcolo e verifica integrità file
 */

echo "=== ESEMPIO 4: Hash di File ===\n\n";

// Crea un file di test
$nomeFile = 'test-documento.txt';
$contenuto = "Questo è un documento importante.\nNon deve essere modificato!";
file_put_contents($nomeFile, $contenuto);

echo "File creato: $nomeFile\n";
echo "Contenuto: " . strlen($contenuto) . " bytes\n\n";

/**
 * Calcola hash di un file
 */
function hashFile($filePath, $algoritmo = 'sha256') {
    if (!file_exists($filePath)) {
        throw new Exception("File non trovato: $filePath");
    }
    
    return hash_file($algoritmo, $filePath);
}

// Calcola hash del file
$hashOriginale = hashFile($nomeFile);
echo "--- HASH ORIGINALE ---\n";
echo "SHA-256: $hashOriginale\n";

// Salva hash
$fileHash = $nomeFile . '.sha256';
file_put_contents($fileHash, $hashOriginale);
echo "💾 Hash salvato in: $fileHash\n\n";

// Test 1: Verifica file non modificato
echo "--- TEST 1: File non modificato ---\n";
$hashAttuale = hashFile($nomeFile);
$integro1 = hash_equals($hashOriginale, $hashAttuale);
echo "Hash attuale: $hashAttuale\n";
echo "Risultato: " . ($integro1 ? "✅ File integro" : "❌ File corrotto") . "\n\n";

// Test 2: Modifica il file
echo "--- TEST 2: File modificato ---\n";
file_put_contents($nomeFile, $contenuto . "\n[MODIFICATO]");
$hashAttuale2 = hashFile($nomeFile);
$integro2 = hash_equals($hashOriginale, $hashAttuale2);
echo "Hash attuale: $hashAttuale2\n";
echo "Risultato: " . ($integro2 ? "✅ File integro" : "❌ File corrotto") . "\n\n";

// Test 3: Ripristina file
echo "--- TEST 3: File ripristinato ---\n";
file_put_contents($nomeFile, $contenuto);
$hashAttuale3 = hashFile($nomeFile);
$integro3 = hash_equals($hashOriginale, $hashAttuale3);
echo "Hash attuale: $hashAttuale3\n";
echo "Risultato: " . ($integro3 ? "✅ File integro" : "❌ File corrotto") . "\n\n";

// Calcola hash di file grandi con stream
echo "--- HASH CON STREAM (file grandi) ---\n";

function hashFileStream($filePath, $algoritmo = 'sha256') {
    $context = hash_init($algoritmo);
    $handle = fopen($filePath, 'rb');
    
    while (!feof($handle)) {
        $chunk = fread($handle, 8192); // 8KB alla volta
        hash_update($context, $chunk);
    }
    
    fclose($handle);
    return hash_final($context);
}

$hashStream = hashFileStream($nomeFile);
echo "Hash con stream: $hashStream\n";
echo "Uguale a hash_file()? " . (hash_equals($hashStream, $hashOriginale) ? "✅ Sì" : "❌ No") . "\n\n";

// Cleanup
unlink($nomeFile);
unlink($fileHash);
echo "🗑️  File di test eliminati\n";
?>
```

**Eseguilo:**
```bash
php esempi/04-file-hash.php
```

---

## 🚀 Progetti Completi

### Progetto 1: Sistema di Login Sicuro (`progetti/login-system/`)

Sistema completo di registrazione e login con password hashing.

#### `progetti/login-system/db.php`

```php
<?php
/**
 * Database semplificato (in-memory con sessioni)
 * In produzione: usa MySQL/PostgreSQL!
 */

session_start();

// Inizializza "database" in sessione
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [];
}

class DB {
    /**
     * Registra nuovo utente
     */
    public static function registerUser($email, $password, $nome) {
        // Verifica se utente esiste
        if (self::userExists($email)) {
            return ['success' => false, 'error' => 'Email già registrata'];
        }
        
        // Valida password
        if (strlen($password) < 8) {
            return ['success' => false, 'error' => 'Password deve essere almeno 8 caratteri'];
        }
        
        // Hash password (bcrypt con cost 12)
        $hashPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Salva utente
        $_SESSION['users'][$email] = [
            'email' => $email,
            'password' => $hashPassword,
            'nome' => $nome,
            'created_at' => time()
        ];
        
        return ['success' => true, 'message' => 'Registrazione completata!'];
    }
    
    /**
     * Login utente
     */
    public static function loginUser($email, $password) {
        // Verifica se utente esiste
        if (!self::userExists($email)) {
            return ['success' => false, 'error' => 'Email o password errati'];
        }
        
        $user = $_SESSION['users'][$email];
        
        // Verifica password
        if (!password_verify($password, $user['password'])) {
            return ['success' => false, 'error' => 'Email o password errati'];
        }
        
        // Controlla se hash deve essere rigenerato
        if (password_needs_rehash($user['password'], PASSWORD_BCRYPT, ['cost' => 12])) {
            $_SESSION['users'][$email]['password'] = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        }
        
        // Imposta sessione
        $_SESSION['logged_in'] = true;
        $_SESSION['user_email'] = $email;
        $_SESSION['user_nome'] = $user['nome'];
        
        return ['success' => true, 'message' => 'Login effettuato!'];
    }
    
    /**
     * Logout utente
     */
    public static function logoutUser() {
        unset($_SESSION['logged_in']);
        unset($_SESSION['user_email']);
        unset($_SESSION['user_nome']);
    }
    
    /**
     * Verifica se utente esiste
     */
    public static function userExists($email) {
        return isset($_SESSION['users'][$email]);
    }
    
    /**
     * Verifica se utente è loggato
     */
    public static function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    /**
     * Ottieni informazioni utente corrente
     */
    public static function getCurrentUser() {
        if (!self::isLoggedIn()) {
            return null;
        }
        
        return [
            'email' => $_SESSION['user_email'],
            'nome' => $_SESSION['user_nome']
        ];
    }
}
?>
```

#### `progetti/login-system/index.php`

```php
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema Login Sicuro</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
            text-align: center;
        }
        h1 { color: #333; margin-bottom: 30px; }
        .button {
            display: inline-block;
            padding: 15px 40px;
            margin: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        .button:hover { transform: translateY(-2px); }
        .info {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            text-align: left;
        }
        .info h3 { color: #667eea; margin-bottom: 10px; }
        .info ul { list-style: none; padding-left: 0; }
        .info li { margin: 5px 0; padding-left: 20px; position: relative; }
        .info li:before { content: "✓"; position: absolute; left: 0; color: #667eea; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Sistema Login Sicuro</h1>
        <p style="color: #666; margin-bottom: 30px;">
            Esempio di autenticazione sicura con PHP
        </p>
        
        <a href="register.php" class="button">📝 Registrati</a>
        <a href="login.php" class="button">🔑 Accedi</a>
        
        <div class="info">
            <h3>🛡️ Sicurezza implementata:</h3>
            <ul>
                <li>Password hashing con bcrypt</li>
                <li>Salt automatico</li>
                <li>Cost factor 12 (4096 iterazioni)</li>
                <li>Sessioni PHP sicure</li>
                <li>Validazione input</li>
            </ul>
        </div>
    </div>
</body>
</html>
```

#### `progetti/login-system/register.php`

```php
<?php
require_once 'db.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';
    $nome = htmlspecialchars($_POST['nome'] ?? '');
    
    if (!$email) {
        $error = 'Email non valida';
    } else {
        $result = DB::registerUser($email, $password, $nome);
        
        if ($result['success']) {
            $success = $result['message'];
        } else {
            $error = $result['error'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrazione</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
        }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .success {
            background: #efe;
            color: #3c3;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 Registrazione</h1>
        
        <?php if ($error): ?>
            <div class="error">❌ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?= htmlspecialchars($success) ?> 
                <a href="login.php">Vai al login</a>
            </div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="form-group">
                <label>👤 Nome</label>
                <input type="text" name="nome" required>
            </div>
            
            <div class="form-group">
                <label>📧 Email</label>
                <input type="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label>🔑 Password (min 8 caratteri)</label>
                <input type="password" name="password" required minlength="8">
            </div>
            
            <button type="submit">Registrati</button>
        </form>
        
        <div class="link">
            Hai già un account? <a href="login.php">Accedi</a>
        </div>
    </div>
</body>
</html>
```

#### `progetti/login-system/login.php`

```php
<?php
require_once 'db.php';

// Se già loggato, redirect alla dashboard
if (DB::isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';
    
    if (!$email) {
        $error = 'Email non valida';
    } else {
        $result = DB::loginUser($email, $password);
        
        if ($result['success']) {
            header('Location: dashboard.php');
            exit;
        } else {
            $error = $result['error'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
        }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Login</h1>
        
        <?php if ($error): ?>
            <div class="error">❌ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="form-group">
                <label>📧 Email</label>
                <input type="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label>🔑 Password</label>
                <input type="password" name="password" required>
            </div>
            
            <button type="submit">Accedi</button>
        </form>
        
        <div class="link">
            Non hai un account? <a href="register.php">Registrati</a>
        </div>
    </div>
</body>
</html>
```

#### `progetti/login-system/dashboard.php`

```php
<?php
require_once 'db.php';

// Controlla se loggato
if (!DB::isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$user = DB::getCurrentUser();
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 600px;
            text-align: center;
        }
        h1 { color: #333; margin-bottom: 20px; }
        .user-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .user-info p { margin: 10px 0; color: #555; }
        .button {
            display: inline-block;
            padding: 12px 30px;
            background: #e74c3c;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin-top: 20px;
        }
        .button:hover { opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Dashboard</h1>
        <p style="color: #666;">Benvenuto nella tua area riservata!</p>
        
        <div class="user-info">
            <p><strong>👤 Nome:</strong> <?= htmlspecialchars($user['nome']) ?></p>
            <p><strong>📧 Email:</strong> <?= htmlspecialchars($user['email']) ?></p>
        </div>
        
        <p style="color: #666; margin: 20px 0;">
            ✅ La tua password è stata hashata con bcrypt<br>
            ✅ La sessione è protetta<br>
            ✅ I dati sono al sicuro
        </p>
        
        <a href="logout.php" class="button">🚪 Logout</a>
    </div>
</body>
</html>
```

#### `progetti/login-system/logout.php`

```php
<?php
require_once 'db.php';

DB::logoutUser();
header('Location: index.php');
exit;
?>
```

**Avvio del progetto:**
```bash
cd progetti/login-system
php -S localhost:8000
# Apri http://localhost:8000
```

---

## 📚 Concetti Appresi

✅ Funzioni hash in PHP (hash, md5, sha256)  
✅ Password hashing sicuro (password_hash, password_verify)  
✅ HMAC per autenticazione (hash_hmac, hash_equals)  
✅ Hash di file (hash_file, hash_init/update/final)  
✅ Sistema di login completo  
✅ Protezione da timing attacks  
✅ Best practices di sicurezza  

---

**Autore**: Prof. Filippo Bilardo  
**Corso**: Sistemi e Reti 3  
**Capitolo**: 04 - Hash e Integrità
