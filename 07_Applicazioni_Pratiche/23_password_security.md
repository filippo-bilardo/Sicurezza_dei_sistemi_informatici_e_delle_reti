# Capitolo 23 - Password Security

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Le **password** sono il meccanismo di autenticazione più diffuso, ma anche il più vulnerabile. La sicurezza delle password dipende da:

1. **Utente**: Scelta password forte
2. **Sistema**: Storage e hashing sicuro
3. **Rete**: Trasmissione protetta

⚠️ **Problema**: Password in chiaro → Disastro!

### Violazioni Famose

- **2012 LinkedIn**: 6.5M hash SHA1 senza salt
- **2013 Adobe**: 150M hash 3DES deboli
- **2016 Yahoo**: 3 miliardi di account
- **2019 Collection #1**: 773M password leaked

---

## ❌ Cosa NON Fare

### 1. Password in Chiaro

```python
# ❌ MAI FARE QUESTO!
users = {
    'alice': 'password123',
    'bob': 'qwerty456'
}

def login(username, password):
    return users.get(username) == password
```

**Problema**: Database compromesso → Tutte le password esposte!

### 2. Hash Semplici (MD5, SHA1)

```python
import hashlib

# ❌ INSICURO!
def store_password_bad(password):
    return hashlib.md5(password.encode()).hexdigest()

# Problema: Rainbow tables!
hashed = store_password_bad("password123")
print(hashed)  # 482c811da5d5b4bc6d497ffa98491e38
# Cerca su Google → password originale!
```

### 3. Hash senza Salt

```python
# ❌ VULNERABILE
def hash_no_salt(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Stesse password → stesso hash!
h1 = hash_no_salt("password")
h2 = hash_no_salt("password")
print(f"Match: {h1 == h2}")  # True → attaccante vede duplicati!
```

---

## ✅ Storage Sicuro: Algoritmi Moderni

### 1. bcrypt (2024: ANCORA VALIDO)

**Caratteristiche**:
- Basato su Blowfish
- **Work factor** configurabile (rallentamento)
- Salt automatico integrato
- Resistente a GPU/ASIC

```python
import bcrypt

def register_user(username, password):
    """Registra utente con bcrypt"""
    # Hash password con salt automatico
    salt = bcrypt.gensalt(rounds=12)  # 2^12 iterazioni
    hashed = bcrypt.hashpw(password.encode(), salt)
    
    # Store in database
    return {
        'username': username,
        'password_hash': hashed
    }

def verify_password(password, stored_hash):
    """Verifica password"""
    return bcrypt.checkpw(password.encode(), stored_hash)

# Test
print("=== bcrypt Demo ===\n")

user = register_user("alice", "SuperSecret123!")
print(f"Hash: {user['password_hash']}")

# Verifica corretta
valid = verify_password("SuperSecret123!", user['password_hash'])
print(f"✅ Password corretta: {valid}")

# Verifica errata
invalid = verify_password("WrongPassword", user['password_hash'])
print(f"❌ Password errata: {invalid}")

# Tempo calcolo
import time
start = time.time()
bcrypt.hashpw(b"test", bcrypt.gensalt(rounds=12))
print(f"\n⏱️  Tempo hash (rounds=12): {time.time() - start:.3f}s")
```

**Output**:
```
Hash: b'$2b$12$KIXxNv.../hashed_password_here'
           ^^  ^^ ^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^
           |   |  |           |
           |   |  Salt (22)   Hash (31)
           |   Work factor
           Algoritmo
```

#### Configurazione Work Factor

```python
# Trova work factor ottimale (~100ms)
for rounds in range(10, 15):
    start = time.time()
    bcrypt.hashpw(b"test", bcrypt.gensalt(rounds=rounds))
    elapsed = time.time() - start
    print(f"Rounds {rounds:2d}: {elapsed:.3f}s ({2**rounds:5d} iterations)")

# Output tipico:
# Rounds 10: 0.050s (1024 iterations)
# Rounds 11: 0.100s (2048 iterations)  ← Minimo consigliato
# Rounds 12: 0.200s (4096 iterations)  ← Default buono
# Rounds 13: 0.400s (8192 iterations)
# Rounds 14: 0.800s (16384 iterations) ← High security
```

### 2. scrypt (Memory-Hard)

**Caratteristiche**:
- Richiede **molta memoria** → resistente a GPU/ASIC
- Parametri: N (CPU/memory cost), r (block size), p (parallelization)

```python
import hashlib
import os
import base64

def scrypt_hash(password, salt=None, n=2**14, r=8, p=1):
    """
    Hash con scrypt
    
    N: CPU/memory cost (2^14 = 16384)
    r: block size (8)
    p: parallelization factor (1)
    """
    if salt is None:
        salt = os.urandom(32)
    
    # scrypt key derivation
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32
    )
    
    # Formato: N|r|p|salt|hash (base64)
    result = f"{n}|{r}|{p}|{base64.b64encode(salt).decode()}|{base64.b64encode(key).decode()}"
    return result

def scrypt_verify(password, stored):
    """Verifica password scrypt"""
    parts = stored.split('|')
    n, r, p = int(parts[0]), int(parts[1]), int(parts[2])
    salt = base64.b64decode(parts[3])
    stored_key = base64.b64decode(parts[4])
    
    # Ricalcola hash
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32
    )
    
    return key == stored_key

# Test
print("\n=== scrypt Demo ===\n")

hashed = scrypt_hash("MyPassword123")
print(f"Hash: {hashed[:50]}...")

print(f"✅ Corretta: {scrypt_verify('MyPassword123', hashed)}")
print(f"❌ Errata: {scrypt_verify('WrongPass', hashed)}")
```

### 3. Argon2 (VINCITORE PHC 2015)

**Caratteristiche**:
- **Winner** Password Hashing Competition
- Resistente a GPU, ASIC, side-channel
- 3 varianti: Argon2i, Argon2d, Argon2id

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Argon2id (raccomandato)
ph = PasswordHasher(
    time_cost=2,        # Iterazioni
    memory_cost=102400, # 100 MB
    parallelism=8,      # Thread
    hash_len=32,        # Byte output
    salt_len=16         # Byte salt
)

def argon2_register(username, password):
    """Registra con Argon2"""
    hash = ph.hash(password)
    return {
        'username': username,
        'password_hash': hash
    }

def argon2_verify(password, stored_hash):
    """Verifica password"""
    try:
        ph.verify(stored_hash, password)
        
        # Check se re-hash necessario (parametri cambiati)
        if ph.check_needs_rehash(stored_hash):
            return 'valid_needs_rehash'
        
        return 'valid'
    except VerifyMismatchError:
        return 'invalid'

# Test
print("\n=== Argon2 Demo ===\n")

user = argon2_register("bob", "StrongP@ssw0rd")
print(f"Hash: {user['password_hash']}\n")

# Formato: $argon2id$v=19$m=102400,t=2,p=8$salt$hash
#          ^^^^^^^^^ ^^^^^ ^^^^^^^^^^^^^^^^ ^^^^ ^^^^
#          Variant   Version Parameters    Salt Hash

print(f"✅ Corretta: {argon2_verify('StrongP@ssw0rd', user['password_hash'])}")
print(f"❌ Errata: {argon2_verify('WrongPassword', user['password_hash'])}")
```

---

## Confronto Algoritmi

| Algoritmo | Anno | Tipo | GPU Resist. | ASIC Resist. | Uso 2024 |
|-----------|------|------|-------------|--------------|----------|
| **MD5** | 1992 | Hash | ❌ | ❌ | ❌ DEPRECATO |
| **SHA-1** | 1995 | Hash | ❌ | ❌ | ❌ DEPRECATO |
| **SHA-256** | 2001 | Hash | ❌ | ❌ | ❌ Solo KDF |
| **bcrypt** | 1999 | KDF | ⚠️ Parziale | ✅ | ✅ Ancora OK |
| **scrypt** | 2009 | KDF | ✅ | ✅ | ✅ Buono |
| **Argon2** | 2015 | KDF | ✅ | ✅ | ✅ MIGLIORE |

### Performance Comparison

```python
import time

passwords = ["Test123", "AnotherPassword", "Str0ng!Pass"]

print("\n=== Performance Benchmark ===\n")

# bcrypt
start = time.time()
for pwd in passwords:
    bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))
bcrypt_time = (time.time() - start) / len(passwords)

# scrypt  
start = time.time()
for pwd in passwords:
    scrypt_hash(pwd, n=2**14)
scrypt_time = (time.time() - start) / len(passwords)

# Argon2
start = time.time()
for pwd in passwords:
    ph.hash(pwd)
argon2_time = (time.time() - start) / len(passwords)

print(f"bcrypt:  {bcrypt_time*1000:.1f}ms per hash")
print(f"scrypt:  {scrypt_time*1000:.1f}ms per hash")
print(f"Argon2:  {argon2_time*1000:.1f}ms per hash")
print("\n⚡ Target: 100-500ms (bilanciamento sicurezza/UX)")
```

---

## Salt e Pepper

### Salt

**Salt**: Valore random aggiunto alla password prima dell'hashing.

```python
import os
import hashlib

def hash_with_salt(password):
    """Hash con salt esplicito"""
    salt = os.urandom(32)
    
    # Combina password + salt
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations=100000,
        dklen=32
    )
    
    # Store: salt + hash
    return salt + key

# Test unicità
p1 = hash_with_salt("password")
p2 = hash_with_salt("password")

print(f"Stesso input, hash diversi:")
print(f"Hash1: {p1.hex()[:40]}...")
print(f"Hash2: {p2.hex()[:40]}...")
print(f"✅ Univoci: {p1 != p2}")
```

**Benefici Salt**:
- ✅ Hash diversi per stesse password
- ✅ Invalida rainbow tables pre-calcolate
- ✅ Attaccante deve bruteforce per ogni utente

### Pepper

**Pepper**: Secret key globale (non in DB).

```python
import hmac
import hashlib

# Pepper: stored in environment variable, NOT in database!
PEPPER = "super-secret-server-side-key-32-bytes!!"

def hash_with_pepper(password, salt):
    """Hash con salt + pepper"""
    # Salt in DB, Pepper in config
    salted = salt + password.encode()
    
    # HMAC con pepper
    return hmac.new(
        PEPPER.encode(),
        salted,
        hashlib.sha256
    ).digest()

# Test
salt = os.urandom(16)
h1 = hash_with_pepper("password", salt)

print(f"\n=== Salt vs Pepper ===")
print(f"Salt: In database (pubblico)")
print(f"Pepper: In app config (segreto)")
print(f"✅ DB leak → Attaccante non ha pepper!")
```

---

## Attacchi alle Password

### 1. Brute Force

Prova tutte le combinazioni.

```python
import itertools
import string

def brute_force_demo(target_hash, max_length=4):
    """Demo brute force (solo numeri)"""
    charset = string.digits  # 0-9
    
    attempts = 0
    for length in range(1, max_length + 1):
        for candidate in itertools.product(charset, repeat=length):
            password = ''.join(candidate)
            attempts += 1
            
            # Test
            if hash_password_simple(password) == target_hash:
                return password, attempts
    
    return None, attempts

def hash_password_simple(pwd):
    """Hash semplice per demo"""
    return hashlib.sha256(pwd.encode()).hexdigest()

# Test
target = hash_password_simple("1234")
found, tries = brute_force_demo(target, max_length=4)

print(f"\n=== Brute Force Demo ===")
print(f"Password trovata: {found}")
print(f"Tentativi: {tries:,}")
print(f"Tempo (1M/sec): {tries/1_000_000:.3f}s")

# Password lunghe → tempo astronomico
# 8 char lowercase+digits: 36^8 = 2.8 trilioni
# Tempo (1M/sec): ~32 giorni
```

### 2. Dictionary Attack

Usa wordlist comuni.

```python
# Wordlist comuni
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein",
    "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey"
]

def dictionary_attack(target_hash):
    """Attacco dizionario"""
    for password in COMMON_PASSWORDS:
        if hash_password_simple(password) == target_hash:
            return password
    return None

# Test
weak_hash = hash_password_simple("password")
cracked = dictionary_attack(weak_hash)

print(f"\n=== Dictionary Attack ===")
print(f"Password debole crackata: {cracked}")
print(f"✅ Usa password NON comuni!")
```

### 3. Rainbow Tables

Tabelle pre-calcolate hash→password.

```
MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
MD5("123456")   = e10adc3949ba59abbe56e057f20f883e
...milioni di entry...
```

**Difesa**: **Salt unico** per utente!

```python
# Con salt → rainbow tables inutili!
def demonstrate_salt_protection():
    password = "password"
    
    # Senza salt
    no_salt = hashlib.md5(password.encode()).hexdigest()
    
    # Con salt diversi
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    
    with_salt1 = hashlib.md5(salt1 + password.encode()).hexdigest()
    with_salt2 = hashlib.md5(salt2 + password.encode()).hexdigest()
    
    print("\n=== Rainbow Table Defense ===")
    print(f"No salt:  {no_salt}")
    print(f"Salt 1:   {with_salt1}")
    print(f"Salt 2:   {with_salt2}")
    print(f"✅ Stesso input, hash diversi → rainbow tables inutili!")

demonstrate_salt_protection()
```

### 4. Timing Attacks

Sfrutta differenze di tempo nelle verifiche.

```python
import time

def vulnerable_compare(a, b):
    """❌ Vulnerabile a timing attack"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # ❌ Return anticipato!
    
    return True

def secure_compare(a, b):
    """✅ Constant-time comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y  # XOR, sempre esegue tutto
    
    return result == 0

# O meglio, usa hmac.compare_digest()
import hmac

# Demo
hash1 = b"correct_hash_value"
hash2 = b"aorrect_hash_value"  # Differisce al 1° char

print("\n=== Timing Attack Defense ===")

# Vulnerable
start = time.perf_counter()
vulnerable_compare(hash1, hash2)
time1 = time.perf_counter() - start

# Secure
start = time.perf_counter()
hmac.compare_digest(hash1, hash2)
time2 = time.perf_counter() - start

print(f"Vulnerable: {time1*1e6:.2f}µs")
print(f"Secure: {time2*1e6:.2f}µs")
print("✅ Usa sempre hmac.compare_digest()!")
```

---

## Best Practices

### ✅ Password Policy

```python
import re

def validate_password_strength(password):
    """Valida forza password"""
    errors = []
    
    # Lunghezza minima
    if len(password) < 12:
        errors.append("❌ Minimo 12 caratteri")
    
    # Maiuscole
    if not re.search(r'[A-Z]', password):
        errors.append("❌ Almeno 1 maiuscola")
    
    # Minuscole
    if not re.search(r'[a-z]', password):
        errors.append("❌ Almeno 1 minuscola")
    
    # Numeri
    if not re.search(r'\d', password):
        errors.append("❌ Almeno 1 numero")
    
    # Simboli
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("❌ Almeno 1 simbolo")
    
    # Password comuni (blacklist)
    common = ["password", "12345678", "qwerty"]
    if password.lower() in common:
        errors.append("❌ Password troppo comune!")
    
    if errors:
        return False, errors
    
    return True, ["✅ Password forte!"]

# Test
passwords = [
    "weak",
    "StillWeak123",
    "Str0ng!P@ssw0rd"
]

print("\n=== Password Validation ===\n")
for pwd in passwords:
    valid, messages = validate_password_strength(pwd)
    print(f"'{pwd}':")
    for msg in messages:
        print(f"  {msg}")
    print()
```

### ✅ Sistema Completo

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re

class SecurePasswordManager:
    """Gestore password sicuro"""
    
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8
        )
        self.users = {}  # DB simulato
    
    def register(self, username, password):
        """Registrazione utente"""
        # Validazione
        valid, errors = self._validate(password)
        if not valid:
            return False, errors
        
        # Check username esistente
        if username in self.users:
            return False, ["Username già esistente"]
        
        # Hash password
        password_hash = self.ph.hash(password)
        
        # Store
        self.users[username] = {
            'hash': password_hash,
            'created': time.time()
        }
        
        return True, ["✅ Registrazione completata"]
    
    def login(self, username, password):
        """Login utente"""
        if username not in self.users:
            return False, "Credenziali non valide"
        
        try:
            # Verifica hash
            self.ph.verify(self.users[username]['hash'], password)
            
            # Check rehash necessario
            if self.ph.check_needs_rehash(self.users[username]['hash']):
                # Aggiorna hash con nuovi parametri
                self.users[username]['hash'] = self.ph.hash(password)
            
            return True, "✅ Login riuscito"
        
        except VerifyMismatchError:
            return False, "Credenziali non valide"
    
    def change_password(self, username, old_password, new_password):
        """Cambio password"""
        # Verifica password attuale
        success, _ = self.login(username, old_password)
        if not success:
            return False, "Password attuale errata"
        
        # Valida nuova password
        valid, errors = self._validate(new_password)
        if not valid:
            return False, errors
        
        # Verifica diversa dalla precedente
        if old_password == new_password:
            return False, "Nuova password uguale alla precedente"
        
        # Aggiorna
        self.users[username]['hash'] = self.ph.hash(new_password)
        
        return True, "✅ Password aggiornata"
    
    def _validate(self, password):
        """Validazione password"""
        return validate_password_strength(password)

# Test completo
print("\n=== Sistema Completo ===\n")

manager = SecurePasswordManager()

# Registrazione
success, msg = manager.register("alice", "Weak")
print(f"Registrazione weak: {msg}")

success, msg = manager.register("alice", "Str0ng!P@ssw0rd2024")
print(f"Registrazione strong: {msg[0]}")

# Login
success, msg = manager.login("alice", "wrong")
print(f"Login errato: {msg}")

success, msg = manager.login("alice", "Str0ng!P@ssw0rd2024")
print(f"Login corretto: {msg}")

# Cambio password
success, msg = manager.change_password(
    "alice",
    "Str0ng!P@ssw0rd2024",
    "N3w!Str0ng!P@ss"
)
print(f"Cambio password: {msg}")
```

---

## Raccomandazioni Finali

### Storage

| ✅ FARE | ❌ NON FARE |
|---------|-------------|
| Argon2id (migliore) | Password in chiaro |
| bcrypt (ancora OK) | MD5, SHA1 |
| scrypt (buono) | SHA-256 senza KDF |
| Salt unico per utente | Stesso salt per tutti |
| Pepper server-side | Hash reversibili |

### Policy

- **Lunghezza**: Minimo 12 caratteri (16+ meglio)
- **Complessità**: Maiuscole + minuscole + numeri + simboli
- **Blacklist**: Password comuni bannate
- **Cambio**: Ogni 90 giorni (sistemi critici)
- **Riuso**: Mai riusare password precedenti

### Implementazione

```python
# ✅ Configurazione produzione
PASSWORD_CONFIG = {
    'algorithm': 'argon2id',
    'time_cost': 3,           # Più alto = più sicuro
    'memory_cost': 65536,     # 64 MB
    'parallelism': 4,
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_symbol': True,
    'max_age_days': 90,
    'prevent_reuse': 5        # Ultime 5 password
}
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 22 - Key Management](22_key_management.md)
- **Successivo**: [Capitolo 24 - Crittografia nelle Applicazioni Web](24_crittografia_nelle_applicazioni_web.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- OWASP Password Storage Cheat Sheet
- NIST SP 800-63B: Digital Identity Guidelines
- Argon2: Password Hashing Competition Winner
- RFC 2898: PBKDF2

**Nota**: Le password sono il punto debole! Storage sicuro è FONDAMENTALE.
