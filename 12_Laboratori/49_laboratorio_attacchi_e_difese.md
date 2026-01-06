# Capitolo 49 - Laboratorio: Attacchi e Difese

> **Corso**: Sistemi e Reti 3  
> **Parte**: 12 - Laboratori Pratici  
> **Autore**: Prof. Filippo Bilardo

---

## Obiettivo

Simulare attacchi crittografici comuni e implementare difese in ambiente controllato.

⚠️ **ATTENZIONE**: Solo in ambiente di test isolato!

## Lab 1: Brute Force su Password Hash

### Scenario

Database compromesso contiene password MD5.

### Attacco

```python
import hashlib
import itertools
import string

def brute_force_md5(target_hash, max_length=4):
    """Brute force su MD5 (SOLO PER DEMO!)"""
    
    chars = string.ascii_lowercase + string.digits
    attempts = 0
    
    for length in range(1, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            password = ''.join(combo)
            hash_result = hashlib.md5(password.encode()).hexdigest()
            attempts += 1
            
            if hash_result == target_hash:
                return password, attempts
            
            if attempts % 10000 == 0:
                print(f"Tentativi: {attempts}")
    
    return None, attempts

# Test con password debole
target = hashlib.md5(b"abc").hexdigest()
print(f"Target hash: {target}")

password, tries = brute_force_md5(target, max_length=3)
print(f"\n✅ Password trovata: '{password}' in {tries} tentativi")
```

### Difesa: Hashing Sicuro

```python
import bcrypt
import time

def secure_password_hash(password):
    """Hash sicuro con bcrypt"""
    
    start = time.time()
    
    # bcrypt con cost factor 12
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    
    elapsed = time.time() - start
    
    print(f"Hash: {hashed.decode()}")
    print(f"Tempo: {elapsed:.3f}s")
    
    return hashed

def verify_password(password, hashed):
    """Verifica password"""
    return bcrypt.checkpw(password.encode(), hashed)

# Test
pwd = "SecurePassword123!"
hashed = secure_password_hash(pwd)

print(f"\n✅ Verifica corretta: {verify_password(pwd, hashed)}")
print(f"❌ Verifica errata: {verify_password('wrong', hashed)}")
```

## Lab 2: Padding Oracle Attack su AES-CBC

### Vulnerabilità

Server rivela se padding è corretto.

### Codice Vulnerabile

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os

def vulnerable_decrypt(key, iv, ciphertext):
    """Decrypt che rivela errori padding"""
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    try:
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Rimuovi padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        
        return True, plaintext  # ❌ Rivela se padding OK!
        
    except ValueError:
        return False, None  # ❌ Padding error!

# Setup
key = os.urandom(32)
iv = os.urandom(16)

# Cifra messaggio
message = b"Secret message"
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

padder = sym_padding.PKCS7(128).padder()
padded = padder.update(message) + padder.finalize()
ciphertext = encryptor.update(padded) + encryptor.finalize()

# Attaccante può modificare IV e vedere errori padding
print(f"Padding valido: {vulnerable_decrypt(key, iv, ciphertext)[0]}")

# IV modificato → padding invalido
fake_iv = os.urandom(16)
print(f"Padding con fake IV: {vulnerable_decrypt(key, fake_iv, ciphertext)[0]}")
```

### Difesa: Usa GCM

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def secure_encrypt_decrypt():
    """GCM non ha padding oracle"""
    
    key = AESGCM.generate_key(bit_length=256)
    cipher = AESGCM(key)
    
    message = b"Secret message"
    nonce = os.urandom(12)
    
    # Cifra
    ciphertext = cipher.encrypt(nonce, message, b"")
    
    # Decifra
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, b"")
        print(f"✅ Decifrato: {plaintext.decode()}")
    except:
        print("❌ Autenticazione fallita (nessun info su padding)")

secure_encrypt_decrypt()
```

## Lab 3: Man-in-the-Middle su Diffie-Hellman

### Attacco (senza autenticazione)

```python
from cryptography.hazmat.primitives.asymmetric import dh

# Alice e Bob vogliono comunicare
params = dh.generate_parameters(generator=2, key_size=512)  # Debole per demo

alice_private = params.generate_private_key()
alice_public = alice_private.public_key()

bob_private = params.generate_private_key()
bob_public = bob_private.public_key()

# Attaccante (Eve) intercetta
eve_private_alice = params.generate_private_key()
eve_public_alice = eve_private_alice.public_key()

eve_private_bob = params.generate_private_key()
eve_public_bob = eve_private_bob.public_key()

# Alice pensa di parlare con Bob, ma parla con Eve
alice_shared = alice_private.exchange(eve_public_alice)

# Bob pensa di parlare con Alice, ma parla con Eve
bob_shared = bob_private.exchange(eve_public_bob)

# Eve può decifrare tutto!
eve_shared_alice = eve_private_alice.exchange(alice_public)
eve_shared_bob = eve_private_bob.exchange(bob_public)

print(f"Alice shared: {alice_shared.hex()[:32]}...")
print(f"Eve-Alice:    {eve_shared_alice.hex()[:32]}...")
print(f"Eve-Bob:      {eve_shared_bob.hex()[:32]}...")
print(f"Bob shared:   {bob_shared.hex()[:32]}...")

print("\n⚠️  Eve può leggere e modificare tutti i messaggi!")
```

### Difesa: Authenticated DH con Firme

```python
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import hashes

# Alice e Bob hanno certificati/chiavi firma
alice_sign_key = ec.generate_private_key(ec.SECP256R1())
bob_sign_key = ec.generate_private_key(ec.SECP256R1())

# DH key exchange
params = dh.generate_parameters(generator=2, key_size=2048)

alice_dh_private = params.generate_private_key()
alice_dh_public = alice_dh_private.public_key()

# Alice firma la sua chiave DH pubblica
alice_dh_bytes = alice_dh_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

alice_signature = alice_sign_key.sign(alice_dh_bytes, ec.ECDSA(hashes.SHA256()))

# Bob può verificare che chiave viene davvero da Alice
alice_sign_pub = alice_sign_key.public_key()

try:
    alice_sign_pub.verify(alice_signature, alice_dh_bytes, ec.ECDSA(hashes.SHA256()))
    print("✅ Chiave Alice autenticata")
except:
    print("❌ MITM rilevato!")
```

## Lab 4: Timing Attack su RSA

### Vulnerabilità

Tempo di decifratura dipende da chiave privata.

### Difesa: Constant-Time Operations

```python
import time
import hmac

def vulnerable_compare(a, b):
    """Confronto vulnerabile a timing attack"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # ❌ Esce subito → timing leak!
    
    return True

def secure_compare(a, b):
    """Confronto constant-time"""
    return hmac.compare_digest(a, b)

# Demo timing difference
token = b"secret_token_123"
fake1 = b"aaaaaaaaaaaaaaa"  # Primo byte sbagliato
fake2 = b"secret_aaaaaaa"   # Primi 7 byte corretti

start = time.perf_counter()
for _ in range(10000):
    vulnerable_compare(token, fake1)
elapsed1 = time.perf_counter() - start

start = time.perf_counter()
for _ in range(10000):
    vulnerable_compare(token, fake2)
elapsed2 = time.perf_counter() - start

print(f"Tempo fake1 (1 byte match): {elapsed1:.6f}s")
print(f"Tempo fake2 (7 byte match): {elapsed2:.6f}s")
print(f"Differenza: {abs(elapsed2-elapsed1):.6f}s")

# secure_compare ha sempre stesso tempo
```

## Lab 5: SQL Injection → Database Encryption

### Scenario

Database con dati sensibili.

### Setup Database Cifrato

```python
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

class SecureDatabase:
    """Database con cifratura field-level"""
    
    def __init__(self, db_file, encryption_key):
        self.conn = sqlite3.connect(db_file)
        self.cipher = AESGCM(encryption_key)
        self.setup()
    
    def setup(self):
        """Crea tabella"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email_encrypted BLOB,
                ssn_encrypted BLOB
            )
        ''')
        self.conn.commit()
    
    def encrypt_field(self, plaintext):
        """Cifra singolo campo"""
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, plaintext.encode(), b"")
        return nonce + ciphertext  # Salva nonce + ciphertext
    
    def decrypt_field(self, encrypted):
        """Decifra campo"""
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, b"")
        return plaintext.decode()
    
    def insert_user(self, username, email, ssn):
        """Inserisci utente con dati cifrati"""
        email_enc = self.encrypt_field(email)
        ssn_enc = self.encrypt_field(ssn)
        
        self.conn.execute(
            'INSERT INTO users (username, email_encrypted, ssn_encrypted) VALUES (?, ?, ?)',
            (username, email_enc, ssn_enc)
        )
        self.conn.commit()
    
    def get_user(self, username):
        """Recupera utente"""
        cursor = self.conn.execute(
            'SELECT email_encrypted, ssn_encrypted FROM users WHERE username = ?',
            (username,)
        )
        
        row = cursor.fetchone()
        if row:
            email = self.decrypt_field(row[0])
            ssn = self.decrypt_field(row[1])
            return {'username': username, 'email': email, 'ssn': ssn}
        
        return None

# Test
key = AESGCM.generate_key(bit_length=256)
db = SecureDatabase(':memory:', key)

# Inserisci dati sensibili
db.insert_user('alice', 'alice@example.com', '123-45-6789')
db.insert_user('bob', 'bob@example.com', '987-65-4321')

# Recupera
user = db.get_user('alice')
print(f"✅ User: {json.dumps(user, indent=2)}")

# Anche se attaccante ha accesso a DB, vede solo ciphertext
```

## Conclusioni Lab

### ✅ Lezioni Apprese

1. **Password**: bcrypt/argon2, non MD5/SHA1
2. **Cifratura**: GCM/ChaCha20, non CBC
3. **Key Exchange**: Authenticated DH, non plain DH
4. **Comparison**: `hmac.compare_digest()`, non `==`
5. **Database**: Field-level encryption per dati sensibili

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 48](48_laboratorio_protocolli_sicuri.md)
- **Successivo**: [Capitolo 50](50_laboratorio_sicurezza_di_rete_e_malware.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

**⚠️ Disclaimer**: Questi attacchi sono solo per scopo educativo in ambiente isolato!
