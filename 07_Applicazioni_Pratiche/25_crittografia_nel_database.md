# Capitolo 25 - Crittografia nel Database

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

I **database** contengono i dati più preziosi. La crittografia protegge da:

1. **Accesso fisico**: Furto disco/backup
2. **Insider threat**: Amministratori malintenzionati
3. **SQL Injection**: Attaccanti esterni
4. **Compliance**: GDPR, HIPAA, PCI-DSS

### Livelli di Cifratura

```
Application Level
    ↑
Column Level (Field Encryption)
    ↑
Table Level
    ↑
Database Level (TDE - Transparent Data Encryption)
    ↑
Disk Level (Full Disk Encryption)
```

---

## Transparent Data Encryption (TDE)

**TDE** cifra l'intero database a livello di storage.

### Architettura TDE

```
Application
    ↓
Database Engine (plaintext)
    ↓
TDE Layer (encryption/decryption)
    ↓
Encrypted Files on Disk
```

**Pro**:
- ✅ Trasparente per applicazioni
- ✅ Protegge backup e file system
- ✅ Basso overhead (~3-5%)

**Contro**:
- ❌ Non protegge da SQL injection
- ❌ Non protegge da insider con accesso DB
- ❌ Dati in memoria plaintext

### TDE in PostgreSQL (pgcrypto)

```sql
-- Installa estensione
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Cifra dati
INSERT INTO users (name, ssn_encrypted) 
VALUES (
    'Alice',
    pgp_sym_encrypt('123-45-6789', 'encryption_key')
);

-- Decifra dati
SELECT 
    name,
    pgp_sym_decrypt(ssn_encrypted, 'encryption_key') AS ssn
FROM users;
```

### TDE in MySQL

```sql
-- Abilita encryption
SET GLOBAL default_table_encryption=ON;

-- Crea tabella cifrata
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY,
    data VARCHAR(255)
) ENCRYPTION='Y';

-- Verifica encryption
SHOW CREATE TABLE sensitive_data;
```

### TDE con Python (SQLCipher)

```python
from sqlcipher3 import dbapi2 as sqlite

# Connetti con password
conn = sqlite.connect('encrypted.db')
cursor = conn.cursor()

# Imposta chiave encryption
cursor.execute("PRAGMA key='strong-encryption-password'")

# Crea tabella
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        email TEXT
    )
''')

# Insert
cursor.execute(
    "INSERT INTO users (username, email) VALUES (?, ?)",
    ('alice', 'alice@example.com')
)

# Query
cursor.execute("SELECT * FROM users")
print(cursor.fetchall())

conn.commit()
conn.close()

# ✅ Database cifrato su disco!
# File non leggibile senza password
```

---

## Column-Level Encryption

Cifra **solo campi sensibili** (SSN, carte credito, etc).

### Vantaggi Column Encryption

- ✅ Protegge anche da insider DB
- ✅ Controllo granulare
- ✅ Dati non sensibili ricercabili
- ⚠️ Overhead maggiore
- ⚠️ Campi cifrati non indicizzabili/ricercabili

### Implementazione Python

```python
from cryptography.fernet import Fernet
import sqlite3
import json

class EncryptedDatabase:
    """Database con column encryption"""
    
    def __init__(self, db_path, encryption_key=None):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        
        # Genera o carica chiave
        if encryption_key:
            self.key = encryption_key
        else:
            self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)
        
        # Crea tabella
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT,
                ssn_encrypted BLOB,
                credit_card_encrypted BLOB
            )
        ''')
    
    def encrypt_field(self, plaintext):
        """Cifra campo"""
        if plaintext is None:
            return None
        return self.cipher.encrypt(plaintext.encode())
    
    def decrypt_field(self, ciphertext):
        """Decifra campo"""
        if ciphertext is None:
            return None
        return self.cipher.decrypt(ciphertext).decode()
    
    def insert_user(self, username, email, ssn, credit_card):
        """Inserisci utente con dati cifrati"""
        self.cursor.execute('''
            INSERT INTO users (username, email, ssn_encrypted, credit_card_encrypted)
            VALUES (?, ?, ?, ?)
        ''', (
            username,
            email,
            self.encrypt_field(ssn),
            self.encrypt_field(credit_card)
        ))
        self.conn.commit()
    
    def get_user(self, user_id):
        """Ottieni utente con decifratura"""
        self.cursor.execute(
            "SELECT id, username, email, ssn_encrypted, credit_card_encrypted FROM users WHERE id = ?",
            (user_id,)
        )
        
        row = self.cursor.fetchone()
        if not row:
            return None
        
        return {
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'ssn': self.decrypt_field(row[3]),
            'credit_card': self.decrypt_field(row[4])
        }
    
    def search_by_username(self, username):
        """Ricerca per campo non cifrato"""
        self.cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )
        
        results = []
        for row in self.cursor.fetchall():
            results.append(self.get_user(row[0]))
        
        return results
    
    def close(self):
        self.conn.close()

# Test
print("=== Column-Level Encryption ===\n")

db = EncryptedDatabase('secure.db')

# Inserisci utenti
db.insert_user(
    username='alice',
    email='alice@example.com',
    ssn='123-45-6789',
    credit_card='4111-1111-1111-1111'
)

db.insert_user(
    username='bob',
    email='bob@example.com',
    ssn='987-65-4321',
    credit_card='5500-0000-0000-0004'
)

# Recupera con decifratura
user = db.get_user(1)
print(f"User: {user['username']}")
print(f"Email: {user['email']}")
print(f"SSN: {user['ssn']}")
print(f"Card: {user['credit_card'][:4]}****")

# Ricerca per username (non cifrato)
results = db.search_by_username('alice')
print(f"\n✅ Found {len(results)} users")

db.close()

# ✅ SSN e carte credito cifrati su disco!
# ❌ Ma username/email in chiaro (ricercabili)
```

### Encryption con ORM (SQLAlchemy)

```python
from sqlalchemy import Column, Integer, String, LargeBinary, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import TypeDecorator
from cryptography.fernet import Fernet

Base = declarative_base()

class EncryptedType(TypeDecorator):
    """Custom SQLAlchemy type per column encryption"""
    
    impl = LargeBinary
    
    def __init__(self, key):
        self.cipher = Fernet(key)
        super().__init__()
    
    def process_bind_param(self, value, dialect):
        """Cifra prima di salvare"""
        if value is not None:
            return self.cipher.encrypt(value.encode())
        return value
    
    def process_result_value(self, value, dialect):
        """Decifra dopo aver letto"""
        if value is not None:
            return self.cipher.decrypt(value).decode()
        return value

# Modello con encryption
ENCRYPTION_KEY = Fernet.generate_key()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String)
    ssn = Column(EncryptedType(ENCRYPTION_KEY))
    credit_card = Column(EncryptedType(ENCRYPTION_KEY))

# Setup database
engine = create_engine('sqlite:///orm_encrypted.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Usage
session = Session()

# Insert
user = User(
    username='alice',
    email='alice@example.com',
    ssn='123-45-6789',
    credit_card='4111-1111-1111-1111'
)
session.add(user)
session.commit()

# Query (decryption automatico!)
user = session.query(User).filter_by(username='alice').first()
print(f"\n=== ORM Encryption ===")
print(f"Username: {user.username}")
print(f"SSN: {user.ssn}")
print(f"✅ Encryption/decryption trasparente!")
```

---

## Key Management

**Problema critico**: Dove conservare le chiavi?

### ❌ Soluzioni Sbagliate

```python
# ❌ MAI hardcode chiavi!
KEY = "my-secret-key-12345"

# ❌ MAI nel codice sorgente!
# ❌ MAI in version control!
# ❌ MAI nello stesso DB dei dati!
```

### ✅ Environment Variables

```python
import os

# .env file (NON committare!)
# ENCRYPTION_KEY=base64_encoded_key_here

from dotenv import load_dotenv
load_dotenv()

KEY = os.environ.get('ENCRYPTION_KEY')
if not KEY:
    raise RuntimeError("ENCRYPTION_KEY not set!")

cipher = Fernet(KEY.encode())
```

### ✅ Key Management Service (KMS)

```python
# AWS KMS Example
import boto3

kms = boto3.client('kms', region_name='us-east-1')

def encrypt_with_kms(plaintext, key_id):
    """Cifra con AWS KMS"""
    response = kms.encrypt(
        KeyId=key_id,
        Plaintext=plaintext
    )
    return response['CiphertextBlob']

def decrypt_with_kms(ciphertext):
    """Decifra con AWS KMS"""
    response = kms.decrypt(
        CiphertextBlob=ciphertext
    )
    return response['Plaintext']

# Genera data encryption key (DEK)
response = kms.generate_data_key(
    KeyId='arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    KeySpec='AES_256'
)

plaintext_key = response['Plaintext']  # Usa per cifrare dati
encrypted_key = response['CiphertextBlob']  # Store cifrato
```

### ✅ Envelope Encryption

**Pattern consigliato**: Chiave master cifra chiavi dati.

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import base64

class EnvelopeEncryption:
    """Envelope encryption pattern"""
    
    def __init__(self, master_password):
        # Master Key derivata da password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'static_salt',  # Prod: random salt stored separately
            iterations=100000
        )
        master_key = base64.urlsafe_b64encode(
            kdf.derive(master_password.encode())
        )
        self.master_cipher = Fernet(master_key)
    
    def generate_data_key(self):
        """Genera coppia (plaintext, encrypted) data key"""
        # Data key (usata per cifrare dati)
        plaintext_key = Fernet.generate_key()
        
        # Cifra data key con master key
        encrypted_key = self.master_cipher.encrypt(plaintext_key)
        
        return plaintext_key, encrypted_key
    
    def decrypt_data_key(self, encrypted_key):
        """Decifra data key con master key"""
        return self.master_cipher.decrypt(encrypted_key)
    
    def encrypt_data(self, data, plaintext_key):
        """Cifra dati con data key"""
        cipher = Fernet(plaintext_key)
        return cipher.encrypt(data.encode())
    
    def decrypt_data(self, ciphertext, encrypted_key):
        """Decifra dati: master key → data key → plaintext"""
        # Decrypt data key
        plaintext_key = self.decrypt_data_key(encrypted_key)
        
        # Decrypt data
        cipher = Fernet(plaintext_key)
        return cipher.decrypt(ciphertext).decode()

# Test
print("\n=== Envelope Encryption ===\n")

envelope = EnvelopeEncryption(master_password="SuperSecretMasterPassword!")

# Genera data key
plaintext_key, encrypted_key = envelope.generate_data_key()
print(f"Data key (plain): {plaintext_key[:20]}...")
print(f"Data key (encrypted): {encrypted_key[:40]}...")

# Cifra dati
data = "Sensitive database record"
ciphertext = envelope.encrypt_data(data, plaintext_key)
print(f"\nCiphertext: {ciphertext[:40]}...")

# Decifra (solo con master password!)
decrypted = envelope.decrypt_data(ciphertext, encrypted_key)
print(f"Decrypted: {decrypted}")

print("\n✅ Master key protegge tutte le data keys!")
print("✅ Rotazione master key = re-encrypt solo data keys (non tutti i dati)")
```

---

## Searchable Encryption

**Problema**: Campi cifrati non ricercabili con `WHERE`.

### Soluzione 1: Deterministic Encryption

Stesso plaintext → stesso ciphertext (ricercabile con `=`).

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class DeterministicEncryption:
    """AES-SIV (Synthetic IV) - deterministic"""
    
    def __init__(self, key):
        # Usa hash per derivare IV da plaintext
        self.key = key
    
    def encrypt(self, plaintext):
        """Encryption deterministico"""
        # IV derivato da plaintext (sempre uguale per stesso plaintext)
        iv = hashlib.sha256(plaintext.encode()).digest()[:16]
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Padding
        padded = self._pad(plaintext.encode())
        
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    
    def decrypt(self, ciphertext):
        """Decryption"""
        # Non possiamo derivare IV... (simplified demo)
        # In produzione: usa AES-SIV library
        pass
    
    def _pad(self, data):
        """PKCS7 padding"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

# Test
key = os.urandom(32)
det = DeterministicEncryption(key)

# Stesso input → stesso output
c1 = det.encrypt("alice@example.com")
c2 = det.encrypt("alice@example.com")
c3 = det.encrypt("bob@example.com")

print("\n=== Deterministic Encryption ===")
print(f"Encrypt 'alice' #1: {c1.hex()[:40]}...")
print(f"Encrypt 'alice' #2: {c2.hex()[:40]}...")
print(f"Match: {c1 == c2}")  # ✅ True!
print(f"Different input: {c1 == c3}")  # ❌ False

print("\n✅ Ricercabile con WHERE encrypted_email = ?")
print("⚠️  Leak: frequenza valori, pattern")
```

### Soluzione 2: Hash per Ricerca

Store hash per ricerca, ciphertext per dati.

```python
import hmac

class SearchableEncryption:
    """Store hash+ciphertext per searchable encryption"""
    
    def __init__(self, encryption_key, search_key):
        self.cipher = Fernet(encryption_key)
        self.search_key = search_key
    
    def compute_search_hash(self, value):
        """Hash per ricerca (HMAC)"""
        return hmac.new(
            self.search_key,
            value.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def encrypt_searchable(self, value):
        """Cifra + genera hash per ricerca"""
        ciphertext = self.cipher.encrypt(value.encode())
        search_hash = self.compute_search_hash(value)
        
        return ciphertext, search_hash
    
    def decrypt(self, ciphertext):
        """Decifra"""
        return self.cipher.decrypt(ciphertext).decode()

# Schema DB
# CREATE TABLE users (
#     id INT PRIMARY KEY,
#     email_encrypted BLOB,
#     email_search_hash VARCHAR(64),  -- Per WHERE
#     INDEX idx_email_hash (email_search_hash)
# );

# Usage
enc_key = Fernet.generate_key()
search_key = os.urandom(32)
searchable = SearchableEncryption(enc_key, search_key)

email = "alice@example.com"
ciphertext, search_hash = searchable.encrypt_searchable(email)

print("\n=== Searchable Encryption ===")
print(f"Ciphertext: {ciphertext[:40]}...")
print(f"Search hash: {search_hash}")

# Query: WHERE email_search_hash = ?
query_email = "alice@example.com"
query_hash = searchable.compute_search_hash(query_email)

if query_hash == search_hash:
    decrypted = searchable.decrypt(ciphertext)
    print(f"✅ Found: {decrypted}")
```

---

## Backup Encryption

```python
import tarfile
import os
from cryptography.fernet import Fernet

def create_encrypted_backup(source_dir, backup_file, password):
    """Crea backup cifrato"""
    # Crea tar
    tar_file = backup_file + '.tar'
    with tarfile.open(tar_file, 'w') as tar:
        tar.add(source_dir, arcname='.')
    
    # Cifra tar
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    with open(tar_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(plaintext)
    
    with open(backup_file + '.enc', 'wb') as f:
        f.write(ciphertext)
    
    # Remove tar non cifrato
    os.remove(tar_file)
    
    # Store key (KMS o password-protected)
    key_encrypted = encrypt_key_with_password(key, password)
    
    with open(backup_file + '.key', 'wb') as f:
        f.write(key_encrypted)
    
    print(f"✅ Backup cifrato: {backup_file}.enc")
    print(f"✅ Key file: {backup_file}.key")

def restore_encrypted_backup(backup_file, password, restore_dir):
    """Restore backup cifrato"""
    # Carica chiave cifrata
    with open(backup_file + '.key', 'rb') as f:
        key_encrypted = f.read()
    
    key = decrypt_key_with_password(key_encrypted, password)
    cipher = Fernet(key)
    
    # Decifra backup
    with open(backup_file + '.enc', 'rb') as f:
        ciphertext = f.read()
    
    plaintext = cipher.decrypt(ciphertext)
    
    # Estrai tar
    tar_file = backup_file + '.tar'
    with open(tar_file, 'wb') as f:
        f.write(plaintext)
    
    with tarfile.open(tar_file, 'r') as tar:
        tar.extractall(restore_dir)
    
    os.remove(tar_file)
    
    print(f"✅ Backup restored to: {restore_dir}")

def encrypt_key_with_password(key, password):
    """Cifra chiave con password"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    password_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    cipher = Fernet(password_key)
    encrypted = cipher.encrypt(key)
    
    return salt + encrypted

def decrypt_key_with_password(encrypted_key, password):
    """Decifra chiave con password"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    
    salt = encrypted_key[:16]
    ciphertext = encrypted_key[16:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    password_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    cipher = Fernet(password_key)
    return cipher.decrypt(ciphertext)
```

---

## Best Practices

### ✅ Raccomandazioni

| Aspetto | Implementazione |
|---------|----------------|
| **Encryption** | TDE + Column per dati critici |
| **Algorithm** | AES-256-GCM |
| **Key Management** | KMS (AWS/Azure/GCP) |
| **Key Rotation** | Ogni 90 giorni |
| **Backup** | Sempre cifrato |
| **Access Control** | Principle of least privilege |
| **Audit** | Log accessi dati sensibili |
| **Compliance** | GDPR, HIPAA checks |

### Performance Considerations

```python
import time

def benchmark_encryption_methods(iterations=1000):
    """Confronta performance encryption methods"""
    
    data = "Sensitive data record" * 10
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # No encryption
    start = time.time()
    for _ in range(iterations):
        _ = data
    no_enc_time = time.time() - start
    
    # Application-level encryption
    start = time.time()
    for _ in range(iterations):
        cipher.encrypt(data.encode())
    app_enc_time = time.time() - start
    
    print("\n=== Performance Impact ===")
    print(f"No encryption: {no_enc_time:.3f}s")
    print(f"App-level encryption: {app_enc_time:.3f}s")
    print(f"Overhead: {(app_enc_time/no_enc_time - 1)*100:.1f}%")
    
benchmark_encryption_methods()
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 24 - Crittografia nelle Applicazioni Web](24_crittografia_nelle_applicazioni_web.md)
- **Successivo**: [Capitolo 26 - Crittografia nelle Comunicazioni](26_crittografia_nelle_comunicazioni.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- NIST SP 800-111: Guide to Storage Encryption
- PCI DSS: Payment Card Industry Data Security Standard
- GDPR: Article 32 (Security of processing)
- AWS RDS Encryption at Rest

**Nota**: Encryption at rest è requisito compliance. Implementala SEMPRE per dati sensibili!
