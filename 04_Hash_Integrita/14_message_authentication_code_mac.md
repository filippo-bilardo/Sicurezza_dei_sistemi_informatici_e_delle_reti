# Capitolo 14 - Message Authentication Code (MAC)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 4 - Hash e Integrità  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Un **MAC** (Message Authentication Code) fornisce **integrità** e **autenticazione** dei messaggi.

### Funzionamento

```
MAC(chiave, messaggio) = tag
```

- Input: messaggio + chiave segreta
- Output: tag di autenticazione (fisso, es. 16 byte)

## Tipologie MAC

### 1. HMAC (Hash-based MAC)

Basato su funzioni hash (vedi [Capitolo 13](13_hmac.md))

```python
import hmac
import hashlib

key = b"chiave_segreta"
msg = b"Messaggio da autenticare"

tag = hmac.new(key, msg, hashlib.sha256).digest()
print(f"HMAC: {tag.hex()}")
```

### 2. CMAC (Cipher-based MAC)

Basato su cifrari a blocchi (AES-CMAC):

```python
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

key = b"0123456789ABCDEF"  # 16 byte per AES-128
msg = b"Messaggio da autenticare"

# Crea CMAC con AES
c = cmac.CMAC(algorithms.AES(key))
c.update(msg)
tag = c.finalize()

print(f"CMAC: {tag.hex()}")
```

### 3. GMAC (Galois MAC)

Parte di AES-GCM (autenticazione + cifratura):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

nonce = os.urandom(12)
msg = b"Dati cifrati e autenticati"

# GCM cifra E autentica
ciphertext = cipher.encrypt(nonce, msg, b"")
print(f"GCM ciphertext+tag: {ciphertext.hex()[:32]}...")
```

## Confronto MAC

| Tipo | Base | Velocità | Sicurezza | Uso Tipico |
|------|------|----------|-----------|------------|
| **HMAC-SHA256** | Hash | Media | ✅ Alta | API, JWT |
| **CMAC-AES** | AES | Alta | ✅ Alta | Standard IEEE |
| **GMAC** | AES-GCM | Altissima | ✅ Alta | TLS, IPsec |
| **Poly1305** | ChaCha20 | Altissima | ✅ Alta | Modern crypto |

## HMAC vs CMAC

### HMAC

```python
import hmac
import hashlib

def hmac_authenticate(key, message):
    tag = hmac.new(key, message, hashlib.sha256).digest()
    return tag[:16]  # 128 bit

key = b"secret_key_123"
msg = b"Transaction: 1000 EUR"

tag = hmac_authenticate(key, msg)
print(f"HMAC-SHA256 (128bit): {tag.hex()}")
```

### CMAC

```python
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

def cmac_authenticate(key, message):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message)
    return c.finalize()

key = b"0123456789ABCDEF"  # 16 byte
msg = b"Transaction: 1000 EUR"

tag = cmac_authenticate(key, msg)
print(f"CMAC-AES (128bit): {tag.hex()}")
```

## Poly1305

MAC moderno usato con ChaCha20:

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# ChaCha20-Poly1305 (cifratura + MAC)
key = ChaCha20Poly1305.generate_key()
cipher = ChaCha20Poly1305(key)

nonce = os.urandom(12)
msg = b"Messaggio moderno"

# Cifra e autentica in un colpo solo
ciphertext = cipher.encrypt(nonce, msg, b"")
print(f"ChaCha20-Poly1305: {ciphertext.hex()[:32]}...")

# Decifra e verifica
plaintext = cipher.decrypt(nonce, ciphertext, b"")
print(f"✅ Verificato: {plaintext.decode()}")
```

## Verifica MAC

### Confronto Sicuro

⚠️ **MAI usare `==` per confrontare MAC!**

```python
import hmac

def verifica_mac_insicuro(tag1, tag2):
    return tag1 == tag2  # ❌ Timing attack!

def verifica_mac_sicuro(tag1, tag2):
    return hmac.compare_digest(tag1, tag2)  # ✅ Constant-time
```

### Esempio Completo

```python
import hmac
import hashlib

def invia_messaggio(key, msg):
    """Sender: calcola MAC"""
    tag = hmac.new(key, msg, hashlib.sha256).digest()
    return msg, tag

def ricevi_messaggio(key, msg, tag_ricevuto):
    """Receiver: verifica MAC"""
    tag_atteso = hmac.new(key, msg, hashlib.sha256).digest()
    
    if hmac.compare_digest(tag_ricevuto, tag_atteso):
        print("✅ Messaggio autentico")
        return True
    else:
        print("❌ Messaggio modificato o falso!")
        return False

# Test
key = b"shared_secret"
msg, tag = invia_messaggio(key, b"Importo: 100 EUR")

# Verifica OK
ricevi_messaggio(key, msg, tag)

# Messaggio modificato
msg_fake = b"Importo: 999 EUR"
ricevi_messaggio(key, msg_fake, tag)  # Fallisce!
```

## Authenticated Encryption

Combina **cifratura + autenticazione**:

### Encrypt-then-MAC (raccomandato)

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

def encrypt_then_mac(key_enc, key_mac, plaintext):
    # 1. Cifra
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Padding
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # 2. MAC su ciphertext
    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(iv + ciphertext)
    tag = h.finalize()
    
    return iv + ciphertext + tag

# Chiavi separate
key_enc = b"0123456789ABCDEF"
key_mac = b"FEDCBA9876543210"

msg = b"Messaggio segreto"
encrypted = encrypt_then_mac(key_enc, key_mac, msg)
print(f"Encrypted+MAC: {encrypted.hex()[:64]}...")
```

### AEAD (preferibile)

Usa direttamente GCM o ChaCha20-Poly1305:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

nonce = os.urandom(12)
plaintext = b"AEAD è più semplice e sicuro"

# Cifra + autentica in un colpo
ciphertext = cipher.encrypt(nonce, plaintext, b"")

# Decifra + verifica
plaintext = cipher.decrypt(nonce, ciphertext, b"")
print(f"✅ {plaintext.decode()}")
```

## Applicazioni

1. **API Authentication**: HMAC-SHA256
2. **Cookie Integrity**: HMAC
3. **TLS Record Layer**: GMAC (GCM mode)
4. **IPsec**: CMAC-AES, GMAC
5. **File Integrity**: HMAC su hash file

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 13 - HMAC](13_hmac.md)
- **Successivo**: [Capitolo 15 - Certificati Digitali](../PARTE_05_Certificati_PKI/15_certificati_digitali.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- NIST SP 800-38B: CMAC
- RFC 4493: The AES-CMAC Algorithm

**Raccomandazione**: HMAC-SHA256 per autenticazione, AES-GCM per cifratura+autenticazione.
