# Capitolo 7 - Introduzione alla Crittografia Asimmetrica

> **Corso**: Sistemi e Reti 3  
> **Parte**: 3 - Crittografia Asimmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

La **crittografia asimmetrica** (o a chiave pubblica) è una rivoluzione nella crittografia moderna, introdotta da Whitfield Diffie e Martin Hellman nel 1976.

### Problema della Crittografia Simmetrica

```
Alice                           Bob
  │                              │
  ├─ Come condividere chiave?───►│
  │  (Canal non sicuro!)         │
```

❌ Distribuzione chiave è difficile  
❌ N utenti = N(N-1)/2 chiavi da gestire  
❌ No firma digitale

## Principio Chiave Pubblica

### Due Chiavi Correlate

```
Chiave Pubblica (K_pub)
  ├─ Condivisa liberamente
  ├─ Usata per CIFRARE
  └─ Usata per VERIFICARE firme

Chiave Privata (K_priv)
  ├─ Mantenuta SEGRETA
  ├─ Usata per DECIFRARE
  └─ Usata per FIRMARE
```

### Proprietà Matematiche

$$C = E_{K_{pub}}(M)$$
$$M = D_{K_{priv}}(C)$$

**Cruciale**: Impossibile derivare $K_{priv}$ da $K_{pub}$

- C: Ciphertext  
- M: Messaggio (plaintext)
- E: Funzione di cifratura
- D: Funzione di decifratura
- K_pub: Chiave pubblica
- K_priv: Chiave privata

## Funzioni Trapdoor

Alla base della crittografia asimmetrica ci sono le **funzioni one-way con trapdoor**: (trapdoor = porta segreta)

### Definizione

- **Facile** calcolare $f(x)$ conoscendo $x$
- **Difficile** calcolare $x$ da $f(x)$ (senza trapdoor)
- **Facile** invertire con informazione segreta (trapdoor)

### Esempi

1. **Fattorizzazione** (RSA)
   - Facile: $n = p \times q$
   - Difficile: trovare $p, q$ da $n$
   - Trapdoor: conoscere $p$ e $q$

2. **Logaritmo Discreto** (DH)
   - Facile: $y = g^x \mod p$
   - Difficile: trovare $x$ da $y$
   - Trapdoor: conoscere $x$

3. **Curve Ellittiche** (ECDH, ECDSA)
   - Facile: $Q = k \cdot P$
   - Difficile: trovare $k$ da $Q$

## Cifratura Asimmetrica

### Schema Base

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# 1. Bob genera coppia chiavi
bob_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
bob_public = bob_private.public_key()

# 2. Alice cifra con chiave pubblica Bob
messaggio = b"Messaggio segreto per Bob"

ciphertext = bob_public.encrypt(
    messaggio,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Ciphertext: {ciphertext.hex()[:64]}...")

# 3. Bob decifra con sua chiave privata
plaintext = bob_private.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Plaintext: {plaintext.decode()}")
```

### Vantaggi

✅ No problema distribuzione chiavi  
✅ Chiave pubblica può essere pubblicata  
✅ N utenti = N coppie chiavi (non N²)  
✅ Permette firma digitale

### Svantaggi

⚠️ **Molto più lento** di simmetrica (100-1000x)  
⚠️ **Limiti dimensione** messaggio  
⚠️ **Chiavi più lunghe** (2048-4096 bit)

## Firma Digitale

### Concetto

La firma digitale fornisce:
- **Autenticità**: Messaggio da chi dice di essere
- **Integrità**: Non modificato
- **Non ripudio**: Mittente non può negare

### Schema

```
Firma:    Hash(M) → Cifra con K_priv → Firma
Verifica: Decifra firma con K_pub → Confronta con Hash(M)
```

### Implementazione

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Alice genera chiavi
alice_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
alice_public = alice_private.public_key()

# Alice firma messaggio
messaggio = b"Contratto da firmare"

signature = alice_private.sign(
    messaggio,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Firma: {signature.hex()[:64]}...")

# Bob verifica firma con chiave pubblica Alice
try:
    alice_public.verify(
        signature,
        messaggio,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Firma valida - messaggio autentico")
except:
    print("❌ Firma non valida - messaggio modificato o falso")
```

## Hybrid Encryption

In pratica si combina simmetrica + asimmetrica:

```
Alice                                    Bob
  │                                       │
  ├─ 1. Genera chiave AES random         │
  ├─ 2. Cifra messaggio con AES          │
  ├─ 3. Cifra chiave AES con RSA_Bob     │
  ├─ 4. Invia: msg_AES + key_RSA ───────►│
  │                                       ├─ 5. Decifra chiave AES con RSA_priv
  │                                       ├─ 6. Decifra messaggio con AES
  │                                       └─ 7. ✅ Plaintext
```

### Implementazione

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os

def hybrid_encrypt(plaintext, recipient_public_key):
    """Hybrid encryption: AES per dati, RSA per chiave AES"""
    
    # 1. Genera chiave AES random
    aes_key = AESGCM.generate_key(bit_length=256)
    
    # 2. Cifra plaintext con AES-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, b"")
    
    # 3. Cifra chiave AES con RSA
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return {
        'encrypted_key': encrypted_key,
        'nonce': nonce,
        'ciphertext': ciphertext
    }

def hybrid_decrypt(encrypted_data, recipient_private_key):
    """Hybrid decryption"""
    
    # 1. Decifra chiave AES con RSA
    aes_key = recipient_private_key.decrypt(
        encrypted_data['encrypted_key'],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2. Decifra ciphertext con AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(
        encrypted_data['nonce'],
        encrypted_data['ciphertext'],
        b""
    )
    
    return plaintext

# Test
bob_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_public = bob_private.public_key()

# Alice cifra
plaintext = b"Messaggio lungo..." * 100
encrypted = hybrid_encrypt(plaintext, bob_public)

print(f"Plaintext size: {len(plaintext)} byte")
print(f"Encrypted key size: {len(encrypted['encrypted_key'])} byte")
print(f"Ciphertext size: {len(encrypted['ciphertext'])} byte")

# Bob decifra
decrypted = hybrid_decrypt(encrypted, bob_private)
print(f"✅ Decryption: {decrypted == plaintext}")
```

## Confronto Algoritmi

| Algoritmo | Base Matematica | Sicurezza | Velocità | Uso |
|-----------|-----------------|-----------|----------|-----|
| **RSA** | Fattorizzazione | ✅ Alta | 🐌 Lenta | Firma, Key exchange |
| **DH** | Log discreto | ✅ Alta | 🐌 Lenta | Key exchange |
| **ECDH** | Curve ellittiche | ✅ Alta | ⚡ Media | Key exchange (moderno) |
| **ECDSA** | Curve ellittiche | ✅ Alta | ⚡ Media | Firma (moderno) |
| **EdDSA** | Curve twist | ✅ Alta | ⚡⚡ Veloce | Firma (Ed25519) |

## Key Exchange vs Encryption

### Key Exchange (DH, ECDH)

```python
# Alice e Bob generano segreto condiviso
# SENZA inviarlo sulla rete!

from cryptography.hazmat.primitives.asymmetric import ec

alice_private = ec.generate_private_key(ec.SECP256R1())
bob_private = ec.generate_private_key(ec.SECP256R1())

# Scambio chiavi pubbliche
alice_public = alice_private.public_key()
bob_public = bob_private.public_key()

# Segreto condiviso (uguale per entrambi!)
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

print(f"Match: {alice_shared == bob_shared}")  # ✅ True
```

### Encryption (RSA)

```python
# Bob cifra messaggio specifico per Alice
# con chiave pubblica Alice

encrypted = alice_public_key.encrypt(messaggio, padding)
decrypted = alice_private_key.decrypt(encrypted, padding)
```

## Sicurezza Computazionale

La sicurezza si basa su problemi matematici **difficili**:

### Complessità

```
Fattorizzare n = p × q (RSA)
├─ n = 2048 bit → Impossibile con tecnologia attuale
├─ Tempo: ~300 trilioni di anni (stima)
└─ Ma: Quantum computer (algoritmo Shor) → Polinomiale!

Logaritmo discreto (DH)
├─ Simile complessità a fattorizzazione
└─ Anche vulnerabile a quantum

Curve ellittiche (ECC)
├─ Più resistente (per ora)
├─ Chiavi più corte a parità di sicurezza
└─ Anche vulnerabile a quantum
```

## Post-Quantum Cryptography

Algoritmi resistenti a computer quantistici:

- **Lattice-based**: CRYSTALS-Kyber
- **Hash-based**: SPHINCS+
- **Code-based**: Classic McEliece

NIST ha standardizzato primi algoritmi nel 2022.

## Gestione Chiavi

### Generazione

```python
# RSA
rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048  # Minimo 2048, raccomandato 3072+
)

# ECDSA
ec_key = ec.generate_private_key(ec.SECP256R1())

# Ed25519 (veloce e sicuro)
from cryptography.hazmat.primitives.asymmetric import ed25519
ed_key = ed25519.Ed25519PrivateKey.generate()
```

### Storage

```python
from cryptography.hazmat.primitives import serialization

# Salva chiave privata (PROTETTA!)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'password')
)

# Salva chiave pubblica
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

## Best Practices

### ✅ Raccomandazioni

1. **RSA**: Minimo 2048 bit, preferibile 3072+ bit
2. **ECC**: Usa curve standard (P-256, P-384, Curve25519)
3. **Padding**: Sempre OAEP per cifratura, PSS per firme
4. **Hybrid**: Combina con AES per dati grandi
5. **Key rotation**: Cambia chiavi periodicamente
6. **Backup**: Chiave privata in luogo sicuro offline

### ❌ Da Evitare

1. RSA < 2048 bit
2. Padding PKCS#1 v1.5 (vulnerabile)
3. Cifrare dati grandi con RSA diretto
4. Chiavi private non protette
5. Riuso chiavi tra applicazioni diverse

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 6 - Cifrari a Flusso](../PARTE_02_Crittografia_Simmetrica/06_cifrari_a_flusso.md)
- **Successivo**: [Capitolo 8 - RSA](08_rsa_rivest-shamir-adleman.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- Diffie-Hellman: "New Directions in Cryptography" (1976)
- RSA: "A Method for Obtaining Digital Signatures" (1978)
- NIST FIPS 186-4: Digital Signature Standard

**Nota**: La crittografia asimmetrica è complementare alla simmetrica, non sostitutiva!
