# Capitolo 14 - Message Authentication Code (MAC)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 4 - Hash e Integrità  
> **Autore**: Prof. Filippo Bilardo  
> **Ultima modifica**: Gennaio 2026

---

## 📋 Indice

1. [Cos'è un MAC](#cose-mac)
2. [Come Funziona un MAC](#come-funziona)
3. [Tipologie di MAC](#tipologie)
4. [HMAC vs CMAC vs GMAC](#confronto)
5. [Authenticated Encryption (AEAD)](#aead)
6. [Implementazioni Pratiche](#implementazioni)
7. [Applicazioni Reali](#applicazioni)
8. [Sicurezza e Vulnerabilità](#sicurezza)
9. [Best Practices](#best-practices)
10. [Esercizi](#esercizi)

---

## 🔐 Cos'è un MAC {#cose-mac}

Un **MAC** (Message Authentication Code) è una funzione crittografica che genera un **tag di autenticazione** per verificare sia l'**integrità** che l'**autenticità** di un messaggio.

### Definizione Formale

> Un MAC è una funzione che prende in input un messaggio e una chiave segreta, e produce un tag (o MAC tag) di lunghezza fissa che può essere verificato solo da chi possiede la stessa chiave.

### Formula Base

$$\text{tag} = \text{MAC}(K, M)$$

Dove:
- $K$ = chiave segreta
- $M$ = messaggio
- $\text{tag}$ = codice di autenticazione (output)

### Analogia del Mondo Reale

```
┌─────────────────────────────────────────┐
│         MAC = Sigillo di Ceralacca      │
│             con Timbro Segreto          │
└─────────────────────────────────────────┘

1. Alice scrive una lettera (messaggio)
2. Usa il suo timbro segreto per sigillare (MAC)
3. Spedisce lettera + sigillo a Bob
4. Bob verifica con lo stesso timbro
   └─ Se il sigillo corrisponde → autentico
   └─ Se non corrisponde → manomesso
```

### Proprietà Fondamentali

1. **Determinismo**: Stesso messaggio + stessa chiave → stesso tag
2. **Non reversibilità**: Dal tag non si può risalire al messaggio
3. **Chiave segreta**: Solo chi ha la chiave può creare/verificare
4. **Avalanche effect**: Minima modifica → tag completamente diverso

### Visualizzazione

```
┌─────────────────────────────────────────────┐
│           SENZA MAC (❌ Insicuro)           │
└─────────────────────────────────────────────┘

Alice                Attaccante                Bob
  │                      │                      │
  ├─ MSG: "Paga 100€" ──┼──── INTERCETTA ──────┤
  │                      │                      │
  │                 MODIFICA:                   │
  │                 "Paga 9999€"                │
  │                      │                      │
  │                      ├──── INVIA ──────────→│
  │                                             │
  │                                      ❌ Bob accetta
  │                                         (nessuna verifica)

┌─────────────────────────────────────────────┐
│             CON MAC (✅ Sicuro)             │
└─────────────────────────────────────────────┘

Alice                Attaccante                Bob
  │                      │                      │
  ├─ MSG: "Paga 100€" ──┼──── INTERCETTA ──────┤
  ├─ TAG: [mac_123] ────┤                      │
  │                      │                      │
  │                 MODIFICA:                   │
  │                 "Paga 9999€"                │
  │                 ❌ Non può generare         │
  │                    TAG valido               │
  │                      │                      │
  │                      ├─ Tenta invio ───────→│
  │                                             │
  │                                      ✅ Bob rifiuta
  │                                         (TAG invalido)
```

---

## ⚙️ Come Funziona un MAC {#come-funziona}

### Processo di Autenticazione

```
┌─────────────────────────────────────┐
│         FASE 1: CREAZIONE MAC       │
└─────────────────────────────────────┘

Sender (Alice):
  ┌──────────────┐
  │  Messaggio M │
  └──────┬───────┘
         │
         ├───────┐
         │       │
  ┌──────▼───┐   │
  │ Chiave K │   │
  └──────┬───┘   │
         │       │
         ▼       ▼
     ┌────────────┐
     │  Funzione  │
     │    MAC     │
     └─────┬──────┘
           │
           ▼
      ┌────────┐
      │  TAG   │  ← Invia (M, TAG)
      └────────┘

┌─────────────────────────────────────┐
│         FASE 2: VERIFICA MAC        │
└─────────────────────────────────────┘

Receiver (Bob):
  ┌──────────────┐  ┌───────────┐
  │  Messaggio M │  │ TAG recv. │
  └──────┬───────┘  └─────┬─────┘
         │                │
         ├────────┐       │
         │        │       │
  ┌──────▼───┐   │       │
  │ Chiave K │   │       │
  └──────┬───┘   │       │
         │       │       │
         ▼       ▼       │
     ┌────────────┐      │
     │  Funzione  │      │
     │    MAC     │      │
     └─────┬──────┘      │
           │             │
           ▼             │
      ┌────────┐         │
      │TAG calc│         │
      └────┬───┘         │
           │             │
           └──── Confronta ──┘
                    │
            ┌───────┴───────┐
            ▼               ▼
         VALIDO         INVALIDO
    (M è autentico)  (M modificato)
```

### Esempio Pratico Semplificato

```python
import hmac
import hashlib

# ═══════════════════════════════════════
# SETUP: Chiave condivisa
# ═══════════════════════════════════════
chiave_segreta = b"chiave_condivisa_alice_bob"

# ═══════════════════════════════════════
# FASE 1: Alice crea messaggio + MAC
# ═══════════════════════════════════════
messaggio = b"Trasferimento: 100 EUR a Bob"

# Calcola MAC
tag = hmac.new(chiave_segreta, messaggio, hashlib.sha256).digest()

print("=" * 50)
print("Alice → Invio messaggio")
print("=" * 50)
print(f"Messaggio: {messaggio.decode()}")
print(f"MAC tag: {tag.hex()[:32]}...")
print(f"Lunghezza tag: {len(tag)} byte")

# ═══════════════════════════════════════
# FASE 2: Bob riceve e verifica
# ═══════════════════════════════════════
print("\n" + "=" * 50)
print("Bob → Verifica messaggio")
print("=" * 50)

# Ricalcola MAC con sua copia della chiave
tag_verificato = hmac.new(chiave_segreta, messaggio, hashlib.sha256).digest()

# Confronto sicuro (constant-time)
if hmac.compare_digest(tag, tag_verificato):
    print("✅ Messaggio AUTENTICO e INTEGRO")
    print(f"→ Procedo con: {messaggio.decode()}")
else:
    print("❌ Messaggio MODIFICATO o FALSO")
    print("→ Rifiuto il messaggio")

# ═══════════════════════════════════════
# ATTACCO: Modifica messaggio
# ═══════════════════════════════════════
print("\n" + "=" * 50)
print("Attaccante → Tenta modifica")
print("=" * 50)

messaggio_falso = b"Trasferimento: 9999 EUR a Bob"
print(f"Messaggio modificato: {messaggio_falso.decode()}")

# Attaccante usa il tag originale (non può generarne uno nuovo)
tag_verificato_falso = hmac.new(chiave_segreta, messaggio_falso, hashlib.sha256).digest()

if hmac.compare_digest(tag, tag_verificato_falso):
    print("✅ Valido")
else:
    print("❌ MAC INVALIDO - Attacco rilevato!")
    print("→ Messaggio rifiutato")
```

**Output**:
```
==================================================
Alice → Invio messaggio
==================================================
Messaggio: Trasferimento: 100 EUR a Bob
MAC tag: 3f8a9c2e1d5b7f4a6c8e0d2f4a6c8...
Lunghezza tag: 32 byte

==================================================
Bob → Verifica messaggio
==================================================
✅ Messaggio AUTENTICO e INTEGRO
→ Procedo con: Trasferimento: 100 EUR a Bob

==================================================
Attaccante → Tenta modifica
==================================================
Messaggio modificato: Trasferimento: 9999 EUR a Bob
❌ MAC INVALIDO - Attacco rilevato!
→ Messaggio rifiutato
```

---

## 🔧 Tipologie di MAC {#tipologie}

Esistono diverse famiglie di MAC basate su costruzioni crittografiche differenti:


### 1. HMAC (Hash-based MAC) 🔐

**Base**: Funzioni hash crittografiche (SHA-256, SHA-512)

**Come funziona**: Applica una funzione hash con una chiave segreta attraverso una costruzione a doppio hash.

**Formula**: 
$$\text{HMAC}(K, M) = H((K \oplus opad) \parallel H((K \oplus ipad) \parallel M))$$

**Caratteristiche**:
- ✅ Veloce e ampiamente supportato
- ✅ Sicuro se la funzione hash è sicura
- ✅ Standardizzato (RFC 2104, FIPS 198-1)
- ❌ Richiede due passate hash

**Implementazione**:
```python
import hmac
import hashlib

key = b"chiave_segreta_32_byte_per_hmac_"
msg = b"Messaggio da autenticare con HMAC"

# HMAC-SHA256 (output: 32 byte)
tag = hmac.new(key, msg, hashlib.sha256).digest()
print(f"HMAC-SHA256: {tag.hex()}")
print(f"Lunghezza: {len(tag)} byte")

# HMAC-SHA512 (output: 64 byte)
tag512 = hmac.new(key, msg, hashlib.sha512).digest()
print(f"HMAC-SHA512: {tag512.hex()[:32]}...")
print(f"Lunghezza: {len(tag512)} byte")
```

**Uso tipico**: API authentication (AWS, GitHub), JWT, session cookies

---

### 2. CMAC (Cipher-based MAC) 🔒

**Base**: Cifrari a blocchi (AES)

**Come funziona**: Usa un cifrario a blocchi (tipicamente AES) in una costruzione CBC-MAC migliorata.

**Formula**:
$$\text{CMAC}(K, M) = \text{AES}_K(\text{ultimo blocco CBC})$$

**Caratteristiche**:
- ✅ Sicurezza provata matematicamente
- ✅ Output compatto (128 bit per AES-128)
- ✅ Standardizzato (NIST SP 800-38B, RFC 4493)
- ❌ Richiede hardware AES o è più lento in software

**Implementazione**:
```python
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

# Chiave AES-128 (16 byte) o AES-256 (32 byte)
key = b"0123456789ABCDEF"  # 16 byte per AES-128
msg = b"Messaggio da autenticare con CMAC"

# Crea CMAC con AES-128
c = cmac.CMAC(algorithms.AES(key))
c.update(msg)
tag = c.finalize()

print(f"CMAC-AES128: {tag.hex()}")
print(f"Lunghezza: {len(tag)} byte")  # 16 byte (128 bit)

# Verifica CMAC
def verifica_cmac(key, msg, tag_ricevuto):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(msg)
    try:
        c.verify(tag_ricevuto)  # Lancia eccezione se invalido
        return True
    except:
        return False

is_valid = verifica_cmac(key, msg, tag)
print(f"Verifica: {'✅ Valido' if is_valid else '❌ Invalido'}")
```

**Uso tipico**: Standard IEEE 802.1AE (MACsec), IPsec, dispositivi hardware

---

### 3. GMAC (Galois Message Authentication Code) ⚡

**Base**: Matematica dei campi di Galois (GF(2^128))

**Come funziona**: È la parte di autenticazione di AES-GCM. Usa moltiplicazione in un campo di Galois per calcolare il tag.

**Formula**:
$$\text{GMAC}(K, M) = \text{GHASH}(H, M) \oplus E_K(\text{counter})$$

Dove $H$ è una chiave hash derivata da $K$.

**Caratteristiche**:
- ✅ **Estremamente veloce** (parallelizzabile)
- ✅ Supporto hardware (AES-NI)
- ✅ Integrato in TLS 1.3
- ❌ Mai riusare nonce con stessa chiave (catastrofico!)

**Implementazione** (come parte di GCM):
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# AES-GCM include GMAC per autenticazione
key = AESGCM.generate_key(bit_length=256)  # 32 byte
cipher = AESGCM(key)

nonce = os.urandom(12)  # 12 byte per GCM
msg = b"Dati cifrati e autenticati con GCM/GMAC"

# GCM = Cifratura (CTR) + Autenticazione (GMAC)
ciphertext = cipher.encrypt(nonce, msg, b"")
# ciphertext contiene: dati cifrati + tag GMAC (16 byte)

print(f"GCM output: {ciphertext.hex()[:32]}...")
print(f"Lunghezza totale: {len(ciphertext)} byte")
print(f"  └─ Ciphertext: {len(msg)} byte")
print(f"  └─ GMAC tag: 16 byte")

# Decifra e verifica GMAC
try:
    plaintext = cipher.decrypt(nonce, ciphertext, b"")
    print(f"✅ GMAC valido, decifrato: {plaintext.decode()}")
except:
    print("❌ GMAC invalido - dati modificati!")
```

**Uso tipico**: TLS 1.2/1.3, IPsec, VPN, Wi-Fi (WPA3)

---

### 4. Poly1305 🚀

**Base**: Matematica modulare (aritmetica modulo 2^130-5)

**Come funziona**: MAC moderno progettato da Daniel J. Bernstein. Estremamente veloce, usato con ChaCha20.

**Formula**:
$$\text{Poly1305}(M, K) = ((M \cdot r) \bmod P) + s$$

Dove $r$ e $s$ derivano dalla chiave $K$, e $P = 2^{130} - 5$.

**Caratteristiche**:
- ✅ **Velocissimo** (anche senza hardware dedicato)
- ✅ Sicurezza provata
- ✅ Usato in protocolli moderni (Wireguard, TLS 1.3)
- ⚠️ Chiave usa-e-getta (non riusabile)

**Implementazione** (con ChaCha20):
```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# ChaCha20-Poly1305: Cifrario stream + MAC
key = ChaCha20Poly1305.generate_key()  # 32 byte
cipher = ChaCha20Poly1305(key)

nonce = os.urandom(12)  # 12 byte
msg = b"Messaggio moderno con Poly1305"

# Cifra + autentica
ciphertext = cipher.encrypt(nonce, msg, b"")
print(f"ChaCha20-Poly1305: {ciphertext.hex()[:32]}...")
print(f"Lunghezza: {len(ciphertext)} byte (msg + 16 byte tag)")

# Decifra + verifica
try:
    plaintext = cipher.decrypt(nonce, ciphertext, b"")
    print(f"✅ Poly1305 valido: {plaintext.decode()}")
except:
    print("❌ Poly1305 invalido!")
```

**Uso tipico**: Wireguard VPN, TLS 1.3 (ChaCha20-Poly1305), SSH, Google QUIC

---

### 5. CBC-MAC (⚠️ Deprecato)

**Base**: Cifrario a blocchi in modalità CBC

**Come funziona**: Cifra il messaggio in CBC mode e usa l'ultimo blocco come MAC.

**Caratteristiche**:
- ❌ **NON sicuro** per messaggi di lunghezza variabile
- ❌ Vulnerabile a length extension attacks
- ✅ Sostituito da CMAC (versione sicura)

**⚠️ NON USARE**: CBC-MAC è insicuro. Usa CMAC invece.

---

### Confronto Visivo

```
┌─────────────────────────────────────────────────────────┐
│              Famiglia di MAC - Overview                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  HASH-BASED                                             │
│  ├─ HMAC-SHA256     ████████░░ Velocità: 8/10          │
│  │                  ██████████ Sicurezza: 10/10        │
│  └─ HMAC-SHA512     ███████░░░ Velocità: 7/10          │
│                     ██████████ Sicurezza: 10/10        │
│                                                         │
│  CIPHER-BASED                                           │
│  ├─ CMAC-AES        █████████░ Velocità: 9/10          │
│  │                  ██████████ Sicurezza: 10/10        │
│  └─ CBC-MAC         ████░░░░░░ Velocità: 4/10          │
│                     ███░░░░░░░ Sicurezza: 3/10 ⚠️      │
│                                                         │
│  GALOIS FIELD                                           │
│  └─ GMAC (GCM)      ██████████ Velocità: 10/10 ⚡      │
│                     ██████████ Sicurezza: 10/10        │
│                                                         │
│  MODERN                                                 │
│  └─ Poly1305        ██████████ Velocità: 10/10 🚀      │
│                     ██████████ Sicurezza: 10/10        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 🆚 HMAC vs CMAC vs GMAC vs Poly1305 {#confronto}

### Tabella Comparativa Completa

| Caratteristica | HMAC-SHA256 | CMAC-AES | GMAC | Poly1305 |
|----------------|-------------|----------|------|----------|
| **Base crittografica** | Hash (SHA-256) | Cifrario blocchi (AES) | Campo Galois | Aritmetica modulare |
| **Tag size** | 32 byte (256 bit) | 16 byte (128 bit) | 16 byte (128 bit) | 16 byte (128 bit) |
| **Velocità software** | Media | Media/Alta | Alta | **Altissima** |
| **Velocità hardware** | Media | **Altissima** (AES-NI) | **Altissima** (AES-NI) | Alta |
| **Parallelizzabile** | ❌ No | ❌ No | ✅ Sì | ✅ Sì |
| **Standardizzazione** | RFC 2104, FIPS 198-1 | RFC 4493, SP 800-38B | RFC 4543 | RFC 7539 |
| **Uso principale** | API, JWT, cookies | IPsec, MACsec | TLS 1.2/1.3, VPN | TLS 1.3, Wireguard |
| **Sicurezza provata** | ✅ Sì | ✅ Sì | ✅ Sì | ✅ Sì |
| **Resistenza nonce reuse** | N/A (no nonce) | N/A (no nonce) | ❌ **Catastrofico** | ❌ **Catastrofico** |
| **Complessità impl.** | Bassa | Media | Alta | Bassa |
| **Supporto librerie** | Universale | Buono | Buono (con GCM) | Crescente |
| **Overhead** | Minimo | Minimo | Minimo | **Minimo** |

### Quando Usare Quale?

```
┌────────────────────────────────────────────────┐
│          Decision Tree: Quale MAC?             │
└────────────────────────────────────────────────┘

Hai bisogno di CIFRATURA + AUTENTICAZIONE?
    │
    ├─ Sì → Usa AEAD (Authenticated Encryption)
    │       │
    │       ├─ CPU moderna con AES-NI?
    │       │   └─ Sì → AES-GCM (GMAC) ⚡
    │       │
    │       └─ CPU senza AES-NI o mobile?
    │           └─ Sì → ChaCha20-Poly1305 🚀
    │
    └─ No → Serve solo AUTENTICAZIONE
            │
            ├─ Standard universale?
            │   └─ Sì → HMAC-SHA256 ✅
            │
            ├─ Ambiente IEEE/IPsec?
            │   └─ Sì → CMAC-AES
            │
            └─ Performance critica?
                └─ Sì → Poly1305 (con nonce)
```

### Esempio: Scelta in Base al Caso d'Uso

| Caso d'Uso | MAC Raccomandato | Motivazione |
|------------|------------------|-------------|
| **API REST Authentication** | HMAC-SHA256 | Universale, stateless, no nonce |
| **JWT Token Signing** | HMAC-SHA256 | Standard de-facto, ampio supporto |
| **Cookie di Sessione** | HMAC-SHA256 | Semplice, sicuro, deterministico |
| **TLS 1.3 Connection** | GMAC (GCM) o Poly1305 | Cifratura + auth, altissima velocità |
| **VPN (Wireguard)** | Poly1305 | Velocissimo, moderno, provato |
| **IPsec** | CMAC-AES o GMAC | Standard IEEE, supporto hardware |
| **File Integrity** | HMAC-SHA256 | No nonce needed, deterministico |
| **Database Record Auth** | HMAC-SHA256 | Semplice, no stato |
| **IoT Low-Power** | Poly1305 | Efficiente, poco overhead |
| **Hardware Security Module** | CMAC-AES | Supporto hardware AES |

---

## 🔐 Authenticated Encryption (AEAD) {#aead}

### Problema: Cifratura + Autenticazione

**Scenario**: Voglio che i dati siano:
1. **Confidenziali** (cifrati) → AES, ChaCha20
2. **Autentici** (verificabili) → MAC

**❌ Approccio ingenuo** (pericoloso):
```python
# ❌ SBAGLIATO - Vulnerabile!
ciphertext = encrypt(plaintext)
tag = mac(ciphertext)
# Problemi: Timing attacks, padding oracle, etc.
```

### Tre Pattern di Combinazione

#### 1. Encrypt-and-MAC (❌ INSICURO)

```
tag = MAC(key_mac, plaintext)
ciphertext = Encrypt(key_enc, plaintext)

Invia: ciphertext || tag
```

**Problemi**:
- Tag rivela informazioni sul plaintext
- Usato in SSH (problemi storici)

#### 2. MAC-then-Encrypt (⚠️ PROBLEMATICO)

```
tag = MAC(key_mac, plaintext)
ciphertext = Encrypt(key_enc, plaintext || tag)

Invia: ciphertext
```

**Problemi**:
- Vulnerabile a padding oracle attacks
- Usato in TLS 1.0-1.1 (problemi noti: BEAST, POODLE)

#### 3. Encrypt-then-MAC (✅ SICURO)

```
ciphertext = Encrypt(key_enc, plaintext)
tag = MAC(key_mac, ciphertext)

Invia: ciphertext || tag
```

**Vantaggi**:
- Verifica MAC PRIMA di decifrare
- Previene padding oracle
- Raccomandato da tutti i crittografi

**Implementazione**:
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.backends import default_backend
import os

def encrypt_then_mac(key_enc, key_mac, plaintext):
    """
    Pattern Encrypt-then-MAC sicuro
    
    1. Cifra il plaintext con AES-CBC
    2. Calcola HMAC sul ciphertext (+ IV)
    3. Ritorna IV || ciphertext || tag
    """
    # 1. Genera IV casuale
    iv = os.urandom(16)
    
    # 2. Padding PKCS#7
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)
    
    # 3. Cifra con AES-CBC
    cipher = Cipher(
        algorithms.AES(key_enc),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # 4. HMAC su (IV || ciphertext)
    h = crypto_hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    tag = h.finalize()
    
    # 5. Ritorna tutto
    return iv + ciphertext + tag

def decrypt_and_verify(key_enc, key_mac, data):
    """
    Verifica MAC PRIMA di decifrare
    
    1. Estrai IV, ciphertext, tag
    2. Verifica HMAC (SE FALLISCE, STOP!)
    3. Solo se valido, decifra
    """
    # 1. Separa componenti
    iv = data[:16]
    tag = data[-32:]  # HMAC-SHA256 = 32 byte
    ciphertext = data[16:-32]
    
    # 2. Verifica HMAC
    h = crypto_hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    
    try:
        h.verify(tag)
    except:
        raise ValueError("❌ HMAC invalido - dati modificati!")
    
    # 3. Solo se HMAC valido, decifra
    cipher = Cipher(
        algorithms.AES(key_enc),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 4. Rimuovi padding
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    
    return plaintext

# ═══════════════════════════════════════════════
# Test Encrypt-then-MAC
# ═══════════════════════════════════════════════

# IMPORTANTE: Usa chiavi DIVERSE!
key_encryption = b"0123456789ABCDEF"  # 16 byte per AES-128
key_mac = b"FEDCBA9876543210"  # 16 byte per HMAC

plaintext = b"Dati molto segreti e importanti"

# Cifra + autentica
encrypted_data = encrypt_then_mac(key_encryption, key_mac, plaintext)
print(f"Encrypted+MAC ({len(encrypted_data)} byte): {encrypted_data.hex()[:64]}...")

# Decifra + verifica
try:
    decrypted = decrypt_and_verify(key_encryption, key_mac, encrypted_data)
    print(f"✅ Decifrato: {decrypted.decode()}")
except ValueError as e:
    print(f"❌ {e}")

# ═══════════════════════════════════════════════
# Test: Modifica dati (attacco)
# ═══════════════════════════════════════════════
print("\n" + "="*50)
print("Attacco: Modifica ciphertext")
print("="*50)

# Modifica un byte del ciphertext
tampered = bytearray(encrypted_data)
tampered[20] ^= 0xFF  # Flip byte

try:
    decrypted = decrypt_and_verify(key_encryption, key_mac, bytes(tampered))
    print(f"✅ Decifrato: {decrypted}")
except ValueError as e:
    print(f"{e}")
```

**Output**:
```
Encrypted+MAC (96 byte): 3a7f2c1e9b4d8f6a5c3e7d2f1a9b4c8e...
✅ Decifrato: Dati molto segreti e importanti

==================================================
Attacco: Modifica ciphertext
==================================================
❌ HMAC invalido - dati modificati!
```

### AEAD: Soluzione Moderna (⭐ PREFERIBILE)

**AEAD** (Authenticated Encryption with Associated Data) combina cifratura + autenticazione in modo nativo.

**Vantaggi**:
- ✅ Un'unica primitiva (no composition bugs)
- ✅ Più veloce (ottimizzato)
- ✅ API semplice
- ✅ Standard moderni (TLS 1.3, Wireguard)

#### AES-GCM (AEAD con GMAC)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# ═══════════════════════════════════════════════
# AES-GCM: Cifratura + Autenticazione
# ═══════════════════════════════════════════════

key = AESGCM.generate_key(bit_length=256)  # 32 byte
cipher = AESGCM(key)

# Nonce univoco (12 byte per GCM)
nonce = os.urandom(12)

plaintext = b"AEAD rende tutto più semplice e sicuro"

# Additional Authenticated Data (opzionale)
# Dati NON cifrati ma autenticati (es. header, metadata)
aad = b"user_id:42,timestamp:1704556800"

# ═══════════════════════════════════════════════
# Cifra + Autentica in un colpo solo
# ═══════════════════════════════════════════════
ciphertext = cipher.encrypt(nonce, plaintext, aad)

print(f"Plaintext ({len(plaintext)} byte): {plaintext}")
print(f"AAD ({len(aad)} byte): {aad}")
print(f"Ciphertext+Tag ({len(ciphertext)} byte): {ciphertext.hex()[:32]}...")
print(f"  └─ Ciphertext: {len(plaintext)} byte")
print(f"  └─ GCM tag: {len(ciphertext) - len(plaintext)} byte")

# ═══════════════════════════════════════════════
# Decifra + Verifica
# ═══════════════════════════════════════════════
try:
    decrypted = cipher.decrypt(nonce, ciphertext, aad)
    print(f"\n✅ GCM valido, decifrato: {decrypted.decode()}")
except:
    print("\n❌ GCM tag invalido!")

# ═══════════════════════════════════════════════
# Test: Modifica ciphertext
# ═══════════════════════════════════════════════
print("\n" + "="*50)
print("Attacco 1: Modifica ciphertext")
print("="*50)

tampered_ct = bytearray(ciphertext)
tampered_ct[5] ^= 0xFF

try:
    cipher.decrypt(nonce, bytes(tampered_ct), aad)
    print("✅ Valido")
except:
    print("❌ GCM rilevato modifica ciphertext!")

# ═══════════════════════════════════════════════
# Test: Modifica AAD
# ═══════════════════════════════════════════════
print("\n" + "="*50)
print("Attacco 2: Modifica AAD")
print("="*50)

fake_aad = b"user_id:666,timestamp:1704556800"  # Modifica user_id

try:
    cipher.decrypt(nonce, ciphertext, fake_aad)
    print("✅ Valido")
except:
    print("❌ GCM rilevato modifica AAD!")
```

**Output**:
```
Plaintext (38 byte): b'AEAD rende tutto più semplice e sicuro'
AAD (31 byte): b'user_id:42,timestamp:1704556800'
Ciphertext+Tag (54 byte): 7a3f9e2c1b8d4f6a5c3e7d2f1a9b...
  └─ Ciphertext: 38 byte
  └─ GCM tag: 16 byte

✅ GCM valido, decifrato: AEAD rende tutto più semplice e sicuro

==================================================
Attacco 1: Modifica ciphertext
==================================================
❌ GCM rilevato modifica ciphertext!

==================================================
Attacco 2: Modifica AAD
==================================================
❌ GCM rilevato modifica AAD!
```

#### ChaCha20-Poly1305 (AEAD alternativo)

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# ═══════════════════════════════════════════════
# ChaCha20-Poly1305: AEAD moderno
# ═══════════════════════════════════════════════

key = ChaCha20Poly1305.generate_key()  # 32 byte
cipher = ChaCha20Poly1305(key)

nonce = os.urandom(12)
plaintext = b"ChaCha20-Poly1305: velocissimo anche senza AES-NI"
aad = b"metadata_non_cifrato"

# Cifra + autentica
ciphertext = cipher.encrypt(nonce, plaintext, aad)

print(f"ChaCha20-Poly1305:")
print(f"  Plaintext: {len(plaintext)} byte")
print(f"  Ciphertext+Tag: {len(ciphertext)} byte")
print(f"  Overhead: {len(ciphertext) - len(plaintext)} byte (Poly1305 tag)")

# Decifra + verifica
try:
    decrypted = cipher.decrypt(nonce, ciphertext, aad)
    print(f"✅ Poly1305 valido: {decrypted.decode()}")
except:
    print("❌ Poly1305 invalido!")
```

### Confronto: Encrypt-then-MAC vs AEAD

| Aspetto | Encrypt-then-MAC | AEAD (GCM/Poly1305) |
|---------|------------------|---------------------|
| **Complessità** | Alta (due primitive) | Bassa (una primitiva) |
| **Velocità** | Media | Alta/Altissima |
| **Sicurezza** | Alta (se fatto bene) | Alta (built-in) |
| **Rischio errori** | Alto (composition) | Basso |
| **Standard moderni** | Meno usato | TLS 1.3, Wireguard |
| **Due chiavi** | ✅ Necessarie | ❌ Una sola |
| **Supporto AAD** | Manuale | ✅ Nativo |
| **Raccomandazione** | Legacy/compatibilità | ⭐ **Preferibile** |

**📌 Conclusione**: Usa **AES-GCM** o **ChaCha20-Poly1305** per nuovi progetti. Usa Encrypt-then-MAC solo per compatibilità con sistemi legacy.

---

## 💻 Implementazioni Pratiche {#implementazioni}

### Esempio 1: Sistema di Messaggistica Sicuro

```python
import hmac
import hashlib
import time
import json

class SecureMessaging:
    def __init__(self, shared_secret):
        self.secret = shared_secret
    
    def send_message(self, sender, recipient, content):
        """
        Crea messaggio autenticato con MAC
        
        Include:
        - Timestamp (previene replay)
        - Sender/Recipient (previene impersonation)
        - Content
        - MAC su tutto
        """
        timestamp = int(time.time())
        
        # Costruisci payload
        message = {
            'sender': sender,
            'recipient': recipient,
            'timestamp': timestamp,
            'content': content
        }
        
        # Serializza
        payload = json.dumps(message, sort_keys=True).encode()
        
        # Calcola MAC
        tag = hmac.new(self.secret, payload, hashlib.sha256).digest()
        
        return {
            'message': message,
            'mac': tag.hex()
        }
    
    def verify_message(self, packet, max_age_seconds=300):
        """
        Verifica messaggio ricevuto
        
        Controlli:
        1. MAC valido
        2. Timestamp non scaduto
        3. Timestamp non nel futuro
        """
        message = packet['message']
        received_mac = bytes.fromhex(packet['mac'])
        
        # 1. Ricalcola MAC
        payload = json.dumps(message, sort_keys=True).encode()
        expected_mac = hmac.new(self.secret, payload, hashlib.sha256).digest()
        
        # 2. Verifica MAC (constant-time)
        if not hmac.compare_digest(received_mac, expected_mac):
            return False, "MAC invalido - messaggio corrotto o falso"
        
        # 3. Controlla timestamp
        now = int(time.time())
        msg_time = message['timestamp']
        
        if msg_time > now + 60:  # Tolleranza 1 minuto clock skew
            return False, "Timestamp nel futuro"
        
        if now - msg_time > max_age_seconds:
            return False, f"Messaggio scaduto (>{max_age_seconds}s)"
        
        return True, message

# ═══════════════════════════════════════════════
# Test Sistema Messaggistica
# ═══════════════════════════════════════════════

secret = b"chiave_condivisa_alice_bob_32byte"
messenger = SecureMessaging(secret)

# Alice invia messaggio
print("="*60)
print("Alice → Invia messaggio a Bob")
print("="*60)

packet = messenger.send_message(
    sender="Alice",
    recipient="Bob",
    content="Incontriamoci alle 15:00 in biblioteca"
)

print(f"Sender: {packet['message']['sender']}")
print(f"Recipient: {packet['message']['recipient']}")
print(f"Content: {packet['message']['content']}")
print(f"MAC: {packet['mac'][:32]}...")

# Bob riceve e verifica
print("\n" + "="*60)
print("Bob → Verifica messaggio")
print("="*60)

valid, result = messenger.verify_message(packet)

if valid:
    print("✅ Messaggio AUTENTICO")
    print(f"   Da: {result['sender']}")
    print(f"   Contenuto: {result['content']}")
else:
    print(f"❌ {result}")

# ═══════════════════════════════════════════════
# Attacco 1: Modifica contenuto
# ═══════════════════════════════════════════════
print("\n" + "="*60)
print("Attaccante → Tenta di modificare il contenuto")
print("="*60)

tampered_packet = {
    'message': {
        'sender': 'Alice',
        'recipient': 'Bob',
        'timestamp': packet['message']['timestamp'],
        'content': 'Incontriamoci alle 15:00 alla BANCA'  # Modificato!
    },
    'mac': packet['mac']  # MAC originale
}

print(f"Contenuto modificato: {tampered_packet['message']['content']}")

valid, result = messenger.verify_message(tampered_packet)

if valid:
    print("✅ Messaggio accettato")
else:
    print(f"❌ {result}")
    print("   → Attacco RILEVATO e BLOCCATO!")

# ═══════════════════════════════════════════════
# Attacco 2: Impersonation
# ═══════════════════════════════════════════════
print("\n" + "="*60)
print("Attaccante → Tenta di impersonare Alice")
print("="*60)

fake_packet = {
    'message': {
        'sender': 'Alice',  # Finge di essere Alice
        'recipient': 'Bob',
        'timestamp': packet['message']['timestamp'],
        'content': 'Trasferisci 1000€ a Charlie'
    },
    'mac': packet['mac']
}

print(f"Sender: {fake_packet['message']['sender']}")
print(f"Contenuto: {fake_packet['message']['content']}")

valid, result = messenger.verify_message(fake_packet)

if valid:
    print("✅ Messaggio accettato")
else:
    print(f"❌ {result}")
    print("   → Impersonation RILEVATA!")

# ═══════════════════════════════════════════════
# Attacco 3: Replay Attack
# ═══════════════════════════════════════════════
print("\n" + "="*60)
print("Attaccante → Replay attack (reinvia messaggio vecchio)")
print("="*60)

# Simula messaggio vecchio di 10 minuti
time.sleep(1)  # In produzione, sarebbe molto più tempo

old_packet = messenger.send_message(
    "Alice", "Bob", "Trasferisci 500€"
)

# Modifica timestamp manualmente (simula messaggio vecchio)
old_packet['message']['timestamp'] = int(time.time()) - 400  # 6+ minuti fa

# Ricalcola MAC con timestamp vecchio
old_payload = json.dumps(old_packet['message'], sort_keys=True).encode()
old_packet['mac'] = hmac.new(secret, old_payload, hashlib.sha256).hexdigest()

print(f"Timestamp messaggio: {old_packet['message']['timestamp']}")
print(f"Età messaggio: {int(time.time()) - old_packet['message']['timestamp']}s")

valid, result = messenger.verify_message(old_packet, max_age_seconds=300)

if valid:
    print("✅ Messaggio accettato")
else:
    print(f"❌ {result}")
    print("   → Replay attack RILEVATO!")
```

### Esempio 2: File Integrity Monitor

```python
import hmac
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, secret_key, db_file='integrity.json'):
        self.secret = secret_key
        self.db_file = db_file
        self.db = self._load_db()
    
    def _load_db(self):
        """Carica database integrità"""
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_db(self):
        """Salva database integrità"""
        with open(self.db_file, 'w') as f:
            json.dump(self.db, f, indent=2)
    
    def _calc_mac(self, filepath):
        """Calcola MAC di un file"""
        h = hmac.new(self.secret, digestmod=hashlib.sha256)
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        
        return h.hexdigest()
    
    def register_file(self, filepath):
        """Registra file per monitoraggio"""
        if not os.path.exists(filepath):
            print(f"❌ File non trovato: {filepath}")
            return False
        
        mac = self._calc_mac(filepath)
        stat = os.stat(filepath)
        
        self.db[filepath] = {
            'mac': mac,
            'size': stat.st_size,
            'registered_at': datetime.now().isoformat(),
            'last_verified': None
        }
        
        self._save_db()
        print(f"✅ Registrato: {filepath}")
        print(f"   MAC: {mac[:32]}...")
        print(f"   Size: {stat.st_size} byte")
        return True
    
    def verify_file(self, filepath):
        """Verifica integrità file"""
        if filepath not in self.db:
            return False, "File non registrato"
        
        if not os.path.exists(filepath):
            return False, "File non trovato"
        
        # Calcola MAC corrente
        current_mac = self._calc_mac(filepath)
        stored_mac = self.db[filepath]['mac']
        current_size = os.path.getsize(filepath)
        stored_size = self.db[filepath]['size']
        
        # Aggiorna timestamp verifica
        self.db[filepath]['last_verified'] = datetime.now().isoformat()
        self._save_db()
        
        # Confronta
        if not hmac.compare_digest(current_mac, stored_mac):
            return False, {
                'reason': 'MAC mismatch',
                'expected_mac': stored_mac,
                'current_mac': current_mac,
                'size_changed': current_size != stored_size
            }
        
        return True, {'size': current_size, 'mac': current_mac[:16] + '...'}
    
    def scan_all(self):
        """Scansiona tutti i file registrati"""
        print("\n" + "="*70)
        print("FILE INTEGRITY SCAN")
        print("="*70)
        
        results = {'ok': 0, 'modified': 0, 'missing': 0}
        
        for filepath in self.db.keys():
            if not os.path.exists(filepath):
                print(f"❌ MISSING: {filepath}")
                results['missing'] += 1
                continue
            
            valid, details = self.verify_file(filepath)
            
            if valid:
                print(f"✅ OK: {filepath}")
                results['ok'] += 1
            else:
                print(f"❌ MODIFIED: {filepath}")
                if isinstance(details, dict) and 'reason' in details:
                    print(f"   Reason: {details['reason']}")
                    if details.get('size_changed'):
                        print(f"   Size changed: YES")
                results['modified'] += 1
        
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        print(f"✅ Integri: {results['ok']}")
        print(f"❌ Modificati: {results['modified']}")
        print(f"⚠️  Mancanti: {results['missing']}")
        print(f"📊 Totali: {len(self.db)}")
        
        return results

# ═══════════════════════════════════════════════
# Test File Integrity Monitor
# ═══════════════════════════════════════════════

# Setup
secret = b"file_monitor_secret_key_32byte__"
monitor = FileIntegrityMonitor(secret, 'test_integrity.json')

# Crea file di test
test_files = {
    'config.txt': b'database_host=localhost\nport=5432',
    'data.bin': os.urandom(1024),
    'script.sh': b'#!/bin/bash\necho "Hello World"'
}

print("Creazione file di test...")
for filename, content in test_files.items():
    with open(filename, 'wb') as f:
        f.write(content)
    monitor.register_file(filename)

# Scan iniziale
print("\n" + "🔍 Scan iniziale (tutto dovrebbe essere OK)")
monitor.scan_all()

# Simula modifica
print("\n" + "⚠️  Simulazione: Modifica config.txt")
with open('config.txt', 'a') as f:
    f.write('\n# Linea aggiunta da attaccante')

# Scan dopo modifica
print("\n" + "🔍 Scan dopo modifica")
results = monitor.scan_all()

# Cleanup
print("\n" + "Pulizia file di test...")
for filename in test_files.keys():
    if os.path.exists(filename):
        os.remove(filename)
if os.path.exists('test_integrity.json'):
    os.remove('test_integrity.json')

print("✅ Test completato!")
```

---

## 🌐 Applicazioni Reali {#applicazioni}

### 1. API Authentication con HMAC

**GitHub Webhooks** usa HMAC-SHA256 per autenticare ogni evento:

```python
import hmac
import hashlib

def verify_github_webhook(payload, signature_header, secret):
    """
    GitHub invia signature nell'header:
    X-Hub-Signature-256: sha256=<hmac_hex>
    """
    # Estrai hash dall'header
    if not signature_header.startswith('sha256='):
        return False
    
    received_hash = signature_header[7:]  # Rimuovi 'sha256='
    
    # Calcola HMAC
    expected_hash = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Confronto sicuro
    return hmac.compare_digest(expected_hash, received_hash)

# Simulazione webhook
webhook_secret = "my_github_webhook_secret"
webhook_payload = b'{"action":"opened","number":42}'
signature = f"sha256={hmac.new(webhook_secret.encode(), webhook_payload, hashlib.sha256).hexdigest()}"

if verify_github_webhook(webhook_payload, signature, webhook_secret):
    print("✅ Webhook autentico da GitHub")
else:
    print("❌ Webhook falso!")
```

### 2. JWT (JSON Web Tokens) con HMAC

```python
import hmac
import hashlib
import base64
import json
import time

def create_jwt_hs256(payload, secret):
    """Crea JWT firmato con HMAC-SHA256"""
    # Header
    header = {"alg": "HS256", "typ": "JWT"}
    
    # Encode header e payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # Firma con HMAC
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    # JWT = header.payload.signature
    return f"{message}.{signature_b64}"

def verify_jwt_hs256(token, secret):
    """Verifica JWT"""
    try:
        header_b64, payload_b64, signature_b64 = token.rsplit('.', 2)
        
        # Ricalcola firma
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        # Padding per base64
        signature_b64 += '=' * (4 - len(signature_b64) % 4)
        received_sig = base64.urlsafe_b64decode(signature_b64)
        
        # Verifica firma
        if not hmac.compare_digest(expected_sig, received_sig):
            return False, "Firma invalida"
        
        # Decode payload
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Controlla expiration
        if 'exp' in payload and payload['exp'] < time.time():
            return False, "Token scaduto"
        
        return True, payload
        
    except Exception as e:
        return False, f"Errore: {e}"

# Test JWT
jwt_secret = "jwt_secret_key_min_32_caratteri"
payload = {
    "user_id": 123,
    "username": "alice",
    "role": "admin",
    "exp": int(time.time()) + 3600  # Scade tra 1 ora
}

token = create_jwt_hs256(payload, jwt_secret)
print(f"JWT: {token[:50]}...")

# Verifica
valid, result = verify_jwt_hs256(token, jwt_secret)
if valid:
    print(f"✅ JWT valido")
    print(f"   User: {result['username']}")
    print(f"   Role: {result['role']}")
else:
    print(f"❌ {result}")
```

### 3. TLS 1.3 Record Layer

TLS 1.3 usa esclusivamente AEAD (GCM o ChaCha20-Poly1305):

```
┌────────────────────────────────────────┐
│      TLS 1.3 Record Protection         │
├────────────────────────────────────────┤
│                                        │
│  Plaintext: HTTP request/response      │
│       ↓                                │
│  AES-GCM or ChaCha20-Poly1305          │
│       ↓                                │
│  Ciphertext + GMAC/Poly1305 tag        │
│       ↓                                │
│  Network transmission                  │
│                                        │
└────────────────────────────────────────┘

Cipher Suites TLS 1.3:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
```

### 4. IPsec con GMAC/CMAC

```
┌────────────────────────────────────────┐
│        IPsec ESP (AH) with MAC         │
├────────────────────────────────────────┤
│                                        │
│  IP Packet                             │
│  ├─ IP Header                          │
│  ├─ ESP Header                         │
│  ├─ Encrypted Payload (AES-GCM)        │
│  └─ GMAC Tag (16 byte)                 │
│                                        │
│  MAC copre:                            │
│  - ESP Header                          │
│  - Ciphertext                          │
│  - ESP Trailer                         │
│                                        │
└────────────────────────────────────────┘
```

### 5. Message Queues (RabbitMQ, Kafka)

```python
import hmac
import hashlib
import time
import json

def create_authenticated_message(producer_id, message, secret):
    """Crea messaggio autenticato per coda"""
    timestamp = int(time.time())
    nonce = os.urandom(8).hex()
    
    envelope = {
        'producer_id': producer_id,
        'timestamp': timestamp,
        'nonce': nonce,
        'message': message
    }
    
    # MAC su envelope serializzato
    payload = json.dumps(envelope, sort_keys=True).encode()
    tag = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    
    envelope['mac'] = tag
    return envelope

# Producer
secret = b"queue_secret_shared_with_consumer"
msg = create_authenticated_message(
    "producer-001",
    {"action": "process_order", "order_id": 12345},
    secret
)

print("Messaggio per coda:")
print(json.dumps(msg, indent=2))
```

---

## 🔒 Sicurezza e Vulnerabilità {#sicurezza}

### Timing Attacks su MAC

**Problema**: Confronto naive rivela informazioni sul MAC:

```python
def verify_mac_VULNERABLE(tag1, tag2):
    """❌ VULNERABILE a timing attack"""
    if len(tag1) != len(tag2):
        return False
    
    for i in range(len(tag1)):
        if tag1[i] != tag2[i]:
            return False  # ← Esce subito! Tempo variabile
    
    return True
```

**Attacco**:
```python
import time

def timing_attack_demo():
    """Dimostra timing attack"""
    real_mac = b"correct_mac_16by"
    
    # Attaccante prova diversi MAC
    guesses = [
        b"aaaaaaaaaaaaaaaa",  # Nessun byte corretto
        b"caaaaaaaaaaaaaaa",  # Primo byte corretto
        b"coaaaaaaaaaaaaaa",  # Due byte corretti
    ]
    
    for guess in guesses:
        start = time.perf_counter()
        
        # Verifica vulnerabile
        for i in range(len(real_mac)):
            if real_mac[i] != guess[i]:
                break
        
        elapsed = time.perf_counter() - start
        print(f"Guess: {guess} → {elapsed*1000000:.2f} μs")
    
    # L'attaccante può vedere che più byte sono corretti,
    # più tempo impiega il confronto!

timing_attack_demo()
```

**Soluzione - Constant-Time Comparison**:
```python
def verify_mac_SECURE(tag1, tag2):
    """✅ SICURO - Constant-time comparison"""
    import hmac
    return hmac.compare_digest(tag1, tag2)

# Oppure implementazione manuale:
def constant_time_compare(a, b):
    """Confronto a tempo costante"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y  # Accumula differenze
    
    return result == 0  # Sempre tutto il loop
```

### Length Extension Attack

**Problema**: Hash semplici sono vulnerabili:

```
Hash(secret || message) è vulnerabile!

Attaccante può calcolare:
Hash(secret || message || extra)
senza conoscere il secret!
```

**Esempio vulnerabile**:
```python
import hashlib

# ❌ SBAGLIATO - Vulnerabile a length extension
def naive_mac(secret, message):
    return hashlib.sha256(secret + message).digest()

# Attaccante può estendere il messaggio!
```

**Soluzione - HMAC è immune**:
```python
import hmac
import hashlib

# ✅ CORRETTO - HMAC previene length extension
def secure_mac(secret, message):
    return hmac.new(secret, message, hashlib.sha256).digest()

# La doppia hash di HMAC previene l'attacco
```

### Nonce Reuse Disaster (GMAC/Poly1305)

**⚠️ CRITICO**: Mai riusare nonce con GMAC o Poly1305!

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)

nonce = b"123456789012"  # 12 byte

msg1 = b"Primo messaggio"
msg2 = b"Secondo messaggio"

# ✅ OK - Nonce diversi
nonce1 = b"123456789001"
nonce2 = b"123456789002"
ct1 = cipher.encrypt(nonce1, msg1, b"")
ct2 = cipher.encrypt(nonce2, msg2, b"")

# ❌ CATASTROFICO - Stesso nonce!
ct1_BAD = cipher.encrypt(nonce, msg1, b"")
ct2_BAD = cipher.encrypt(nonce, msg2, b"")
# Rivela XOR dei plaintext + compromette chiave!
```

**Best Practice**:
```python
import os

# ✅ Genera nonce casuale ogni volta
nonce = os.urandom(12)

# ✅ Oppure usa counter (se gestito correttamente)
nonce_counter = 0
def get_next_nonce():
    global nonce_counter
    nonce_counter += 1
    return nonce_counter.to_bytes(12, 'big')
```

---

## ✅ Best Practices {#best-practices}

### 1. Scegli il MAC Giusto

```python
# ✅ Uso generale: HMAC-SHA256
import hmac, hashlib
tag = hmac.new(key, msg, hashlib.sha256).digest()

# ✅ Cifratura + auth: AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
cipher = AESGCM(key)
ciphertext = cipher.encrypt(nonce, plaintext, aad)

# ✅ Mobile/performance: ChaCha20-Poly1305
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
cipher = ChaCha20Poly1305(key)
ciphertext = cipher.encrypt(nonce, plaintext, aad)
```

### 2. Usa Chiavi Adeguate

```python
import secrets

# ✅ HMAC: ≥32 byte
hmac_key = secrets.token_bytes(32)

# ✅ AES-GCM: 16 (AES-128) o 32 (AES-256) byte
aes_key = secrets.token_bytes(32)

# ✅ ChaCha20-Poly1305: 32 byte
chacha_key = secrets.token_bytes(32)

# ❌ MAI hardcode
BAD_KEY = b"password123"  # NO!
```

### 3. Sempre Constant-Time Comparison

```python
import hmac

# ✅ CORRETTO
if hmac.compare_digest(received_mac, expected_mac):
    print("Valido")

# ❌ SBAGLIATO
if received_mac == expected_mac:  # Timing attack!
    print("Valido")
```

### 4. Includi Contesto nel MAC

```python
# ✅ CORRETTO - Include tutto il contesto
context = f"{sender}:{recipient}:{timestamp}:{message}"
mac = hmac.new(key, context.encode(), hashlib.sha256).digest()

# ❌ SBAGLIATO - Solo messaggio
mac = hmac.new(key, message.encode(), hashlib.sha256).digest()
# Vulnerabile a substitution attacks
```

### 5. Previeni Replay Attacks

```python
import time

# ✅ Include timestamp
timestamp = int(time.time())
payload = f"{timestamp}:{message}"
mac = hmac.new(key, payload.encode(), hashlib.sha256).digest()

# Verifica età messaggio
MAX_AGE = 300  # 5 minuti
if time.time() - timestamp > MAX_AGE:
    raise ValueError("Messaggio scaduto")
```

### 6. Usa Chiavi Separate

```python
# ✅ CORRETTO - Chiavi diverse per cifratura e MAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

master_key = secrets.token_bytes(32)

# Deriva chiavi separate
kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'encryption')
enc_key = kdf.derive(master_key)

kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'mac')
mac_key = kdf.derive(master_key)

# ❌ SBAGLIATO - Stessa chiave
key = secrets.token_bytes(32)
ciphertext = encrypt(key, plaintext)
mac = hmac.new(key, ciphertext, hashlib.sha256).digest()  # NO!
```

### 7. Preferisci AEAD

```python
# ✅ MODERNO - Usa AEAD (raccomandato)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
cipher = AESGCM(key)
ciphertext = cipher.encrypt(nonce, plaintext, aad)

# ⚠️ LEGACY - Solo se necessario per compatibilità
ciphertext = encrypt(enc_key, plaintext)
mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
```

### Checklist Finale

- [ ] MAC appropriato per il caso d'uso
- [ ] Chiave ≥256 bit generata con `secrets`
- [ ] `hmac.compare_digest()` per confronti
- [ ] Timestamp per prevenire replay
- [ ] Chiavi separate per cifratura e MAC (se non AEAD)
- [ ] Nonce univoco (se GMAC/Poly1305)
- [ ] Verifica MAC PRIMA di decifrare
- [ ] Gestione sicura chiavi (key vault, env vars)

---

## 📝 Esercizi {#esercizi}

### Esercizio 1: Implementa Sistema di Token (★★☆)

Crea un sistema di token API autenticati con HMAC che include:
- Token con expiration
- Rate limiting
- Revoca token

<details>
<summary>Hint</summary>

```python
token_structure = {
    'user_id': int,
    'issued_at': timestamp,
    'expires_at': timestamp,
    'nonce': random,
    'hmac': tag
}
```
</details>

### Esercizio 2: Confronta Performance (★★★)

Benchmark di diversi MAC:
- HMAC-SHA256 vs HMAC-SHA512
- CMAC-AES vs HMAC
- GCM vs ChaCha20-Poly1305

Su messaggi di 1KB, 1MB, 100MB.

### Esercizio 3: Secure Chat Protocol (★★★)

Progetta un protocollo chat che garantisca:
- Confidenzialità (cifratura)
- Autenticazione (MAC)
- Forward secrecy
- Protezione da replay

---

## 🎓 Riepilogo

### Cos'è un MAC

Un **MAC** (Message Authentication Code) garantisce:
- **Integrità**: Il messaggio non è stato modificato
- **Autenticazione**: Il mittente possiede la chiave

### Tipi Principali

| Tipo | Base | Velocità | Uso |
|------|------|----------|-----|
| HMAC | Hash | Media | API, JWT, cookies |
| CMAC | AES | Alta | IPsec, IEEE |
| GMAC | Galois Field | Altissima | TLS, VPN |
| Poly1305 | Modular | Altissima | Wireguard, TLS 1.3 |

### Quando Usare

- **Solo autenticazione**: HMAC-SHA256
- **Cifratura + autenticazione**: AES-GCM o ChaCha20-Poly1305 (AEAD)
- **Performance critica**: Poly1305 o GMAC
- **Standard IEEE**: CMAC-AES

### Regole d'Oro

1. Usa `hmac.compare_digest()` SEMPRE
2. Preferisci AEAD (GCM, Poly1305) per cifratura + auth
3. Mai riusare nonce con GMAC/Poly1305
4. Includi timestamp per prevenire replay
5. Chiavi separate per cifratura e MAC

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 13 - HMAC](13_hmac.md)
- **Successivo**: [Capitolo 15 - Certificati Digitali](../05_Certificati_PKI/15_certificati_digitali.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

### Standard
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication
- **RFC 4493**: The AES-CMAC Algorithm
- **RFC 4543**: The Use of GMAC in IPsec ESP and AH
- **RFC 7539**: ChaCha20 and Poly1305 for IETF Protocols
- **NIST SP 800-38B**: Recommendation for Block Cipher Modes: CMAC
- **NIST SP 800-38D**: Recommendation for Block Cipher Modes: GCM and GMAC

### Approfondimenti
- **"Authenticated Encryption"** by Rogaway (paper fondamentale)
- **TLS 1.3 RFC 8446**: Modern AEAD usage
- **Wireguard Protocol**: ChaCha20-Poly1305 in action

---

**💡 Raccomandazione**: Per nuovi progetti, usa **AES-GCM** (se hai AES-NI) o **ChaCha20-Poly1305** (altrimenti). Per API authentication senza cifratura, **HMAC-SHA256** è la scelta standard.

---
