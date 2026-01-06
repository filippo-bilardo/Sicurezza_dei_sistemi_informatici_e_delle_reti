# Capitolo 5 - Modi di Operazione dei Cifrari a Blocchi

> **Corso**: Sistemi e Reti 3  
> **Parte**: 2 - Crittografia Simmetrica  
> **Autore**: Prof. Filippo Bilardo  
> **Prerequisiti**: Capitolo 4 - Cifrari a Blocchi

---

## 📋 Indice

1. [Introduzione](#introduzione)
2. [ECB - Electronic Codebook](#ecb)
3. [CBC - Cipher Block Chaining](#cbc)
4. [CTR - Counter Mode](#ctr)
5. [GCM - Galois/Counter Mode](#gcm)
6. [Altri Modi](#altri-modi)
7. [Confronto e Best Practices](#confronto)
8. [Esempi Pratici](#esempi-pratici)
9. [Esercizi](#esercizi)

---

## 🎯 Introduzione {#introduzione}

I **modi di operazione** (block cipher modes of operation) definiscono come applicare un cifrario a blocchi a messaggi più lunghi di un singolo blocco.

### Perché sono necessari?

Un cifrario a blocchi come AES opera su blocchi fissi (128 bit per AES). Per cifrare messaggi più lunghi serve un modo di operazione che:
- **Concateni** più blocchi in modo sicuro
- **Preveda** pattern ripetitivi nel ciphertext
- **Gestisca** messaggi di lunghezza arbitraria

### Caratteristiche principali

```
Messaggio lungo → Suddivisione in blocchi → Applicazione cifrario
                                         → Modalità di concatenazione
```

---

## 🔓 ECB - Electronic Codebook {#ecb}

### 5.1 Funzionamento

Il modo più semplice: ogni blocco di plaintext viene cifrato **indipendentemente**.

```
Plaintext:  P₁   P₂   P₃   P₄
              ↓    ↓    ↓    ↓
           [E_K] [E_K] [E_K] [E_K]
              ↓    ↓    ↓    ↓
Ciphertext: C₁   C₂   C₃   C₄
```

**Formula**:
- Cifratura: $C_i = E_K(P_i)$
- Decifratura: $P_i = D_K(C_i)$

### 5.2 Implementazione Python

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def cifra_ecb(plaintext, key):
    """Cifra usando AES in modalità ECB"""
    cipher = AES.new(key, AES.MODE_ECB)
    # Padding per rendere il plaintext multiplo di 16 byte
    padded = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return ciphertext

def decifra_ecb(ciphertext, key):
    """Decifra usando AES in modalità ECB"""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext

# Esempio
key = get_random_bytes(16)  # Chiave AES-128
plaintext = b"Messaggio segreto da cifrare"

ciphertext = cifra_ecb(plaintext, key)
decrypted = decifra_ecb(ciphertext, key)

print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted:  {decrypted}")
```

### 5.3 Vulnerabilità di ECB

**PROBLEMA CRITICO**: Blocchi identici di plaintext producono blocchi identici di ciphertext!

**Dimostrazione visiva** (famoso esempio del pinguino Tux):

```python
# Simulazione: messaggio con pattern ripetuti
plaintext = b"AAAAAAAAAAAAAAAA" * 10  # Pattern ripetitivo

ciphertext = cifra_ecb(plaintext, key)

# Ogni 16 byte del ciphertext sarà IDENTICO!
# Questo rivela pattern nel plaintext originale
```

**Conseguenze**:
- ❌ Pattern visibili nel ciphertext
- ❌ Vulnerabile ad analisi di frequenza
- ❌ Possibili attacchi replay
- ❌ **MAI usare ECB in produzione!**

---

## 🔗 CBC - Cipher Block Chaining {#cbc}

### 5.4 Funzionamento

Ogni blocco di plaintext viene fatto XOR con il blocco di ciphertext precedente prima della cifratura.

```
IV ⊕ P₁ → [E_K] → C₁
         C₁ ⊕ P₂ → [E_K] → C₂
                  C₂ ⊕ P₃ → [E_K] → C₃
```

**Formule**:
- Cifratura: $C_i = E_K(P_i \oplus C_{i-1})$, con $C_0 = IV$
- Decifratura: $P_i = D_K(C_i) \oplus C_{i-1}$

### 5.5 Initialization Vector (IV)

L'**IV** (vettore di inizializzazione) è essenziale per CBC:
- ✅ Deve essere **imprevedibile** (random)
- ✅ Deve essere **unico** per ogni messaggio
- ✅ Può essere trasmesso in chiaro (non è segreto)
- ❌ **MAI riutilizzare** lo stesso IV con la stessa chiave

### 5.6 Implementazione Python

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def cifra_cbc(plaintext, key):
    """Cifra usando AES in modalità CBC"""
    # Genera IV random di 16 byte
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    
    # Restituisce IV + ciphertext (IV serve per decifrare)
    return iv + ciphertext

def decifra_cbc(iv_ciphertext, key):
    """Decifra usando AES in modalità CBC"""
    # Estrai IV e ciphertext
    iv = iv_ciphertext[:AES.block_size]
    ciphertext = iv_ciphertext[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext

# Esempio
key = get_random_bytes(16)
plaintext = b"Messaggio segreto molto lungo" * 5

encrypted = cifra_cbc(plaintext, key)
decrypted = decifra_cbc(encrypted, key)

print(f"Plaintext uguale?: {plaintext == decrypted}")

# Verifica: blocchi identici NON producono ciphertext identico
plaintext_ripetitivo = b"A" * 64
encrypted1 = cifra_cbc(plaintext_ripetitivo, key)
encrypted2 = cifra_cbc(plaintext_ripetitivo, key)
print(f"Ciphertext diversi con stesso plaintext?: {encrypted1 != encrypted2}")
```

### 5.7 Padding in CBC

CBC richiede che il plaintext sia multiplo della dimensione del blocco.

**PKCS#7 Padding**:
```python
# Se mancano n byte per completare il blocco,
# aggiungi n byte con valore n

# Esempio: blocco di 16 byte, plaintext di 13 byte
# Aggiungi 3 byte di valore 0x03

plaintext = b"Hello"  # 5 byte
# Padding: b"Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
#          (aggiunge 11 byte di valore 11)
```

### 5.8 Vantaggi e Svantaggi di CBC

**Vantaggi**:
- ✅ Sicuro contro analisi pattern
- ✅ Ampiamente supportato
- ✅ Standard ben testato

**Svantaggi**:
- ❌ Cifratura **non parallelizzabile**
- ❌ Decifratura parallelizzabile ma non cifratura
- ❌ Vulnerabile a Padding Oracle Attack
- ❌ Propagazione errori

---

## 🔢 CTR - Counter Mode {#ctr}

### 5.9 Funzionamento

Trasforma un cifrario a blocchi in un **cifrario a flusso** usando un contatore.

```
Counter₁ → [E_K] → Keystream₁ ⊕ P₁ → C₁
Counter₂ → [E_K] → Keystream₂ ⊕ P₂ → C₂
Counter₃ → [E_K] → Keystream₃ ⊕ P₃ → C₃
```

**Formule**:
- Cifratura: $C_i = P_i \oplus E_K(Nonce || Counter_i)$
- Decifratura: $P_i = C_i \oplus E_K(Nonce || Counter_i)$

### 5.10 Implementazione Python

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

def cifra_ctr(plaintext, key):
    """Cifra usando AES in modalità CTR"""
    # Genera nonce random di 8 byte
    nonce = get_random_bytes(8)
    
    # Crea contatore: nonce (8 byte) + counter (8 byte)
    ctr = Counter.new(64, prefix=nonce, initial_value=1)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    ciphertext = cipher.encrypt(plaintext)
    
    # Restituisce nonce + ciphertext
    return nonce + ciphertext

def decifra_ctr(nonce_ciphertext, key):
    """Decifra usando AES in modalità CTR"""
    # Estrai nonce e ciphertext
    nonce = nonce_ciphertext[:8]
    ciphertext = nonce_ciphertext[8:]
    
    # Ricrea lo stesso contatore
    ctr = Counter.new(64, prefix=nonce, initial_value=1)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Esempio
key = get_random_bytes(16)
plaintext = b"Messaggio con CTR mode"

encrypted = cifra_ctr(plaintext, key)
decrypted = decifra_ctr(encrypted, key)

print(f"Original:  {plaintext}")
print(f"Decrypted: {decrypted}")
print(f"Match: {plaintext == decrypted}")
```

### 5.11 Vantaggi di CTR

**Vantaggi**:
- ✅ **Parallelizzabile** (cifratura e decifratura)
- ✅ Non richiede padding
- ✅ Accesso random ai blocchi
- ✅ Cifratura e decifratura usano solo la funzione E
- ✅ Errori non si propagano

**Svantaggi**:
- ❌ **MAI riutilizzare** nonce+counter con stessa chiave
- ❌ Non fornisce autenticazione

---

## 🛡️ GCM - Galois/Counter Mode {#gcm}

### 5.12 Funzionamento

**GCM** combina CTR per la cifratura con GMAC per l'autenticazione: **AEAD** (Authenticated Encryption with Associated Data).

```
Plaintext → [CTR Encryption] → Ciphertext
            ↓
         [GMAC Auth]
            ↓
      Authentication Tag
```

### 5.13 Implementazione Python

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def cifra_gcm(plaintext, key, associated_data=b""):
    """Cifra usando AES-GCM (con autenticazione)"""
    # Genera nonce random di 12 byte (raccomandato per GCM)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Associated Data (opzionale): dati autenticati ma NON cifrati
    if associated_data:
        cipher.update(associated_data)
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Restituisce nonce + ciphertext + tag
    return nonce + ciphertext + tag

def decifra_gcm(nonce_ciphertext_tag, key, associated_data=b""):
    """Decifra usando AES-GCM e verifica autenticità"""
    # Estrai componenti
    nonce = nonce_ciphertext_tag[:12]
    tag = nonce_ciphertext_tag[-16:]  # Tag è 16 byte
    ciphertext = nonce_ciphertext_tag[12:-16]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    if associated_data:
        cipher.update(associated_data)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext, True
    except ValueError:
        # Tag non valido: messaggio modificato!
        return None, False

# Esempio
key = get_random_bytes(16)
plaintext = b"Messaggio segreto e autenticato"
associated_data = b"Header: user_id=123"

# Cifra
encrypted = cifra_gcm(plaintext, key, associated_data)
print(f"Encrypted size: {len(encrypted)} bytes")

# Decifra correttamente
decrypted, valid = decifra_gcm(encrypted, key, associated_data)
print(f"Decrypted: {decrypted}")
print(f"Valid: {valid}")

# Tenta modifica del ciphertext
encrypted_modificato = bytearray(encrypted)
encrypted_modificato[20] ^= 0x01  # Flippa un bit
decrypted, valid = decifra_gcm(bytes(encrypted_modificato), key, associated_data)
print(f"Dopo modifica - Valid: {valid}")  # False!
```

### 5.14 Vantaggi di GCM

**Vantaggi**:
- ✅ **Cifratura + autenticazione** in un solo passo
- ✅ Molto veloce (parallelizzabile)
- ✅ Standard moderno (TLS 1.3, IPsec)
- ✅ Protegge da modifiche al ciphertext
- ✅ Supporta Associated Data

**Quando usare GCM**:
- 🔐 Comunicazioni di rete (TLS, VPN)
- 💾 Crittografia disco
- 📧 Email cifrate
- 🌐 API REST sicure

---

## 🔄 Altri Modi di Operazione {#altri-modi}

### 5.15 CFB - Cipher Feedback

Trasforma cifrario a blocchi in cifrario a flusso.

```python
from Crypto.Cipher import AES

def cifra_cfb(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext
```

### 5.16 OFB - Output Feedback

Simile a CFB ma genera keystream indipendente dal plaintext.

```python
def cifra_ofb(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext
```

### 5.17 XTS - XEX-based Tweaked Codebook

Usato per crittografia di disco (BitLocker, dm-crypt).

---

## 📊 Confronto e Best Practices {#confronto}

### 5.18 Tabella Comparativa

| Modo | Parallelizzabile | Padding | Autenticazione | Uso Principale |
|------|------------------|---------|----------------|----------------|
| **ECB** | ✅ Sì | ✅ Sì | ❌ No | ❌ MAI USARE |
| **CBC** | ⚠️ Solo decrypt | ✅ Sì | ❌ No | Legacy systems |
| **CTR** | ✅ Sì | ❌ No | ❌ No | Streaming |
| **GCM** | ✅ Sì | ❌ No | ✅ Sì | ⭐ RACCOMANDATO |
| **XTS** | ✅ Sì | ❌ No | ❌ No | Disk encryption |

### 5.19 Best Practices

**✅ DA FARE**:
1. **Usa GCM** per nuove implementazioni
2. **Genera IV/Nonce random** per ogni messaggio
3. **MAI riutilizzare** IV/Nonce con stessa chiave
4. **Usa librerie crittografiche** standard (non implementare da zero)
5. **Verifica sempre** il tag di autenticazione in GCM

**❌ DA EVITARE**:
1. **Mai usare ECB** in produzione
2. **Non inventare** il proprio modo di operazione
3. **Non usare IV prevedibili** (es. counter sequenziale)
4. **Non ignorare** errori di autenticazione
5. **Non usare padding** vulnerabile a oracle attacks

---

## 💡 Esempi Pratici {#esempi-pratici}

### Esempio Completo: File Encryption Tool

```python
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

class FileEncryption:
    def __init__(self, password):
        """Inizializza con password (KDF genera chiave)"""
        # Genera chiave da password usando PBKDF2
        salt = b"salt_1234567890"  # In produzione: salt random
        self.key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    def encrypt_file(self, input_file, output_file):
        """Cifra un file usando AES-GCM"""
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        with open(output_file, 'wb') as f:
            # Scrivi: nonce (12) + tag (16) + ciphertext
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        
        print(f"✅ File cifrato: {output_file}")
    
    def decrypt_file(self, input_file, output_file):
        """Decifra un file usando AES-GCM"""
        with open(input_file, 'rb') as f:
            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print(f"✅ File decifrato: {output_file}")
            return True
        except ValueError:
            print("❌ Errore: File corrotto o password errata")
            return False

# Utilizzo
password = "SuperSecretPassword123!"
encryptor = FileEncryption(password)

# Cifra
encryptor.encrypt_file("documento.pdf", "documento.pdf.enc")

# Decifra
encryptor.decrypt_file("documento.pdf.enc", "documento_decrypted.pdf")
```

---

## 📝 Esercizi {#esercizi}

### Esercizio 1: Identificare il Modo (★☆☆)

Per ciascuno scenario, scegli il modo di operazione più appropriato:

1. Cifrare un file di log da 10 GB
2. Implementare HTTPS per un'API REST
3. Cifrare hard disk di un laptop
4. Streaming video cifrato

**Soluzioni**:
<details>
<summary>Clicca per vedere</summary>

1. **GCM o CTR** - File grande richiede parallelizzazione
2. **GCM** - Necessaria autenticazione
3. **XTS** - Standard per disk encryption
4. **CTR** - Streaming richiede no-padding e parallelizzazione
</details>

### Esercizio 2: Debug ECB (★★☆)

Analizza questo codice e spiega perché è insicuro:

```python
def cifra_password_db(passwords, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_passwords = []
    for pwd in passwords:
        padded = pad(pwd.encode(), 16)
        encrypted_passwords.append(cipher.encrypt(padded).hex())
    return encrypted_passwords

# Uso
passwords = ["password123", "admin", "password123", "letmein"]
key = get_random_bytes(16)
encrypted = cifra_password_db(passwords, key)
print(encrypted)
```

**Soluzione**:
<details>
<summary>Clicca per vedere</summary>

**Problema**: Password identiche producono ciphertext identici in ECB!

```
encrypted[0] == encrypted[2]  # Entrambi "password123"
```

Un attaccante può:
1. Identificare password duplicate
2. Creare dizionario di hash
3. Attacco di frequenza

**Fix**: Usa GCM o CBC con IV random per ogni password.
</details>

### Esercizio 3: Implementa Verifica Integrità (★★★)

Implementa una funzione che cifri un messaggio con CBC e aggiunga HMAC per autenticazione (CBC + HMAC = encrypt-then-MAC).

**Schema**:
```
Plaintext → [AES-CBC] → Ciphertext → [HMAC-SHA256] → Tag
                ↓
              IV + Ciphertext + Tag
```

**Template**:
```python
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_and_mac(plaintext, encryption_key, mac_key):
    # TODO: Implementa cifratura CBC + HMAC
    pass

def decrypt_and_verify(data, encryption_key, mac_key):
    # TODO: Implementa verifica HMAC + decifratura CBC
    pass
```

**Soluzione**:
<details>
<summary>Clicca per vedere</summary>

```python
def encrypt_and_mac(plaintext, encryption_key, mac_key):
    # 1. Cifra con AES-CBC
    iv = get_random_bytes(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    
    # 2. Calcola HMAC su IV + ciphertext
    h = hmac.new(mac_key, iv + ciphertext, hashlib.sha256)
    tag = h.digest()
    
    # 3. Restituisci IV + ciphertext + tag
    return iv + ciphertext + tag

def decrypt_and_verify(data, encryption_key, mac_key):
    # 1. Estrai componenti
    iv = data[:16]
    tag = data[-32:]  # SHA-256 = 32 byte
    ciphertext = data[16:-32]
    
    # 2. Verifica HMAC
    h = hmac.new(mac_key, iv + ciphertext, hashlib.sha256)
    expected_tag = h.digest()
    
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("HMAC verification failed!")
    
    # 3. Decifra
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    
    return plaintext
```
</details>

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 4 - Cifrari a Blocchi](04_cifrari_a_blocchi.md)
- **Successivo**: [Capitolo 6 - Cifrari a Flusso](06_cifrari_a_flusso.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

1. **NIST SP 800-38 Series**: Recommendation for Block Cipher Modes of Operation
2. **RFC 5116**: An Interface and Algorithms for Authenticated Encryption
3. **RFC 5288**: AES-GCM Cipher Suites for TLS
4. **Cryptography Engineering** - Ferguson, Schneier, Kohno

---

**Nota Importante**: GCM è il modo raccomandato per nuove implementazioni. ECB non deve MAI essere usato in produzione!

---

## Best Practices

1. [Pratica 1]
2. [Pratica 2]
3. [Pratica 3]

---

## Esercizi

### Esercizio 05.1 (★☆☆)
[Descrizione esercizio]

### Esercizio 05.2 (★★☆)
[Descrizione esercizio]

### Esercizio 05.3 (★★★)
[Descrizione esercizio]

---

## Domande di Verifica

1. [Domanda 1]
2. [Domanda 2]
3. [Domanda 3]

---

## Riferimenti

- [Riferimento 1]
- [Riferimento 2]

---

**Capitolo Precedente**: [04 - Cifrari a Blocchi](04_cifrari_a_blocchi.md)  
**Prossimo Capitolo**: [06 - Cifrari a Flusso](06_cifrari_a_flusso.md)