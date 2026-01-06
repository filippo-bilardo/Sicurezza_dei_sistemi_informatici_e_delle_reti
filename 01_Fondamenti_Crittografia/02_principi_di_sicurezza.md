# Capitolo 2 - Principi di Sicurezza

> **Parte 1 - FONDAMENTI DI CRITTOGRAFIA**

---

## 2.1 Il Principio di Kerckhoffs

### Enunciato
> "Un sistema crittografico deve essere sicuro anche se tutto del sistema, tranne la chiave, è di pubblico dominio."
> 
> — Auguste Kerckhoffs (1883)

### Interpretazione Moderna
La sicurezza di un sistema crittografico deve dipendere **esclusivamente dalla segretezza della chiave**, non dall'algoritmo.

### Implicazioni
✅ **Buone pratiche:**
- Usare algoritmi pubblici e testati (AES, RSA, SHA-256)
- Pubblicare l'algoritmo per revisione peer
- Concentrarsi sulla protezione delle chiavi

❌ **Cattive pratiche:**
- "Security through obscurity" (sicurezza per oscurità)
- Algoritmi proprietari non testati
- Fidarsi solo del segreto dell'implementazione

### Esempio
**AES** è un algoritmo pubblico, documentato, analizzato da migliaia di esperti. La sua sicurezza dipende solo dalla chiave segreta di 128/192/256 bit.

---

## 2.2 Sicurezza Computazionale

### Definizione
Un sistema è **computazionalmente sicuro** se violare la cifratura richiede risorse computazionali irrealistiche (tempo, memoria, energia).

### Classi di Sicurezza

#### 1. Sicurezza Perfetta (Teorica)
Il ciphertext non fornisce **nessuna** informazione sul plaintext, indipendentemente dalla potenza computazionale.

**Esempio**: One-Time Pad (OTP)
- Chiave casuale lunga quanto il messaggio
- Usata una sola volta
- XOR bit per bit

```
Plaintext:  01001000 (H)
Key:        10110101 (random)
Ciphertext: 11111101 (XOR)
```

**Problema**: Distribuzione e gestione della chiave impraticabile.

#### 2. Sicurezza Computazionale (Pratica)
Violare richiede tempo > età dell'universo con tutta la potenza computazionale disponibile.

**Esempio**: AES-256
- 2^256 combinazioni possibili
- Testare 1 trilione di chiavi/secondo → ~10^57 anni

### Complessità Temporale

| Dimensione Chiave | Combinazioni | Tempo Brute-Force (1 THz) |
|-------------------|--------------|---------------------------|
| 56 bit (DES) | 2^56 ≈ 7.2×10^16 | ~1 giorno |
| 128 bit (AES) | 2^128 ≈ 3.4×10^38 | ~10^21 anni |
| 256 bit (AES) | 2^256 ≈ 1.1×10^77 | ~10^57 anni |

---

## 2.3 Attacchi Crittografici

### 2.3.1 Attacco Brute-Force

**Definizione**: Provare sistematicamente tutte le chiavi possibili.

**Esempio Python:**
```python
import itertools
import hashlib

def brute_force_pin(target_hash, max_length=4):
    """Brute-force di un PIN numerico"""
    for length in range(1, max_length + 1):
        for pin in itertools.product('0123456789', repeat=length):
            pin_str = ''.join(pin)
            if hashlib.sha256(pin_str.encode()).hexdigest() == target_hash:
                return pin_str
    return None

# Test
pin = "1234"
hash_pin = hashlib.sha256(pin.encode()).hexdigest()
print(f"Hash del PIN: {hash_pin}")

result = brute_force_pin(hash_pin, 4)
print(f"PIN trovato: {result}")
```

**Difese:**
- Chiavi lunghe (≥128 bit)
- Rate limiting
- Account lockout dopo N tentativi
- CAPTCHA

### 2.3.2 Crittoanalisi

**Definizione**: Analisi matematica per trovare debolezze nell'algoritmo.

**Tipi:**
- **Crittoanalisi differenziale**: Analizza differenze tra input/output
- **Crittoanalisi lineare**: Trova approssimazioni lineari
- **Crittoanalisi algebrica**: Risolve sistemi di equazioni

**Esempio Storico**: Breaking di Enigma
- Sfruttamento di pattern nel plugboard
- Uso di "cribs" (parole probabili)
- Errori operativi degli operatori

### 2.3.3 Attacchi a Testo in Chiaro Noto

**Known-Plaintext Attack (KPA)**

**Scenario**: L'attaccante possiede coppie (plaintext, ciphertext).

**Esempio**:
```
Plaintext noto:     "WEATHER REPORT"
Ciphertext corrisp: "XFBUIFS SFQPSU"
```

**Obiettivo**: Dedurre la chiave o decifrare altri messaggi.

**Difese:**
- Algoritmi resistenti a KPA (AES, RSA)
- Vettori di inizializzazione casuali (IV)
- Salt per password

### 2.3.4 Attacchi a Testo in Chiaro Scelto

**Chosen-Plaintext Attack (CPA)**

**Scenario**: L'attaccante può scegliere plaintext e ottenere il corrispondente ciphertext.

**Esempio**: Oracle di cifratura
```python
def encryption_oracle(plaintext):
    # Attaccante può chiamare questa funzione
    return aes_encrypt(plaintext, secret_key)
```

**Attacco Pratico**: Padding Oracle Attack
- Manipolare il padding PKCS#7
- Ottenere informazioni bit per bit

**Difese:**
- Authenticated Encryption (AES-GCM)
- Constant-time operations
- Non rivelare errori di padding

---

## 2.4 Entropia e Casualità

### Entropia

**Definizione**: Misura dell'imprevedibilità di un sistema.

**Formula di Shannon:**
```
H(X) = -Σ p(x) log₂ p(x)
```

Dove:
- H(X) = entropia in bit
- p(x) = probabilità dell'evento x

**Esempio**:
- Lanciare una moneta: H = 1 bit
- Lanciare un dado: H = log₂(6) ≈ 2.58 bit
- Password di 8 caratteri minuscole: H = log₂(26^8) ≈ 37.6 bit

### Casualità Crittografica

**PRNG** (Pseudo-Random Number Generator): 
- Deterministico
- Usare **solo** per simulazioni, non per crittografia

**CSPRNG** (Cryptographically Secure PRNG):
- Imprevedibile
- Passa test statistici rigorosi
- Esempi: `/dev/urandom`, `CryptGenRandom`, `secrets` module in Python

**Esempio Python:**
```python
import secrets
import random

# ❌ NON usare per crittografia
weak_key = random.randint(0, 2**128)

# ✅ Usare per crittografia
strong_key = secrets.randbits(128)
secure_token = secrets.token_hex(16)  # 32 caratteri esadecimali

print(f"Token sicuro: {secure_token}")
```

### Fonti di Entropia
- **Hardware**: Rumore termico, jitter del clock
- **Sistema Operativo**: Timing eventi, movimenti mouse, interrupt
- **/dev/random** (Linux): Blocca se entropia insufficiente
- **/dev/urandom** (Linux): Non blocca, ma richiede boot con entropia sufficiente

---

## 2.5 Best Practices di Sicurezza

### 1. Non Reinventare la Ruota
❌ Non creare algoritmi crittografici custom  
✅ Usare librerie standard (OpenSSL, libsodium, cryptography)

### 2. Mantenere le Chiavi Segrete
✅ Non hard-codare chiavi nel codice sorgente  
✅ Usare environment variables o key management systems  
✅ Ruotare le chiavi periodicamente  
❌ Non committare chiavi su Git

### 3. Usare Algoritmi Moderni
✅ AES-256, RSA-2048/4096, SHA-256, Ed25519  
❌ DES, MD5, SHA-1, RC4

### 4. Authenticated Encryption
✅ AES-GCM, ChaCha20-Poly1305  
❌ AES-CBC senza HMAC

### 5. Password Hashing
✅ bcrypt, scrypt, Argon2  
❌ MD5, SHA-256 senza salt

### 6. Aggiornamenti
✅ Tenere aggiornate le librerie crittografiche  
✅ Seguire security advisories  
✅ Patch tempestive

### 7. Defense in Depth
Non affidarsi a un singolo controllo di sicurezza:
- Cifratura + Autenticazione
- Firewall + IDS/IPS
- Strong passwords + MFA

---

## Checklist di Sicurezza

```
□ Usare CSPRNG per generare chiavi
□ Chiavi ≥128 bit per simmetrica, ≥2048 bit per RSA
□ Algoritmi approvati da NIST/IETF
□ Authenticated Encryption quando possibile
□ Salt casuali per password hashing
□ Vettori di inizializzazione (IV) casuali e unici
□ Constant-time operations per prevenire timing attacks
□ Secure key storage (HSM, Key Vault)
□ Regular security audits
□ Logging (ma non delle chiavi!)
```

---

## Esercizi

### Esercizio 2.1: Principio di Kerckhoffs (★☆☆)
1. Spiega perché "security through obscurity" è considerata una cattiva pratica
2. Trova un esempio reale di violazione di un algoritmo proprietario
3. Confronta AES (pubblico) con un ipotetico algoritmo segreto

### Esercizio 2.2: Calcolo Entropia (★★☆)
Calcola l'entropia di:
1. Password di 8 cifre numeriche
2. Password di 8 caratteri alfanumerici (maiuscole + minuscole + numeri)
3. Password di 12 caratteri con simboli speciali

### Esercizio 2.3: Brute-Force (★★☆)
1. Scrivi un programma per brute-force di PIN a 4 cifre
2. Calcola quanto tempo ci vorrebbe per un PIN a 6 cifre
3. Implementa un rate limiter per difendersi

### Esercizio 2.4: PRNG vs CSPRNG (★★★)
1. Implementa un test statistico per valutare la casualità
2. Confronta `random` e `secrets` in Python
3. Visualizza la distribuzione dei numeri generati

---

## Domande di Verifica

1. Cosa afferma il principio di Kerckhoffs?
2. Qual è la differenza tra sicurezza perfetta e computazionale?
3. Perché MD5 non è più considerato sicuro?
4. Cos'è un CSPRNG e perché è importante?
5. Descrivi un attacco Known-Plaintext

---

## Riferimenti

- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [Cryptography Engineering - Ferguson, Schneier, Kohno](https://www.schneier.com/books/cryptography-engineering/)
- [RFC 4086 - Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)

---

**Capitolo Precedente**: [01 - Introduzione alla Crittografia](01_introduzione_alla_crittografia.md)  
**Prossimo Capitolo**: [03 - Introduzione alla Crittografia Simmetrica](../02_Crittografia_Simmetrica/03_introduzione_crittografia_simmetrica.md)
