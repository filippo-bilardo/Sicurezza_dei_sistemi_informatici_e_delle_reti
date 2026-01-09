# Capitolo 13 - HMAC (Hash-based Message Authentication Code)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 4 - Hash e Integrità  
> **Autore**: Prof. Filippo Bilardo  
> **Ultima modifica**: Gennaio 2026

---

## 📋 Indice

1. [Cos'è HMAC](#cose-hmac)
2. [Il Problema da Risolvere](#problema)
3. [Come Funziona HMAC](#come-funziona)
4. [A Cosa Serve](#a-cosa-serve)
5. [HMAC vs Hash Semplice](#hmac-vs-hash)
6. [Implementazione Pratica](#implementazione)
7. [Applicazioni Reali](#applicazioni)
8. [Sicurezza e Best Practices](#sicurezza)
9. [Esercizi](#esercizi)

---

## 🔐 Cos'è HMAC {#cose-hmac}

**HMAC** (Hash-based Message Authentication Code) è un meccanismo crittografico che combina:
- Una **funzione hash** (come SHA-256)
- Una **chiave segreta** condivisa

per garantire **autenticazione** e **integrità** dei messaggi.

### Definizione Formale

> HMAC è un codice di autenticazione del messaggio (MAC) che utilizza una funzione hash crittografica e una chiave segreta per verificare sia l'integrità che l'autenticità di un messaggio.

### Analogia del Mondo Reale

Immagina di ricevere un pacco:
- **Hash**: È come il nastro adesivo sul pacco - ti dice se è stato aperto
- **HMAC**: È come un sigillo di cera con il timbro reale - ti dice se è stato aperto **E** che proviene davvero dal mittente

```
┌─────────────────────────────────────────┐
│         MESSAGGIO ORIGINALE             │
│  "Trasferimento: 1000€ a Alice"         │
└─────────────────────────────────────────┘
                    │
                    ├─── Hash normale (SHA-256)
                    │    └─→ Chiunque può calcolarlo
                    │        ❌ Non protetto da attacchi
                    │
                    └─── HMAC (con chiave segreta)
                         └─→ Solo chi ha la chiave
                             ✅ Protetto e autenticato
```

---

## ⚠️ Il Problema da Risolvere {#problema}

### Scenario 1: Hash Semplice - NON Sicuro

```python
import hashlib

# Alice invia un messaggio
messaggio = "Paga 100€ a Bob"
hash_msg = hashlib.sha256(messaggio.encode()).hexdigest()

print(f"Messaggio: {messaggio}")
print(f"Hash: {hash_msg}")

# 🚨 PROBLEMA: Un attaccante può modificare entrambi!
messaggio_falso = "Paga 10000€ a Bob"
hash_falso = hashlib.sha256(messaggio_falso.encode()).hexdigest()

# Il destinatario non può distinguere l'originale dal falso
```

**Problema**: Chiunque può:
1. Modificare il messaggio
2. Ricalcolare l'hash
3. Inviare la coppia modificata

### Scenario 2: Con HMAC - Sicuro

```python
import hmac
import hashlib

# Chiave segreta condivisa tra Alice e Bob
chiave_segreta = b"solo_alice_e_bob_la_conoscono"

# Alice invia un messaggio con HMAC
messaggio = b"Paga 100 euro a Bob"
tag_hmac = hmac.new(chiave_segreta, messaggio, hashlib.sha256).hexdigest()

print(f"Messaggio: {messaggio.decode()}")
print(f"HMAC: {tag_hmac}")

# ✅ SOLUZIONE: L'attaccante NON può creare un HMAC valido
messaggio_falso = b"Paga 10000 euro a Bob"
# Senza la chiave, non può generare un tag HMAC valido!
```

**Soluzione**: Solo chi possiede la chiave segreta può:
- Creare un HMAC valido
- Verificare l'autenticità del messaggio

---

## 🔧 Come Funziona HMAC {#come-funziona}

### Formula Matematica

$$HMAC(K, M) = H((K \oplus opad) || H((K \oplus ipad) || M))$$

Dove:
- $K$ = chiave segreta
- $M$ = messaggio
- $H$ = funzione hash (es. SHA-256)
- $\oplus$ = XOR (operazione bit-a-bit)
- $||$ = concatenazione
- $opad$ = outer padding (0x5c ripetuto)
- $ipad$ = inner padding (0x36 ripetuto)

### Spiegazione Passo-Passo

```
STEP 1: Preparazione della chiave
┌──────────────────────┐
│  Chiave Segreta (K)  │
└──────────────────────┘
         │
         ├─── Se troppo corta → padding con zeri
         └─── Se troppo lunga → hash della chiave

STEP 2: Inner hash
┌──────────────────────┐
│  K ⊕ ipad (0x36...)  │────┐
└──────────────────────┘    │
                            ├─→ Concatena
┌──────────────────────┐    │
│    Messaggio (M)     │────┘
└──────────────────────┘
         │
         ▼
    Hash interno
         │
STEP 3: Outer hash
┌──────────────────────┐
│  K ⊕ opad (0x5c...)  │────┐
└──────────────────────┘    │
                            ├─→ Concatena
┌──────────────────────┐    │
│    Hash interno      │────┘
└──────────────────────┘
         │
         ▼
   HMAC finale (tag)
```

### Esempio Visivo

```python
import hmac
import hashlib

key = b"chiave_segreta"
messaggio = b"Ciao, Alice!"

# Python fa tutto questo automaticamente:
h = hmac.new(key, messaggio, hashlib.sha256)
tag = h.hexdigest()

print(f"HMAC-SHA256: {tag}")
# Output: 7c5f4... (64 caratteri hex = 256 bit)
```

---

## 🎯 A Cosa Serve HMAC {#a-cosa-serve}

HMAC risolve **due problemi fondamentali**:

### 1. Autenticazione del Mittente

**Domanda**: "Come faccio a sapere che il messaggio proviene davvero da Alice?"

**Risposta**: Solo Alice ha la chiave segreta, quindi solo lei può generare un HMAC valido.

```python
# Alice genera il messaggio
messaggio = b"Ti invio i documenti riservati"
tag_alice = hmac.new(chiave_condivisa, messaggio, hashlib.sha256).digest()

# Bob verifica che provenga da Alice
tag_calcolato = hmac.new(chiave_condivisa, messaggio, hashlib.sha256).digest()

if hmac.compare_digest(tag_alice, tag_calcolato):
    print("✅ Messaggio autentico da Alice")
else:
    print("❌ Messaggio falso o compromesso!")
```

### 2. Integrità del Messaggio

**Domanda**: "Come faccio a sapere che il messaggio non è stato modificato?"

**Risposta**: Qualsiasi modifica al messaggio invalida l'HMAC.

```python
messaggio_originale = b"Trasferimento: 100 EUR"
tag_originale = hmac.new(key, messaggio_originale, hashlib.sha256).digest()

# Attaccante modifica il messaggio
messaggio_modificato = b"Trasferimento: 999 EUR"
tag_verificato = hmac.new(key, messaggio_modificato, hashlib.sha256).digest()

# La verifica fallisce
if hmac.compare_digest(tag_originale, tag_verificato):
    print("✅ Integrità OK")
else:
    print("❌ Messaggio MODIFICATO!")  # ← Questo viene stampato
```

### Casi d'Uso Principali

| Caso d'Uso | Descrizione | Esempio |
|------------|-------------|---------|
| **API Authentication** | Autenticare richieste HTTP | AWS Signature v4, GitHub webhooks |
| **Session Tokens** | Verificare token di sessione | Cookie firmati, JWT |
| **File Integrity** | Verificare file condivisi | Backup autenticati, aggiornamenti software |
| **Message Queues** | Autenticare messaggi | RabbitMQ, Kafka con SASL |
| **IoT Security** | Comunicazione dispositivi | Sensori → Server autenticato |
| **Database** | Verificare record | Audit logs inviolabili |

---

## 🆚 HMAC vs Hash Semplice {#hmac-vs-hash}

### Confronto Dettagliato

### Formula

$$HMAC(K, M) = H((K \oplus opad) || H((K \oplus ipad) || M))$$

Dove:
- $K$ = chiave segreta
- $M$ = messaggio
- $H$ = funzione hash (es. SHA-256)
- $opad$ = outer padding (0x5c ripetuto)
- $ipad$ = inner padding (0x36 ripetuto)

## Implementazione Python

```python
import hmac
import hashlib

# Chiave segreta condivisa
key = b"chiave_segreta_condivisa"

# Messaggio da autenticare
messaggio = b"Trasferimento: 1000 EUR a Alice"

# Calcola HMAC
h = hmac.new(key, messaggio, hashlib.sha256)
tag = h.digest()

print(f"HMAC-SHA256: {tag.hex()}")
```

## Verifica HMAC

```python
def verifica_hmac(messaggio, tag_ricevuto, key):
    """Verifica HMAC ricevuto"""
    # Ricalcola HMAC
    h = hmac.new(key, messaggio, hashlib.sha256)
    tag_atteso = h.digest()
    
    # Confronto timing-safe
    return hmac.compare_digest(tag_ricevuto, tag_atteso)

# Test
if verifica_hmac(messaggio, tag, key):
    print("✅ Messaggio autentico")
else:
    print("❌ Messaggio modificato!")
```

## HMAC vs Hash Semplice

| Caratteristica | Hash | HMAC |
|----------------|------|------|
| **Input** | Solo messaggio | Messaggio + chiave |
| **Autenticazione** | ❌ No | ✅ Sì |
| **Integrità** | ✅ Sì | ✅ Sì |
| **Protezione** | Chiunque può calcolare | Solo chi ha la chiave |

## Applicazioni

1. **API Authentication**: JWT, OAuth
2. **Challenge-Response**: Protocolli autenticazione
3. **Key Derivation**: PBKDF2 usa HMAC
4. **Integrità file**: Con chiave condivisa

## Esempio: API Authentication

```python
import hmac
import hashlib
import time

def genera_token_api(api_key, user_id, timestamp):
    """Genera token HMAC per richiesta API"""
    payload = f"{user_id}:{timestamp}"
    
    h = hmac.new(api_key.encode(), payload.encode(), hashlib.sha256)
    token = h.hexdigest()
    
    return token

def verifica_token_api(api_key, user_id, timestamp, token_ricevuto):
    """Verifica token API"""
    # Controlla timestamp (valido 5 minuti)
    now = int(time.time())
    if abs(now - timestamp) > 300:
        return False
    
    # Verifica HMAC
    token_atteso = genera_token_api(api_key, user_id, timestamp)
    return hmac.compare_digest(token_atteso, token_ricevuto)

# Uso
api_key = "secret_api_key_123"
user_id = "user_42"
timestamp = int(time.time())

token = genera_token_api(api_key, user_id, timestamp)
print(f"Token: {token}")

# Verifica
is_valid = verifica_token_api(api_key, user_id, timestamp, token)
print(f"Token valido: {is_valid}")
```


## 🔒 Sicurezza e Best Practices {#sicurezza}

### ✅ Cosa HMAC Garantisce

1. **Autenticazione**: Solo chi ha la chiave può generare HMAC validi
2. **Integrità**: Qualsiasi modifica al messaggio invalida l'HMAC
3. **Non-Ripudio Parziale**: Prova che il mittente aveva la chiave (ma entrambe le parti l'hanno)

### ❌ Cosa HMAC NON Garantisce

1. **Confidenzialità**: HMAC NON cifra il messaggio
   ```python
   messaggio = b"Dati sensibili visibili in chiaro"
   tag = hmac.new(key, messaggio, hashlib.sha256).digest()
   
   # Il messaggio è ancora leggibile!
   # Soluzione: Usa HMAC + Cifratura (Encrypt-then-MAC)
   ```

2. **Non-Ripudio Completo**: Entrambe le parti hanno la chiave
   - Per non-ripudio completo serve firma digitale (RSA, ECDSA)

### 🛡️ Best Practices

#### 1. Usa `hmac.compare_digest()` - Sempre!

```python
# ❌ SBAGLIATO - Vulnerabile a timing attacks
if tag_ricevuto == tag_calcolato:
    print("Valido")

# ✅ CORRETTO - Confronto a tempo costante
if hmac.compare_digest(tag_ricevuto, tag_calcolato):
    print("Valido")
```

**Perché?** Un attaccante può misurare il tempo di confronto per indovinare il tag byte-per-byte.

```python
import time

def confronto_insicuro(a, b):
    """Vulnerabile a timing attack"""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # ← Esce subito! Tempo variabile
    return True

def confronto_sicuro(a, b):
    """Resistente a timing attack"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y  # ← Sempre tutto il loop
    return result == 0  # Tempo costante
```

#### 2. Lunghezza Chiave Adeguata

```python
# ❌ Chiave troppo corta
key_weak = b"123"

# ✅ Chiave forte (almeno 32 byte per HMAC-SHA256)
import secrets
key_strong = secrets.token_bytes(32)

# ✅ Oppure genera da password con PBKDF2
from hashlib import pbkdf2_hmac
key_derived = pbkdf2_hmac('sha256', b'password', b'salt', 100000)
```

**Raccomandazioni**:
- **HMAC-SHA256**: Chiave ≥ 32 byte (256 bit)
- **HMAC-SHA512**: Chiave ≥ 64 byte (512 bit)

#### 3. Scegli Algoritmo Hash Appropriato

```python
# ✅ RACCOMANDATO per maggior parte usi
tag256 = hmac.new(key, msg, hashlib.sha256).digest()  # 32 byte

# ✅ Per sicurezza extra (file grandi, long-term storage)
tag512 = hmac.new(key, msg, hashlib.sha512).digest()  # 64 byte

# ❌ DEPRECATO - NON usare
tag_md5 = hmac.new(key, msg, hashlib.md5).digest()     # Insicuro
tag_sha1 = hmac.new(key, msg, hashlib.sha1).digest()   # Deprecato
```

**Raccomandazione**: **HMAC-SHA256** è il migliore compromesso velocità/sicurezza.

#### 4. Includi Timestamp per Prevenire Replay Attacks

```python
import time
import hmac
import hashlib

def genera_messaggio_sicuro(data, key, validity_seconds=300):
    """Genera messaggio con timestamp"""
    timestamp = int(time.time())
    
    # Includi timestamp nel payload
    payload = f"{timestamp}:{data}"
    
    tag = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    
    return {
        'timestamp': timestamp,
        'data': data,
        'hmac': tag
    }

def verifica_messaggio_sicuro(msg, key, validity_seconds=300):
    """Verifica messaggio con controllo timestamp"""
    # 1. Controlla timestamp
    now = int(time.time())
    if abs(now - msg['timestamp']) > validity_seconds:
        return False, "Timestamp scaduto o nel futuro"
    
    # 2. Verifica HMAC
    payload = f"{msg['timestamp']}:{msg['data']}"
    expected_tag = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(msg['hmac'], expected_tag):
        return True, "Valido"
    else:
        return False, "HMAC invalido"

# Uso
key = b"shared_secret"
msg = genera_messaggio_sicuro("Ordine #12345", key)

# Verifica immediata: OK
valid, reason = verifica_messaggio_sicuro(msg, key)
print(f"{reason}")  # "Valido"

# Dopo 6 minuti: FAIL
time.sleep(301)
valid, reason = verifica_messaggio_sicuro(msg, key)
print(f"{reason}")  # "Timestamp scaduto"
```

#### 5. Encrypt-then-MAC Pattern

Se serve **confidenzialità + autenticazione**, usa questo pattern:

```python
from cryptography.fernet import Fernet
import hmac
import hashlib

def encrypt_then_mac(plaintext, enc_key, mac_key):
    """
    Pattern sicuro: Cifra PRIMA, poi autentica
    """
    # 1. Cifra il messaggio
    f = Fernet(enc_key)
    ciphertext = f.encrypt(plaintext.encode())
    
    # 2. Calcola HMAC del ciphertext
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    
    return ciphertext, tag

def verify_then_decrypt(ciphertext, tag, enc_key, mac_key):
    """Verifica MAC PRIMA, poi decifra"""
    # 1. Verifica HMAC
    expected_tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("HMAC invalido - possibile manipolazione!")
    
    # 2. Solo se valido, decifra
    f = Fernet(enc_key)
    plaintext = f.decrypt(ciphertext).decode()
    
    return plaintext

# Usa due chiavi diverse!
enc_key = Fernet.generate_key()
mac_key = b"different_key_for_mac_32byte"

# Cifra e autentica
ciphertext, tag = encrypt_then_mac("Dati segreti", enc_key, mac_key)

# Verifica e decifra
try:
    plaintext = verify_then_decrypt(ciphertext, tag, enc_key, mac_key)
    print(f"✅ Decifrato: {plaintext}")
except ValueError as e:
    print(f"❌ {e}")
```

**⚠️ IMPORTANTE**: Mai usare la stessa chiave per cifratura e MAC!

#### 6. Gestione Sicura delle Chiavi

```python
import os
from pathlib import Path

# ❌ SBAGLIATO - Chiave hardcoded
SECRET_KEY = "hardcoded_secret_123"

# ✅ CORRETTO - Chiave da variabile ambiente
SECRET_KEY = os.getenv('HMAC_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("HMAC_SECRET_KEY non configurata!")

# ✅ CORRETTO - Chiave da file protetto
key_file = Path('/etc/secrets/hmac.key')
key_file.chmod(0o600)  # Solo owner può leggere
with open(key_file, 'rb') as f:
    SECRET_KEY = f.read()

# ✅ CORRETTO - Genera chiave sicura
import secrets
new_key = secrets.token_bytes(32)
# Salva in un key vault (AWS KMS, HashiCorp Vault, etc.)
```

### ⚠️ Vulnerabilità Comuni

#### 1. Timing Attacks

```python
# ❌ VULNERABILE
def check_mac_insecure(received, expected):
    return received == expected  # Esce al primo byte diverso

# ✅ SICURO
def check_mac_secure(received, expected):
    return hmac.compare_digest(received, expected)  # Tempo costante
```

#### 2. Replay Attacks

```python
# ❌ VULNERABILE - Nessun timestamp
msg = {"data": "transfer $1000", "hmac": "abc123..."}

# Attaccante può reinviare lo stesso messaggio infinite volte!

# ✅ SICURO - Con timestamp e nonce
msg = {
    "data": "transfer $1000",
    "timestamp": 1704556800,
    "nonce": "unique_random_id",
    "hmac": "xyz789..."
}
```

#### 3. Length Extension Attacks

**HMAC è IMMUNE** a length extension attacks (a differenza di hash semplici).

```python
# Con hash semplice (SHA-256) - VULNERABILE
# Attaccante può estendere: hash(secret + msg) → hash(secret + msg + extra)

# Con HMAC - SICURO
# L'attaccante NON può fare length extension grazie alla doppia hash
```

### 📊 Performance e Ottimizzazione

```python
import timeit
import hmac
import hashlib

# Benchmark algoritmi
key = b"test_key_32_bytes_long_secret_"
msg = b"Test message" * 100  # 1.2 KB

algos = ['sha256', 'sha512', 'sha3_256', 'blake2b']

for algo in algos:
    hash_func = getattr(hashlib, algo)
    
    time = timeit.timeit(
        lambda: hmac.new(key, msg, hash_func).digest(),
        number=10000
    )
    
    print(f"HMAC-{algo.upper()}: {time:.4f}s")

# Output tipico:
# HMAC-SHA256:   0.1234s  ← Più veloce
# HMAC-SHA512:   0.1456s
# HMAC-SHA3_256: 0.3789s
# HMAC-BLAKE2B:  0.0987s  ← Velocissimo (Python 3.6+)
```

**Raccomandazioni**:
- **Uso generale**: HMAC-SHA256 (ottimo compromesso)
- **Performance critica**: HMAC-BLAKE2b (se disponibile)
- **Sicurezza massima**: HMAC-SHA512 (overhead minimo)

### 🔐 HMAC-SHA256 vs HMAC-SHA512

```python
import hmac
import hashlib

key = b"test_key"
msg = b"test message"

# HMAC-SHA256 (32 byte output)
tag256 = hmac.new(key, msg, hashlib.sha256).digest()
print(f"HMAC-SHA256: {len(tag256)} byte - {tag256.hex()[:32]}...")

# HMAC-SHA512 (64 byte output)
tag512 = hmac.new(key, msg, hashlib.sha512).digest()
print(f"HMAC-SHA512: {len(tag512)} byte - {tag512.hex()[:32]}...")
```

| Caratteristica | HMAC-SHA256 | HMAC-SHA512 |
|----------------|-------------|-------------|
| **Output** | 32 byte (256 bit) | 64 byte (512 bit) |
| **Velocità** | Molto veloce | Leggermente più lento |
| **Sicurezza** | Eccellente | Eccellente+ |
| **Banda** | Minore | Maggiore |
| **Uso** | Standard | Long-term, extra sicurezza |

**Conclusione**: HMAC-SHA256 è sufficiente per la maggior parte delle applicazioni.

---

## 📝 Esercizi {#esercizi}

### Esercizio 1: Implementazione Base (★☆☆)

Implementa un sistema di messaggi autenticati tra Alice e Bob.

```python
import hmac
import hashlib

# TODO: Completa le funzioni

def alice_invia_messaggio(testo, chiave_condivisa):
    """Alice crea messaggio + HMAC"""
    # 1. Converti testo in bytes
    # 2. Genera HMAC-SHA256
    # 3. Ritorna dizionario con 'messaggio' e 'tag'
    pass

def bob_verifica_messaggio(msg_dict, chiave_condivisa):
    """Bob verifica e legge messaggio"""
    # 1. Estrai messaggio e tag
    # 2. Ricalcola HMAC
    # 3. Confronta con hmac.compare_digest()
    # 4. Ritorna (valido: bool, messaggio: str)
    pass

# Test
chiave = b"chiave_segreta_alice_bob"

# Alice invia
msg = alice_invia_messaggio("Ciao Bob!", chiave)
print(f"Messaggio inviato: {msg}")

# Bob riceve e verifica
valido, testo = bob_verifica_messaggio(msg, chiave)
if valido:
    print(f"✅ Messaggio autentico: {testo}")
else:
    print("❌ Messaggio corrotto!")

# Attacco: modifica messaggio
msg['messaggio'] = b"Ciao Hacker!"
valido, testo = bob_verifica_messaggio(msg, chiave)
print(f"Dopo modifica: {'✅ Valido' if valido else '❌ Invalido'}")
```

<details>
<summary>Soluzione</summary>

```python
def alice_invia_messaggio(testo, chiave_condivisa):
    messaggio_bytes = testo.encode()
    tag = hmac.new(chiave_condivisa, messaggio_bytes, hashlib.sha256).digest()
    return {'messaggio': messaggio_bytes, 'tag': tag}

def bob_verifica_messaggio(msg_dict, chiave_condivisa):
    messaggio = msg_dict['messaggio']
    tag_ricevuto = msg_dict['tag']
    
    tag_calcolato = hmac.new(chiave_condivisa, messaggio, hashlib.sha256).digest()
    
    if hmac.compare_digest(tag_ricevuto, tag_calcolato):
        return True, messaggio.decode()
    else:
        return False, None
```
</details>

### Esercizio 2: API con Rate Limiting (★★☆)

Crea un sistema API con autenticazione HMAC e rate limiting.

```python
import hmac
import hashlib
import time
from collections import defaultdict

class SecureAPI:
    def __init__(self):
        # Mappa: api_key → secret
        self.api_keys = {
            'client_abc': 'secret_abc_123',
            'client_xyz': 'secret_xyz_456'
        }
        
        # Rate limiting: api_key → [timestamps]
        self.request_log = defaultdict(list)
        self.max_requests_per_minute = 10
    
    def make_request(self, api_key, endpoint, data):
        """Client fa richiesta autenticata"""
        # TODO:
        # 1. Ottieni secret per api_key
        # 2. Crea timestamp
        # 3. Genera payload: f"{api_key}:{timestamp}:{endpoint}:{data}"
        # 4. Calcola HMAC-SHA256
        # 5. Ritorna dizionario request
        pass
    
    def verify_request(self, request):
        """Server verifica richiesta"""
        # TODO:
        # 1. Controlla se api_key esiste
        # 2. Controlla timestamp (valido 60 secondi)
        # 3. Verifica HMAC
        # 4. Controlla rate limit
        # 5. Ritorna (success: bool, message: str)
        pass
    
    def _check_rate_limit(self, api_key):
        """Controlla se superato rate limit"""
        now = time.time()
        minute_ago = now - 60
        
        # Rimuovi richieste vecchie
        self.request_log[api_key] = [
            ts for ts in self.request_log[api_key]
            if ts > minute_ago
        ]
        
        # Controlla limite
        if len(self.request_log[api_key]) >= self.max_requests_per_minute:
            return False
        
        # Aggiungi richiesta corrente
        self.request_log[api_key].append(now)
        return True

# Test
api = SecureAPI()

# Client fa 5 richieste
for i in range(5):
    req = api.make_request('client_abc', '/api/data', f'query_{i}')
    success, msg = api.verify_request(req)
    print(f"Richiesta {i+1}: {msg}")

# Attacco: 15 richieste rapide (rate limit)
print("\n" + "="*40)
print("Attacco: 15 richieste rapide")
print("="*40)
for i in range(15):
    req = api.make_request('client_abc', '/api/data', 'spam')
    success, msg = api.verify_request(req)
    if not success:
        print(f"❌ Richiesta {i+1}: {msg}")
        break
```

<details>
<summary>Soluzione</summary>

```python
def make_request(self, api_key, endpoint, data):
    if api_key not in self.api_keys:
        return None
    
    secret = self.api_keys[api_key]
    timestamp = int(time.time())
    
    payload = f"{api_key}:{timestamp}:{endpoint}:{data}"
    signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return {
        'api_key': api_key,
        'timestamp': timestamp,
        'endpoint': endpoint,
        'data': data,
        'signature': signature
    }

def verify_request(self, request):
    # 1. Controlla API key
    api_key = request['api_key']
    if api_key not in self.api_keys:
        return False, "API key invalida"
    
    # 2. Controlla timestamp
    now = int(time.time())
    if abs(now - request['timestamp']) > 60:
        return False, "Timestamp scaduto"
    
    # 3. Verifica HMAC
    secret = self.api_keys[api_key]
    payload = f"{api_key}:{request['timestamp']}:{request['endpoint']}:{request['data']}"
    expected_sig = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(request['signature'], expected_sig):
        return False, "Firma HMAC invalida"
    
    # 4. Rate limiting
    if not self._check_rate_limit(api_key):
        return False, "Rate limit superato (max 10/min)"
    
    return True, "Richiesta autorizzata"
```
</details>

### Esercizio 3: File Integrity Monitoring (★★★)

Crea un sistema di monitoraggio integrità file con HMAC.

```python
import hmac
import hashlib
import os
from pathlib import Path
import json

class FileIntegrityMonitor:
    def __init__(self, secret_key, database_file='integrity.db'):
        self.secret = secret_key
        self.db_file = database_file
        self.db = self._load_db()
    
    def _load_db(self):
        """Carica database HMAC"""
        # TODO: Carica da JSON file, ritorna dict vuoto se non esiste
        pass
    
    def _save_db(self):
        """Salva database HMAC"""
        # TODO: Salva self.db in JSON file
        pass
    
    def register_file(self, filepath):
        """Registra file nel sistema"""
        # TODO:
        # 1. Leggi contenuto file
        # 2. Calcola HMAC-SHA256
        # 3. Salva in self.db[filepath] = {'hmac': ..., 'size': ..., 'timestamp': ...}
        # 4. Salva database
        pass
    
    def check_file(self, filepath):
        """Verifica integrità file"""
        # TODO:
        # 1. Controlla se file registrato
        # 2. Ricalcola HMAC
        # 3. Confronta con database
        # 4. Ritorna (integro: bool, details: dict)
        pass
    
    def scan_directory(self, directory):
        """Scansiona directory per file modificati"""
        # TODO:
        # 1. Per ogni file nella directory
        # 2. Controlla integrità
        # 3. Stampa report
        pass

# Test
monitor = FileIntegrityMonitor(b"secret_monitoring_key")

# Registra file
print("Registrazione file...")
monitor.register_file('documento.txt')
monitor.register_file('config.json')

# Verifica integrità
print("\nVerifica integrità...")
integro, details = monitor.check_file('documento.txt')
print(f"documento.txt: {'✅ Integro' if integro else '❌ Modificato'}")

# Simula modifica
with open('documento.txt', 'a') as f:
    f.write('\n[MODIFICATO DA ATTACCANTE]')

# Rileva modifica
integro, details = monitor.check_file('documento.txt')
print(f"documento.txt: {'✅ Integro' if integro else '❌ Modificato'}")
if not integro:
    print(f"Dettagli: {details}")
```

<details>
<summary>Soluzione parziale</summary>

```python
def register_file(self, filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    
    file_hmac = hmac.new(self.secret, content, hashlib.sha256).hexdigest()
    
    self.db[filepath] = {
        'hmac': file_hmac,
        'size': len(content),
        'timestamp': time.time()
    }
    
    self._save_db()
    print(f"✅ Registrato: {filepath}")

def check_file(self, filepath):
    if filepath not in self.db:
        return False, {'error': 'File non registrato'}
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    current_hmac = hmac.new(self.secret, content, hashlib.sha256).hexdigest()
    stored_hmac = self.db[filepath]['hmac']
    
    if hmac.compare_digest(current_hmac, stored_hmac):
        return True, {'status': 'integro'}
    else:
        return False, {
            'status': 'modificato',
            'expected_hmac': stored_hmac,
            'current_hmac': current_hmac
        }
```
</details>

---

---

## 🎓 Riepilogo {#riepilogo}

### Cos'è HMAC in 3 Punti

1. **HMAC = Hash + Chiave Segreta**
   - Combina una funzione hash (SHA-256) con una chiave condivisa
   - Solo chi ha la chiave può creare/verificare HMAC validi

2. **Garantisce Autenticazione + Integrità**
   - **Autenticazione**: Prova che il mittente ha la chiave
   - **Integrità**: Prova che il messaggio non è stato modificato

3. **Usato Ovunque**
   - API (AWS, GitHub webhooks)
   - Token (JWT)
   - 2FA (TOTP/Google Authenticator)
   - Cookie di sessione

### Formula HMAC

$$HMAC(K, M) = H((K \oplus opad) || H((K \oplus ipad) || M))$$

**In pratica** (Python):
```python
import hmac, hashlib
tag = hmac.new(key, message, hashlib.sha256).digest()
```

### Quando Usare HMAC

| Scenario | Usa HMAC? | Note |
|----------|-----------|------|
| Autenticare richieste API | ✅ Sì | Standard (AWS Signature, GitHub) |
| Verificare integrità file | ✅ Sì | Con chiave condivisa |
| Cookie di sessione | ✅ Sì | Previene tampering |
| Token 2FA | ✅ Sì | TOTP usa HMAC |
| Verificare download pubblici | ❌ No | Usa hash (SHA-256) |
| Firme digitali legali | ❌ No | Usa RSA/ECDSA (non-ripudio) |
| Cifrare dati sensibili | ❌ No | HMAC non cifra! Usa AES |

### Checklist Best Practices

- [ ] Usa HMAC-SHA256 (o SHA512 per extra sicurezza)
- [ ] Chiave ≥ 32 byte (256 bit) generata con `secrets`
- [ ] Usa `hmac.compare_digest()` per confrontare (mai `==`)
- [ ] Includi timestamp per prevenire replay attacks
- [ ] Se serve confidenzialità: Cifra PRIMA, poi HMAC (Encrypt-then-MAC)
- [ ] Usa chiavi diverse per cifratura e HMAC
- [ ] Gestisci chiavi con key vault (non hardcode)
- [ ] Rate limiting su API autenticate con HMAC

### Differenze Chiave

```
┌────────────────────────────────────────────────┐
│                 HASH vs HMAC                   │
├────────────────────────────────────────────────┤
│                                                │
│  HASH (SHA-256)                                │
│  └─ Input: Solo messaggio                     │
│  └─ Chiunque può calcolare                    │
│  └─ Uso: Checksum, fingerprint                │
│                                                │
│  HMAC (HMAC-SHA256)                            │
│  └─ Input: Messaggio + chiave segreta         │
│  └─ Solo chi ha chiave può calcolare          │
│  └─ Uso: Autenticazione, API, token           │
│                                                │
└────────────────────────────────────────────────┘
```

### Link Utili

- 📚 **RFC 2104**: Specifica HMAC ufficiale
- 🔐 **FIPS 198-1**: Standard NIST per HMAC
- 🐍 **Python hmac**: https://docs.python.org/3/library/hmac.html
- 🔧 **OWASP**: Cryptographic Storage Cheat Sheet

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 12 - Funzioni Hash](12_funzioni_hash_crittografiche.md)
- **Successivo**: [Capitolo 14 - MAC](14_message_authentication_code_mac.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

### Documenti Ufficiali
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication
  - https://www.ietf.org/rfc/rfc2104.txt
- **FIPS 198-1**: The Keyed-Hash Message Authentication Code (HMAC)
  - https://csrc.nist.gov/publications/detail/fips/198/1/final

### Standard e Best Practices
- **NIST SP 800-107**: Recommendation for Applications Using Approved Hash Algorithms
- **OWASP**: Cryptographic Storage Cheat Sheet
  - https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

### Tool e Librerie
- **Python hmac**: https://docs.python.org/3/library/hmac.html
- **Cryptography.io**: https://cryptography.io/
- **HMAC Calculator Online**: https://www.freeformatter.com/hmac-generator.html

### Approfondimenti
- **"Security Pitfalls of HMAC"**: Analisi vulnerabilità comuni
- **AWS Signature v4**: Esempio real-world di HMAC in produzione
- **JWT RFC 7519**: JSON Web Token con HMAC-SHA256

---

**💡 Raccomandazione Finale**: HMAC-SHA256 è lo standard de-facto per autenticazione messaggi. Usalo sempre quando serve autenticazione + integrità con chiave simmetrica.

**⚠️ Ricorda**: HMAC NON fornisce confidenzialità. Se i dati sono sensibili, cifra PRIMA con AES, poi applica HMAC al ciphertext (Encrypt-then-MAC pattern).

---

> **Prossimo passo**: Nel Capitolo 14 esploreremo altri tipi di MAC (Message Authentication Code) e confronteremo HMAC con CBC-MAC e GMAC.

---
