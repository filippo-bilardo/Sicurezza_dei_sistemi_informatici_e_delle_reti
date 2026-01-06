# Capitolo 13 - HMAC (Hash-based Message Authentication Code)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 4 - Hash e Integrità  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**HMAC** fornisce autenticazione e integrità dei messaggi usando funzioni hash e una chiave segreta.

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

## Sicurezza

### ✅ Vantaggi
- Protegge da modifiche non autorizzate
- Resistente a collision attacks
- Veloce da calcolare

### ⚠️ Attenzioni
- Richiede chiave condivisa sicura
- Non fornisce confidenzialità (usa insieme a cifratura)
- Timing attacks: usa `hmac.compare_digest()`

## HMAC-SHA256 vs HMAC-SHA512

```python
import hmac
import hashlib

key = b"test_key"
msg = b"test message"

# HMAC-SHA256 (32 byte)
tag256 = hmac.new(key, msg, hashlib.sha256).digest()
print(f"HMAC-SHA256: {len(tag256)} byte")

# HMAC-SHA512 (64 byte)
tag512 = hmac.new(key, msg, hashlib.sha512).digest()
print(f"HMAC-SHA512: {len(tag512)} byte")

# SHA-256 è sufficiente per la maggior parte degli usi
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 12 - Funzioni Hash](12_funzioni_hash_crittografiche.md)
- **Successivo**: [Capitolo 14 - MAC](14_message_authentication_code_mac.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- FIPS 198-1: The Keyed-Hash Message Authentication Code

**Raccomandazione**: HMAC-SHA256 è lo standard per autenticazione messaggi.
