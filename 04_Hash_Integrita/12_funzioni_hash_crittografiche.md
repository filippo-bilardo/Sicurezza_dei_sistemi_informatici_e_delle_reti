# Capitolo 12 - Funzioni Hash Crittografiche

> **Corso**: Sistemi e Reti 3  
> **Parte**: 4 - Hash e Integrità  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Una **funzione hash crittografica** trasforma un input di lunghezza arbitraria in un output di lunghezza fissa (digest).

### Proprietà Essenziali

1. **Deterministica**: Stesso input → stesso output
2. **Veloce da calcolare**
3. **Avalanche effect**: Piccola modifica → digest completamente diverso
4. **One-way**: Impossibile risalire allinput
5. **Collision-resistant**: Difficile trovare due input con stesso hash

## Algoritmi Principali

| Algoritmo | Output | Stato | Uso |
|-----------|--------|-------|-----|
| MD5 | 128 bit | ❌ Rotto | Mai usare |
| SHA-1 | 160 bit | ⚠️ Deprecato | Legacy |
| SHA-256 | 256 bit | ✅ Sicuro | Raccomandato |
| SHA-3 | Variabile | ✅ Sicuro | Moderno |
| BLAKE2 | Variabile | ✅ Sicuro | Veloce |

## Esempi Python

### SHA-256

```python
import hashlib

# Calcola hash
messaggio = b"Hello, World!"
hash_obj = hashlib.sha256(messaggio)
digest = hash_obj.hexdigest()

print(f"SHA-256: {digest}")
# Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

### Verifica Integrità File

```python
def hash_file(filename):
    """Calcola SHA-256 di un file"""
    sha256 = hashlib.sha256()
    
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    
    return sha256.hexdigest()

# Uso
hash1 = hash_file("documento.pdf")
# ... trasmissione file ...
hash2 = hash_file("documento_ricevuto.pdf")

if hash1 == hash2:
    print("✅ File integro")
else:
    print("⚠️ File modificato!")
```

## Applicazioni

1. **Verifica integrità**: Checksum di file
2. **Password hashing**: bcrypt, scrypt, Argon2
3. **Blockchain**: Proof of Work
4. **Firme digitali**: Input per algoritmi RSA/ECDSA
5. **HMAC**: Autenticazione messaggi

## Collision Attacks

### MD5 Collision (2004)

```python
# Due file diversi con stesso MD5 (collision trovata)
file1 = b"...[dati specifici]..."
file2 = b"...[dati diversi]..."

# Entrambi producono lo stesso MD5!
# hashlib.md5(file1).hexdigest() == hashlib.md5(file2).hexdigest()
```

⚠️ **Per questo MD5 non deve essere usato per sicurezza!**

---

## 🔗 Collegamenti

- **Indice**: [Torna all'indice](../00_INDICE.md)

---

**Ultima modifica**: Dicembre 2024
