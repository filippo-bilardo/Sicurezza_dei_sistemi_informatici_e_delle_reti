# Capitolo 11 - Altri Algoritmi Asimmetrici

> **Corso**: Sistemi e Reti 3  
> **Parte**: 3 - Crittografia Asimmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Oltre a RSA, Diffie-Hellman ed ECC, esistono altri algoritmi asimmetrici interessanti e/o storici.

---

## 1. ElGamal

### Storia

Inventato da Taher ElGamal nel 1985, basato sul problema del logaritmo discreto.

### Crittografia ElGamal

```python
import random

def elgamal_keygen(p, g):
    """Genera chiavi ElGamal"""
    # Chiave privata: x random
    x = random.randint(2, p-2)
    
    # Chiave pubblica: y = g^x mod p
    y = pow(g, x, p)
    
    return {
        'public': (p, g, y),
        'private': x
    }

def elgamal_encrypt(m, public_key):
    """Cifra messaggio con ElGamal"""
    p, g, y = public_key
    
    # Scegli k random (ephemeral key)
    k = random.randint(2, p-2)
    
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # c2 = m * y^k mod p
    c2 = (m * pow(y, k, p)) % p
    
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, public_key):
    """Decifra con ElGamal"""
    c1, c2 = ciphertext
    p, g, y = public_key
    x = private_key
    
    # s = c1^x mod p
    s = pow(c1, x, p)
    
    # s_inv = s^(-1) mod p (inverso modulare)
    s_inv = pow(s, p-2, p)  # Fermat's little theorem
    
    # m = c2 * s_inv mod p
    m = (c2 * s_inv) % p
    
    return m

# Test
p = 467  # Primo (piccolo per demo)
g = 2    # Generatore

keys = elgamal_keygen(p, g)
print(f"Public key: {keys['public']}")
print(f"Private key: {keys['private']}")

# Cifra
messaggio = 123
ciphertext = elgamal_encrypt(messaggio, keys['public'])
print(f"\nMessaggio: {messaggio}")
print(f"Ciphertext: {ciphertext}")

# Decifra
plaintext = elgamal_decrypt(ciphertext, keys['private'], keys['public'])
print(f"Decifrato: {plaintext}")
print(f"✅ Corretto: {plaintext == messaggio}")
```

### Caratteristiche

✅ Sicurezza basata su logaritmo discreto  
✅ **Randomizzato**: Stesso plaintext → ciphertext diversi  
⚠️ Ciphertext 2x dimensione plaintext  
⚠️ Meno diffuso di RSA

### Firma ElGamal

Base per **DSA** (Digital Signature Algorithm).

---

## 2. DSA (Digital Signature Algorithm)

### Storia

Proposto da NIST nel 1991, standard FIPS 186.

### Parametri

- $p$: primo grande (2048-3072 bit)
- $q$: primo che divide $p-1$ (256 bit)
- $g$: generatore

### Firma DSA

```python
import hashlib
import random

class DSA:
    """Implementazione semplificata DSA"""
    
    def __init__(self, p, q, g):
        self.p = p  # Primo grande
        self.q = q  # Primo piccolo (divide p-1)
        self.g = g  # Generatore
    
    def keygen(self):
        """Genera coppia chiavi"""
        # Chiave privata: x random
        x = random.randint(1, self.q - 1)
        
        # Chiave pubblica: y = g^x mod p
        y = pow(self.g, x, self.p)
        
        return x, y
    
    def sign(self, message, private_key):
        """Firma messaggio"""
        x = private_key
        
        # Hash messaggio
        h = int(hashlib.sha256(message).hexdigest(), 16) % self.q
        
        # k random per ogni firma
        k = random.randint(1, self.q - 1)
        
        # r = (g^k mod p) mod q
        r = pow(self.g, k, self.p) % self.q
        
        # k_inv = k^(-1) mod q
        k_inv = pow(k, self.q - 2, self.q)  # Fermat
        
        # s = k_inv * (h + x*r) mod q
        s = (k_inv * (h + x * r)) % self.q
        
        return (r, s)
    
    def verify(self, message, signature, public_key):
        """Verifica firma"""
        r, s = signature
        y = public_key
        
        # Controlli base
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        # Hash messaggio
        h = int(hashlib.sha256(message).hexdigest(), 16) % self.q
        
        # w = s^(-1) mod q
        w = pow(s, self.q - 2, self.q)
        
        # u1 = (h * w) mod q
        u1 = (h * w) % self.q
        
        # u2 = (r * w) mod q
        u2 = (r * w) % self.q
        
        # v = ((g^u1 * y^u2) mod p) mod q
        v = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q
        
        return v == r

# Test (parametri piccoli per demo)
p = 23  # Dovrebbe essere molto più grande!
q = 11  # Divide p-1 = 22
g = 2

dsa = DSA(p, q, g)

# Genera chiavi
private, public = dsa.keygen()
print(f"Public key: {public}")

# Firma
message = b"Documento importante"
signature = dsa.sign(message, private)
print(f"Signature: {signature}")

# Verifica
valid = dsa.verify(message, signature, public)
print(f"✅ Firma valida: {valid}")

# Test con messaggio modificato
fake_message = b"Documento modificato"
valid_fake = dsa.verify(fake_message, signature, public)
print(f"❌ Messaggio fake valido: {valid_fake}")
```

### Sicurezza

⚠️ **Cruciale**: k deve essere random per ogni firma!

```python
# Se k riusato o predicibile → Chiave privata compromessa!

# Attacco con k riusato:
# s1 = k^(-1) * (h1 + x*r) mod q
# s2 = k^(-1) * (h2 + x*r) mod q
# 
# s1 - s2 = k^(-1) * (h1 - h2) mod q
# k = (h1 - h2) / (s1 - s2) mod q
# 
# Con k noto → x = (s*k - h) / r mod q
```

**Esempio storico**: PlayStation 3 hack (2010) - Sony riusò k!

---

## 3. Schnorr Signatures

### Caratteristiche

- **Più semplice** di DSA
- **Provably secure** (riducibile a logaritmo discreto)
- **Firma corta**: 64 byte (256 bit)
- Usato in **Bitcoin (BIP-340)** e **EdDSA**

### Schema

```python
import hashlib
import random

class Schnorr:
    """Schnorr signatures"""
    
    def __init__(self, p, q, g):
        self.p = p  # Primo
        self.q = q  # Ordine sottogruppo
        self.g = g  # Generatore
    
    def keygen(self):
        """Genera chiavi"""
        x = random.randint(1, self.q - 1)  # Privata
        y = pow(self.g, x, self.p)         # Pubblica
        return x, y
    
    def sign(self, message, private_key):
        """Firma Schnorr"""
        x = private_key
        
        # k random
        k = random.randint(1, self.q - 1)
        
        # r = g^k mod p
        r = pow(self.g, k, self.p)
        
        # e = H(r || message)
        h = hashlib.sha256(str(r).encode() + message).digest()
        e = int.from_bytes(h, 'big') % self.q
        
        # s = k - x*e mod q
        s = (k - x * e) % self.q
        
        return (e, s)
    
    def verify(self, message, signature, public_key):
        """Verifica firma Schnorr"""
        e, s = signature
        y = public_key
        
        # r_v = g^s * y^e mod p
        r_v = (pow(self.g, s, self.p) * pow(y, e, self.p)) % self.p
        
        # e_v = H(r_v || message)
        h = hashlib.sha256(str(r_v).encode() + message).digest()
        e_v = int.from_bytes(h, 'big') % self.q
        
        return e == e_v

# Test
schnorr = Schnorr(p=23, q=11, g=2)
priv, pub = schnorr.keygen()

msg = b"Schnorr signature test"
sig = schnorr.sign(msg, priv)
print(f"Signature: {sig}")
print(f"✅ Valid: {schnorr.verify(msg, sig, pub)}")
```

### Vantaggi

✅ **Linearità**: Aggregazione firme (multi-sig)  
✅ **Batch verification**: Verifica multipla efficiente  
✅ **Provably secure**: Dimostrazione matematica  
✅ **Firma breve**: 64 byte

---

## 4. McEliece Cryptosystem

### Storia

Proposto nel 1978, basato su **teoria dei codici**.

### Caratteristiche

✅ **Post-quantum**: Resistente a computer quantistici  
✅ **Veloce**: Cifratura/decifratura rapida  
❌ **Chiavi enormi**: Chiave pubblica ~1 MB  
❌ **Poco usato**: Per dimensione chiavi

### Concetto

Usa **codici correttori di errori**:

1. Genera codice Goppa (privato)
2. Maschera struttura (pubblica)
3. Cifra = encoding + errori random
4. Decifra = correggi errori con codice privato

```python
# Pseudocodice (implementazione complessa!)

class McEliece:
    def keygen(self):
        # Genera codice Goppa casuale
        goppa_code = generate_goppa_code(n, k, t)
        
        # Matrici casuali per mascherare
        S = random_invertible_matrix(k)
        P = random_permutation_matrix(n)
        
        # Chiave pubblica: G' = S*G*P
        public_key = S @ goppa_code.generator @ P
        
        # Chiave privata: (S, G, P)
        private_key = (S, goppa_code, P)
        
        return public_key, private_key
    
    def encrypt(self, message, public_key):
        # c = m*G' + e (e = errori casuali, peso t)
        errors = random_error_vector(weight=t)
        ciphertext = message @ public_key + errors
        return ciphertext
    
    def decrypt(self, ciphertext, private_key):
        S, goppa, P = private_key
        
        # Applica P^(-1)
        c_perm = ciphertext @ P.inv()
        
        # Correggi errori con Goppa
        m_decoded = goppa.decode(c_perm)
        
        # Applica S^(-1)
        message = m_decoded @ S.inv()
        
        return message
```

### Uso Moderno

**Classic McEliece** è uno dei finalisti NIST per post-quantum crypto.

---

## 5. Paillier Cryptosystem

### Caratteristiche

**Homomorphic encryption** (parziale):

$$E(m_1) \times E(m_2) = E(m_1 + m_2)$$

### Applicazioni

- Voto elettronico (somma voti senza decifrarli)
- Computazione su dati cifrati
- Privacy-preserving analytics

### Schema Semplificato

```python
import random

class Paillier:
    """Paillier homomorphic encryption (semplificato)"""
    
    def __init__(self, p, q):
        self.n = p * q
        self.n2 = self.n * self.n
        
        # Lambda = lcm(p-1, q-1)
        self.lam = self.lcm(p-1, q-1)
        
        # g = n + 1 (generatore semplice)
        self.g = self.n + 1
        
        # mu = lambda^(-1) mod n
        self.mu = self.modinv(self.lam, self.n)
    
    @staticmethod
    def lcm(a, b):
        return abs(a * b) // Paillier.gcd(a, b)
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def modinv(a, m):
        return pow(a, -1, m)
    
    def encrypt(self, m):
        """Cifra messaggio"""
        # r random
        r = random.randint(1, self.n - 1)
        
        # c = g^m * r^n mod n^2
        c = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        
        return c
    
    def decrypt(self, c):
        """Decifra"""
        # L(x) = (x - 1) / n
        def L(x):
            return (x - 1) // self.n
        
        # m = L(c^lambda mod n^2) * mu mod n
        m = (L(pow(c, self.lam, self.n2)) * self.mu) % self.n
        
        return m
    
    def add_encrypted(self, c1, c2):
        """Somma su cifrati: E(m1) * E(m2) = E(m1 + m2)"""
        return (c1 * c2) % self.n2

# Test
paillier = Paillier(p=61, q=53)  # Piccoli per demo

# Cifra
m1 = 15
m2 = 7

c1 = paillier.encrypt(m1)
c2 = paillier.encrypt(m2)

print(f"E({m1}) = {c1}")
print(f"E({m2}) = {c2}")

# Somma homomorphic
c_sum = paillier.add_encrypted(c1, c2)

# Decifra
m_sum = paillier.decrypt(c_sum)

print(f"\nE({m1}) * E({m2}) = E({m1 + m2})")
print(f"Decrypt = {m_sum}")
print(f"✅ {m1} + {m2} = {m_sum}")
```

---

## 6. NTRUEncrypt

### Caratteristiche

- Basato su **lattice** (reticoli)
- **Post-quantum** resistente
- **Veloce**: ~10x più veloce di RSA
- **Chiavi compatte**: ~1 KB

### Sicurezza

Basata su **Shortest Vector Problem (SVP)** in reticoli.

⚠️ Ancora in studio per standardizzazione

---

## 7. Rabin Cryptosystem

### Storia

Michael Rabin (1979), provably secure come fattorizzazione.

### Schema

$$C = M^2 \mod n$$

Dove $n = p \times q$ (prodotto primi)

### Problema

Decifratura ha 4 possibili plaintext! Serve disambiguazione.

```python
def rabin_encrypt(m, n):
    """Rabin encryption"""
    return (m * m) % n

def rabin_decrypt(c, p, q):
    """Rabin decryption (4 possibili output!)"""
    n = p * q
    
    # Calcola radici mod p e mod q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    
    # Chinese Remainder Theorem (4 combinazioni)
    # ... implementazione complessa
    
    # Serve ridondanza nel plaintext per disambiguare
    pass
```

### Uso

Poco usato in pratica per ambiguità decifratura.

---

## Confronto Finale

| Algoritmo | Base | Post-Quantum | Velocità | Uso |
|-----------|------|--------------|----------|-----|
| **RSA** | Fattorizzazione | ❌ | 🐌 | Standard attuale |
| **ElGamal** | Log discreto | ❌ | 🐌 | Meno comune |
| **DSA** | Log discreto | ❌ | 🐌 | Firma standard |
| **Schnorr** | Log discreto | ❌ | ⚡ | Bitcoin, EdDSA |
| **ECC** | Curve ellittiche | ❌ | ⚡ | Moderno standard |
| **McEliece** | Codici | ✅ | ⚡⚡ | Post-quantum |
| **Paillier** | Fattorizzazione | ❌ | 🐌 | Homomorphic |
| **NTRU** | Lattice | ✅ | ⚡⚡ | Post-quantum |

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 10 - ECC](10_crittografia_a_curva_ellittica_ecc.md)
- **Successivo**: [Capitolo 12 - Hash](../04_Hash_Integrita/12_funzioni_hash_crittografiche.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- Paillier: "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes" (1999)

**Nota**: Il futuro è post-quantum! RSA/ECC avranno vita limitata.
