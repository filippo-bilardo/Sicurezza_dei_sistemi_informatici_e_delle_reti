# Capitolo 6 - Cifrari a Flusso

> **Corso**: Sistemi e Reti 3  
> **Parte**: 2 - Crittografia Simmetrica  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

I **cifrari a flusso** (stream ciphers) cifrano il plaintext un bit o byte alla volta, a differenza dei cifrari a blocchi che operano su blocchi di dimensione fissa.

### Schema Base

```
Chiave (K) + IV/Nonce → [PRNG] → Keystream (KS) → Plaintext ⊕ KS = Ciphertext
```

### Funzionamento

$$C_i = P_i \oplus KS_i$$

Dove:
- $P_i$ = i-esimo byte plaintext
- $KS_i$ = i-esimo byte keystream
- $C_i$ = i-esimo byte ciphertext

### Vantaggi

✅ **Velocità elevata**: Operazioni semplici (XOR)  
✅ **No padding**: Ciphertext = dimensione plaintext  
✅ **Bassa latenza**: Elaborazione byte-by-byte  
✅ **Ideale per streaming**: Video, audio, rete  
✅ **Hardware-friendly**: Facile implementare in HW

### Svantaggi

⚠️ **Nonce critico**: Mai riusare con stessa chiave!  
⚠️ **No autenticazione**: Serve MAC separato  
⚠️ **Vulnerabile a bit-flipping**: Modifica C_i → modifica P_i

---

## Principi di Funzionamento

### One-Time Pad (OTP)

Il **cifrario perfetto** teoricamente inattaccabile.

#### Proprietà

- Chiave **completamente casuale**
- Chiave **lunga quanto messaggio**
- Chiave **usata una sola volta**

#### Implementazione

```python
import os

def otp_encrypt(plaintext):
    """One-Time Pad perfetto"""
    # Genera chiave casuale vera (non pseudo!)
    key = os.urandom(len(plaintext))
    
    # XOR bit-a-bit
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, key)])
    
    return ciphertext, key

def otp_decrypt(ciphertext, key):
    """Decifratura OTP"""
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext

# Test
msg = b"ATTACK AT DAWN"
cipher, key = otp_encrypt(msg)

print(f"Plaintext:  {msg.hex()}")
print(f"Key:        {key.hex()}")
print(f"Ciphertext: {cipher.hex()}")

decrypted = otp_decrypt(cipher, key)
print(f"Decrypted:  {decrypted}")
print(f"✅ Corretto: {decrypted == msg}")
```

#### Sicurezza Teorica

**Perfetta segretezza** (Shannon 1949):

$$P(M | C) = P(M)$$

Ciphertext non fornisce **nessuna** informazione su plaintext!

#### Problema Pratico

❌ Distribuzione chiave impossibile  
❌ Chiave lunga quanto tutti i messaggi  
❌ Storage enorme

### PRNG (Pseudo-Random Number Generator)

Soluzione pratica: generare keystream **pseudocasuale** da chiave corta.

```
Chiave (128-256 bit) + IV/Nonce → [PRNG] → Keystream (illimitato)
```

⚠️ **Cruciale**: PRNG deve essere crittograficamente sicuro!

---

## Registri a Scorrimento (LFSR)

### Linear Feedback Shift Register

Base per molti stream cipher classici.

#### Struttura

```
[bit_n] [bit_n-1] ... [bit_2] [bit_1] [bit_0]
   ↓        ↓              ↓       ↓       ↓
   ⊕────────⊕──────────────⊕───────⊕ → Output
   │
   └─────────────────────────────────────┘ (feedback)
```

#### Implementazione

```python
class LFSR:
    """Linear Feedback Shift Register"""
    
    def __init__(self, seed, taps):
        """
        seed: stato iniziale (es. 0b1101)
        taps: posizioni feedback (es. [3, 2])
        """
        self.state = seed
        self.taps = taps
        self.size = seed.bit_length()
    
    def clock(self):
        """Genera un bit"""
        # Calcola feedback (XOR dei tap bits)
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        
        # Output = bit meno significativo
        output = self.state & 1
        
        # Shift right e inserisci feedback
        self.state = (self.state >> 1) | (feedback << (self.size - 1))
        
        return output
    
    def generate_keystream(self, length):
        """Genera keystream di lunghezza data"""
        keystream = []
        for _ in range(length * 8):
            keystream.append(self.clock())
        
        # Converti bits in bytes
        result = []
        for i in range(0, len(keystream), 8):
            byte = 0
            for j in range(8):
                if i + j < len(keystream):
                    byte |= keystream[i + j] << (7 - j)
            result.append(byte)
        
        return bytes(result)

# Test LFSR
lfsr = LFSR(seed=0b1101, taps=[3, 2])

print("Sequenza LFSR:")
for i in range(16):
    bit = lfsr.clock()
    print(bit, end='')
    if (i + 1) % 4 == 0:
        print(' ', end='')
print()

# Uso per cifratura (INSICURO! Solo didattico)
lfsr = LFSR(seed=0b11010110, taps=[7, 5, 4, 3])
plaintext = b"HELLO"
keystream = lfsr.generate_keystream(len(plaintext))

ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
print(f"\nPlaintext:  {plaintext.hex()}")
print(f"Keystream:  {keystream.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")
```

### Vulnerabilità LFSR

❌ **Prevedibile**: Con 2n bit output si ricava tutto il keystream!  
❌ **Algebrici**: Attacchi basati su equazioni lineari

**Soluzione**: Combinare più LFSR con funzioni non-lineari

---

## RC4 (Rivest Cipher 4)

### Storia

- Progettato da Ron Rivest (1987)
- **Leak** del codice (1994)
- Usato in WEP, WPA-TKIP, SSL/TLS
- ⚠️ **DEPRECATO** (2015)

### Algoritmo

#### Key Scheduling Algorithm (KSA)

```python
def rc4_ksa(key):
    """Inizializza stato RC4"""
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
    
    return S

def rc4_prga(S):
    """Genera byte keystream"""
    i = 0
    j = 0
    
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        
        K = S[(S[i] + S[j]) % 256]
        yield K

def rc4(key, data):
    """RC4 encryption/decryption"""
    S = rc4_ksa(key)
    keystream = rc4_prga(S)
    
    result = []
    for byte in data:
        result.append(byte ^ next(keystream))
    
    return bytes(result)

# Test RC4
key = b"SecretKey"
plaintext = b"Attack at dawn!"

ciphertext = rc4(key, plaintext)
print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")

decrypted = rc4(key, ciphertext)
print(f"Decrypted:  {decrypted}")
print(f"✅ Match: {decrypted == plaintext}")
```

### Vulnerabilità RC4

#### 1. Bias nei primi byte

Primi 256 byte del keystream hanno bias statistici.

**Mitigazione**: Scartare primi 3072 byte (RC4-drop[3072])

#### 2. Attacco WEP (2001)

```python
# WEP usa: IV || Chiave
# IV trasmesso in chiaro
# IV 24 bit → Collisione dopo ~5000 pacchetti

# Con 2 pacchetti stesso IV:
# C1 = P1 ⊕ KS
# C2 = P2 ⊕ KS
# C1 ⊕ C2 = P1 ⊕ P2  # Keystream cancellato!
```

#### 3. BEAST Attack SSL/TLS (2011)

Prevedibilità IV in CBC mode + RC4.

#### 4. RC4 NOMORE (2015)

Attacco statistico su TLS, recupero cookie in 75 ore.

### Conclusione RC4

🚫 **NON USARE MAI**  
✅ Sostituire con **ChaCha20** o **AES-GCM**

---

## Salsa20 / ChaCha20

### Storia

- **Salsa20**: Daniel Bernstein (2005)
- **ChaCha20**: Versione migliorata (2008)
- Adottato da Google (2014)
- Standard TLS 1.3 (2018)

### ChaCha20: Struttura

#### Stato Iniziale (512 bit)

```
+----------+----------+----------+----------+
| Constant | Constant | Constant | Constant |  (128 bit)
+----------+----------+----------+----------+
|   Key    |   Key    |   Key    |   Key    |  (256 bit)
+----------+----------+----------+----------+
| Counter  | Counter  |  Nonce   |  Nonce   |  (128 bit)
+----------+----------+----------+----------+
```

#### Quarter Round

Operazione base: **QR(a, b, c, d)**

```python
def quarter_round(a, b, c, d):
    """ChaCha20 quarter round"""
    a = (a + b) & 0xFFFFFFFF
    d = ((d ^ a) << 16 | (d ^ a) >> 16) & 0xFFFFFFFF  # Rotate 16
    
    c = (c + d) & 0xFFFFFFFF
    b = ((b ^ c) << 12 | (b ^ c) >> 20) & 0xFFFFFFFF  # Rotate 12
    
    a = (a + b) & 0xFFFFFFFF
    d = ((d ^ a) << 8 | (d ^ a) >> 24) & 0xFFFFFFFF   # Rotate 8
    
    c = (c + d) & 0xFFFFFFFF
    b = ((b ^ c) << 7 | (b ^ c) >> 25) & 0xFFFFFFFF   # Rotate 7
    
    return a, b, c, d
```

### Implementazione ChaCha20

```python
def chacha20_block(key, counter, nonce):
    """Genera blocco ChaCha20 (64 byte)"""
    
    # Costanti magiche "expand 32-byte k"
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # Costanti
    ]
    
    # Chiave (8 words di 32 bit)
    for i in range(0, 32, 4):
        state.append(int.from_bytes(key[i:i+4], 'little'))
    
    # Counter (1 word) + Nonce (3 words)
    state.append(counter)
    for i in range(0, 12, 4):
        state.append(int.from_bytes(nonce[i:i+4], 'little'))
    
    # Copia working state
    working = state[:]
    
    # 20 round (10 double rounds)
    for _ in range(10):
        # Column rounds
        working[0], working[4], working[8], working[12] = \
            quarter_round(working[0], working[4], working[8], working[12])
        working[1], working[5], working[9], working[13] = \
            quarter_round(working[1], working[5], working[9], working[13])
        working[2], working[6], working[10], working[14] = \
            quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = \
            quarter_round(working[3], working[7], working[11], working[15])
        
        # Diagonal rounds
        working[0], working[5], working[10], working[15] = \
            quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = \
            quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8], working[13] = \
            quarter_round(working[2], working[7], working[8], working[13])
        working[3], working[4], working[9], working[14] = \
            quarter_round(working[3], working[4], working[9], working[14])
    
    # Aggiungi stato iniziale
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xFFFFFFFF
    
    # Converti in bytes (little-endian)
    result = b''
    for word in working:
        result += word.to_bytes(4, 'little')
    
    return result

def chacha20_encrypt(key, nonce, plaintext, counter=0):
    """Cifra con ChaCha20"""
    ciphertext = b''
    
    for i in range(0, len(plaintext), 64):
        block = chacha20_block(key, counter, nonce)
        chunk = plaintext[i:i+64]
        
        ciphertext += bytes([p ^ k for p, k in zip(chunk, block)])
        counter += 1
    
    return ciphertext

# Test ChaCha20
import os

key = os.urandom(32)
nonce = os.urandom(12)
plaintext = b"The quick brown fox jumps over the lazy dog" * 10

ciphertext = chacha20_encrypt(key, nonce, plaintext)
decrypted = chacha20_encrypt(key, nonce, ciphertext)

print(f"Plaintext length: {len(plaintext)}")
print(f"Ciphertext: {ciphertext[:32].hex()}...")
print(f"✅ Decryption: {decrypted == plaintext}")
```

### ChaCha20-Poly1305 (AEAD)

Combinazione di **ChaCha20** (cifratura) + **Poly1305** (MAC).

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class ChaCha20Poly1305Cipher:
    """ChaCha20-Poly1305 AEAD"""
    
    def __init__(self, key=None):
        if key is None:
            key = ChaCha20Poly1305.generate_key()
        self.cipher = ChaCha20Poly1305(key)
        self.key = key
    
    def encrypt(self, plaintext, associated_data=b""):
        """Cifra con autenticazione"""
        nonce = os.urandom(12)
        
        ciphertext = self.cipher.encrypt(
            nonce, 
            plaintext, 
            associated_data
        )
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'tag': ciphertext[-16:]  # Poly1305 tag
        }
    
    def decrypt(self, nonce, ciphertext, associated_data=b""):
        """Decifra e verifica autenticità"""
        try:
            plaintext = self.cipher.decrypt(
                nonce,
                ciphertext,
                associated_data
            )
            return plaintext
        except Exception as e:
            raise ValueError("❌ Tag non valido - dati modificati!")

# Test AEAD
cipher = ChaCha20Poly1305Cipher()

# Cifra
msg = b"Messaggio segreto e autentico"
aad = b"metadata: sender=alice, timestamp=12345"

encrypted = cipher.encrypt(msg, aad)
print(f"Nonce: {encrypted['nonce'].hex()}")
print(f"Ciphertext: {encrypted['ciphertext'][:32].hex()}...")
print(f"Tag: {encrypted['tag'].hex()}")

# Decifra
try:
    decrypted = cipher.decrypt(
        encrypted['nonce'],
        encrypted['ciphertext'],
        aad
    )
    print(f"✅ Decrypted: {decrypted}")
except ValueError as e:
    print(e)

# Test tampering
try:
    fake_ciphertext = encrypted['ciphertext'][:-16] + os.urandom(16)
    cipher.decrypt(encrypted['nonce'], fake_ciphertext, aad)
except ValueError as e:
    print(e)
```

### Vantaggi ChaCha20

✅ **Veloce su software**: No AES-NI necessario  
✅ **Constant-time**: Resistente a timing attacks  
✅ **Mobile-friendly**: Ottimo su ARM  
✅ **Sicuro**: No vulnerabilità note  
✅ **Standardizzato**: RFC 7539, TLS 1.3

---

## Confronto Stream vs Block Cipher

| Caratteristica | Stream Cipher | Block Cipher |
|----------------|---------------|--------------|
| **Operazione** | Byte/bit singolo | Blocchi fissi (128 bit) |
| **Padding** | ❌ Non necessario | ✅ Necessario (ECB, CBC) |
| **Latenza** | ⚡ Bassissima | 🐌 Alta (blocco completo) |
| **Velocità** | ⚡⚡ Molto veloce | ⚡ Veloce (con HW) |
| **Hardware** | Più complesso | Semplice (AES-NI) |
| **Error propagation** | 1 bit → 1 bit | 1 bit → blocco intero |
| **Uso ideale** | Streaming, rete | File, disco, database |
| **Esempi** | ChaCha20, RC4 | AES, DES, 3DES |

### Quando Usare Stream Cipher

✅ **Streaming**: Video, audio real-time  
✅ **Low latency**: Gaming, VoIP  
✅ **Dispositivi mobili**: Senza AES-NI  
✅ **Rete**: VPN (WireGuard usa ChaCha20)

### Quando Usare Block Cipher

✅ **Storage**: File encryption, database  
✅ **CPU moderne**: Intel/AMD con AES-NI  
✅ **Standard consolidati**: AES ubiquo

---

## Vulnerabilità Comuni

### 1. Nonce Reuse (Riuso IV)

**DISASTRO CRITTOGRAFICO!**

```python
# ❌ MAI FARE QUESTO!

key = os.urandom(32)
nonce = os.urandom(12)  # FISSO!

# Due messaggi con stesso nonce
cipher1 = chacha20_encrypt(key, nonce, b"Message 1")
cipher2 = chacha20_encrypt(key, nonce, b"Message 2")

# Attacco:
# C1 = P1 ⊕ KS
# C2 = P2 ⊕ KS
# C1 ⊕ C2 = P1 ⊕ P2  # Keystream cancellato!

xor_result = bytes([c1 ^ c2 for c1, c2 in zip(cipher1, cipher2)])
# Se P1 è noto → P2 = P1 ⊕ (C1 ⊕ C2)
```

**Soluzione**: Nonce **sempre diverso**!

```python
def safe_encrypt(key, plaintext):
    """✅ Genera nonce unico ogni volta"""
    nonce = os.urandom(12)
    ciphertext = chacha20_encrypt(key, nonce, plaintext)
    return nonce + ciphertext  # Prepend nonce
```

### 2. Bit-Flipping Attack

Stream cipher vulnerabile a modifiche mirate.

```python
# Attaccante intercetta:
ciphertext = b'\x42\x53\x61...'  # "Attack at dawn"

# Vuole cambiare "dawn" in "noon"
# Conosce posizione e plaintext

# XOR differenza:
# "dawn" ⊕ "noon" ⊕ ciphertext[pos] = ciphertext_modificato

# SENZA autenticazione → Attacco riesce!
```

**Soluzione**: **AEAD** (ChaCha20-Poly1305, AES-GCM)

### 3. Weak PRNG

❌ **Mai usare** `random` per crittografia!

```python
import random

# ❌ INSICURO!
random.seed(12345)
keystream = bytes([random.randint(0, 255) for _ in range(100)])

# ✅ SICURO
import os
keystream = os.urandom(100)
```

---

## Esempi Pratici

### 1. File Encryption Streaming

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

def encrypt_file_chacha20(input_path, output_path, key):
    """Cifra file grande con ChaCha20"""
    chacha = ChaCha20Poly1305(key)
    
    # Nonce unico
    nonce = os.urandom(12)
    
    with open(output_path, 'wb') as f_out:
        # Scrivi nonce all'inizio
        f_out.write(nonce)
        
        with open(input_path, 'rb') as f_in:
            counter = 0
            while True:
                # Leggi chunk 64 KB
                chunk = f_in.read(64 * 1024)
                if not chunk:
                    break
                
                # Cifra con nonce + counter
                nonce_counter = nonce[:-4] + counter.to_bytes(4, 'little')
                encrypted = chacha.encrypt(nonce_counter, chunk, b"")
                
                f_out.write(encrypted)
                counter += 1

def decrypt_file_chacha20(input_path, output_path, key):
    """Decifra file"""
    chacha = ChaCha20Poly1305(key)
    
    with open(input_path, 'rb') as f_in:
        # Leggi nonce
        nonce = f_in.read(12)
        
        with open(output_path, 'wb') as f_out:
            counter = 0
            while True:
                # Leggi chunk cifrato
                chunk = f_in.read(64 * 1024 + 16)  # +16 per tag
                if not chunk:
                    break
                
                nonce_counter = nonce[:-4] + counter.to_bytes(4, 'little')
                decrypted = chacha.decrypt(nonce_counter, chunk, b"")
                
                f_out.write(decrypted)
                counter += 1

# Test
key = ChaCha20Poly1305.generate_key()

# Crea file test
with open('/tmp/test.txt', 'w') as f:
    f.write("Hello World! " * 10000)

# Cifra
encrypt_file_chacha20('/tmp/test.txt', '/tmp/test.enc', key)
print("✅ File cifrato")

# Decifra
decrypt_file_chacha20('/tmp/test.enc', '/tmp/test_dec.txt', key)
print("✅ File decifrato")
```

### 2. Network Streaming

```python
import socket
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class SecureStreamSocket:
    """Socket con cifratura ChaCha20"""
    
    def __init__(self, sock, key):
        self.sock = sock
        self.cipher = ChaCha20Poly1305(key)
        self.send_counter = 0
        self.recv_counter = 0
    
    def send_secure(self, data):
        """Invia dati cifrati"""
        # Nonce = counter
        nonce = self.send_counter.to_bytes(12, 'big')
        
        # Cifra con AEAD
        encrypted = self.cipher.encrypt(nonce, data, b"")
        
        # Invia: length + encrypted
        length = len(encrypted).to_bytes(4, 'big')
        self.sock.sendall(length + encrypted)
        
        self.send_counter += 1
    
    def recv_secure(self):
        """Ricevi dati cifrati"""
        # Leggi length
        length_bytes = self.sock.recv(4)
        length = int.from_bytes(length_bytes, 'big')
        
        # Leggi encrypted data
        encrypted = b''
        while len(encrypted) < length:
            chunk = self.sock.recv(length - len(encrypted))
            encrypted += chunk
        
        # Decifra
        nonce = self.recv_counter.to_bytes(12, 'big')
        plaintext = self.cipher.decrypt(nonce, encrypted, b"")
        
        self.recv_counter += 1
        return plaintext

# Server
def server():
    key = ChaCha20Poly1305.generate_key()
    
    server_sock = socket.socket()
    server_sock.bind(('localhost', 9999))
    server_sock.listen(1)
    
    conn, addr = server_sock.accept()
    secure = SecureStreamSocket(conn, key)
    
    # Ricevi messaggio
    msg = secure.recv_secure()
    print(f"Server ricevuto: {msg}")
    
    # Rispondi
    secure.send_secure(b"Hello from server!")

# Client
def client(key):
    sock = socket.socket()
    sock.connect(('localhost', 9999))
    
    secure = SecureStreamSocket(sock, key)
    
    # Invia
    secure.send_secure(b"Hello from client!")
    
    # Ricevi
    response = secure.recv_secure()
    print(f"Client ricevuto: {response}")
```

---

## Best Practices

### ✅ Raccomandazioni

1. **Usa ChaCha20-Poly1305 o AES-GCM**: AEAD sempre!
2. **Nonce unico**: Mai riusare con stessa chiave
3. **Counter mode**: Per file grandi usa counter
4. **Key derivation**: Deriva chiavi da password con PBKDF2/Argon2
5. **Secure random**: `os.urandom()` o `secrets`

### ❌ Da Evitare

1. **RC4**: Vulnerabile, deprecato
2. **Nonce fisso**: Catastrofico!
3. **random.random()**: Non crittografico
4. **No MAC**: Sempre autentica!
5. **LFSR semplici**: Facilmente attaccabili

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 5 - Modi di Operazione](05_modi_di_operazione.md)
- **Successivo**: [Capitolo 7 - Introduzione Crittografia Asimmetrica](../03_Crittografia_Asimmetrica/07_introduzione_alla_crittografia_asimmetrica.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 7539: ChaCha20 and Poly1305
- Daniel Bernstein: "ChaCha, a variant of Salsa20"
- "Analysis of the Stream Cipher RC4" (Klein, 2008)

**Nota**: ChaCha20-Poly1305 è il futuro! Veloce, sicuro, moderno.
