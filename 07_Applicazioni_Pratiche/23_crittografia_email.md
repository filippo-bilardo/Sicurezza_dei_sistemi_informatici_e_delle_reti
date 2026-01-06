# Capitolo 23 - Crittografia Email (PGP/GPG, S/MIME)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Problema Email

Email standard (SMTP) è **plaintext**:

```
From: alice@example.com
To: bob@example.com
Subject: Password database

La password è: SuperSecret123
```

❌ Chiunque nel percorso può leggere!

## Soluzioni

### 1. PGP/GPG

**Pretty Good Privacy** (commerciale)  
**GNU Privacy Guard** (open source)

### 2. S/MIME

**Secure/Multipurpose Internet Mail Extensions**

## PGP/GPG

### Installazione

```bash
# Linux
sudo apt install gnupg

# Verifica
gpg --version
```

### Genera Chiavi

```bash
# Genera coppia chiavi
gpg --full-generate-key

# Selezioni:
# - RSA (4096 bit) o EdDSA (Curve 25519)
# - Validità: 2y
# - Nome, email, passphrase

# Lista chiavi
gpg --list-keys

# Output:
# pub   ed25519 2024-01-01 [SC]
#       ABCD1234...
# uid   Alice <alice@example.com>
# sub   cv25519 2024-01-01 [E]
```

### Esporta Chiavi

```bash
# Esporta chiave pubblica
gpg --armor --export alice@example.com > alice_public.asc

# Esporta chiave privata (backup sicuro!)
gpg --armor --export-secret-keys alice@example.com > alice_private.asc
```

### Importa Chiave

```bash
# Importa chiave pubblica di Bob
gpg --import bob_public.asc

# Lista chiavi importate
gpg --list-keys
```

### Cifra Email

```bash
# Cifra messaggio per Bob
echo "Messaggio segreto" | gpg --encrypt --armor \
  --recipient bob@example.com > message.asc

# Bob decifra
gpg --decrypt message.asc
```

### Firma Digitale

```bash
# Firma messaggio
echo "Messaggio autentico" | gpg --clearsign > message_signed.asc

# Verifica firma
gpg --verify message_signed.asc
```

### Cifra + Firma

```bash
# Cifra per Bob e firma da Alice
echo "Top secret" | gpg --encrypt --sign \
  --armor \
  --recipient bob@example.com \
  --local-user alice@example.com > secure_message.asc
```

## GPG in Python

```python
import gnupg

def send_encrypted_email(recipient_email, message):
    """Cifra messaggio con GPG"""
    
    gpg = gnupg.GPG()
    
    # Cifra
    encrypted = gpg.encrypt(
        message,
        recipient_email,
        always_trust=True  # In produzione: verifica fingerprint!
    )
    
    if encrypted.ok:
        print(f"✅ Messaggio cifrato per {recipient_email}")
        return str(encrypted)
    else:
        print(f"❌ Errore: {encrypted.status}")
        return None

def verify_and_decrypt(encrypted_message):
    """Decifra e verifica firma"""
    
    gpg = gnupg.GPG()
    
    # Decifra
    decrypted = gpg.decrypt(encrypted_message)
    
    if decrypted.ok:
        print(f"✅ Decifrato")
        print(f"Firma da: {decrypted.username}")
        print(f"Fingerprint: {decrypted.fingerprint}")
        return str(decrypted)
    else:
        print(f"❌ Errore: {decrypted.status}")
        return None

# Uso
msg = "Dati riservati aziendali"
encrypted = send_encrypted_email("bob@example.com", msg)

# Bob decifra
# decrypted = verify_and_decrypt(encrypted)
```

## S/MIME

Usa certificati X.509 (come HTTPS).

### Ottenere Certificato

1. **CA commerciale**: Sectigo, DigiCert
2. **Gratuito**: Let's Encrypt (solo server)
3. **Self-signed**: Solo per test

### Genera Certificato Self-Signed

```bash
# 1. Chiave privata
openssl genrsa -out email_private.key 2048

# 2. CSR
openssl req -new -key email_private.key -out email.csr \
  -subj "/C=IT/O=Company/CN=alice@example.com/emailAddress=alice@example.com"

# 3. Certificato auto-firmato
openssl x509 -req -days 365 -in email.csr \
  -signkey email_private.key -out email_cert.crt

# 4. PKCS#12 (per email client)
openssl pkcs12 -export -out email.p12 \
  -inkey email_private.key -in email_cert.crt
```

### Cifra con S/MIME

```bash
# Cifra messaggio
openssl smime -encrypt -in message.txt -out encrypted.msg \
  -aes256 recipient_cert.crt

# Decifra
openssl smime -decrypt -in encrypted.msg \
  -inkey private.key -recip certificate.crt
```

### Firma con S/MIME

```bash
# Firma
openssl smime -sign -in message.txt -out signed.msg \
  -signer certificate.crt -inkey private.key

# Verifica firma
openssl smime -verify -in signed.msg \
  -CAfile ca_cert.crt
```

## S/MIME in Python

```python
from email.mime.text import MIMEText
from M2Crypto import BIO, SMIME

def smime_encrypt(message, recipient_cert_file):
    """Cifra email con S/MIME"""
    
    # Setup S/MIME
    s = SMIME.SMIME()
    
    # Carica certificato destinatario
    x509 = SMIME.X509.load_cert(recipient_cert_file)
    sk = SMIME.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)
    
    # Cipher
    s.set_cipher(SMIME.Cipher('aes_256_cbc'))
    
    # Cifra
    msg = MIMEText(message)
    p7 = s.encrypt(BIO.MemoryBuffer(msg.as_bytes()))
    
    # Output S/MIME
    out = BIO.MemoryBuffer()
    s.write(out, p7)
    
    return out.read()

def smime_sign(message, cert_file, key_file):
    """Firma email con S/MIME"""
    
    s = SMIME.SMIME()
    
    # Carica chiave + certificato
    s.load_key(key_file, cert_file)
    
    # Firma
    msg = MIMEText(message)
    p7 = s.sign(BIO.MemoryBuffer(msg.as_bytes()))
    
    # Output
    out = BIO.MemoryBuffer()
    s.write(out, p7, BIO.MemoryBuffer(msg.as_bytes()))
    
    return out.read()

# Uso
encrypted = smime_encrypt(
    "Messaggio confidenziale",
    "recipient_cert.crt"
)
```

## Confronto PGP vs S/MIME

| Caratteristica | PGP/GPG | S/MIME |
|----------------|---------|--------|
| **Modello** | Web of Trust | PKI/CA |
| **Costo** | ✅ Gratuito | 💰 Certificati a pagamento |
| **Integrazione** | Plugin necessari | ✅ Nativo email client |
| **Diffusione** | Tecnici, sviluppatori | ✅ Business, aziende |
| **Complessità** | ⚠️ Media | ✅ Semplice |
| **Standardizzazione** | ⚠️ Varia | ✅ Standard |

## Keyserver PGP

```bash
# Upload chiave pubblica
gpg --send-keys ABCD1234

# Cerca chiave
gpg --search-keys alice@example.com

# Importa da keyserver
gpg --recv-keys ABCD1234

# Keyservers popolari:
# - keys.openpgp.org
# - keyserver.ubuntu.com
# - pgp.mit.edu
```

## Web of Trust

```bash
# Firma chiave di Bob (dopo verifica identità!)
gpg --sign-key bob@example.com

# Livelli fiducia:
# 1 = Unknown
# 2 = Non fidato
# 3 = Marginal
# 4 = Full
# 5 = Ultimate (tue chiavi)

# Modifica fiducia
gpg --edit-key bob@example.com
> trust
> 4 (full)
> save
```

## Best Practices

### ✅ Sicurezza

1. **Passphrase forte** per chiave privata
2. **Backup chiave privata** (offline, cifrato)
3. **Scadenza chiavi**: 1-2 anni
4. **Subkeys**: Firma/Cifratura/Autenticazione separate
5. **Revoca**: Genera certificato revoca subito

```bash
# Genera certificato revoca
gpg --gen-revoke alice@example.com > revoke.asc

# Se chiave compromessa:
gpg --import revoke.asc
gpg --send-keys ABCD1234  # Pubblica revoca
```

### ❌ Evita

1. Email chiave privata
2. Chiavi senza passphrase
3. Trust automatico senza verifica
4. Chiavi troppo vecchie

## Thunderbird + GPG

```bash
# Installa Enigmail/OpenPGP
# Thunderbird 78+ ha GPG integrato

# Configurazione:
# 1. Crea o importa chiave
# 2. Account Settings → End-to-End Encryption
# 3. Add Key → Seleziona chiave personale

# Invia email cifrata:
# - Compose → Security → Encrypt
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 22 - VPN](22_vpn.md)
- **Successivo**: [Capitolo 24 - Blockchain](24_blockchain_e_crittografia.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- GnuPG: https://gnupg.org
- OpenPGP Standard: RFC 4880
- S/MIME: RFC 5751

**Raccomandazione**: S/MIME per business, PGP/GPG per tecnici e open source.
