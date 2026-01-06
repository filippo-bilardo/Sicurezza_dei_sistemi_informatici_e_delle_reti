# Capitolo 15 - Certificati Digitali X.509

> **Corso**: Sistemi e Reti 3  
> **Parte**: 5 - Certificati e PKI  
> **Autore**: Prof. Filippo Bilardo

---

## Cos'è un Certificato Digitale?

Un **certificato digitale** è un documento elettronico che lega una chiave pubblica a un'identità.

### Contenuto

```
+---------------------------+
| Versione                  |
| Serial Number             |
| Algoritmo Firma           |
| Issuer (CA)              |
| Validity (date)          |
| Subject (owner)          |
| Public Key               |
| Extensions               |
| Signature (CA)           |
+---------------------------+
```

## Standard X.509

Formato standard per certificati, definito da ITU-T.

### Versioni

- **v1** (1988): Base
- **v2** (1993): Unique IDs
- **v3** (1996): ✅ **Usato oggi** (extensions)

## Gerarchia PKI

```
Root CA (auto-firmato, trust anchor)
   │
   ├── Intermediate CA 1
   │      ├── End-Entity Cert (www.example.com)
   │      └── End-Entity Cert (mail.example.com)
   │
   └── Intermediate CA 2
          └── End-Entity Cert (api.example.com)
```

## Generare Certificati

### 1. Chiave Privata

```bash
# RSA-2048
openssl genrsa -out private.key 2048

# ECC P-256
openssl ecparam -genkey -name prime256v1 -out private.key
```

### 2. Certificate Signing Request (CSR)

```bash
openssl req -new -key private.key -out request.csr \
  -subj "/C=IT/ST=Lazio/L=Roma/O=MyCompany/CN=www.example.com"
```

### 3. Certificato Auto-Firmato (test)

```bash
openssl req -x509 -new -nodes -key private.key \
  -sha256 -days 365 -out certificate.crt \
  -subj "/C=IT/O=Test/CN=localhost"
```

### 4. Firma da CA

```bash
# CA firma CSR
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out certificate.crt -days 365 -sha256
```

## Leggere Certificati in Python

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def read_certificate(cert_path):
    """Leggi e stampa info certificato"""
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    print("=== CERTIFICATO ===")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial: {cert.serial_number}")
    print(f"Not Before: {cert.not_valid_before}")
    print(f"Not After: {cert.not_valid_after}")
    print(f"Algorithm: {cert.signature_algorithm_oid._name}")
    
    # Extensions
    for ext in cert.extensions:
        print(f"Extension: {ext.oid._name}")

# Uso
# read_certificate("certificate.crt")
```

## Verifica Certificato

```python
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def verify_certificate(cert, ca_cert):
    """Verifica firma certificato con CA"""
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print("✅ Certificato valido")
        return True
    except:
        print("❌ Certificato non valido")
        return False
```

## Extensions Importanti

### 1. Subject Alternative Name (SAN)

Permette più domini:

```
CN=example.com
SAN: example.com, www.example.com, api.example.com
```

```python
from cryptography.x509.oid import ExtensionOID

# Leggi SAN
try:
    san = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    print(f"SAN: {san.value.get_values_for_type(x509.DNSName)}")
except:
    print("Nessun SAN")
```

### 2. Key Usage

Definisce uso chiave:

```
- Digital Signature
- Key Encipherment
- Certificate Sign
- CRL Sign
```

### 3. Extended Key Usage

```
- Server Authentication (TLS server)
- Client Authentication (TLS client)
- Code Signing
- Email Protection
```

## Chain of Trust

```python
import ssl
import socket

def get_cert_chain(hostname, port=443):
    """Ottieni chain certificati"""
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Binary certificate
            cert_bin = ssock.getpeercert(binary_form=True)
            
            # Parse
            cert = x509.load_der_x509_certificate(cert_bin)
            
            print(f"Subject: {cert.subject.rfc4514_string()}")
            print(f"Issuer: {cert.issuer.rfc4514_string()}")
            print(f"Valid: {cert.not_valid_before} - {cert.not_valid_after}")

# Test
get_cert_chain("www.google.com")
```

## Let's Encrypt

CA gratuita per certificati TLS:

```bash
# Installa certbot
sudo apt install certbot

# Ottieni certificato per dominio
sudo certbot certonly --standalone -d example.com

# Rinnovo automatico
sudo certbot renew --dry-run
```

## Revoca Certificati

### CRL (Certificate Revocation List)

```bash
# Download CRL
openssl x509 -in cert.crt -noout -text | grep "CRL Distribution"

# Verifica CRL
openssl crl -in revoked.crl -noout -text
```

### OCSP (Online Certificate Status Protocol)

```bash
# Estrai OCSP URL
openssl x509 -in cert.crt -noout -ocsp_uri

# Verifica OCSP
openssl ocsp -issuer ca.crt -cert cert.crt \
  -url http://ocsp.example.com -resp_text
```

## Formati Certificati

| Formato | Estensione | Encoding | Uso |
|---------|-----------|----------|-----|
| **PEM** | .pem, .crt, .cer | Base64 | Linux, web server |
| **DER** | .der, .cer | Binario | Windows, Java |
| **PKCS#12** | .p12, .pfx | Binario | Cert + chiave privata |
| **PKCS#7** | .p7b, .p7c | Base64/Binary | Chain senza chiave |

### Conversioni

```bash
# PEM → DER
openssl x509 -in cert.pem -outform DER -out cert.der

# PEM → PKCS#12 (cert + key)
openssl pkcs12 -export -out cert.p12 -inkey private.key -in cert.pem

# PKCS#12 → PEM
openssl pkcs12 -in cert.p12 -out cert.pem -nodes
```

## Esempio: Server HTTPS

```python
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 8443), SimpleHTTPRequestHandler)

# SSL Context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certificate.crt', 'private.key')

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Server HTTPS su https://localhost:8443")
httpd.serve_forever()
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 14 - MAC](../PARTE_04_Hash_Integrita/14_message_authentication_code_mac.md)
- **Successivo**: [Capitolo 16 - PKI](16_pki_public_key_infrastructure.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 5280: X.509 Certificate Profile
- Let's Encrypt: https://letsencrypt.org

**Nota**: Certificati auto-firmati solo per test. In produzione usa CA riconosciuta.
