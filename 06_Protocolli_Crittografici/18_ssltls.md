# Capitolo 18 - SSL/TLS (Transport Layer Security)

> **Corso**: Sistemi e Reti 3  
> **Parte**: 6 - Protocolli Crittografici  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**TLS** (Transport Layer Security) è il protocollo per comunicazioni sicure su Internet.

### Storia

- **SSL 1.0** (1994): Mai rilasciato
- **SSL 2.0** (1995): ❌ Insicuro
- **SSL 3.0** (1996): ❌ Vulnerabile (POODLE)
- **TLS 1.0** (1999): ⚠️ Deprecato
- **TLS 1.1** (2006): ⚠️ Deprecato
- **TLS 1.2** (2008): ✅ Sicuro
- **TLS 1.3** (2018): ✅ Raccomandato

## Obiettivi

1. **Confidenzialità**: Cifratura dati
2. **Integrità**: Rilevamento modifiche
3. **Autenticazione**: Verifica identità server (opzionalmente client)

## Handshake TLS 1.2

```
Client                              Server
------                              ------
ClientHello
(versioni, cipher suites)     ─────>
                               
                              <───── ServerHello
                                     Certificate
                                     ServerHelloDone

ClientKeyExchange
ChangeCipherSpec              ─────>
Finished

                              <───── ChangeCipherSpec
                                     Finished

[Applicazione cifrata]        <───>  [Applicazione cifrata]
```

## Cipher Suite

Formato: `TLS_KEYEXCHANGE_CIPHER_MAC`

Esempio:
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
│    │     │        │       │   │
│    │     │        │       │   └─ Hash (SHA-384)
│    │     │        │       └───── Mode (GCM)
│    │     │        └──────────── Cipher (AES-256)
│    │     └───────────────────── Firma (RSA)
│    └─────────────────────────── Key Exchange (ECDHE)
└──────────────────────────────── Protocollo (TLS)
```

## Certificati X.509

```python
import ssl
import socket

def verifica_certificato(hostname, port=443):
    """Ottieni e verifica certificato"""
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            
            print(f"Subject: {cert['subject']}")
            print(f"Issuer: {cert['issuer']}")
            print(f"Version: {cert['version']}")
            print(f"Not Before: {cert['notBefore']}")
            print(f"Not After: {cert['notAfter']}")
            
            # Verifica hostname
            ssl.match_hostname(cert, hostname)
            print("✅ Certificato valido")

# Test
verifica_certificato("www.google.com")
```

## TLS in Python (Client)

```python
import ssl
import socket

def https_request(hostname, path="/"):
    """Richiesta HTTPS sicura"""
    # Context con verifica certificati
    context = ssl.create_default_context()
    
    # Connessione
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Richiesta HTTP
            request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            ssock.send(request.encode())
            
            # Risposta
            response = ssock.recv(4096)
            print(response.decode())

https_request("www.example.com")
```

## TLS Server in Python

```python
import ssl
import socket

def tls_server(certfile, keyfile, port=8443):
    """Server HTTPS semplice"""
    # Context SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    
    # Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        
        with context.wrap_socket(sock, server_side=True) as ssock:
            print(f"Server TLS in ascolto su porta {port}")
            
            while True:
                client, addr = ssock.accept()
                print(f"Connessione da {addr}")
                
                data = client.recv(1024)
                response = b"HTTP/1.1 200 OK\r\n\r\nHello TLS!\r\n"
                client.send(response)
                client.close()

# Genera certificato self-signed:
# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

## TLS 1.3 Miglioramenti

### Handshake più Veloce

```
Client                     Server
------                     ------
ClientHello
+ KeyShare              ─────>
                         
                        <───── ServerHello
                               {Certificate}
                               {Finished}

{Finished}              ─────>

[Application Data]      <───> [Application Data]
```

**1-RTT** invece di 2-RTT (TLS 1.2)

### Cipher Suites Semplificate

Solo 5 cipher suites sicure:
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_CCM_SHA256
TLS_AES_128_CCM_8_SHA256
```

### Perfect Forward Secrecy Obbligatorio

Solo ECDHE/DHE (no RSA statico)

## Vulnerabilità Storiche

| Attacco | Anno | Versione | Descrizione |
|---------|------|----------|-------------|
| **BEAST** | 2011 | TLS 1.0 | CBC IV predictable |
| **CRIME** | 2012 | TLS | Compressione |
| **POODLE** | 2014 | SSL 3.0 | Padding oracle |
| **Heartbleed** | 2014 | OpenSSL | Buffer overflow |
| **FREAK** | 2015 | TLS | Export ciphers |
| **Logjam** | 2015 | TLS | DH debole |
| **DROWN** | 2016 | SSL 2.0 | Cross-protocol |

## Best Practices

### ✅ Configurazione Sicura

```python
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

# 1. Solo TLS 1.2+
context.minimum_version = ssl.TLSVersion.TLSv1_2

# 2. Cipher suites moderne
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')

# 3. Verifica certificati
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

# 4. Carica CA certificates
context.load_default_certs()
```

### ❌ Configurazioni Insicure

```python
# MAI fare questo in produzione!
context = ssl._create_unverified_context()  # ❌
context.check_hostname = False              # ❌
context.verify_mode = ssl.CERT_NONE         # ❌
```

## Testing con OpenSSL

```bash
# Test connessione
openssl s_client -connect www.google.com:443

# Test TLS 1.3
openssl s_client -connect www.google.com:443 -tls1_3

# Verifica certificato
openssl s_client -connect www.example.com:443 -showcerts

# Test cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 17 - Protocolli di Autenticazione](17_protocolli_di_autenticazione.md)
- **Successivo**: [Capitolo 19 - SSH](19_ssh_secure_shell.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- OWASP TLS Cheat Sheet

**Raccomandazione**: Usa sempre TLS 1.2+ con cipher suites moderne (ECDHE + AESGCM).
