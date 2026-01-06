# Capitolo 26 - Crittografia nelle Comunicazioni

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Le **comunicazioni di rete** attraversano infrastrutture non fidate. La crittografia garantisce:

1. **Confidenzialità**: Nessuno intercetta dati
2. **Integrità**: Dati non modificati
3. **Autenticazione**: Identità verificate
4. **Non-ripudio**: Mittente non può negare

### Stack Crittografico

```
Application:  Signal, WhatsApp (E2EE)
    ↓
Transport:    TLS 1.3, SSH
    ↓
Network:      IPsec, WireGuard VPN
    ↓
Link:         WPA3 (WiFi), MACsec (Ethernet)
```

---

## TLS 1.3

**Transport Layer Security** protegge HTTP, Email, FTP, etc.

### Differenze TLS 1.2 → 1.3

| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| **Handshake** | 2 round-trips | 1 round-trip (0-RTT) |
| **Ciphers** | 37 cipher suites | 5 cipher suites |
| **RSA KeyEx** | ✅ Supported | ❌ Removed |
| **Forward Secrecy** | Optional (DHE) | ✅ Always (ECDHE) |
| **Encryption** | After handshake | ✅ Handshake encrypted |

### TLS 1.3 Handshake

```
Client                                Server
------                                ------
ClientHello
  + key_share (X25519)
  + signature_algorithms   ──────►
  
                           ◄──────  ServerHello
                                     + key_share
                                     {EncryptedExtensions}
                                     {Certificate}
                                     {CertificateVerify}
                                     {Finished}
[Derive keys]                        [Derive keys]

{Finished}               ──────►

[Application Data]       ◄─────►   [Application Data]

{} = Encrypted with handshake keys
[] = Encrypted with application keys
```

### TLS 1.3 Client (Python)

```python
import ssl
import socket

def tls13_client(hostname, port=443):
    """TLS 1.3 client"""
    # Crea contesto SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Force TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Carica certificati CA
    context.load_default_certs()
    
    # Ciphers TLS 1.3 (tutti con forward secrecy)
    context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256')
    
    # Connetti
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(f"=== TLS 1.3 Connection ===\n")
            print(f"TLS Version: {ssock.version()}")
            print(f"Cipher: {ssock.cipher()}")
            print(f"Compression: {ssock.compression()}")
            
            # Certificato server
            cert = ssock.getpeercert()
            print(f"\nServer Certificate:")
            print(f"  Subject: {dict(x[0] for x in cert['subject'])}")
            print(f"  Issuer: {dict(x[0] for x in cert['issuer'])}")
            print(f"  Valid: {cert['notBefore']} → {cert['notAfter']}")
            
            # HTTP request
            ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\nConnection: close\r\n\r\n")
            
            # Response
            response = ssock.recv(4096)
            print(f"\nResponse preview: {response[:100]}...")

# Test
tls13_client("www.cloudflare.com")
```

### TLS 1.3 Server (Python)

```python
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

def tls13_server(port=8443):
    """TLS 1.3 HTTPS server"""
    
    # HTTP handler
    httpd = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
    
    # TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')
    
    # Force TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Best ciphers
    context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
    
    # Wrap socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"✅ TLS 1.3 server listening on port {port}")
    httpd.serve_forever()

# Run: python server.py
# Test: curl -k https://localhost:8443
```

---

## SSH (Secure Shell)

### SSH Handshake

```
Client                          Server
------                          ------
1. TCP Connection       ──────►

2. Version Exchange     ◄─────►
   SSH-2.0-OpenSSH_8.2

3. Key Exchange Init    ◄─────►
   + algorithms
   + host key types

4. Diffie-Hellman       ◄─────►
   [ECDH or X25519]

5. Session Keys Derived

6. Authentication       ──────►
   + password / pubkey

7. Encrypted Channel    ◄─────►
```

### SSH Client (Python - Paramiko)

```python
import paramiko

def ssh_client(hostname, username, password=None, key_file=None):
    """SSH client"""
    client = paramiko.SSHClient()
    
    # Auto-add host keys (dev only!)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Connect
    if key_file:
        # Public key authentication
        client.connect(
            hostname,
            username=username,
            key_filename=key_file
        )
    else:
        # Password authentication
        client.connect(
            hostname,
            username=username,
            password=password
        )
    
    print(f"✅ Connected to {hostname}")
    
    # Execute command
    stdin, stdout, stderr = client.exec_command('uname -a')
    print(f"Output: {stdout.read().decode()}")
    
    # SFTP transfer
    sftp = client.open_sftp()
    sftp.put('local_file.txt', '/tmp/remote_file.txt')
    print("✅ File uploaded via SFTP")
    sftp.close()
    
    client.close()

# Test
ssh_client('example.com', 'user', password='pass')
```

### SSH Key Generation

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_ssh_keypair(output_prefix='id_ed25519'):
    """Genera SSH keypair (Ed25519)"""
    
    # Genera chiave privata Ed25519
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Salva privata (OpenSSH format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(output_prefix, 'wb') as f:
        f.write(private_pem)
    
    # Salva pubblica (OpenSSH format)
    public_key = private_key.public_key()
    public_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    with open(output_prefix + '.pub', 'wb') as f:
        f.write(public_ssh)
    
    print(f"✅ SSH keypair generated:")
    print(f"  Private: {output_prefix}")
    print(f"  Public: {output_prefix}.pub")
    
    return private_key, public_key

# Generate
generate_ssh_keypair()

# Uso:
# ssh-copy-id -i id_ed25519.pub user@server
# ssh -i id_ed25519 user@server
```

---

## VPN (Virtual Private Network)

### WireGuard

**WireGuard**: VPN moderno, veloce, sicuro.

**Features**:
- ✅ X25519 (ECDH)
- ✅ ChaCha20-Poly1305 (AEAD)
- ✅ BLAKE2s (hash)
- ✅ ~4K LOC (vs 100K+ OpenVPN)

#### Configurazione WireGuard

```bash
# Genera chiavi
wg genkey | tee privatekey | wg pubkey > publickey

# Server config: /etc/wireguard/wg0.conf
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32

# Client config
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = server.example.com:51820
AllowedIPs = 0.0.0.0/0  # Route all traffic
PersistentKeepalive = 25
```

#### WireGuard Python Client

```python
import subprocess
import os

class WireGuardManager:
    """WireGuard VPN manager"""
    
    def __init__(self, interface='wg0'):
        self.interface = interface
    
    def generate_keypair(self):
        """Genera keypair WireGuard"""
        # Private key
        result = subprocess.run(['wg', 'genkey'], capture_output=True)
        private_key = result.stdout.decode().strip()
        
        # Public key
        result = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key.encode(),
            capture_output=True
        )
        public_key = result.stdout.decode().strip()
        
        return private_key, public_key
    
    def create_config(self, private_key, server_pubkey, server_endpoint, address):
        """Crea file configurazione"""
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        
        config_path = f'/etc/wireguard/{self.interface}.conf'
        with open(config_path, 'w') as f:
            f.write(config)
        
        os.chmod(config_path, 0o600)
        
        return config_path
    
    def up(self):
        """Attiva VPN"""
        subprocess.run(['wg-quick', 'up', self.interface], check=True)
        print(f"✅ WireGuard {self.interface} UP")
    
    def down(self):
        """Disattiva VPN"""
        subprocess.run(['wg-quick', 'down', self.interface], check=True)
        print(f"✅ WireGuard {self.interface} DOWN")
    
    def status(self):
        """Status VPN"""
        result = subprocess.run(['wg', 'show', self.interface], capture_output=True)
        print(result.stdout.decode())

# Usage
wg = WireGuardManager()
priv, pub = wg.generate_keypair()
print(f"Public key: {pub}")
```

### IPsec VPN

**IPsec**: Standard VPN enterprise.

```python
# strongSwan IPsec config example

# /etc/ipsec.conf
"""
config setup
    charondebug="all"
    uniqueids=yes

conn myvpn
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=secret
    left=%any
    leftid=@client
    right=server.example.com
    rightid=@server
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    dpdaction=restart
"""

# /etc/ipsec.secrets
"""
@client @server : PSK "SuperSecretPreSharedKey123!"
"""
```

---

## Signal Protocol (End-to-End Encryption)

### Architettura Signal

```
Alice                                     Bob
-----                                     ---
Identity Key (long-term)                  Identity Key
Signed PreKey (medium-term)               Signed PreKey  
One-Time PreKeys (single-use)             One-Time PreKeys

1. Fetch Bob's keys from server  ───────►

2. X3DH (Extended Triple DH)
   - DH(IK_A, SPK_B)
   - DH(EK_A, IK_B)
   - DH(EK_A, SPK_B)
   - DH(EK_A, OPK_B)
   
3. Derive root key + chain keys

4. Double Ratchet per ogni messaggio
   - DH ratchet (perfect forward secrecy)
   - Symmetric key ratchet (KDF chains)
```

### Signal-like Implementation

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class SignalSession:
    """Simplified Signal Protocol"""
    
    def __init__(self):
        # Identity key (long-term)
        self.identity_key = x25519.X25519PrivateKey.generate()
        
        # Ratchet keys
        self.dh_ratchet_key = x25519.X25519PrivateKey.generate()
        
        # Symmetric state
        self.root_key = None
        self.send_chain_key = None
        self.recv_chain_key = None
        
        self.message_counter = 0
    
    def get_public_keys(self):
        """Ottieni chiavi pubbliche"""
        return {
            'identity': self.identity_key.public_key(),
            'ratchet': self.dh_ratchet_key.public_key()
        }
    
    def initialize_session(self, peer_identity_pub, peer_ratchet_pub):
        """X3DH key agreement"""
        # DH1: identity x peer_ratchet
        dh1 = self.identity_key.exchange(peer_ratchet_pub)
        
        # DH2: ratchet x peer_identity
        dh2 = self.dh_ratchet_key.exchange(peer_identity_pub)
        
        # DH3: ratchet x peer_ratchet
        dh3 = self.dh_ratchet_key.exchange(peer_ratchet_pub)
        
        # Derive root key
        shared_secret = dh1 + dh2 + dh3
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 3 keys x 32 byte
            salt=None,
            info=b"Signal_v1"
        )
        
        key_material = kdf.derive(shared_secret)
        
        self.root_key = key_material[:32]
        self.send_chain_key = key_material[32:64]
        self.recv_chain_key = key_material[64:96]
        
        print("✅ Session initialized (X3DH complete)")
    
    def ratchet_chain_key(self, chain_key):
        """KDF ratchet for chain key"""
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"chain_ratchet"
        )
        
        output = kdf.derive(chain_key)
        
        new_chain_key = output[:32]
        message_key = output[32:64]
        
        return new_chain_key, message_key
    
    def encrypt_message(self, plaintext):
        """Cifra messaggio con ratcheting"""
        # Ratchet chain key
        self.send_chain_key, message_key = self.ratchet_chain_key(self.send_chain_key)
        
        # Encrypt con message key
        cipher = ChaCha20Poly1305(message_key)
        nonce = os.urandom(12)
        
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), b"")
        
        self.message_counter += 1
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'counter': self.message_counter
        }
    
    def decrypt_message(self, encrypted_msg):
        """Decifra messaggio"""
        # Ratchet chain key
        self.recv_chain_key, message_key = self.ratchet_chain_key(self.recv_chain_key)
        
        # Decrypt
        cipher = ChaCha20Poly1305(message_key)
        plaintext = cipher.decrypt(
            encrypted_msg['nonce'],
            encrypted_msg['ciphertext'],
            b""
        )
        
        return plaintext.decode()

# Test
print("\n=== Signal Protocol Demo ===\n")

# Alice e Bob
alice = SignalSession()
bob = SignalSession()

# Scambio chiavi pubbliche
alice_keys = alice.get_public_keys()
bob_keys = bob.get_public_keys()

# Initialize sessions (X3DH)
alice.initialize_session(bob_keys['identity'], bob_keys['ratchet'])
bob.initialize_session(alice_keys['identity'], alice_keys['ratchet'])

# Alice → Bob
msg1 = alice.encrypt_message("Hello Bob!")
decrypted1 = bob.decrypt_message(msg1)
print(f"Bob riceve: {decrypted1}")

# Bob → Alice
msg2 = bob.encrypt_message("Hi Alice!")
decrypted2 = alice.decrypt_message(msg2)
print(f"Alice riceve: {decrypted2}")

# Multiple messages (ratcheting)
for i in range(3):
    msg = alice.encrypt_message(f"Message {i+1}")
    dec = bob.decrypt_message(msg)
    print(f"Bob riceve: {dec}")

print("\n✅ Perfect Forward Secrecy: ogni messaggio ha chiave diversa!")
```

---

## mTLS (Mutual TLS)

**Mutual TLS**: Client e server si autenticano con certificati.

```python
import ssl
import socket

def mtls_server(port=8443):
    """mTLS server (richiede client cert)"""
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('server.crt', 'server.key')
    
    # Richiedi certificato client
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('ca.crt')  # CA che ha firmato client cert
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('', port))
        sock.listen(5)
        
        with context.wrap_socket(sock, server_side=True) as ssock:
            print(f"✅ mTLS server listening on port {port}")
            
            conn, addr = ssock.accept()
            
            # Verifica client cert
            client_cert = conn.getpeercert()
            client_cn = dict(x[0] for x in client_cert['subject'])['commonName']
            
            print(f"✅ Client authenticated: {client_cn}")

def mtls_client(hostname, port=8443):
    """mTLS client (presenta certificato)"""
    
    context = ssl.create_default_context()
    context.load_cert_chain('client.crt', 'client.key')
    context.load_verify_locations('ca.crt')
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(f"✅ mTLS connection established")
            
            # Verifica server cert
            server_cert = ssock.getpeercert()
            print(f"Server: {dict(x[0] for x in server_cert['subject'])}")
```

---

## Best Practices

### ✅ Comunicazioni Sicure

| Scenario | Protocollo | Config |
|----------|-----------|--------|
| **Web** | TLS 1.3 | HTTPS, HSTS |
| **Email** | STARTTLS | SMTP/IMAP over TLS |
| **File Transfer** | SFTP/FTPS | SSH/TLS |
| **Remote Shell** | SSH | Ed25519 keys |
| **VPN** | WireGuard | X25519 + ChaCha20 |
| **Messaging** | Signal Protocol | E2EE, PFS |
| **API** | mTLS | Mutual authentication |

### ❌ Da Evitare

```
❌ HTTP (no encryption)
❌ FTP (plaintext)
❌ Telnet (plaintext)
❌ TLS 1.0/1.1 (deprecated)
❌ RSA key exchange (no PFS)
❌ Weak ciphers (RC4, 3DES)
❌ Self-signed certs in prod
```

### Cipher Suite Recommendations

```python
# TLS 1.3 (auto-secured, tutti con PFS)
TLS_CIPHERS_1_3 = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256'
]

# TLS 1.2 (legacy support)
TLS_CIPHERS_1_2 = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-GCM-SHA256'
]

# ❌ Weak ciphers (NEVER use)
WEAK_CIPHERS = [
    'NULL', 'EXPORT', 'DES', '3DES', 'MD5',
    'RC4', 'PSK', 'SRP', 'anon', 'aNULL', 'eNULL'
]
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 25 - Crittografia nel Database](25_crittografia_nel_database.md)
- **Successivo**: [Capitolo 27 - Blockchain e Criptovalute](27_blockchain_e_criptovalute.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- RFC 8446: TLS 1.3
- WireGuard Whitepaper
- Signal Protocol Documentation
- NIST SP 800-52: TLS Guidelines
- OpenSSH Documentation

**Nota**: La crittografia delle comunicazioni è fondamentale! Usa SEMPRE protocolli moderni con Perfect Forward Secrecy.
