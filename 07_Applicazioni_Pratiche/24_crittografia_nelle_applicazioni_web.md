# Capitolo 24 - Crittografia nelle Applicazioni Web

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Le **applicazioni web** gestiscono dati sensibili (credenziali, pagamenti, dati personali). La crittografia protegge:

1. **Trasporto**: HTTPS/TLS
2. **Storage**: Session, cookies, local storage
3. **Autenticazione**: JWT, OAuth2
4. **API**: Firmatura richieste

---

## HTTPS e TLS

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
    
    # Configurazione sicura
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    
    # Avvia server HTTPS
    app.run(host='0.0.0.0', port=443, ssl_context=context)
```

### Generazione Certificato Self-Signed

```bash
# Genera chiave privata RSA
openssl genrsa -out server.key 2048

# Genera certificato autofirmato
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=IT/ST=Lazio/L=Rome/O=MyCompany/CN=localhost"

# Per produzione: usa Let's Encrypt!
```

### Client HTTPS (Python)

```python
import requests

# Request HTTPS
response = requests.get('https://api.example.com/data')

# Verifica certificato
response = requests.get(
    'https://api.example.com/data',
    verify=True  # ✅ Sempre True in produzione!
)

# Certificate pinning (sicurezza extra)
import certifi
response = requests.get(
    'https://api.example.com/data',
    verify=certifi.where()
)

print(f"Status: {response.status_code}")
print(f"TLS Version: {response.raw.version}")
```

---

## Certificate Pinning

**Problema**: Attaccante con CA compromessa può falsificare certificati.

**Soluzione**: **Pin** (fissa) il certificato o la chiave pubblica del server.

```python
import hashlib
import ssl
import socket
from urllib.parse import urlparse

def get_cert_fingerprint(hostname, port=443):
    """Ottieni fingerprint certificato"""
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            
            # SHA-256 fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            return fingerprint

def verify_pinned_cert(hostname, expected_fingerprint):
    """Verifica certificate pinning"""
    actual = get_cert_fingerprint(hostname)
    
    if actual != expected_fingerprint:
        raise ValueError(f"Certificate mismatch! MITM attack?")
    
    return True

# Test
print("=== Certificate Pinning ===\n")

# Ottieni fingerprint
fp = get_cert_fingerprint("www.google.com")
print(f"Google cert fingerprint: {fp}")

# Verifica
try:
    verify_pinned_cert("www.google.com", fp)
    print("✅ Certificate valid!")
except ValueError as e:
    print(f"❌ {e}")
```

---

## HTTP Security Headers

### HSTS (HTTP Strict Transport Security)

Forza browser a usare HTTPS.

```python
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """Aggiungi header di sicurezza"""
    
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
    
    return response

@app.route('/')
def index():
    return "Secure headers enabled!"
```

### CSP (Content Security Policy)

Previene XSS specificando sorgenti consentite.

```python
# CSP Examples
CSP_POLICIES = {
    'strict': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'",
    
    'moderate': "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' https:",
    
    'with_cdn': "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://cdn.example.com"
}

# Applica policy
@app.route('/secure')
def secure_page():
    response = make_response("<h1>Secure Page</h1>")
    response.headers['Content-Security-Policy'] = CSP_POLICIES['strict']
    return response
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

### Struttura JWT

```
header.payload.signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
Signature: HMAC-SHA256(header+payload, secret)
```

### Implementazione JWT

```python
import jwt
import datetime

SECRET_KEY = "super-secret-key-change-in-production!"

def create_jwt(user_id, username):
    """Crea JWT token"""
    payload = {
        'sub': user_id,           # Subject (user ID)
        'username': username,
        'iat': datetime.datetime.utcnow(),  # Issued at
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Expiration
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def verify_jwt(token):
    """Verifica JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"

# Test
print("\n=== JWT Demo ===\n")

# Create token
token = create_jwt(user_id=123, username="alice")
print(f"Token: {token}\n")

# Verify
valid, payload = verify_jwt(token)
print(f"Valid: {valid}")
print(f"Payload: {payload}")

# Test expired token
old_payload = {
    'sub': 123,
    'exp': datetime.datetime.utcnow() - datetime.timedelta(hours=1)
}
expired_token = jwt.encode(old_payload, SECRET_KEY, algorithm='HS256')

valid, msg = verify_jwt(expired_token)
print(f"\n❌ Expired token: {msg}")
```

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

## Best Practices

### ✅ Security Checklist

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

### ❌ Vulnerabilità Comuni

```python
# ❌ VULNERABILITÀ

# 1. Eval di input utente
user_input = request.args.get('code')
eval(user_input)  # ❌ RCE!

# 2. SQL Injection
query = f"SELECT * FROM users WHERE id = {request.args.get('id')}"  # ❌

# 3. XSS
return f"<h1>Hello {request.args.get('name')}</h1>"  # ❌

# 4. Insecure deserialization
import pickle
data = pickle.loads(request.data)  # ❌ RCE!

# ✅ SOLUZIONI

# 1. No eval, use safe alternatives
# 2. Prepared statements / ORM
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# 3. Escape output / use templates
from markupsafe import escape
return f"<h1>Hello {escape(name)}</h1>"

# 4. Use JSON, not pickle
import json
data = json.loads(request.data)
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
