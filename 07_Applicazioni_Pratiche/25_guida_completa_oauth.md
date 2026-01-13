# Guida Completa a OAuth 2.0

## Indice
1. [Introduzione](#introduzione)
2. [Cos'è OAuth 2.0](#cosè-oauth-20)
3. [Perché OAuth?](#perché-oauth)
4. [Ruoli in OAuth 2.0](#ruoli-in-oauth-20)
5. [I Quattro Grant Types](#i-quattro-grant-types)
6. [Flusso Authorization Code](#flusso-authorization-code)
7. [Implementazione Pratica](#implementazione-pratica)
8. [Security Best Practices](#security-best-practices)
9. [OAuth vs OpenID Connect](#oauth-vs-openid-connect)

---

## 1. Introduzione a OAuth 2.0

### Cos'è OAuth?

**OAuth 2.0** (Open Authorization 2.0) è un protocollo di autorizzazione che permette a un'applicazione di accedere a risorse protette su un server in nome dell'utente, **senza condividere le credenziali** dell'utente stesso.

### Il Problema che OAuth Risolve

**Scenario senza OAuth:**
```
L'utente vuole che l'App A acceda ai suoi dati sul Servizio B
├─ L'utente fornisce la sua password all'App A
├─ L'App A memorizza la password (rischio di sicurezza!)
├─ L'App A ora può fare QUALSIASI COSA con l'account dell'utente
└─ L'utente deve cambiare la password per revocare l'accesso
```

**Con OAuth:**
```
L'utente vuole che l'App A acceda ai suoi dati sul Servizio B
├─ L'App A reindirizza l'utente al Servizio B
├─ L'utente effettua il login direttamente sul Servizio B (sicuro!)
├─ Il Servizio B chiede: "Consentire all'App A di accedere alle tue foto?"
├─ L'utente concede il permesso
└─ L'App A riceve un token di accesso LIMITATO (non la password!)
```

### Benefici di OAuth

1. **Sicurezza**: L'app non vede mai la password dell'utente
2. **Granularità**: Permessi specifici (es. "solo lettura foto")
3. **Revocabilità**: L'utente può revocare l'accesso in qualsiasi momento
4. **Scadenza**: I token hanno una durata limitata

---

## I 4 Ruoli in OAuth 2.0

```
┌─────────────────┐
│  Resource Owner │  (L'utente che possiede i dati)
└────────┬────────┘
         │ 1. "Voglio che App X acceda ai miei dati"
         │
         ▼
┌─────────────────┐        2. Redirect         ┌──────────────────┐
│     Client      │ ─────────────────────────► │ Authorization    │
│  (App di terze  │                            │     Server       │
│     parti)      │ ◄───────────────────────── │ (es. Google,     │
└────────┬────────┘   3. Authorization Code    │  GitHub, ecc.)   │
         │                                     └────────┬─────────┘
         │ 4. Code + Client Credentials                 │
         └─────────────────────────────────────────────►│
                                                        │
         ┌──────────────────────────────────────────────┘
         │ 5. Access Token
         ▼
┌─────────────────┐
│     Client      │
└────────┬────────┘
         │ 6. Access Token
         ▼
┌─────────────────┐
│    Resource     │  (L'API che contiene i dati)
│     Server      │
└─────────────────┘
```

### Descrizione dei Ruoli

1. **Resource Owner** (Proprietario della Risorsa)
   - L'utente finale che possiede i dati
   - Esempio: Tu che hai un account Google

2. **Client** (Applicazione)
   - L'app che vuole accedere ai dati
   - Esempio: Un'app di editing foto che vuole accedere a Google Photos

3. **Authorization Server** (Server di Autorizzazione)
   - Il servizio che autentica l'utente e emette token
   - Esempio: accounts.google.com

4. **Resource Server** (Server delle Risorse)
   - L'API che contiene i dati protetti
   - Esempio: photos.googleapis.com

---

## I 4 Flussi OAuth 2.0 (Grant Types)

### 1. Authorization Code Flow (Il più sicuro)

**Quando usarlo:** Applicazioni web server-side

```
┌──────┐                                         ┌───────────┐
│      │  1. Click "Login with Google"           │           │
│      │────────────────────────────────────────►│           │
│      │                                         │           │
│      │  2. Redirect to Authorization Server    │  Client   │
│ User │◄────────────────────────────────────────│    App    │
│      │                                         │           │
│      │  3. Login + Grant Permission            │           │
│      │──────────────┐                          │           │
│      │              │                          └─────┬─────┘
└──────┘              │                                │
                      ▼                                │
              ┌───────────────┐                        │
              │ Authorization │                        │
              │    Server     │                        │
              │  (Google)     │                        │
              └───────┬───────┘                        │
                      │                                │
                      │ 4. Authorization Code          │
                      └───────────────────────────────►│
                                                       │
                      ┌────────────────────────────────┘
                      │ 5. Code + Client ID + Secret
                      ▼
              ┌───────────────┐
              │ Authorization │
              │    Server     │
              └───────┬───────┘
                      │
                      │ 6. Access Token + Refresh Token
                      ▼
              ┌───────────────┐
              │    Client     │
              └───────┬───────┘
                      │ 7. Access Token
                      ▼
              ┌──────────────┐
              │   Resource   │
              │    Server    │
              │  (API dati)  │
              └──────────────┘
```

**Implementazione Completa:**

```python
from flask import Flask, request, redirect, session, jsonify
import requests
import secrets
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Configurazione OAuth (esempio con GitHub)
OAUTH_CONFIG = {
    'client_id': 'your_github_client_id',
    'client_secret': 'your_github_client_secret',
    'authorize_url': 'https://github.com/login/oauth/authorize',
    'token_url': 'https://github.com/login/oauth/access_token',
    'api_url': 'https://api.github.com/user',
    'redirect_uri': 'http://localhost:5000/callback',
    'scope': 'user:email'
}

@app.route('/')
def index():
    """Homepage"""
    if 'user' in session:
        return f"""
        <h1>Benvenuto {session['user']['name']}!</h1>
        <img src="{session['user']['avatar']}" width="100">
        <p>Email: {session['user']['email']}</p>
        <a href="/logout">Logout</a>
        """
    return '<a href="/login">Login with GitHub</a>'

@app.route('/login')
def login():
    """Step 1: Redirect user to authorization server"""
    # Generate and store state (CSRF protection)
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    params = {
        'client_id': OAUTH_CONFIG['client_id'],
        'redirect_uri': OAUTH_CONFIG['redirect_uri'],
        'scope': OAUTH_CONFIG['scope'],
        'state': state,
        'response_type': 'code'
    }
    
    auth_url = f"{OAUTH_CONFIG['authorize_url']}?" + \
               '&'.join([f"{k}={v}" for k, v in params.items()])
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Step 2: Handle callback from authorization server"""
    
    # Check for errors
    error = request.args.get('error')
    if error:
        return f"Error: {error}", 400
    
    # Verify state (CSRF protection)
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "Invalid state parameter", 400
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "No code provided", 400
    
    # Step 3: Exchange authorization code for access token
    token_data = {
        'client_id': OAUTH_CONFIG['client_id'],
        'client_secret': OAUTH_CONFIG['client_secret'],
        'code': code,
        'redirect_uri': OAUTH_CONFIG['redirect_uri'],
        'grant_type': 'authorization_code'
    }
    
    token_response = requests.post(
        OAUTH_CONFIG['token_url'],
        data=token_data,
        headers={'Accept': 'application/json'}
    )
    
    if token_response.status_code != 200:
        return f"Token exchange failed: {token_response.text}", 400
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    if not access_token:
        return "No access token received", 400
    
    # Step 4: Use access token to get user info
    user_response = requests.get(
        OAUTH_CONFIG['api_url'],
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
    )
    
    if user_response.status_code != 200:
        return f"Failed to get user info: {user_response.text}", 400
    
    user_data = user_response.json()
    
    # Store user info in session
    session['user'] = {
        'id': user_data['id'],
        'name': user_data['name'] or user_data['login'],
        'email': user_data['email'],
        'avatar': user_data['avatar_url']
    }
    session['access_token'] = access_token
    
    return redirect('/')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect('/')

@app.route('/api/repos')
def repos():
    """Example: Access user's repositories"""
    access_token = session.get('access_token')
    
    if not access_token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    response = requests.get(
        'https://api.github.com/user/repos',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
    )
    
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

---

### 2. Implicit Flow (Deprecato, non usare!)

**Quando era usato:** Single Page Applications (SPA)  
**Perché deprecato:** Il token viene esposto nell'URL, vulnerabile

```
┌──────┐                                        ┌───────────┐
│      │  1. Redirect to Auth Server            │           │
│ User │◄───────────────────────────────────────│  Client   │
│      │                                        │  (SPA)    │
│      │  2. Login + Consent                    └───────────┘
│      │──────────────┐
└──────┘              │
                      ▼
              ┌───────────────┐
              │ Authorization │
              │    Server     │
              └───────┬───────┘
                      │
                      │ 3. Access Token in URL Fragment
                      │    (NO authorization code!)
                      ▼
              ┌──────────────┐
              │    Client    │
              │  (JavaScript)│
              └──────────────┘
```

**⚠️ NON USARE! Usa invece Authorization Code Flow con PKCE**

---

### 3. Resource Owner Password Credentials (Legacy)

**Quando usarlo:** Solo per applicazioni altamente fidate (sconsigliato)

```
┌──────┐                               ┌───────────┐
│      │  1. Username + Password       │           │
│ User │──────────────────────────────►│  Client   │
└──────┘                               │   (App)   │
                                       └─────┬─────┘
                                             │
              ┌──────────────────────────────┘
              │ 2. Username + Password + Client Credentials
              ▼
      ┌───────────────┐
      │ Authorization │
      │    Server     │
      └───────┬───────┘
              │
              │ 3. Access Token
              ▼
      ┌──────────────┐
      │    Client    │
      └──────────────┘
```

**Implementazione (solo per legacy systems):**

```python
@app.route('/token', methods=['POST'])
def token():
    """Direct username/password exchange"""
    username = request.form.get('username')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    # Verify credentials
    if not verify_user(username, password):
        return jsonify({'error': 'invalid_grant'}), 401
    
    if not verify_client(client_id, client_secret):
        return jsonify({'error': 'invalid_client'}), 401
    
    # Generate token
    access_token = generate_token(username, client_id)
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600
    })
```

---

### 4. Client Credentials Flow

**Quando usarlo:** Comunicazione server-to-server (nessun utente coinvolto)

```
┌──────────────┐
│    Client    │  1. Client ID + Client Secret
│   (Server)   │─────────────────────────────────┐
└──────────────┘                                 │
                                                 ▼
                                         ┌───────────────┐
                                         │ Authorization │
                                         │    Server     │
                                         └───────┬───────┘
                                                 │
┌──────────────┐                                 │
│    Client    │  2. Access Token                │
│   (Server)   │◄────────────────────────────────┘
└──────┬───────┘
       │ 3. Access Token
       ▼
┌──────────────┐
│   Resource   │
│    Server    │
│    (API)     │
└──────────────┘
```

**Implementazione:**

```python
import requests
from requests.auth import HTTPBasicAuth

# Client credentials
CLIENT_ID = 'your_client_id'
CLIENT_SECRET = 'your_client_secret'
TOKEN_URL = 'https://oauth.provider.com/token'

def get_client_token():
    """Get access token using client credentials"""
    response = requests.post(
        TOKEN_URL,
        data={
            'grant_type': 'client_credentials',
            'scope': 'api:read api:write'
        },
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    )
    
    token_data = response.json()
    return token_data['access_token']

def call_api():
    """Use token to call API"""
    token = get_client_token()
    
    response = requests.get(
        'https://api.provider.com/data',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    return response.json()

# Esempio con caching del token
class OAuthClient:
    def __init__(self, client_id, client_secret, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.token = None
        self.token_expires = 0
    
    def get_token(self):
        """Get valid token (refresh if expired)"""
        import time
        
        if self.token and time.time() < self.token_expires:
            return self.token
        
        # Request new token
        response = requests.post(
            self.token_url,
            data={'grant_type': 'client_credentials'},
            auth=HTTPBasicAuth(self.client_id, self.client_secret)
        )
        
        data = response.json()
        self.token = data['access_token']
        self.token_expires = time.time() + data.get('expires_in', 3600)
        
        return self.token
    
    def api_request(self, url, method='GET', **kwargs):
        """Make authenticated API request"""
        token = self.get_token()
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        kwargs['headers'] = headers
        
        return requests.request(method, url, **kwargs)

# Uso
client = OAuthClient(CLIENT_ID, CLIENT_SECRET, TOKEN_URL)
response = client.api_request('https://api.provider.com/data')
print(response.json())
```

---

## PKCE (Proof Key for Code Exchange)

### Perché PKCE?

PKCE risolve il problema dell'intercettazione del codice di autorizzazione in app native e SPA.

**Problema senza PKCE:**
```
Malicious App potrebbe intercettare il codice di autorizzazione
e usarlo per ottenere un access token
```

**Soluzione PKCE:**
```
1. App genera code_verifier (random string)
2. App calcola code_challenge = SHA256(code_verifier)
3. App invia code_challenge al server di autorizzazione
4. Server restituisce il codice
5. App invia code_verifier per scambiare il codice
6. Server verifica: SHA256(code_verifier) == code_challenge
```

### Implementazione PKCE

```python
import secrets
import hashlib
import base64
from flask import Flask, request, redirect, session
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def generate_code_verifier():
    """Generate code verifier (random string 43-128 chars)"""
    code_verifier = secrets.token_urlsafe(64)
    return code_verifier[:128]  # Max 128 chars

def generate_code_challenge(verifier):
    """Generate code challenge from verifier"""
    # SHA256 hash
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    # Base64 URL encode
    challenge = base64.urlsafe_b64encode(digest).decode('utf-8')
    # Remove padding
    challenge = challenge.rstrip('=')
    return challenge

@app.route('/login')
def login():
    """Start OAuth flow with PKCE"""
    # Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store verifier in session
    session['code_verifier'] = code_verifier
    
    # Generate state
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    auth_params = {
        'client_id': 'your_client_id',
        'redirect_uri': 'http://localhost:5000/callback',
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    auth_url = 'https://oauth.provider.com/authorize?' + \
               '&'.join([f"{k}={v}" for k, v in auth_params.items()])
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Handle OAuth callback with PKCE"""
    # Verify state
    if request.args.get('state') != session.get('oauth_state'):
        return "Invalid state", 400
    
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')
    
    # Exchange code for token (with code_verifier)
    token_data = {
        'client_id': 'your_client_id',
        'code': code,
        'redirect_uri': 'http://localhost:5000/callback',
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier  # PKCE parameter
    }
    
    response = requests.post(
        'https://oauth.provider.com/token',
        data=token_data
    )
    
    token_json = response.json()
    access_token = token_json['access_token']
    
    # Store token
    session['access_token'] = access_token
    
    return redirect('/')
```

---

## Refresh Tokens

### Perché i Refresh Token?

- **Access Token**: Vita breve (15 min - 1 ora), usato per le richieste API
- **Refresh Token**: Vita lunga (giorni/mesi), usato per ottenere nuovi access token

```
┌──────────────┐
│    Client    │  1. Access Token (expired)
└──────┬───────┘
       │
       │ 2. Refresh Token
       ▼
┌───────────────┐
│ Authorization │
│    Server     │
└───────┬───────┘
        │
        │ 3. New Access Token + New Refresh Token
        ▼
┌──────────────┐
│    Client    │
└──────────────┘
```

### Implementazione Refresh Token

```python
import requests
import time
from functools import wraps

class TokenManager:
    def __init__(self, client_id, client_secret, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0
    
    def set_tokens(self, access_token, refresh_token, expires_in):
        """Store tokens"""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = time.time() + expires_in
    
    def is_token_expired(self):
        """Check if token is expired (with 5 min buffer)"""
        return time.time() >= (self.expires_at - 300)
    
    def refresh_access_token(self):
        """Use refresh token to get new access token"""
        if not self.refresh_token:
            raise Exception("No refresh token available")
        
        response = requests.post(
            self.token_url,
            data={
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")
        
        data = response.json()
        self.set_tokens(
            data['access_token'],
            data.get('refresh_token', self.refresh_token),
            data.get('expires_in', 3600)
        )
        
        return self.access_token
    
    def get_valid_token(self):
        """Get valid access token (refresh if needed)"""
        if not self.access_token or self.is_token_expired():
            return self.refresh_access_token()
        return self.access_token

# Decorator per API calls con auto-refresh
def with_auto_refresh(token_manager):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get valid token
            token = token_manager.get_valid_token()
            
            # Make request
            response = func(token, *args, **kwargs)
            
            # If 401, try to refresh and retry once
            if response.status_code == 401:
                token = token_manager.refresh_access_token()
                response = func(token, *args, **kwargs)
            
            return response
        return wrapper
    return decorator

# Uso
token_manager = TokenManager(
    'client_id',
    'client_secret',
    'https://oauth.provider.com/token'
)

# Set initial tokens from login
token_manager.set_tokens(
    access_token='...',
    refresh_token='...',
    expires_in=3600
)

@with_auto_refresh(token_manager)
def get_user_data(token):
    """API call with automatic token refresh"""
    return requests.get(
        'https://api.provider.com/user',
        headers={'Authorization': f'Bearer {token}'}
    )

# Le richieste rinfrescano automaticamente il token se scaduto
response = get_user_data()
print(response.json())
```

---

## Sicurezza OAuth

### Best Practices

#### 1. **Usa sempre HTTPS**
```python
# ❌ SBAGLIATO
REDIRECT_URI = 'http://example.com/callback'

# ✅ CORRETTO
REDIRECT_URI = 'https://example.com/callback'
```

#### 2. **Valida sempre lo State Parameter (CSRF Protection)**
```python
@app.route('/login')
def login():
    # Generate cryptographic random state
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    # Include in authorization URL
    return redirect(f"{AUTH_URL}?state={state}&...")

@app.route('/callback')
def callback():
    # Verify state matches
    if request.args.get('state') != session.get('oauth_state'):
        return "CSRF detected", 403
```

#### 3. **Usa PKCE per SPA e Mobile Apps**
```python
# Sempre includere code_challenge e code_verifier
```

#### 4. **Non memorizzare token in localStorage**
```javascript
// ❌ SBAGLIATO (vulnerabile a XSS)
localStorage.setItem('access_token', token);

// ✅ CORRETTO (httpOnly cookie)
// Set dal server con flag httpOnly e secure
```

#### 5. **Valida Redirect URI**
```python
ALLOWED_REDIRECT_URIS = [
    'https://myapp.com/callback',
    'https://myapp.com/oauth/callback'
]

redirect_uri = request.args.get('redirect_uri')
if redirect_uri not in ALLOWED_REDIRECT_URIS:
    return "Invalid redirect_uri", 400
```

#### 6. **Scope Minimi Necessari**
```python
# ❌ SBAGLIATO (troppi permessi)
scope = 'user repo admin:org delete_repo'

# ✅ CORRETTO (solo necessari)
scope = 'user:email read:repo'
```

#### 7. **Token Rotation con Refresh**
```python
# Sempre rilasciare un NUOVO refresh token quando viene usato
# e invalidare quello vecchio
```

---

## Implementazione Server OAuth (Authorization Server)

### Server Completo con Flask

```python
from flask import Flask, request, jsonify, render_template_string, redirect
import secrets
import time
import jwt
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Database simulato
users_db = {
    'alice': {'password': 'password123', 'email': 'alice@example.com'}
}

clients_db = {
    'client_123': {
        'client_secret': 'secret_456',
        'redirect_uris': ['http://localhost:5000/callback'],
        'name': 'My App'
    }
}

# Storage temporaneo per authorization codes
auth_codes = {}
# Storage per access e refresh token
tokens = {}

JWT_SECRET = 'your-jwt-secret-key'
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRES = 3600  # 1 ora
REFRESH_TOKEN_EXPIRES = 2592000  # 30 giorni

def generate_auth_code():
    """Generate authorization code"""
    return secrets.token_urlsafe(32)

def generate_access_token(user_id, client_id, scope):
    """Generate JWT access token"""
    payload = {
        'user_id': user_id,
        'client_id': client_id,
        'scope': scope,
        'exp': time.time() + ACCESS_TOKEN_EXPIRES,
        'iat': time.time()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_refresh_token(user_id, client_id):
    """Generate refresh token"""
    token = secrets.token_urlsafe(32)
    tokens[token] = {
        'user_id': user_id,
        'client_id': client_id,
        'expires': time.time() + REFRESH_TOKEN_EXPIRES
    }
    return token

def verify_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """Authorization endpoint"""
    if request.method == 'GET':
        # Show consent screen
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope')
        state = request.args.get('state')
        
        # Validate client
        if client_id not in clients_db:
            return "Invalid client_id", 400
        
        client = clients_db[client_id]
        
        # Validate redirect_uri
        if redirect_uri not in client['redirect_uris']:
            return "Invalid redirect_uri", 400
        
        # Show consent form
        consent_form = f'''
        <h2>Authorization Request</h2>
        <p><strong>{client['name']}</strong> wants to access your account</p>
        <p>Requested permissions: {scope}</p>
        <form method="POST">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state}">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="action" value="allow">Allow</button>
            <button type="submit" name="action" value="deny">Deny</button>
        </form>
        '''
        return render_template_string(consent_form)
    
    else:  # POST
        action = request.form.get('action')
        
        if action == 'deny':
            redirect_uri = request.form.get('redirect_uri')
            state = request.form.get('state')
            return redirect(f"{redirect_uri}?error=access_denied&state={state}")
        
        # Verify credentials
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username not in users_db or users_db[username]['password'] != password:
            return "Invalid credentials", 401
        
        # Generate authorization code
        code = generate_auth_code()
        
        # Store authorization code
        auth_codes[code] = {
            'user_id': username,
            'client_id': request.form.get('client_id'),
            'redirect_uri': request.form.get('redirect_uri'),
            'scope': request.form.get('scope'),
            'expires': time.time() + 600  # 10 minutes
        }
        
        # Redirect back to client with code
        redirect_uri = request.form.get('redirect_uri')
        state = request.form.get('state')
        return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/token', methods=['POST'])
def token():
    """Token endpoint"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        # Exchange authorization code for token
        code = request.form.get('code')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        redirect_uri = request.form.get('redirect_uri')
        
        # Verify client credentials
        if client_id not in clients_db or \
           clients_db[client_id]['client_secret'] != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        # Verify authorization code
        if code not in auth_codes:
            return jsonify({'error': 'invalid_grant'}), 400
        
        code_data = auth_codes[code]
        
        # Check expiration
        if time.time() > code_data['expires']:
            del auth_codes[code]
            return jsonify({'error': 'expired_token'}), 400
        
        # Verify redirect_uri matches
        if redirect_uri != code_data['redirect_uri']:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Generate tokens
        access_token = generate_access_token(
            code_data['user_id'],
            client_id,
            code_data['scope']
        )
        refresh_token = generate_refresh_token(
            code_data['user_id'],
            client_id
        )
        
        # Delete used authorization code
        del auth_codes[code]
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_EXPIRES,
            'refresh_token': refresh_token,
            'scope': code_data['scope']
        })
    
    elif grant_type == 'refresh_token':
        # Refresh access token
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        # Verify client
        if client_id not in clients_db or \
           clients_db[client_id]['client_secret'] != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        # Verify refresh token
        if refresh_token not in tokens:
            return jsonify({'error': 'invalid_grant'}), 400
        
        token_data = tokens[refresh_token]
        
        # Check expiration
        if time.time() > token_data['expires']:
            del tokens[refresh_token]
            return jsonify({'error': 'expired_token'}), 400
        
        # Generate new access token
        access_token = generate_access_token(
            token_data['user_id'],
            client_id,
            'user:email'  # scope from original request
        )
        
        # Optionally rotate refresh token
        new_refresh_token = generate_refresh_token(
            token_data['user_id'],
            client_id
        )
        del tokens[refresh_token]  # Invalidate old refresh token
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_EXPIRES,
            'refresh_token': new_refresh_token
        })
    
    elif grant_type == 'client_credentials':
        # Client credentials flow
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        # Verify client
        if client_id not in clients_db or \
           clients_db[client_id]['client_secret'] != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        # Generate token (no user_id)
        access_token = generate_access_token(
            None,
            client_id,
            request.form.get('scope', '')
        )
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_EXPIRES
        })
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

# Protected resource server
def require_token(f):
    """Decorator to protect endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'missing_token'}), 401
        
        try:
            token_type, token = auth_header.split()
            if token_type != 'Bearer':
                return jsonify({'error': 'invalid_token_type'}), 401
        except ValueError:
            return jsonify({'error': 'invalid_authorization_header'}), 401
        
        # Verify token
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'invalid_token'}), 401
        
        return f(payload, *args, **kwargs)
    return decorated

@app.route('/api/user')
@require_token
def get_user(token_payload):
    """Protected endpoint - get user info"""
    user_id = token_payload['user_id']
    user = users_db.get(user_id)
    
    if not user:
        return jsonify({'error': 'user_not_found'}), 404
    
    return jsonify({
        'id': user_id,
        'email': user['email']
    })

if __name__ == '__main__':
    app.run(debug=True, port=8000)
```

---

## OpenID Connect (OIDC)

OpenID Connect è un layer di identità costruito sopra OAuth 2.0 che aggiunge l'autenticazione.

### Differenze OAuth vs OIDC

| Aspetto | OAuth 2.0 | OpenID Connect |
|---------|-----------|----------------|
| Scopo | **Autorizzazione** | **Autenticazione** + Autorizzazione |
| Use case | "App X vuole accedere ai tuoi file" | "Fai login con Google" |
| Cosa ricevi | Access Token | Access Token + **ID Token** |
| Informazioni utente | Tramite API | Nel **ID Token** (JWT) |

### ID Token (JWT)

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "your_client_id",
  "exp": 1672531200,
  "iat": 1672527600,
  "email": "user@example.com",
  "email_verified": true,
  "name": "Alice Smith",
  "picture": "https://example.com/avatar.jpg"
}
```

### Implementazione OIDC Client

```python
import requests
import jwt
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# OIDC Configuration (example: Google)
OIDC_CONFIG = {
    'client_id': 'your_google_client_id',
    'client_secret': 'your_google_client_secret',
    'discovery_url': 'https://accounts.google.com/.well-known/openid-configuration',
    'redirect_uri': 'http://localhost:5000/callback',
    'scope': 'openid profile email'
}

# Fetch OIDC configuration
def get_oidc_config():
    """Get OIDC endpoints from discovery document"""
    response = requests.get(OIDC_CONFIG['discovery_url'])
    return response.json()

@app.route('/login')
def login():
    """Start OIDC flow"""
    config = get_oidc_config()
    
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oidc_nonce'] = nonce
    
    auth_url = (
        f"{config['authorization_endpoint']}?"
        f"client_id={OIDC_CONFIG['client_id']}&"
        f"redirect_uri={OIDC_CONFIG['redirect_uri']}&"
        f"response_type=code&"
        f"scope={OIDC_CONFIG['scope']}&"
        f"state={state}&"
        f"nonce={nonce}"
    )
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """OIDC callback"""
    # Verify state
    if request.args.get('state') != session.get('oauth_state'):
        return "Invalid state", 400
    
    code = request.args.get('code')
    config = get_oidc_config()
    
    # Exchange code for tokens
    token_response = requests.post(
        config['token_endpoint'],
        data={
            'client_id': OIDC_CONFIG['client_id'],
            'client_secret': OIDC_CONFIG['client_secret'],
            'code': code,
            'redirect_uri': OIDC_CONFIG['redirect_uri'],
            'grant_type': 'authorization_code'
        }
    )
    
    tokens = token_response.json()
    id_token = tokens['id_token']
    access_token = tokens['access_token']
    
    # Verify and decode ID token
    # In production, verify signature with provider's public key
    id_payload = jwt.decode(
        id_token,
        options={"verify_signature": False}  # Insicuro! Solo per demo
    )
    
    # Verify nonce
    if id_payload['nonce'] != session.get('oidc_nonce'):
        return "Invalid nonce", 400
    
    # Store user info
    session['user'] = {
        'id': id_payload['sub'],
        'email': id_payload['email'],
        'name': id_payload['name'],
        'picture': id_payload.get('picture')
    }
    
    return redirect('/')
```

---

## Checklist di Sicurezza OAuth

### ✅ Authorization Server

- [ ] Usa HTTPS ovunque
- [ ] Valida redirect_uri contro whitelist
- [ ] Genera authorization code crittograficamente sicuri
- [ ] Authorization code validità MAX 10 minuti
- [ ] Authorization code monouso (elimina dopo uso)
- [ ] Access token con scadenza breve (< 1 ora)
- [ ] Refresh token con scadenza lunga ma revocabili
- [ ] Rate limiting su tutti gli endpoint
- [ ] Log di tutti i grant e revoke
- [ ] Supporta PKCE per client pubblici

### ✅ Client Application

- [ ] Usa HTTPS per redirect_uri
- [ ] Genera e valida state parameter (CSRF)
- [ ] Usa PKCE per SPA e mobile
- [ ] Non esporre client_secret in codice client-side
- [ ] Memorizza token in modo sicuro (httpOnly cookies server-side)
- [ ] Implementa token refresh automatico
- [ ] Richiedi solo scope necessari
- [ ] Gestisci scadenza e revoca token
- [ ] Implementa logout corretto (revoca token)

### ✅ Resource Server

- [ ] Valida sempre access token
- [ ] Verifica scope richiesti per ogni endpoint
- [ ] Implementa rate limiting per token
- [ ] Log accessi con token
- [ ] Gestisci token scaduti correttamente

---

## Risorse e Standard

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: PKCE (Proof Key for Code Exchange)
- **RFC 6750**: Bearer Token Usage
- **OpenID Connect Core**: https://openid.net/specs/openid-connect-core-1_0.html
- **OAuth 2.0 Security Best Practices**: https://tools.ietf.org/html/draft-ietf-oauth-security-topics

---

## Conclusione

OAuth 2.0 è uno standard complesso ma essenziale per la sicurezza moderna delle applicazioni web. Punti chiave:

1. **Usa Authorization Code Flow con PKCE** per la maggior parte delle applicazioni
2. **Client Credentials** solo per comunicazioni server-to-server
3. **NON usare** Implicit Flow o Password Credentials
4. **HTTPS obbligatorio** ovunque
5. **Valida sempre state** (CSRF protection)
6. **Token con scadenza breve** + refresh token
7. **Scope minimi** necessari
8. **OpenID Connect** per autenticazione utente