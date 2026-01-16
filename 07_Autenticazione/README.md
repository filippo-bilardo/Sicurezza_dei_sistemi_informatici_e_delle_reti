# Parte 7 - Autenticazione e Controllo degli Accessi

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Autenticazione  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

Questa sezione copre i **principi fondamentali dell'autenticazione** nei sistemi informatici, dalle tecniche tradizionali (password) alle moderne soluzioni (biometria, autenticazione multi-fattore, SSO).

L'autenticazione è il processo di verifica dell'identità di un utente o sistema. È la prima linea di difesa nella sicurezza informatica e un componente critico di qualsiasi architettura di sicurezza.

---

## 📚 Indice dei Capitoli

### Fondamenti di Autenticazione

#### [01 - Introduzione all'Autenticazione](01_introduzione_autenticazione.md)
- Cos'è l'autenticazione
- Differenza tra autenticazione, autorizzazione e accounting (AAA)
- I tre fattori di autenticazione
  - Qualcosa che conosci (knowledge)
  - Qualcosa che possiedi (possession)
  - Qualcosa che sei (inherence)
- Principi di sicurezza nell'autenticazione
- Threat model e attacchi comuni

#### [02 - Password e Gestione delle Credenziali](02_password_credenziali.md)
- Storia e evoluzione delle password
- Password strength e complessità
- Policy di sicurezza per password
- Attacchi alle password
  - Brute force
  - Dictionary attack
  - Rainbow tables
  - Credential stuffing
  - Password spraying
- Hashing delle password
  - MD5, SHA-1, SHA-256 (problemi)
  - bcrypt, scrypt, Argon2
  - Salt e pepper
- Password manager
- Best practices per utenti e sviluppatori

### Autenticazione Multi-Fattore (MFA)

#### [03 - Autenticazione Multi-Fattore (MFA)](03_autenticazione_multifattore.md)
- Principi della MFA/2FA
- Tipologie di secondo fattore
  - SMS e chiamate vocali
  - Email
  - Authenticator apps (TOTP)
  - Hardware tokens (FIDO2, YubiKey)
  - Biometria
- Time-based One-Time Password (TOTP)
  - Algoritmo TOTP/HOTP
  - Implementazione pratica
  - Google Authenticator, Authy
- FIDO2 e WebAuthn
- Backup codes e account recovery
- MFA fatigue attacks
- Best practices MFA

#### [04 - Biometria e Autenticazione Comportamentale](04_biometria_comportamentale.md)
- Introduzione alla biometria
- Tipi di biometria
  - Fingerprint (impronte digitali)
  - Face recognition (riconoscimento facciale)
  - Iris/retina scan
  - Voice recognition
  - DNA
- Accuratezza biometrica
  - False Acceptance Rate (FAR)
  - False Rejection Rate (FRR)
  - Equal Error Rate (EER)
- Attacchi alla biometria
  - Spoofing
  - Deepfake
  - Liveness detection
- Biometria comportamentale
  - Keystroke dynamics
  - Mouse movement patterns
  - Gait analysis
- Privacy e considerazioni legali (GDPR)
- Continuous authentication

### Protocolli e Standard

#### [05 - Protocolli di Autenticazione](05_protocolli_autenticazione.md)
- Kerberos
  - Architettura e componenti
  - Ticket Granting Service
  - Autenticazione Windows Active Directory
- LDAP e Active Directory
- RADIUS e TACACS+
- SAML (Security Assertion Markup Language)
- OAuth 2.0
  - Authorization code flow
  - Implicit flow
  - Client credentials
  - Resource owner password
- OpenID Connect (OIDC)
- JWT (JSON Web Tokens)
  - Struttura JWT
  - Firma e validazione
  - Vulnerabilità comuni
- Certificate-based authentication (PKI)

#### [06 - Single Sign-On (SSO)](06_single_sign_on.md)
- Concetti di SSO
- Vantaggi e rischi del SSO
- Tipologie di SSO
  - Enterprise SSO
  - Web SSO
  - Federated SSO
- Implementazioni SSO
  - SAML-based SSO
  - OAuth/OIDC SSO
  - CAS (Central Authentication Service)
- Identity Provider (IdP) vs Service Provider (SP)
- SSO in cloud: Azure AD, Okta, Auth0
- Session management
- Logout e session invalidation

### Autenticazione Passwordless

#### [07 - Autenticazione Passwordless](07_passwordless.md)
- Il problema delle password
- Tecnologie passwordless
  - Magic links (email)
  - Biometria integrata (Face ID, Touch ID)
  - FIDO2/WebAuthn
  - Passkeys (Apple, Google, Microsoft)
  - Hardware security keys
- Implementazione passwordless
- Zero-knowledge proofs
- Passwordless vs password-free
- Adoption challenges
- Future dell'autenticazione

### Autenticazione Avanzata

#### [08 - Risk-Based e Adaptive Authentication](08_risk_based_authentication.md)
- Autenticazione contestuale
- Risk scoring
- Fattori di rischio
  - Geolocation
  - Device fingerprinting
  - IP reputation
  - Behavioral analytics
  - Time-based patterns
- Step-up authentication
- Continuous authentication
- Machine learning per fraud detection
- User and Entity Behavior Analytics (UEBA)
- Zero Trust Architecture

#### [09 - Autenticazione in Ambienti Distribuiti](09_autenticazione_distribuita.md)
- Microservices authentication
- API authentication
  - API keys
  - OAuth 2.0 per API
  - JWT bearer tokens
- Service-to-service authentication
  - Mutual TLS (mTLS)
  - Service mesh (Istio, Linkerd)
- Container authentication (Docker, Kubernetes)
- Serverless authentication (AWS Lambda, Azure Functions)
- Cross-domain authentication
- Token refresh e rotation

### Implementazione e Sicurezza

#### [10 - Implementare Autenticazione Sicura](10_implementazione_sicura.md)
- Secure session management
  - Session ID generation
  - Session storage (server-side vs client-side)
  - Session timeout
  - Session fixation prevention
- Cookie security
  - Secure flag
  - HttpOnly flag
  - SameSite attribute
- CSRF protection
- Rate limiting e account lockout
- Captcha e bot detection
- Account enumeration prevention
- Timing attacks prevention
- Secure password reset flow
- Email verification
- Testing authentication systems

#### [11 - Attacchi all'Autenticazione e Difese](11_attacchi_difese.md)
- Phishing e social engineering
- Man-in-the-Middle (MitM)
- Session hijacking
- Session fixation
- Replay attacks
- Pass-the-hash (PtH)
- Pass-the-ticket (PtT)
- Golden ticket attack
- Silver ticket attack
- Kerberoasting
- Credential stuffing a scala
- Account takeover (ATO)
- SIM swapping
- OAuth vulnerabilities
  - Open redirect
  - CSRF in OAuth
  - Token leakage
- Difese e contromisure
- Incident response per compromissioni account

---

## 🛠️ Laboratori Pratici

### Lab 1: Implementazione Sistema di Login Sicuro
- Hashing password con bcrypt
- Salting e pepper
- Rate limiting
- CSRF protection

### Lab 2: Implementazione TOTP
- Generazione secret key
- QR code per Authenticator
- Validazione TOTP code
- Backup codes

### Lab 3: Integrazione OAuth 2.0
- Setup OAuth provider
- Authorization code flow
- Token validation
- Refresh token rotation

### Lab 4: WebAuthn Implementation
- Registrazione credenziale
- Autenticazione con security key
- Fallback mechanisms

### Lab 5: JWT Authentication API
- Generazione JWT
- Validazione firma
- Claims management
- Token refresh

### Lab 6: SSO con SAML
- Setup Identity Provider
- Service Provider integration
- Assertion validation

---

## 📊 Progetti

### Progetto 1: Sistema di Autenticazione Multi-Tenant
Implementare sistema completo con:
- Registrazione utenti
- Login con password + MFA
- Password recovery
- Session management
- Admin dashboard

### Progetto 2: Passwordless Authentication System
Creare sistema passwordless con:
- Magic links via email
- WebAuthn/FIDO2
- Biometric authentication (mobile)
- Fallback mechanisms

### Progetto 3: Enterprise SSO Platform
Sviluppare piattaforma SSO con:
- SAML/OIDC support
- Multiple IdP integration
- User provisioning (SCIM)
- Audit logging

---

## 🔍 Casi di Studio

### Caso 1: Breach Analisi - LinkedIn (2012)
- Weak password hashing (SHA-1 without salt)
- Lessons learned

### Caso 2: LastPass Security Model
- Zero-knowledge architecture
- Master password hashing
- Vault encryption

### Caso 3: Google Advanced Protection Program
- Hardware security keys
- Mandatory 2FA
- Enhanced safe browsing

### Caso 4: Apple Passkeys
- Implementation details
- Cross-platform syncing
- Security guarantees

---

## 📖 Risorse Aggiuntive

### Standard e Specifiche
- **NIST SP 800-63B**: Digital Identity Guidelines (Authentication and Lifecycle Management)
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **FIDO2 Specification**: https://fidoalliance.org/specifications/
- **RFC 6238**: TOTP Time-Based One-Time Password Algorithm
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)

### Tool e Librerie
- **Passport.js**: Authentication middleware per Node.js
- **Auth0**: Identity platform
- **Keycloak**: Open source IAM
- **FreeIPA**: Linux identity management
- **Duo Security**: MFA platform
- **YubiKey**: Hardware authentication

### Framework e Best Practices
- OWASP Top 10 - Broken Authentication
- CIS Controls - Identity and Access Management
- NIST Cybersecurity Framework
- Zero Trust principles

---

## 🎯 Obiettivi di Apprendimento

Al termine di questa parte, gli studenti sapranno:

✅ Comprendere i principi fondamentali dell'autenticazione  
✅ Implementare sistemi di autenticazione sicuri  
✅ Configurare autenticazione multi-fattore  
✅ Integrare OAuth 2.0 e OIDC  
✅ Implementare SSO in ambiente enterprise  
✅ Riconoscere e mitigare attacchi all'autenticazione  
✅ Applicare best practices per session management  
✅ Valutare e scegliere tecnologie di autenticazione appropriate  
✅ Implementare autenticazione passwordless  
✅ Configurare risk-based authentication  

---

## 📝 Nota per gli Studenti

L'autenticazione è uno dei pilastri fondamentali della sicurezza informatica. Un sistema di autenticazione debole può compromettere l'intera sicurezza di un'applicazione, indipendentemente da quanto sia sicuro il resto del sistema.

**Ricorda**: 
- Non reinventare la ruota: usa librerie e framework consolidati
- Abilita sempre MFA quando possibile
- Mai memorizzare password in chiaro
- Considera il user experience: la sicurezza non deve essere un ostacolo
- Stay updated: le tecnologie di autenticazione evolvono rapidamente

---

**🔗 Collegamenti**
- **Parte Precedente**: [06 - Crittografia](../06_Crittografia/README.md)
- **Parte Successiva**: [08 - Firewall e IDS/IPS](../08_Firewall_IDS_IPS/README.md)
- **Torna all'Indice Principale**: [Indice Corso](../../README.md) 