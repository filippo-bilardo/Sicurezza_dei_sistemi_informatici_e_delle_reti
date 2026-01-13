# Sicurezza_dei_sistemi_informatici_e_delle_reti

> **Corso**: Sistemi e Reti 3  
> **Autore**: Prof. Filippo Bilardo  
> **Anno Accademico**: 2025/2026

---

## 📚 Indice Generale

### **PARTE 0 - FONDAMENTI DI SICUREZZA INFORMATICA**

#### 0. Introduzione alla Sicurezza Informatica
   - 0.1 Concetti Base di Sicurezza
     - 0.1.1 Definizione di Sicurezza Informatica
     - 0.1.2 CIA Triad (Confidenzialità, Integrità, Disponibilità)
     - 0.1.3 Autenticazione e Autorizzazione
     - 0.1.4 Accountability e Non-Repudiation
   - 0.2 Panorama delle Minacce
     - 0.2.1 Attori delle Minacce (Threat Actors)
     - 0.2.2 Motivazioni degli Attaccanti
     - 0.2.3 Superfici di Attacco
     - 0.2.4 Vettori di Attacco
   - 0.3 Vulnerabilità e Exploit
     - 0.3.1 CVE (Common Vulnerabilities and Exposures)
     - 0.3.2 CWE (Common Weakness Enumeration)
     - 0.3.3 CVSS (Common Vulnerability Scoring System)
     - 0.3.4 Zero-Day Vulnerabilities
   - 0.4 Risk Management
     - 0.4.1 Identificazione dei Rischi
     - 0.4.2 Valutazione dei Rischi
     - 0.4.3 Mitigazione e Accettazione
     - 0.4.4 Monitoraggio Continuo

---

### **PARTE 1 - FONDAMENTI DI CRITTOGRAFIA**

#### 1. Introduzione alla Crittografia
   - 1.1 Cos'è la Crittografia
   - 1.2 Storia della Crittografia
     - 1.2.1 Cifrari Classici (Cesare, Vigenère)
     - 1.2.2 Enigma e la Seconda Guerra Mondiale
     - 1.2.3 Era Moderna e Computer
   - 1.3 Terminologia Fondamentale
     - 1.3.1 Testo in Chiaro (Plaintext)
     - 1.3.2 Testo Cifrato (Ciphertext)
     - 1.3.3 Cifratura e Decifratura
     - 1.3.4 Chiave Crittografica
   - 1.4 Obiettivi della Crittografia
     - 1.4.1 Confidenzialità
     - 1.4.2 Integrità
     - 1.4.3 Autenticazione
     - 1.4.4 Non Ripudio

#### 2. Principi di Sicurezza
   - 2.1 Il Principio di Kerckhoffs
   - 2.2 Sicurezza Computazionale
   - 2.3 Attacchi Crittografici
     - 2.3.1 Attacco Brute-Force
     - 2.3.2 Crittoanalisi
     - 2.3.3 Attacchi a Testo in Chiaro Noto
     - 2.3.4 Attacchi a Testo in Chiaro Scelto
   - 2.4 Entropia e Casualità
   - 2.5 Best Practices di Sicurezza

---

### **PARTE 2 - CRITTOGRAFIA SIMMETRICA**

#### 3. Introduzione alla Crittografia Simmetrica
   - 3.1 Concetti Base
   - 3.2 Vantaggi e Svantaggi
   - 3.3 Applicazioni Pratiche
   - 3.4 Gestione delle Chiavi

#### 4. Cifrari a Blocchi
   - 4.1 Principi di Funzionamento
   - 4.2 DES (Data Encryption Standard)
     - 4.2.1 Struttura di DES
     - 4.2.2 Funzione di Feistel
     - 4.2.3 Vulnerabilità di DES
   - 4.3 3DES (Triple DES)
   - 4.4 AES (Advanced Encryption Standard)
     - 4.4.1 Architettura di AES
     - 4.4.2 SubBytes, ShiftRows, MixColumns
     - 4.4.3 Key Expansion
     - 4.4.4 AES-128, AES-192, AES-256
   - 4.5 Altri Algoritmi
     - 4.5.1 Blowfish
     - 4.5.2 Twofish
     - 4.5.3 ChaCha20

#### 5. Modi di Operazione
   - 5.1 ECB (Electronic Codebook)
     - 5.1.1 Funzionamento
     - 5.1.2 Vulnerabilità
   - 5.2 CBC (Cipher Block Chaining)
     - 5.2.1 Vettore di Inizializzazione (IV)
     - 5.2.2 Padding
   - 5.3 CFB (Cipher Feedback)
   - 5.4 OFB (Output Feedback)
   - 5.5 CTR (Counter Mode)
   - 5.6 GCM (Galois/Counter Mode)
     - 5.6.1 AEAD (Authenticated Encryption)

#### 6. Cifrari a Flusso
   - 6.1 Principi di Funzionamento
   - 6.2 RC4
   - 6.3 Salsa20 e ChaCha20
   - 6.4 Confronto con Cifrari a Blocchi

---

### **PARTE 3 - CRITTOGRAFIA ASIMMETRICA**

#### 7. Introduzione alla Crittografia Asimmetrica
   - 7.1 Concetto di Chiave Pubblica e Privata
   - 7.2 Vantaggi e Svantaggi
   - 7.3 Applicazioni
   - 7.4 Confronto con Crittografia Simmetrica

#### 8. RSA (Rivest-Shamir-Adleman)
   - 8.1 Fondamenti Matematici
     - 8.1.1 Numeri Primi
     - 8.1.2 Aritmetica Modulare
     - 8.1.3 Funzione di Eulero
   - 8.2 Generazione delle Chiavi
   - 8.3 Processo di Cifratura
   - 8.4 Processo di Decifratura
   - 8.5 Firma Digitale con RSA
   - 8.6 Padding (OAEP, PSS)
   - 8.7 Dimensioni delle Chiavi (1024, 2048, 4096 bit)
   - 8.8 Vulnerabilità e Attacchi

#### 9. Diffie-Hellman
   - 9.1 Scambio di Chiavi
   - 9.2 Problema del Logaritmo Discreto
   - 9.3 Ephemeral Diffie-Hellman (DHE)
   - 9.4 Elliptic Curve Diffie-Hellman (ECDH)
   - 9.5 Attacco Man-in-the-Middle

#### 10. Crittografia su Curve Ellittiche (ECC)
   - 10.1 Introduzione alle Curve Ellittiche
   - 10.2 Vantaggi rispetto a RSA
   - 10.3 ECDSA (Elliptic Curve Digital Signature Algorithm)
   - 10.4 ECDH (Elliptic Curve Diffie-Hellman)
   - 10.5 Curve25519 ed Ed25519
   - 10.6 Applicazioni Moderne

#### 11. Altri Algoritmi Asimmetrici
   - 11.1 DSA (Digital Signature Algorithm)
   - 11.2 ElGamal
   - 11.3 Crittografia Post-Quantistica
     - 11.3.1 Minacce dei Computer Quantistici
     - 11.3.2 Lattice-Based Cryptography
     - 11.3.3 NIST PQC Competition

---

### **PARTE 4 - FUNZIONI HASH E INTEGRITÀ**

#### 12. Funzioni Hash Crittografiche
   - 12.1 Proprietà delle Funzioni Hash
     - 12.1.1 Determinismo
     - 12.1.2 Resistenza alle Collisioni
     - 12.1.3 Effetto Valanga
     - 12.1.4 One-Way Function
   - 12.2 MD5 (Message Digest 5)
     - 12.2.1 Funzionamento
     - 12.2.2 Vulnerabilità
   - 12.3 SHA (Secure Hash Algorithm)
     - 12.3.1 SHA-1
     - 12.3.2 SHA-2 (SHA-256, SHA-512)
     - 12.3.3 SHA-3
   - 12.4 BLAKE2 e BLAKE3
   - 12.5 Applicazioni
     - 12.5.1 Verifica Integrità File
     - 12.5.2 Password Hashing
     - 12.5.3 Blockchain

#### 13. HMAC (Hash-based Message Authentication Code)
   - 13.1 Principi di Funzionamento
   - 13.2 Costruzione di HMAC
   - 13.3 HMAC-SHA256
   - 13.4 Applicazioni
   - 13.5 Confronto con Firma Digitale

#### 14. Message Authentication Code (MAC)
   - 14.1 Autenticazione dei Messaggi
   - 14.2 CBC-MAC
   - 14.3 CMAC
   - 14.4 GMAC
   - 14.5 Poly1305

---

### **PARTE 5 - CERTIFICATI DIGITALI E PKI**

#### 15. Certificati Digitali
   - 15.1 Cos'è un Certificato Digitale
   - 15.2 Standard X.509
   - 15.3 Contenuto di un Certificato
     - 15.3.1 Subject
     - 15.3.2 Issuer
     - 15.3.3 Validity Period
     - 15.3.4 Public Key
     - 15.3.5 Extensions
   - 15.4 Catena di Certificazione
   - 15.5 Certificati Self-Signed
   - 15.6 Wildcard Certificates

#### 16. PKI (Public Key Infrastructure)
   - 16.1 Componenti della PKI
   - 16.2 Certificate Authority (CA)
     - 16.2.1 Root CA
     - 16.2.2 Intermediate CA
   - 16.3 Registration Authority (RA)
   - 16.4 Certificate Revocation
     - 16.4.1 CRL (Certificate Revocation List)
     - 16.4.2 OCSP (Online Certificate Status Protocol)
   - 16.5 Trust Models
   - 16.6 Let's Encrypt e ACME Protocol

#### 17. Gestione dei Certificati
   - 17.1 Generazione CSR (Certificate Signing Request)
   - 17.2 Installazione Certificati
   - 17.3 Conversione Formati (PEM, DER, PKCS#12)
   - 17.4 OpenSSL
     - 17.4.1 Comandi Base
     - 17.4.2 Generazione Chiavi
     - 17.4.3 Creazione Certificati
   - 17.5 KeyStore e TrustStore (Java)

---

### **PARTE 6 - PROTOCOLLI CRITTOGRAFICI**

#### 18. SSL/TLS (Secure Sockets Layer / Transport Layer Security)
   - 18.1 Storia di SSL/TLS
   - 18.2 Architettura del Protocollo
   - 18.3 Handshake TLS
     - 18.3.1 ClientHello
     - 18.3.2 ServerHello
     - 18.3.3 Certificate Exchange
     - 18.3.4 Key Exchange
     - 18.3.5 Finished Messages
   - 18.4 Cipher Suites
   - 18.5 Perfect Forward Secrecy (PFS)
   - 18.6 TLS 1.2 vs TLS 1.3
   - 18.7 SNI (Server Name Indication)
   - 18.8 ALPN (Application-Layer Protocol Negotiation)

#### 19. SSH (Secure Shell)
   - 19.1 Architettura SSH
   - 19.2 Autenticazione
     - 19.2.1 Password
     - 19.2.2 Public Key
     - 19.2.3 Host-Based
   - 19.3 Generazione Chiavi SSH
   - 19.4 SSH Agent
   - 19.5 Port Forwarding
     - 19.5.1 Local Port Forwarding
     - 19.5.2 Remote Port Forwarding
     - 19.5.3 Dynamic Port Forwarding
   - 19.6 SSH Tunneling
   - 19.7 SCP e SFTP
   - 19.8 Configurazione Avanzata

#### 20. IPsec (Internet Protocol Security)
   - 20.1 Architettura IPsec
   - 20.2 AH (Authentication Header)
   - 20.3 ESP (Encapsulating Security Payload)
   - 20.4 IKE (Internet Key Exchange)
   - 20.5 Transport Mode vs Tunnel Mode
   - 20.6 VPN con IPsec

#### 21. PGP/GPG (Pretty Good Privacy / GNU Privacy Guard)
   - 21.1 Storia e Filosofia
   - 21.2 Web of Trust
   - 21.3 Cifratura Email
   - 21.4 Firma Digitale
   - 21.5 Gestione Keyring
   - 21.6 GPG Command Line
   - 21.7 Integrazione con Email Clients

#### 22. Altri Protocolli
   - 22.1 S/MIME
   - 22.2 Kerberos
   - 22.3 WPA/WPA2/WPA3 (Wi-Fi)
   - 22.4 Signal Protocol
   - 22.5 HTTPS e HSTS

---

### **PARTE 7 - APPLICAZIONI PRATICHE**

#### 23. Password Security
   - 23.1 Password Hashing
     - 23.1.1 bcrypt
     - 23.1.2 scrypt
     - 23.1.3 Argon2
   - 23.2 Salt e Pepper
   - 23.3 Key Derivation Functions (KDF)
     - 23.3.1 PBKDF2
     - 23.3.2 HKDF
   - 23.4 Password Managers
   - 23.5 Multi-Factor Authentication (MFA)
     - 23.5.1 TOTP (Time-based OTP)
     - 23.5.2 HOTP (HMAC-based OTP)
     - 23.5.3 U2F/WebAuthn

#### 24. Crittografia nelle Applicazioni Web
   - 24.1 HTTPS Setup
   - 24.2 Cookie Security
     - 24.2.1 Secure Flag
     - 24.2.2 HttpOnly Flag
     - 24.2.3 SameSite Attribute
   - 24.3 JWT (JSON Web Tokens)
     - 24.3.1 Struttura JWT
     - 24.3.2 JWS (JSON Web Signature)
     - 24.3.3 JWE (JSON Web Encryption)
   - 24.4 OAuth 2.0 e OpenID Connect
   - 24.5 Content Security Policy (CSP)

#### 25. Crittografia nel Database
   - 25.1 Encryption at Rest
   - 25.2 Transparent Data Encryption (TDE)
   - 25.3 Field-Level Encryption
   - 25.4 Key Management
   - 25.5 Backup Encryption

#### 26. Crittografia nelle Comunicazioni
   - 26.1 Email Encryption
   - 26.2 Messaging Apps (Signal, WhatsApp)
   - 26.3 VoIP Security
   - 26.4 End-to-End Encryption (E2EE)
   - 26.5 Zero-Knowledge Encryption

#### 27. Blockchain e Criptovalute
   - 27.1 Principi della Blockchain
   - 27.2 Proof of Work
   - 27.3 Bitcoin e Crittografia
   - 27.4 Smart Contracts
   - 27.5 Wallet e Private Keys

---

### **PARTE 8 - IMPLEMENTAZIONE E TOOLS**

#### 28. Librerie Crittografiche
   - 28.1 OpenSSL
   - 28.2 LibreSSL
   - 28.3 BoringSSL
   - 28.4 Bouncy Castle
   - 28.5 Crypto++ (C++)
   - 28.6 PyCryptodome (Python)
   - 28.7 Node.js Crypto Module

#### 29. Best Practices di Implementazione
   - 29.1 Non Reinventare la Ruota
   - 29.2 Gestione Sicura delle Chiavi
   - 29.3 Generazione Numeri Casuali (CSPRNG)
   - 29.4 Constant-Time Operations
   - 29.5 Side-Channel Attacks
   - 29.6 Code Review e Audit

#### 30. Tools e Utilities
   - 30.1 OpenSSL Command Line
   - 30.2 GPG/GnuPG
   - 30.3 ssh-keygen
   - 30.4 certbot (Let's Encrypt)
   - 30.5 Wireshark (Analisi TLS)
   - 30.6 Hashcat (Password Cracking)
   - 30.7 John the Ripper
   - 30.8 CyberChef

---

### **PARTE 9 - MALWARE E MINACCE INFORMATICHE**

#### 31. Tipologie di Malware
   - 31.1 Virus Informatici
     - 31.1.1 Ciclo di Vita di un Virus
     - 31.1.2 Tecniche di Propagazione
     - 31.1.3 Payload e Trigger
   - 31.2 Worms (Vermi)
     - 31.2.1 Auto-Replicazione
     - 31.2.2 Network Worms
     - 31.2.3 Casi Storici (Morris Worm, Conficker)
   - 31.3 Trojan Horse
     - 31.3.1 Remote Access Trojans (RAT)
     - 31.3.2 Banking Trojans
     - 31.3.3 Backdoors
   - 31.4 Ransomware
     - 31.4.1 Crypto-Ransomware
     - 31.4.2 Locker Ransomware
     - 31.4.3 Casi Studio (WannaCry, NotPetya, REvil)
     - 31.4.4 Difese e Recovery
   - 31.5 Spyware e Adware
     - 31.5.1 Keyloggers
     - 31.5.2 Screen Scrapers
     - 31.5.3 Cookie Trackers
   - 31.6 Rootkit
     - 31.6.1 Kernel-Mode Rootkits
     - 31.6.2 User-Mode Rootkits
     - 31.6.3 Bootkit e Firmware Rootkits
     - 31.6.4 Rilevamento e Rimozione
   - 31.7 Botnet
     - 31.7.1 Architettura C&C (Command and Control)
     - 31.7.2 DDoS Attacks
     - 31.7.3 Spam e Phishing
     - 31.7.4 Crypto-Mining

#### 32. Attacchi Crittografici Avanzati
   - 31.1 Timing Attacks
   - 31.2 Padding Oracle Attack
   - 31.3 BEAST Attack
   - 31.4 CRIME e BREACH
   - 31.5 Heartbleed
   - 31.6 POODLE
   - 31.7 Sweet32
   - 31.8 ROBOT Attack

---

### **PARTE 10 - ATTACCHI E DIFESE DI RETE**

#### 33. Attacchi di Rete Comuni
   - 33.1 Phishing e Social Engineering
     - 33.1.1 Email Phishing
     - 33.1.2 Spear Phishing
     - 33.1.3 Whaling
     - 33.1.4 Vishing e Smishing
     - 33.1.5 Tecniche di Prevenzione
   - 33.2 Man-in-the-Middle (MITM)
     - 33.2.1 ARP Spoofing
     - 33.2.2 DNS Spoofing
     - 33.2.3 SSL Stripping
     - 33.2.4 Session Hijacking
   - 33.3 Denial of Service (DoS/DDoS)
     - 33.3.1 Network Flooding
     - 33.3.2 Application Layer Attacks
     - 33.3.3 Amplification Attacks
     - 33.3.4 Mitigazione DDoS
   - 33.4 SQL Injection
     - 33.4.1 Tipi di SQL Injection
     - 33.4.2 Blind SQL Injection
     - 33.4.3 Prepared Statements
     - 33.4.4 ORM e Difese
   - 33.5 Cross-Site Scripting (XSS)
     - 33.5.1 Stored XSS
     - 33.5.2 Reflected XSS
     - 33.5.3 DOM-Based XSS
     - 33.5.4 Content Security Policy
   - 33.6 Cross-Site Request Forgery (CSRF)
     - 33.6.1 CSRF Tokens
     - 33.6.2 SameSite Cookies
     - 33.6.3 Difese e Best Practices
   - 33.7 Password Attacks
     - 33.7.1 Dictionary Attacks
     - 33.7.2 Rainbow Tables
     - 33.7.3 Credential Stuffing
     - 33.7.4 Pass-the-Hash

#### 34. Side-Channel Attacks
   - 32.1 Power Analysis
   - 32.2 Electromagnetic Analysis
   - 32.3 Cache-Timing Attacks
   - 32.4 Spectre e Meltdown
   - 32.5 Mitigazioni

#### 36. Quantum Cryptography
   - 36.1 Minaccia dei Computer Quantistici
   - 36.2 Algoritmo di Shor
   - 36.3 Quantum Key Distribution (QKD)
   - 36.4 BB84 Protocol
   - 36.5 Crittografia Post-Quantistica

#### 37. Firewall e Protezione Perimetrale
   - 37.1 Tipologie di Firewall
     - 37.1.1 Packet Filtering Firewall
     - 37.1.2 Stateful Inspection Firewall
     - 37.1.3 Application Layer Firewall
     - 37.1.4 Next-Gen Firewall (NGFW)
   - 37.2 Configurazione Firewall
     - 37.2.1 Default Deny Policy
     - 37.2.2 DMZ (Demilitarized Zone)
     - 37.2.3 NAT e Port Forwarding
     - 37.2.4 Firewall Rules Best Practices
   - 37.3 IDS/IPS (Intrusion Detection/Prevention Systems)
     - 37.3.1 Network-Based IDS/IPS
     - 37.3.2 Host-Based IDS/IPS
     - 37.3.3 Signature vs Anomaly Detection
     - 37.3.4 Snort, Suricata, Zeek
   - 37.4 WAF (Web Application Firewall)
     - 37.4.1 OWASP Top 10 Protection
     - 37.4.2 ModSecurity
     - 37.4.3 Cloud WAF Solutions

#### 38. Hardware Security
   - 38.1 HSM (Hardware Security Module)
   - 38.2 TPM (Trusted Platform Module)
   - 38.3 Secure Enclave
   - 38.4 Smart Cards
   - 38.5 YubiKey e Security Keys

---

### **PARTE 10 - COMPLIANCE E STANDARD**

#### 39. Standard e Normative
   - 39.1 NIST Guidelines
   - 39.2 ISO/IEC 27001
   - 39.3 FIPS 140-2/140-3
   - 39.4 Common Criteria
   - 39.5 PCI DSS
   - 39.6 GDPR e Privacy
   - 39.7 OWASP (Open Web Application Security Project)
     - 39.7.1 OWASP Top 10
     - 39.7.2 OWASP ASVS
     - 39.7.3 OWASP Testing Guide

#### 40. Gestione delle Chiavi
   - 40.1 Key Lifecycle
     - 40.1.1 Generation
     - 40.1.2 Distribution
     - 40.1.3 Storage
     - 40.1.4 Rotation
     - 40.1.5 Destruction
   - 40.2 KMS (Key Management Service)
   - 40.3 AWS KMS
   - 40.4 Azure Key Vault
   - 40.5 Google Cloud KMS
   - 40.6 HashiCorp Vault

#### 41. Audit e Monitoring
   - 41.1 Crypto Audit
   - 41.2 Penetration Testing
     - 41.2.1 Metodologie (PTES, OWASP)
     - 41.2.2 Reconnaissance
     - 41.2.3 Exploitation
     - 41.2.4 Post-Exploitation
     - 41.2.5 Reporting
   - 41.3 Vulnerability Assessment
     - 41.3.1 Vulnerability Scanners
     - 41.3.2 Nessus, OpenVAS, Qualys
     - 41.3.3 Patch Management
   - 41.4 Logging Best Practices
   - 41.5 Incident Response
     - 41.5.1 Incident Response Plan
     - 41.5.2 Detection and Analysis
     - 41.5.3 Containment and Eradication
     - 41.5.4 Recovery and Lessons Learned
   - 41.6 Security Operations Center (SOC)
     - 41.6.1 SOC Roles e Responsabilità
     - 41.6.2 Threat Intelligence
     - 41.6.3 Security Orchestration (SOAR)

---

### **PARTE 12 - ESERCITAZIONI PRATICHE**

#### 42. Laboratorio: Crittografia Simmetrica
   - 42.1 Esercizio: Cifratura AES con OpenSSL
   - 42.2 Esercizio: Implementazione Cifrario di Cesare
   - 42.3 Esercizio: Test Modi di Operazione
   - 42.4 Esercizio: Confronto Prestazioni AES vs ChaCha20

#### 43. Laboratorio: Crittografia Asimmetrica
   - 43.1 Esercizio: Generazione Chiavi RSA
   - 43.2 Esercizio: Cifratura/Decifratura RSA
   - 43.3 Esercizio: Firma Digitale
   - 43.4 Esercizio: Diffie-Hellman Key Exchange
   - 43.5 Esercizio: Curve Ellittiche (Ed25519)

#### 44. Laboratorio: Funzioni Hash
   - 44.1 Esercizio: Calcolo Hash di File
   - 44.2 Esercizio: Verifica Integrità
   - 44.3 Esercizio: Implementazione HMAC
   - 40.4 Esercizio: Password Hashing con bcrypt
   - 40.5 Esercizio: Collisioni MD5

#### 41. Laboratorio: Certificati e TLS
   - 41.1 Esercizio: Creazione CA Privata
   - 41.2 Esercizio: Generazione Certificato SSL
   - 41.3 Esercizio: Setup HTTPS con Apache/Nginx
   - 41.4 Esercizio: Analisi Handshake TLS con Wireshark
   - 41.5 Esercizio: Let's Encrypt con Certbot

#### 45. Laboratorio: Certificati e TLS
   - 45.1 Esercizio: Creazione CA Privata
   - 45.2 Esercizio: Generazione Certificato SSL
   - 45.3 Esercizio: Setup HTTPS con Apache/Nginx
   - 45.4 Esercizio: Analisi Handshake TLS con Wireshark
   - 45.5 Esercizio: Let's Encrypt con Certbot

#### 46. Laboratorio: SSH Avanzato
   - 46.1 Esercizio: Autenticazione con Chiavi SSH
   - 46.2 Esercizio: SSH Port Forwarding
   - 46.3 Esercizio: SSH Tunneling
   - 46.4 Esercizio: SSH Bastion Host
   - 46.5 Esercizio: Hardening SSH Server

#### 47. Laboratorio: PGP/GPG
   - 43.1 Esercizio: Generazione Keypair GPG
   - 43.2 Esercizio: Cifratura Email
   - 43.3 Esercizio: Firma File
   - 43.4 Esercizio: Web of Trust
   - 43.5 Esercizio: Revoca Certificati

#### 44. Laboratorio: Applicazioni Web
   - 44.1 Esercizio: Implementazione JWT
   - 44.2 Esercizio: Password Hashing (bcrypt/Argon2)
   - 44.3 Esercizio: Setup TOTP (2FA)
   - 44.4 Esercizio: Cookie Security
   - 44.5 Esercizio: CSRF Protection

#### 45. Laboratorio: Attacchi e Difese
   - 45.1 Esercizio: Attacco Brute-Force
   - 45.2 Esercizio: Man-in-the-Middle
   - 45.3 Esercizio: SSL Strip
   - 45.4 Esercizio: Padding Oracle
   - 45.5 Esercizio: Timing Attack

---

### **PARTE 13 - PROGETTI E CASI DI STUDIO**

#### 51. Progetti Guidati
   - 51.1 Progetto: Chat Cifrata End-to-End
   - 51.2 Progetto: Sistema di Gestione Password
   - 51.3 Progetto: File Encryption Tool
   - 51.4 Progetto: Secure REST API
   - 51.5 Progetto: VPN Personale
   - 51.6 Progetto: Mini-Blockchain
   - 51.7 Progetto: Sistema di Rilevamento Intrusioni
   - 51.8 Progetto: Security Dashboard con SIEM

#### 52. Casi di Studio
   - 52.1 WhatsApp Encryption
   - 52.2 Bitcoin e Blockchain
   - 52.3 Signal Protocol
   - 52.4 TLS 1.3 Adoption
   - 52.5 Let's Encrypt Revolution
   - 52.6 WannaCry e Ransomware
   - 52.7 Target Data Breach (2013)
   - 52.8 Equifax Breach (2017)
   - 52.9 SolarWinds Supply Chain Attack (2020)
   - 52.10 Log4Shell Vulnerability (2021)

#### 53. Analisi di Vulnerabilità Storiche
   - 53.1 Heartbleed (2014)
   - 53.2 POODLE (2014)
   - 53.3 Logjam (2015)
   - 53.4 Cloudflare Leak (2017)
   - 53.5 Spectre/Meltdown (2018)
   - 53.6 BlueKeep (2019)
   - 53.7 Zerologon (2020)

---

### **APPENDICI**

#### Appendice A: Matematica per la Crittografia
   - A.1 Teoria dei Numeri
   - A.2 Aritmetica Modulare
   - A.3 Numeri Primi
   - A.4 Algoritmo di Euclide
   - A.5 Teorema di Fermat
   - A.6 Curve Ellittiche

#### Appendice B: Tabelle di Riferimento
   - B.1 Lunghezze Chiavi Raccomandate
   - B.2 Cipher Suites TLS
   - B.3 Hash Algorithm Comparison
   - B.4 Formati Certificati
   - B.5 Port Numbers

#### Appendice C: Comandi di Riferimento Rapido
   - C.1 OpenSSL Quick Reference
   - C.2 GPG Quick Reference
   - C.3 SSH Quick Reference
   - C.4 Git Cryptographic Signatures

#### Appendice D: Glossario
   - Termini Crittografici A-Z

#### Appendice E: Risorse e Bibliografia
   - E.1 Libri Consigliati
   - E.2 Corsi Online
   - E.3 Paper Accademici
   - E.4 Siti Web e Blog
   - E.5 Tools e Software
   - E.6 Community e Forum

#### Appendice F: Checklist di Sicurezza
   - F.1 Web Application Security
   - F.2 Server Configuration
   - F.3 Key Management
   - F.4 Code Review

---

## 📖 Come Utilizzare Questa Guida

### Per gli Studenti
- Seguire l'ordine dei capitoli per una comprensione progressiva
- Completare gli esercizi pratici di ogni sezione
- Sperimentare con i tools presentati
- Partecipare ai progetti guidati

### Per i Docenti
- Utilizzare come materiale di riferimento per le lezioni
- Assegnare esercizi specifici per ogni argomento
- Adattare il contenuto al livello della classe
- Integrare con esempi reali e casi di studio

### Prerequisiti Consigliati
- Conoscenza base di programmazione
- Familiarità con la riga di comando (Linux/Bash)
- Nozioni di networking
- Matematica di base (algebra)

### Livelli di Difficoltà
- ★☆☆ Base - Introduttivo
- ★★☆ Intermedio - Richiede pratica
- ★★★ Avanzato - Per utenti esperti

---

**Nota**: Questa è una guida in continua evoluzione. Contributi, correzioni e suggerimenti sono sempre benvenuti.

**Licenza**: Materiale didattico per uso educativo  
**Contatti**: filippo.bilardo@example.com  
**Ultimo aggiornamento**: Dicembre 2025