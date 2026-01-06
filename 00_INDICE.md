# Indice Navigabile - Guida Completa alla Crittografia

> **Corso**: Sistemi e Reti 3  
> **Autore**: Prof. Filippo Bilardo  
> **Anno Accademico**: 2024/2025

---

## 📖 Come Navigare Questa Guida

Ogni capitolo è un file markdown separato organizzato in cartelle tematiche. Clicca sui link per aprire i capitoli specifici.

---

## 🛡️ PARTE 0 - FONDAMENTI DI SICUREZZA INFORMATICA

### [Capitolo 0 - Introduzione alla Sicurezza Informatica](PARTE_00_Fondamenti_Sicurezza/00_fondamenti_di_sicurezza_informatica.md)
- CIA Triad (Confidenzialità, Integrità, Disponibilità)
- Panorama delle minacce
- CVE, CWE, CVSS
- Risk Management

---

## 📚 PARTE 1 - FONDAMENTI DI CRITTOGRAFIA

### [Capitolo 1 - Introduzione alla Crittografia](PARTE_01_Fondamenti_Crittografia/01_introduzione_alla_crittografia.md)
- Storia della crittografia
- Cifrari classici (Cesare, Vigenère)
- Terminologia fondamentale
- Obiettivi: Confidenzialità, Integrità, Autenticazione, Non Ripudio

### [Capitolo 2 - Principi di Sicurezza](PARTE_01_Fondamenti_Crittografia/02_principi_di_sicurezza.md)
- Principio di Kerckhoffs
- Sicurezza computazionale
- Attacchi crittografici (Brute-force, KPA, CPA)
- Entropia e casualità

---

## 🔐 PARTE 2 - CRITTOGRAFIA SIMMETRICA

### [Capitolo 3 - Introduzione alla Crittografia Simmetrica](PARTE_02_Crittografia_Simmetrica/03_introduzione_crittografia_simmetrica.md)
- Concetti base
- Vantaggi e svantaggi
- Applicazioni pratiche
- Gestione delle chiavi

### [Capitolo 4 - Cifrari a Blocchi](PARTE_02_Crittografia_Simmetrica/04_cifrari_a_blocchi.md)
- DES e 3DES
- **AES** (Advanced Encryption Standard)
- Blowfish, Twofish, ChaCha20
- Operazioni: SubBytes, ShiftRows, MixColumns

### [Capitolo 5 - Modi di Operazione](PARTE_02_Crittografia_Simmetrica/05_modi_di_operazione.md)
- ECB, CBC, CFB, OFB, CTR
- GCM (Galois/Counter Mode)
- Vettori di inizializzazione (IV)
- Padding

### [Capitolo 6 - Cifrari a Flusso](PARTE_02_Crittografia_Simmetrica/06_cifrari_a_flusso.md)
- Principi di funzionamento
- RC4, Salsa20, ChaCha20
- Confronto con cifrari a blocchi

---

## 🔑 PARTE 3 - CRITTOGRAFIA ASIMMETRICA

### [Capitolo 7 - Introduzione alla Crittografia Asimmetrica](PARTE_03_Crittografia_Asimmetrica/07_introduzione_alla_crittografia_asimmetrica.md)
- Chiave pubblica e privata
- Vantaggi e svantaggi
- Confronto con crittografia simmetrica

### [Capitolo 8 - RSA (Rivest-Shamir-Adleman)](PARTE_03_Crittografia_Asimmetrica/08_rsa_rivest-shamir-adleman.md)
- Fondamenti matematici
- Generazione delle chiavi
- Cifratura e decifratura
- Firma digitale
- Padding (OAEP, PSS)

### [Capitolo 9 - Diffie-Hellman](PARTE_03_Crittografia_Asimmetrica/09_diffie-hellman.md)
- Scambio di chiavi
- Problema del logaritmo discreto
- ECDH (Elliptic Curve Diffie-Hellman)
- Attacco Man-in-the-Middle

### [Capitolo 10 - Crittografia su Curve Ellittiche (ECC)](PARTE_03_Crittografia_Asimmetrica/10_crittografia_su_curve_ellittiche_ecc.md)
- Introduzione alle curve ellittiche
- ECDSA, ECDH
- Curve25519 ed Ed25519
- Vantaggi rispetto a RSA

### [Capitolo 11 - Altri Algoritmi Asimmetrici](PARTE_03_Crittografia_Asimmetrica/11_altri_algoritmi_asimmetrici.md)
- DSA (Digital Signature Algorithm)
- ElGamal
- Crittografia post-quantistica

---

## 🔨 PARTE 4 - FUNZIONI HASH E INTEGRITÀ

### [Capitolo 12 - Funzioni Hash Crittografiche](PARTE_04_Hash_Integrita/12_funzioni_hash_crittografiche.md)
- Proprietà delle funzioni hash
- MD5, SHA-1, SHA-2, SHA-3
- BLAKE2 e BLAKE3
- Applicazioni (verifica integrità, blockchain)

### [Capitolo 13 - HMAC](PARTE_04_Hash_Integrita/13_hmac.md)
- Hash-based Message Authentication Code
- Costruzione di HMAC
- HMAC-SHA256
- Confronto con firma digitale

### [Capitolo 14 - Message Authentication Code (MAC)](PARTE_04_Hash_Integrita/14_message_authentication_code_mac.md)
- Autenticazione dei messaggi
- CBC-MAC, CMAC, GMAC
- Poly1305

---

## 📜 PARTE 5 - CERTIFICATI DIGITALI E PKI

### [Capitolo 15 - Certificati Digitali](PARTE_05_Certificati_PKI/15_certificati_digitali.md)
- Standard X.509
- Contenuto di un certificato
- Catena di certificazione
- Wildcard certificates

### [Capitolo 16 - PKI (Public Key Infrastructure)](PARTE_05_Certificati_PKI/16_pki_public_key_infrastructure.md)
- Certificate Authority (CA)
- Registration Authority (RA)
- CRL e OCSP
- Trust models

### [Capitolo 17 - Gestione dei Certificati](PARTE_05_Certificati_PKI/17_gestione_dei_certificati.md)
- Generazione CSR
- OpenSSL
- Conversione formati (PEM, DER, PKCS#12)
- Let's Encrypt

---

## 🌐 PARTE 6 - PROTOCOLLI CRITTOGRAFICI

### [Capitolo 18 - SSL/TLS](PARTE_06_Protocolli_Crittografici/18_ssltls.md)
- Storia di SSL/TLS
- Handshake TLS
- Cipher suites
- TLS 1.2 vs TLS 1.3
- Perfect Forward Secrecy

### [Capitolo 19 - SSH (Secure Shell)](PARTE_06_Protocolli_Crittografici/19_ssh_secure_shell.md)
- Architettura SSH
- Autenticazione (password, public key)
- SSH Agent
- Port forwarding e tunneling
- SCP e SFTP

### [Capitolo 20 - IPsec](PARTE_06_Protocolli_Crittografici/20_ipsec.md)
- Architettura IPsec
- AH (Authentication Header)
- ESP (Encapsulating Security Payload)
- Transport Mode vs Tunnel Mode
- VPN con IPsec

### [Capitolo 21 - PGP/GPG](PARTE_06_Protocolli_Crittografici/21_pgpgpg.md)
- Pretty Good Privacy
- Web of Trust
- Cifratura email
- Firma digitale
- GPG command line

### [Capitolo 22 - Altri Protocolli](PARTE_06_Protocolli_Crittografici/22_altri_protocolli.md)
- S/MIME
- Kerberos
- WPA/WPA2/WPA3
- Signal Protocol

---

## 💻 PARTE 7 - APPLICAZIONI PRATICHE

### [Capitolo 23 - Password Security](PARTE_07_Applicazioni_Pratiche/23_password_security.md)
- bcrypt, scrypt, Argon2
- Salt e Pepper
- Key Derivation Functions (PBKDF2, HKDF)
- MFA (TOTP, U2F, WebAuthn)

### [Capitolo 24 - Crittografia nelle Applicazioni Web](PARTE_07_Applicazioni_Pratiche/24_crittografia_nelle_applicazioni_web.md)
- HTTPS setup
- Cookie security
- JWT (JSON Web Tokens)
- OAuth 2.0 e OpenID Connect

### [Capitolo 25 - Crittografia nel Database](PARTE_07_Applicazioni_Pratiche/25_crittografia_nel_database.md)
- Encryption at rest
- Transparent Data Encryption (TDE)
- Field-level encryption
- Key management

### [Capitolo 26 - Crittografia nelle Comunicazioni](PARTE_07_Applicazioni_Pratiche/26_crittografia_nelle_comunicazioni.md)
- Email encryption
- Messaging apps (Signal, WhatsApp)
- End-to-end encryption (E2EE)
- Zero-knowledge encryption

### [Capitolo 27 - Blockchain e Criptovalute](PARTE_07_Applicazioni_Pratiche/27_blockchain_e_criptovalute.md)
- Principi della blockchain
- Proof of Work
- Bitcoin e crittografia
- Smart contracts

---

## 🛠️ PARTE 8 - IMPLEMENTAZIONE E TOOLS

### [Capitolo 28 - Librerie Crittografiche](PARTE_08_Implementazione_Tools/28_librerie_crittografiche.md)
- OpenSSL, LibreSSL, BoringSSL
- Bouncy Castle
- PyCryptodome (Python)
- Node.js Crypto Module

### [Capitolo 29 - Best Practices di Implementazione](PARTE_08_Implementazione_Tools/29_best_practices_di_implementazione.md)
- Non reinventare la ruota
- Gestione sicura delle chiavi
- CSPRNG
- Constant-time operations

### [Capitolo 30 - Tools e Utilities](PARTE_08_Implementazione_Tools/30_tools_e_utilities.md)
- OpenSSL command line
- GPG/GnuPG
- ssh-keygen
- Wireshark, Hashcat
- CyberChef

---

## � PARTE 9 - MALWARE E MINACCE INFORMATICHE

### [Capitolo 31 - Tipologie di Malware](PARTE_09_Malware_Minacce/31_tipologie_di_malware.md)
- Virus, Worms, Trojan
- Ransomware
- Rootkit e Botnet
- Advanced Persistent Threats (APT)

### [Capitolo 32 - Side-Channel Attacks](PARTE_09_Malware_Minacce/32_side-channel_attacks.md)
- Power analysis
- Cache-timing attacks
- Spectre e Meltdown
- Mitigazioni

---

## 🔧 PARTE 10 - ATTACCHI E DIFESE DI RETE

### [Capitolo 33 - Attacchi di Rete Comuni](PARTE_10_Attacchi_Difese_Rete/33_attacchi_di_rete_comuni.md)
- Phishing e Social Engineering
- Man-in-the-Middle (MITM)
- DoS e DDoS
- SQL Injection, XSS, CSRF

### [Capitolo 34 - Quantum Cryptography](PARTE_10_Attacchi_Difese_Rete/34_quantum_cryptography.md)
- Minaccia dei computer quantistici
- Algoritmo di Shor
- Quantum Key Distribution (QKD)
- Crittografia post-quantistica

### [Capitolo 35 - Sicurezza dei Sistemi Operativi](PARTE_10_Attacchi_Difese_Rete/35_sicurezza_dei_sistemi_operativi.md)
- Hardening dei sistemi
- Access Control (ACL, RBAC)
- Antivirus e Anti-malware
- Patch Management

### [Capitolo 36 - Hardware Security](PARTE_10_Attacchi_Difese_Rete/36_hardware_security.md)
- HSM (Hardware Security Module)
- TPM (Trusted Platform Module)
- Smart cards
- YubiKey

### [Capitolo 37 - Firewall e Protezione Perimetrale](PARTE_10_Attacchi_Difese_Rete/37_firewall_e_protezione_perimetrale.md)
- Firewall tradizionali e NGFW
- IDS/IPS (Snort, Suricata)
- WAF (Web Application Firewall)
- DMZ e Network Segmentation

### [Capitolo 38 - Gestione delle Chiavi](PARTE_10_Attacchi_Difese_Rete/38_gestione_delle_chiavi.md)
- Key lifecycle
- KMS (Key Management Service)
- AWS KMS, Azure Key Vault
- HashiCorp Vault

---

## 📜 PARTE 11 - COMPLIANCE E STANDARD

### [Capitolo 39 - Standard e Normative](PARTE_11_Compliance_Standard/39_standard_e_normative.md)
- NIST Guidelines
- ISO/IEC 27001
- FIPS 140-2/140-3
- GDPR e privacy

### [Capitolo 40 - Attacchi Crittografici Avanzati](PARTE_11_Compliance_Standard/40_attacchi_crittografici_avanzati.md)
- Timing attacks
- Padding Oracle Attack
- BEAST, CRIME, BREACH
- Heartbleed, POODLE

### [Capitolo 41 - Audit e Monitoring](PARTE_11_Compliance_Standard/41_audit_e_monitoring.md)
- Crypto audit
- Penetration testing
- SOC (Security Operations Center)
- Incident response

---

## 🧪 PARTE 12 - LABORATORI

### [Capitolo 42 - Laboratorio: Crittografia Simmetrica](PARTE_12_Laboratori/42_laboratorio_crittografia_simmetrica.md)
- Cifratura AES con OpenSSL
- Implementazione cifrario di Cesare
- Test modi di operazione
- Confronto prestazioni

### [Capitolo 43 - Laboratorio: Crittografia Asimmetrica](PARTE_12_Laboratori/43_laboratorio_crittografia_asimmetrica.md)
- Generazione chiavi RSA
- Cifratura/decifratura RSA
- Firma digitale
- Diffie-Hellman key exchange

### [Capitolo 44 - Laboratorio: Funzioni Hash](PARTE_12_Laboratori/44_laboratorio_funzioni_hash.md)
- Calcolo hash di file
- Verifica integrità
- Implementazione HMAC
- Password hashing

### [Capitolo 45 - Laboratorio: Certificati e TLS](PARTE_12_Laboratori/45_laboratorio_certificati_e_tls.md)
- Creazione CA privata
- Generazione certificato SSL
- Setup HTTPS
- Analisi handshake TLS

### [Capitolo 46 - Laboratorio: SSH Avanzato](PARTE_12_Laboratori/46_laboratorio_ssh_avanzato.md)
- Autenticazione con chiavi SSH
- Port forwarding
- SSH tunneling
- Hardening SSH server

### [Capitolo 47 - Laboratorio: PGP/GPG](PARTE_12_Laboratori/47_laboratorio_pgpgpg.md)
- Generazione keypair GPG
- Cifratura email
- Firma file
- Web of Trust

### [Capitolo 48 - Laboratorio: Applicazioni Web](PARTE_12_Laboratori/48_laboratorio_applicazioni_web.md)
- Implementazione JWT
- Password hashing
- Setup 2FA (TOTP)
- Cookie security

### [Capitolo 49 - Laboratorio: Attacchi e Difese](PARTE_12_Laboratori/49_laboratorio_attacchi_e_difese.md)
- Attacco brute-force
- Man-in-the-Middle
- SSL Strip
- Padding Oracle

### [Capitolo 50 - Laboratorio: Sicurezza di Rete e Malware](PARTE_12_Laboratori/50_laboratorio_sicurezza_di_rete_e_malware.md)
- Analisi malware
- Configurazione IDS/IPS
- Firewall rules
- Network monitoring

---

## 🎯 PARTE 13 - PROGETTI E CASI DI STUDIO

### [Capitolo 51 - Progetti Guidati](PARTE_13_Progetti_Casi_Studio/51_progetti_guidati.md)
- Chat cifrata end-to-end
- Sistema di gestione password
- File encryption tool
- Secure REST API

### [Capitolo 52 - Casi di Studio](PARTE_13_Progetti_Casi_Studio/52_casi_di_studio.md)
- WhatsApp Encryption
- Bitcoin e blockchain
- Signal Protocol
- Let's Encrypt revolution

### [Capitolo 53 - Analisi di Vulnerabilità Storiche](PARTE_13_Progetti_Casi_Studio/53_analisi_di_vulnerabilità_storiche.md)
- Heartbleed (2014)
- POODLE (2014)
- Spectre/Meltdown (2018)
- Log4Shell (2021)
- Analisi e lezioni apprese

---

## 📊 Statistiche

- **Capitoli totali**: 53
- **Parti**: 14
- **Laboratori pratici**: 9
- **Progetti**: 6
- **Ore di studio stimate**: 100-120

---

## 🎓 Percorsi di Studio Consigliati

### Percorso Base (Principianti)
1. Capitoli 0-3: Fondamenti sicurezza e crittografia
2. Capitoli 12-13: Hash e HMAC
3. Capitolo 19: SSH
4. Capitolo 42: Lab Crittografia Simmetrica

### Percorso Intermedio
1. Tutte le Parti 1-6
2. Capitoli 23-27: Applicazioni
3. Laboratori 42-47

### Percorso Avanzato (Completo)
1. Tutti i 53 capitoli in sequenza
2. Tutti i 9 laboratori
3. Almeno 3 progetti guidati
4. Casi di studio approfonditi

---

## 🔗 Link Utili

- [Torna al README principale](README.md)
- [Inizia dal Capitolo 0](PARTE_00_Fondamenti_Sicurezza/00_fondamenti_di_sicurezza_informatica.md)
- [Inizia dal Capitolo 1](PARTE_01_Fondamenti_Crittografia/01_introduzione_alla_crittografia.md)

---

**Ultimo aggiornamento**: Dicembre 2025
