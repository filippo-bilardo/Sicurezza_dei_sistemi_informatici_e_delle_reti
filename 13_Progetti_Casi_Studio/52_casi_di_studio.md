# Capitolo 52 - Casi di Studio

> **Corso**: Sistemi e Reti 3  
> **Parte**: 13 - Progetti e Casi di Studio  
> **Autore**: Prof. Filippo Bilardo

---

## Caso 1: WannaCry Ransomware (2017)

### Descrizione Attacco

**WannaCry** fu un attacco ransomware globale nel maggio 2017.

### Timeline

```
12 Maggio 2017
├─ 07:44 UTC: Prima infezione rilevata
├─ 10:00 UTC: 45.000 attacchi in 74 paesi
├─ 15:00 UTC: 200.000+ computer infetti
└─ Kill switch attivato (dominio registrato)
```

### Tecnica

1. **Exploit**: EternalBlue (NSA leak)
   - Vulnerabilità: MS17-010 (SMBv1)
   - Remote Code Execution

2. **Propagazione**: Worm
   - Scansione rete per porta 445
   - Auto-replica senza interazione utente

3. **Payload**: Ransomware
   - Cifratura: RSA + AES
   - Richiesta: $300-600 in Bitcoin

### Crittografia Usata

```python
# Pseudocodice WannaCry
def encrypt_files():
    # 1. Genera coppia RSA (embedded nel malware)
    attacker_public_key = load_embedded_rsa_key()
    
    # 2. Per ogni file
    for file in victim_files:
        # Genera chiave AES random
        aes_key = generate_random_aes_key()
        
        # Cifra file con AES
        encrypted_file = aes_encrypt(file, aes_key)
        
        # Cifra chiave AES con RSA attaccante
        encrypted_key = rsa_encrypt(aes_key, attacker_public_key)
        
        # Salva
        save(encrypted_file + encrypted_key)
        
        # Elimina originale
        secure_delete(file)
```

### Difese

```python
# Patch Microsoft
# MS17-010 - Disabilita SMBv1

# PowerShell: Disabilita SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Backup offline
# Segmentazione rete
# Firewall: Blocca porta 445 esterna
```

### Lezioni

✅ **Aggiorna sempre** il sistema  
✅ **Backup offline** frequenti  
✅ **Segmenta** la rete  
✅ **Disabilita** servizi non necessari (SMBv1)

---

## Caso 2: Heartbleed (2014)

### Descrizione

Bug in OpenSSL che permetteva lettura memoria server.

### Vulnerabilità

```c
// OpenSSL bug (CVE-2014-0160)
// Manca controllo lunghezza!

memcpy(bp, pl, payload);  // ❌ payload non verificato!
```

### Exploit

```python
# Heartbleed exploit (semplificato)
def heartbleed_exploit(target):
    # 1. Invia heartbeat con lunghezza fake
    heartbeat = {
        'type': 'heartbeat',
        'payload_length': 65535,  # ❌ FAKE! (reale: 1 byte)
        'payload': 'X'  # 1 byte reale
    }
    
    # 2. Server risponde con 65535 byte
    # Include: payload + 65534 byte di MEMORIA!
    response = send_heartbeat(target, heartbeat)
    
    # 3. Nella memoria ci sono:
    #    - Chiavi private
    #    - Password
    #    - Session cookies
    #    - Dati utenti
    
    return response  # Leak 64KB memoria!
```

### Impatto

- **500.000+** server vulnerabili
- Leak chiavi private SSL
- Password in chiaro
- Session hijacking

### Fix

```c
// Patch OpenSSL
int dtls1_process_heartbeat(SSL *s) {
    unsigned int payload;
    
    // Leggi lunghezza dichiarata
    n2s(p, payload);
    
    // ✅ VERIFICA LUNGHEZZA!
    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0; // Heartbeat silenzioso
    
    // Procedi solo se lunghezza valida
    memcpy(bp, pl, payload);
}
```

### Lezioni

✅ **Validazione input** sempre  
✅ **Bounds checking** rigoroso  
✅ **Audit codice** critico  
✅ **Memory-safe languages** (Rust)  

---

## Caso 3: SHA-1 Collision Attack (2017)

### Contesto

Google e CWI Amsterdam dimostrano collisione SHA-1.

### Attacco

```python
# SHAttered Attack
# https://shattered.io

# Due PDF diversi con stesso SHA-1!
pdf1_sha1 = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
pdf2_sha1 = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

# Ma contenuti COMPLETAMENTE diversi!
# pdf1 = "Hello World"
# pdf2 = "Goodbye World"

# Stessi hash → Collisione!
```

### Impatto Sicurezza

```python
# Scenario attacco

# 1. Attaccante crea due file:
good_file = "Contratto legittimo.pdf"
bad_file = "Contratto malevolo.pdf"

# 2. Trova collisione SHA-1
sha1(good_file) == sha1(bad_file)

# 3. Invia good_file per firma
signed_hash = sign(sha1(good_file))

# 4. Sostituisce con bad_file
# Firma ancora valida! ❌
verify(bad_file, signed_hash)  # ✅ Valido!
```

### Costo Attacco

- **2017**: 110 GPU-years
- **2020**: ~11.000 USD
- **Trend**: Sempre più economico

### Migrazione

```python
# ❌ SHA-1 (deprecato)
import hashlib
hash_sha1 = hashlib.sha1(data).hexdigest()

# ✅ SHA-256 (sicuro)
hash_sha256 = hashlib.sha256(data).hexdigest()

# ✅ SHA-3 (moderno)
hash_sha3 = hashlib.sha3_256(data).hexdigest()
```

### Lezioni

✅ **SHA-1 deprecato** (no uso produzione)  
✅ **SHA-256 minimo** per nuovi sistemi  
✅ **Crypto agility**: Facile aggiornare algoritmi  

---

## Caso 4: Zoom Encryption Issue (2020)

### Problema

Zoom dichiarava "end-to-end encryption" ma usava TLS.

### Architettura Reale

```
Alice         Zoom Server      Bob
  │               │             │
  ├─ TLS ────────>│             │
  │               ├─ Decifra    │
  │               ├─ Re-cifra   │
  │               └─ TLS ──────>│
```

❌ **Non è E2E!** Server può leggere tutto.

### End-to-End Vero

```
Alice                           Bob
  │                              │
  ├─ Cifra con chiave Bob ──────>│
  │  (Server vede solo ciphertext)│
```

### Fix Zoom (2021)

```python
# Zoom E2EE (Post-2021)

# 1. Key exchange
alice_dh = generate_dh_keypair()
bob_dh = generate_dh_keypair()

# Scambio via server (ma server non ha chiavi private!)
shared_secret = dh_exchange(alice_dh, bob_dh)

# 2. Deriva chiave AES
meeting_key = HKDF(shared_secret)

# 3. Cifra video/audio
encrypted_stream = AES_GCM(meeting_key, video_audio_data)

# ✅ Server non può decifrare!
```

### Lezioni

✅ **Verifica claims** di sicurezza  
✅ **E2E significa**: Solo endpoint possono decifrare  
✅ **Trasparenza**: Audit indipendenti  

---

## Caso 5: Colonial Pipeline (2021)

### Descrizione

Ransomware DarkSide colpisce oleodotto USA.

### Impatto

- Pipeline chiuso 6 giorni
- Carenza carburante East Coast
- Riscatto: $4.4M in Bitcoin (parzialmente recuperato)

### Vettore Infezione

```
VPN account compromesso
    ↓
No 2FA attivo
    ↓
Credenziali rubate
    ↓
Accesso rete aziendale
    ↓
Ransomware deployment
```

### Difese Mancanti

❌ 2FA non attivo  
❌ Segmentazione rete insufficiente  
❌ Backup non testati  
❌ Incident response plan debole  

### Lezioni

✅ **2FA obbligatorio** ovunque  
✅ **Zero Trust**: Segmenta tutto  
✅ **Backup** testati regolarmente  
✅ **Incident Response Plan** documentato  
✅ **Air-gapped backups**  

---

## Caso 6: LastPass Breach (2022)

### Timeline

```
Agosto 2022
├─ Accesso a sistema sviluppo
├─ Furto codice sorgente
└─ Accesso a backup cloud

Dicembre 2022
├─ Rivelazione: Backup vault cifrati rubati
└─ Master password users = Ultima difesa
```

### Architettura LastPass

```python
# Vault cifrato

user_vault_encrypted = AES_encrypt(
    user_data,
    key = PBKDF2(master_password, salt, iterations=100100)
)

# ✅ LastPass non ha master password
# ✅ Vault cifrato client-side

# ❌ Ma attaccanti hanno vault cifrati!
# ❌ Brute force offline possibile
```

### Rischio

```python
# Attaccante può brute force offline
for password_guess in password_list:
    derived_key = PBKDF2(password_guess, salt, 100100)
    
    try:
        decrypted = AES_decrypt(vault, derived_key)
        if valid(decrypted):
            print(f"💀 Password trovata: {password_guess}")
            break
    except:
        continue
```

### Difese Utente

✅ **Master password forte** (20+ caratteri)  
✅ **Cambia passwords** critiche  
✅ **Abilita 2FA** su tutti i servizi  
✅ **Monitora** account per accessi sospetti  

### Lezioni Azienda

✅ **Zero Trust** anche interno  
✅ **Backup encryption** separata  
✅ **Trasparenza** tempestiva  
✅ **Incident Response** rapido  

---

## Conclusioni Casi Studio

### Pattern Comuni

1. **Human Factor**: Phishing, password deboli
2. **Patch Management**: Vulnerabilità note non patchate
3. **Configuration**: Default insicure, 2FA disabilitato
4. **Monitoring**: Rilevamento tardivo
5. **Backup**: Non testati o accessibili da attaccante

### Best Practices

```
Defense in Depth
├─ Prevenzione
│  ├─ Patch management
│  ├─ 2FA everywhere
│  ├─ Least privilege
│  └─ Input validation
│
├─ Rilevamento
│  ├─ SIEM / IDS
│  ├─ Anomaly detection
│  └─ Log analysis
│
└─ Risposta
   ├─ Incident Response Plan
   ├─ Backup testati
   └─ Business Continuity
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 51 - Progetti Guidati](51_progetti_guidati.md)
- **Successivo**: [Capitolo 53 - Analisi Vulnerabilità](53_analisi_di_vulnerabilità_storiche.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

**Fonti**:
- CVE Database: https://cve.mitre.org
- NIST: https://nvd.nist.gov
- Krebs on Security: https://krebsonsecurity.com
