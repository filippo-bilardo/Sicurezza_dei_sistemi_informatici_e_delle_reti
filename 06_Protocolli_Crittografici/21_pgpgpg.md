# Capitolo 21 - PGP/GPG

> **Corso**: Sistemi e Reti 3  
> **Parte**: 6 - Protocolli Crittografici  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**PGP** (Pretty Good Privacy) è un sistema di cifratura e firma digitale per email, file e comunicazioni in generale. Creato da Phil Zimmermann nel 1991, è diventato lo standard de facto per la crittografia delle email.

**GPG** (GNU Privacy Guard) è l'implementazione libera e open source di PGP, compatibile con lo standard **OpenPGP** (RFC 4880).

```
PGP (Phil Zimmermann, 1991, proprietario)
          ↓
    OpenPGP (RFC 4880, standard aperto)
          ↓
GPG / GnuPG (implementazione libera GNU)
```

---

## Come Funziona PGP

PGP usa la **crittografia ibrida**: combina crittografia simmetrica e asimmetrica.

### Cifratura di un Messaggio

```
1. Genera chiave simmetrica casuale (session key)
2. Cifra il messaggio con la session key (AES)
3. Cifra la session key con la chiave pubblica del destinatario (RSA/ElGamal)
4. Invia: messaggio cifrato + session key cifrata
```

```
Mittente:                    Destinatario:
  messaggio                    messaggio cifrato
     │                                │
  [AES-256] ←── session key      [RSA decrypt]
     │               │                │
  CIFRATO      [RSA encrypt]     session key
                    │                 │
               chiave pubblica   [AES-256 decrypt]
               destinatario           │
                               MESSAGGIO
```

### Firma Digitale

```
1. Calcola hash del messaggio (SHA-256)
2. Cifra l'hash con la chiave PRIVATA del mittente
3. Allega la firma al messaggio
```

```
Mittente:                    Destinatario:
  messaggio                    messaggio + firma
     │                              │
  [SHA-256]                   [SHA-256]   [RSA decrypt]
     │                              │        │
   hash ──[RSA sign]──> firma    hash'      hash
                                    └── == ──┘
                               ✅ Autentico  ❌ Alterato
```

---

## Installazione GPG

### Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install gnupg
```

### macOS

```bash
brew install gnupg
```

### Windows

- **Gpg4win**: https://www.gpg4win.org (include Kleopatra, GUI grafica)

### Verifica installazione

```bash
gpg --version
# gpg (GnuPG) 2.4.x
```

---

## Gestione delle Chiavi

### Generare una Coppia di Chiavi

```bash
gpg --full-generate-key
```

Scelte consigliate:
```
Tipo chiave:    (1) RSA e RSA   oppure  (9) ECC (Curve25519, consigliato)
Dimensione:     4096 bit (RSA) / default (ECC)
Scadenza:       1 anno (es. 1y)
Nome:           Mario Rossi
Email:          mario@example.com
Passphrase:     [forte e memorabile]
```

### Listare le Chiavi

```bash
# Chiavi pubbliche (keyring)
gpg --list-keys
gpg -k

# Output di esempio:
# pub   ed25519 2025-01-01 [SC] [expires: 2026-01-01]
#       A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0
# uid   [ultimate] Mario Rossi <mario@example.com>
# sub   cv25519 2025-01-01 [E] [expires: 2026-01-01]

# Chiavi private
gpg --list-secret-keys
gpg -K
```

### Esportare una Chiave Pubblica

```bash
# Formato ASCII (per invio email / incolla in sito)
gpg --armor --export mario@example.com > mario_pub.asc

# Visualizza la chiave pubblica
gpg --armor --export mario@example.com
# -----BEGIN PGP PUBLIC KEY BLOCK-----
# ...
# -----END PGP PUBLIC KEY BLOCK-----
```

### Importare una Chiave Pubblica

```bash
# Da file
gpg --import mario_pub.asc

# Da keyserver
gpg --keyserver keys.openpgp.org --recv-keys A1B2C3D4

# Verifica importazione
gpg --list-keys mario@example.com
```

### Fingerprint e Verifica

> ⚠️ Prima di usare una chiave altrui, **verifica sempre il fingerprint** via canale sicuro (telefono, di persona).

```bash
# Mostra fingerprint
gpg --fingerprint mario@example.com
# Fingerprint: A1B2 C3D4 E5F6 A7B8 C9D0  E1F2 A3B4 C5D6 E7F8 A9B0
```

### Firmare una Chiave (Web of Trust)

```bash
# Dopo aver verificato il fingerprint di persona
gpg --sign-key mario@example.com

# Firma con livello di certificazione
gpg --edit-key mario@example.com
# gpg> trust   (assegna livello di fiducia)
# gpg> sign    (firma la chiave)
# gpg> quit
```

### Keyserver

```bash
# Pubblicare la propria chiave
gpg --keyserver keys.openpgp.org --send-keys A1B2C3D4

# Cercare una chiave
gpg --keyserver keys.openpgp.org --search-keys mario@example.com

# Aggiornare le chiavi importate
gpg --refresh-keys
```

---

## Cifratura e Decifratura

### Cifrare un File per un Destinatario

```bash
# Cifra per mario (usa la sua chiave pubblica)
gpg --encrypt --recipient mario@example.com documento.pdf

# Output: documento.pdf.gpg

# Con armatura ASCII (per email/testo)
gpg --armor --encrypt --recipient mario@example.com documento.txt
# Output: documento.txt.asc
```

### Cifrare per Più Destinatari

```bash
gpg --encrypt \
    --recipient mario@example.com \
    --recipient lucia@example.com \
    documento.pdf
```

### Decifrare

```bash
# GPG usa automaticamente la chiave privata giusta
gpg --decrypt documento.pdf.gpg

# Salva su file
gpg --output documento.pdf --decrypt documento.pdf.gpg
```

### Cifratura Simmetrica (solo password, senza chiavi)

```bash
# Cifra con passphrase
gpg --symmetric --armor file.txt
# Output: file.txt.asc

# Decifra
gpg --decrypt file.txt.asc
```

---

## Firma Digitale

### Firmare un File

```bash
# Firma separata (file + file.sig)
gpg --detach-sign --armor documento.pdf
# Output: documento.pdf.asc

# Firma inclusa nel file cifrato
gpg --sign documento.txt
# Output: documento.txt.gpg

# Firma in chiaro (testo leggibile + firma allegata)
gpg --clearsign messaggio.txt
# Output: messaggio.txt.asc
```

**Esempio output `--clearsign`:**

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Questo è il messaggio firmato.
-----BEGIN PGP SIGNATURE-----

iQGzBAABCgAdFiEE... [firma]
-----END PGP SIGNATURE-----
```

### Verificare una Firma

```bash
# Verifica firma separata
gpg --verify documento.pdf.asc documento.pdf

# Output quando valida:
# gpg: Good signature from "Mario Rossi <mario@example.com>"
# gpg: WARNING: This key is not certified with a trusted signature!

# Verifica firma inclusa
gpg --verify messaggio.txt.asc
```

### Cifrare E Firmare Insieme (uso tipico)

```bash
gpg --encrypt --sign \
    --recipient mario@example.com \
    --armor \
    documento.txt
```

---

## Web of Trust (WoT)

Il modello di fiducia di PGP è decentralizzato: non usa CA (Certificate Authority) come SSL/TLS, ma si basa sulla rete di firme tra utenti.

```
         [Alice]
        /       \
  firma         firma
     /             \
  [Bob]           [Carlo]
     \             /
      firma    firma
          \   /
          [Dave]

Dave si fida di Alice → si fida (in parte) di Bob e Carlo
```

### Livelli di Fiducia (Trust Level)

| Livello | Significato |
|---------|-------------|
| **unknown** | Non si conosce l'utente |
| **none** | Non ci si fida |
| **marginal** | Fiducia parziale |
| **full** | Fiducia completa |
| **ultimate** | Fiducia assoluta (proprie chiavi) |

```bash
# Impostare il livello di fiducia
gpg --edit-key mario@example.com
# gpg> trust
# Scegli: 4 = full trust
# gpg> quit
```

---

## Gestione Avanzata

### Revocare una Chiave

```bash
# Genera certificato di revoca (farlo subito dopo la creazione!)
gpg --gen-revoke mario@example.com > revoca.asc

# Importare il certificato di revoca (rende la chiave inutilizzabile)
gpg --import revoca.asc

# Pubblicare la revoca su keyserver
gpg --keyserver keys.openpgp.org --send-keys mario@example.com
```

> ⚠️ **Conserva il certificato di revoca** in un posto sicuro. Senza di esso non potrai revocare una chiave compromessa.

### Sottochiavi (Subkeys)

GPG usa sottochiavi per separare le funzioni:

| Chiave | Scopo | Flag |
|--------|-------|------|
| **Principale (master)** | Certificazione e firma identità | `[SC]` |
| **Sottochiave firma** | Firma documenti | `[S]` |
| **Sottochiave cifratura** | Cifratura messaggi | `[E]` |
| **Sottochiave autenticazione** | Login SSH | `[A]` |

```bash
gpg --edit-key mario@example.com
# gpg> addkey    (aggiunge sottochiave)
# gpg> expire    (cambia scadenza)
# gpg> save
```

### Backup delle Chiavi

```bash
# Esporta chiave privata (tieni al sicuro!)
gpg --armor --export-secret-keys mario@example.com > chiave_privata.asc

# Esporta tutto (pubblica + privata + trust)
gpg --armor --export-secret-keys > private_backup.asc
gpg --export-ownertrust > trust_backup.txt

# Ripristino
gpg --import private_backup.asc
gpg --import-ownertrust trust_backup.txt
```

---

## GPG per Email

### Thunderbird con OpenPGP Integrato

A partire da Thunderbird 78, il supporto OpenPGP è **integrato** nativamente.

1. **Impostazioni Account** → **Crittografia end-to-end**
2. Importa o genera la chiave
3. Scrivendo un'email: pulsanti **Cifra** e **Firma**

### Formato di un'Email Cifrata

```
From: mario@example.com
To: lucia@example.com
Subject: [messaggio cifrato]

-----BEGIN PGP MESSAGE-----

hQGMA1234567890...
[contenuto cifrato]
-----END PGP MESSAGE-----
```

---

## GPG per Firma di Commit Git

```bash
# Configura GPG con Git
git config --global user.signingkey A1B2C3D4
git config --global commit.gpgsign true

# Firma un commit
git commit -S -m "Messaggio commit firmato"

# Verifica la firma di un commit
git log --show-signature

# Firma un tag
git tag -s v1.0 -m "Release v1.0"
git tag -v v1.0  # verifica
```

Su **GitHub**: la chiave pubblica aggiunta all'account mostra il badge **"Verified"** accanto ai commit firmati.

---

## Confronto PGP vs S/MIME

| Caratteristica | PGP/GPG | S/MIME |
|----------------|---------|--------|
| **PKI** | Web of Trust (decentralizzato) | Gerarchia CA (centralizzato) |
| **Certificati** | Chiavi GPG | Certificati X.509 |
| **Costo** | Gratuito | Spesso a pagamento |
| **Compatibilità email** | Buona (plugin) | Nativa nei client aziendali |
| **Complessità gestione** | Media | Bassa (automatizzata) |
| **Usato in** | Open source, tecnici | Ambienti aziendali |

---

## Best Practices

1. **Usa ECC (Curve25519)** invece di RSA quando possibile — più sicuro e leggero
2. **Imposta una scadenza** alla chiave (1-2 anni) e rinnovala periodicamente
3. **Genera subito il certificato di revoca** e conservalo offline
4. **Proteggi la chiave privata** con una passphrase forte
5. **Verifica il fingerprint** di persona prima di firmare la chiave altrui
6. **Non caricare la chiave privata** su macchine non fidate
7. **Usa un keyserver moderno** (keys.openpgp.org) che rispetta il GDPR
8. **Tieni separata la chiave master** (su smartcard o offline) e usa solo le sottochiavi

---

## Esercizi

### Esercizio 21.1 (★☆☆) — Gestione chiavi base
1. Installa GPG sul tuo sistema
2. Genera una coppia di chiavi con nome, email e scadenza a 1 anno
3. Esporta la chiave pubblica in formato ASCII
4. Visualizza il fingerprint della chiave generata
5. Scambia la chiave pubblica con un compagno e importala

### Esercizio 21.2 (★★☆) — Cifratura e firma
1. Cifra un file di testo usando la chiave pubblica di un compagno
2. Il compagno decifra il file e verifica il contenuto
3. Firma un documento con la tua chiave privata (`--clearsign`)
4. Il compagno verifica la firma con la tua chiave pubblica
5. Modifica il documento firmato e tenta di nuovo la verifica: cosa succede?

### Esercizio 21.3 (★★★) — Scenario completo
1. Simula uno scambio di email cifrate e firmate tramite GPG (`--encrypt --sign`)
2. Genera un certificato di revoca per la tua chiave e salvalo in un posto sicuro
3. Configura Git per firmare automaticamente tutti i commit e verifica con `git log --show-signature`
4. Pubblica la tua chiave su `keys.openpgp.org` e recupera quella di un compagno dal keyserver
5. Imposta il livello di fiducia appropriato per la chiave del compagno dopo aver verificato il fingerprint di persona

---

## Domande di Verifica

1. Qual è la differenza tra PGP e GPG?
2. Perché PGP usa la crittografia ibrida invece di cifrare tutto con RSA?
3. Cosa si intende per "Web of Trust" e come si differenzia dal modello PKI con CA?
4. A cosa serve il certificato di revoca e perché va generato subito?
5. Qual è la differenza tra firma con `--sign`, `--detach-sign` e `--clearsign`?
6. Cosa indica il flag `[SC]` accanto alla chiave principale e `[E]` accanto alla sottochiave?
7. Come si verifica l'autenticità di una chiave pubblica scaricata da un keyserver?
8. Perché è consigliato usare ECC (ed25519/cv25519) rispetto a RSA per le nuove chiavi?

---

## Riferimenti

- [OpenPGP Standard - RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880)
- [GnuPG Official Documentation](https://www.gnupg.org/documentation/)
- [GPG Cheatsheet](https://devhints.io/gpg)
- [keys.openpgp.org](https://keys.openpgp.org) — Keyserver moderno GDPR-compliant
- [Gpg4win](https://www.gpg4win.org) — Client Windows con GUI Kleopatra

---

## Riferimenti

- [Riferimento 1]
- [Riferimento 2]

---

**Capitolo Precedente**: [20 - Precedente](#)  
**Prossimo Capitolo**: [22 - Successivo](#)
