# WireGuard: VPN moderna e ad alte prestazioni su Linux

> **Materia**: Sistemi e Reti — Classe 5ª  
> **Argomento**: VPN con WireGuard su Ubuntu Server  
> **Durata stimata**: 2–3 ore (esercizio A), 3–5 ore (esercizio B)

---

## 🌐 Introduzione

**WireGuard** è la VPN più moderna disponibile: integrata nel kernel Linux dalla versione 5.6 (2020), è **4–10 volte più veloce** di OpenVPN e ha una superficie d'attacco minima (~4.000 righe di codice contro ~70.000 di OpenVPN).

A differenza di OpenVPN — che usa certificati X.509 e una PKI — WireGuard usa esclusivamente **coppie di chiavi pubbliche/private** (simile a SSH). La configurazione è radicale nella sua semplicità: un file, pochi parametri, nessun dialogo di negoziazione.

> 💡 **Analogia**: configurare WireGuard è simile a scambiare chiavi SSH tra due server — si scambiano le chiavi pubbliche e il tunnel funziona.

---

## 🎯 Competenze Coperte

| # | Competenza | Livello |
|---|-----------|---------|
| 1 | Installare WireGuard su Ubuntu Server | ⭐ |
| 2 | Generare coppie di chiavi WireGuard (pubkey/privkey) | ⭐⭐ |
| 3 | Configurare server e client con `wg0.conf` | ⭐⭐ |
| 4 | Abilitare IP forwarding e NAT per i client VPN | ⭐⭐ |
| 5 | Attivare e gestire il tunnel con `wg-quick` | ⭐⭐ |
| 6 | Verificare il tunnel con `wg show` e ping | ⭐⭐ |
| 7 | Aggiungere e rimuovere peer senza riavviare | ⭐⭐⭐ |
| 8 | Confrontare WireGuard con OpenVPN e IPsec | ⭐⭐⭐ |

---

## 📚 Guide Teoriche

| # | File | Argomento | Priorità |
|---|------|-----------|----------|
| 1 | [`docs/01_WireGuard_Concetti.md`](docs/01_WireGuard_Concetti.md) | Architettura WireGuard, crittografia, confronto | 📖 Prima di tutto |
| 2 | [`docs/02_WireGuard_Chiavi.md`](docs/02_WireGuard_Chiavi.md) | Generazione chiavi, scambio pubbliche, sicurezza | 📖 Prima degli esercizi |
| 3 | [`docs/03_WireGuard_Config.md`](docs/03_WireGuard_Config.md) | Riferimento completo wg0.conf server e client | 🔧 Riferimento durante lab |
| 4 | [`docs/04_Troubleshooting.md`](docs/04_Troubleshooting.md) | Diagnostica, errori comuni, `wg show` | 🛠️ Quando qualcosa non funziona |

---

## 🏋️ Esercizi

| Esercizio | File | Tipo | Difficoltà | Punti |
|-----------|------|------|------------|-------|
| **A** | [`esercizio_a.md`](esercizio_a.md) | Laboratorio guidato — Server WireGuard + client road warrior | ⭐⭐ | /100 |
| **B** | [`esercizio_b.md`](esercizio_b.md) | Progetto autonomo — VPN mesh a 3 peer | ⭐⭐⭐⭐ | /100 + bonus |
| **C** | [`esercizio_c.md`](esercizio_c.md) | Teoria — 18 domande su WireGuard, crittografia, confronti | ⭐⭐ | /70 |

---

## 🗂️ Struttura Cartelle

```
ES03-WireGuard/
├── README.md                          ← Questo file
├── esercizio_a.md                     ← Lab guidato: server WireGuard + 1 client
├── esercizio_b.md                     ← Progetto autonomo: rete mesh 3 peer
├── esercizio_c.md                     ← Domande di teoria
├── docs/
│   ├── 01_WireGuard_Concetti.md       ← Teoria: architettura e crittografia
│   ├── 02_WireGuard_Chiavi.md         ← Teoria: gestione chiavi
│   ├── 03_WireGuard_Config.md         ← Pratica: wg0.conf completo
│   └── 04_Troubleshooting.md          ← Pratica: diagnostica
└── img/                               ← Screenshot degli esercizi
```

---

## 🔧 Software Richiesto

- **VirtualBox** o **VMware** (per le VM Linux)
- **Ubuntu Server 22.04 LTS** (kernel 5.15 — WireGuard integrato)
- **WireGuard** (installato tramite `apt`)

> ✅ **Vantaggio**: WireGuard è integrato nel kernel Linux 5.6+. Su Ubuntu 22.04 basta installare `wireguard` e `wireguard-tools` — nessuna compilazione.

---

## 🔑 Concetti Chiave da Ricordare

| Concetto | Descrizione breve |
|---------|-------------------|
| **Peer** | Ogni endpoint WireGuard — sia server che client sono "peer" |
| **PrivateKey** | Chiave privata del peer (tenere segreta) |
| **PublicKey** | Chiave pubblica derivata dalla privata (da condividere) |
| **AllowedIPs** | IP che il peer può inviare/ricevere — funziona come routing + firewall |
| **Endpoint** | IP:porta del peer raggiungibile (solo per chi inizia la connessione) |
| **wg0** | Nome dell'interfaccia WireGuard (configurabile) |
| **PresharedKey** | Chiave simmetrica opzionale tra due peer (protezione post-quantum) |
| **Curve25519** | Algoritmo di scambio chiavi DH — sicuro e veloce |
| **ChaCha20-Poly1305** | Algoritmo AEAD per la cifratura dei dati (moderno, fast su CPU senza AES-NI) |
| **BLAKE2s** | Hash per session keys e MAC (alternativa moderna a SHA) |

---

## 📋 Sequenza di Studio Consigliata

```
1. Leggi docs/01_WireGuard_Concetti.md   →  Comprendi l'architettura WireGuard
2. Leggi docs/02_WireGuard_Chiavi.md     →  Studia la gestione delle chiavi
3. Leggi docs/03_WireGuard_Config.md     →  Tieni aperto come riferimento durante il lab
4. Esegui esercizio_a.md                 →  Lab guidato passo-passo
5. Esegui esercizio_b.md                 →  Progetto autonomo mesh
6. Rispondi esercizio_c.md               →  Verifica teoria
   (usa docs/04_Troubleshooting.md se hai problemi durante i lab)
```

---

*ES03 — Sistemi e Reti | Versione 1.0 | Ubuntu Server 22.04 + WireGuard*
