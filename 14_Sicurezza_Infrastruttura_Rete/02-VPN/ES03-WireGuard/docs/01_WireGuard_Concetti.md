# WireGuard — Concetti e Architettura

> **ES03 — WireGuard** | Documento teorico 01

---

## Cos'è WireGuard

**WireGuard** è un protocollo VPN moderno, open source, integrato nel kernel Linux dalla versione 5.6 (marzo 2020). È stato progettato con tre obiettivi principali:

1. **Semplicità**: ~4.000 righe di codice (OpenVPN ~70.000, IPsec ~400.000)
2. **Performance**: routing nel kernel, crittografia moderna ottimizzata per CPU
3. **Sicurezza**: algoritmi crittografici fissi e moderni (no negoziazione, no cipher suite obsolete)

---

## Confronto con OpenVPN e IPsec

| | WireGuard | OpenVPN | IPsec/IKEv2 |
|-|-----------|---------|-------------|
| **Layer OSI** | 3 (rete) | 4-7 (applicativo) | 3 (rete) |
| **Integrazione kernel** | ✅ Sì (Linux 5.6+) | ❌ Userspace | ✅ Sì |
| **Righe di codice** | ~4.000 | ~70.000 | ~400.000 |
| **Performance** | ★★★★★ | ★★★ | ★★★★ |
| **Cifratura** | ChaCha20-Poly1305 (fisso) | AES-GCM (negoziato) | AES-GCM (negoziato) |
| **Scambio chiavi** | Curve25519 (fisso) | RSA/ECDH (negoziato) | DH/ECDH (negoziato) |
| **Autenticazione** | Chiavi pubbliche | Certificati X.509 | Certificati/PSK |
| **PKI necessaria** | ❌ No | ✅ Sì | ✅ Sì (spesso) |
| **Configurazione** | 10 righe | 50+ righe | Molto complessa |
| **Firewall friendly** | ⚠️ Solo UDP | ✅ TCP/UDP 443 | ⚠️ UDP 500/4500 |

---

## Architettura WireGuard

### Il Modello "Peer to Peer"

In WireGuard non esiste una distinzione tra "server" e "client" a livello di protocollo — ogni dispositivo è un **peer**. Quello che chiamiamo "server" è semplicemente un peer con `ListenPort` configurato.

```
Peer A (server)                          Peer B (client)
───────────────                          ──────────────
PrivateKey: priv_A                       PrivateKey: priv_B
PublicKey: pub_A ←─── si scambiano ───→  PublicKey: pub_B

Configurazione A:                        Configurazione B:
[Peer]                                   [Peer]
PublicKey = pub_B                        PublicKey = pub_A
AllowedIPs = 10.0.0.2/32                Endpoint = IP_A:51820
                                         AllowedIPs = 0.0.0.0/0
```

### AllowedIPs: routing + firewall in uno

Il campo `AllowedIPs` di ogni peer svolge due ruoli simultaneamente:

1. **Routing in uscita**: i pacchetti destinati a quegli IP vengono inviati a quel peer
2. **Firewall in ingresso**: solo i pacchetti sorgenti con quegli IP sono accettati da quel peer

```
AllowedIPs = 10.0.0.2/32  →  "invia a questo peer tutto il traffico per 10.0.0.2
                               e accetta solo pacchetti con sorgente 10.0.0.2 da lui"

AllowedIPs = 0.0.0.0/0    →  "invia a questo peer tutto il traffico (full tunnel)
                               e accetta qualsiasi pacchetto da lui"
```

---

## Crittografia WireGuard

WireGuard usa un insieme di algoritmi **fisso e moderno** — non c'è negoziazione, non ci sono suite obsolete da abilitare per errore.

### Algoritmi Usati

| Funzione | Algoritmo | Note |
|----------|-----------|------|
| **Scambio chiavi** | Curve25519 (ECDH) | Sicuro, 128-bit di sicurezza effettiva |
| **Cifratura dati** | ChaCha20-Poly1305 | AEAD — cifra + autentica in un'unica operazione |
| **Hash / derivazione chiavi** | BLAKE2s | Più veloce di SHA-256, sicuro quanto SHA-3 |
| **Handshake** | Noise Protocol Framework | Protocollo formalmente verificato |
| **Chiavi di sessione** | Rotazione ogni 3 minuti (Perfect Forward Secrecy) | Una chiave compromessa non compromette il passato |

### Perché Curve25519 + ChaCha20 invece di RSA + AES?

- **Curve25519** offre sicurezza equivalente a RSA-3072 con una chiave di soli 32 byte
- **ChaCha20** è più veloce di AES su CPU senza istruzione AES-NI (dispositivi mobile, router embedded)
- Entrambi progettati da crittografi con l'obiettivo esplicito di evitare backdoor

---

## Confronto delle Performance

```
Benchmark throughput (stessa macchina, tunnel localhost):

OpenVPN UDP:    ~800 Mbps
IPsec/IKEv2:   ~1.5 Gbps
WireGuard:      ~3-4 Gbps  (e oltre, su hardware recente)

Latenza round-trip:
OpenVPN:    +1–3 ms
IPsec:      +0.5–1 ms
WireGuard:  +0.1–0.3 ms  ≈ overhead trascurabile
```

---

## Domande di Riepilogo

1. Perché WireGuard ha meno righe di codice di OpenVPN? Qual è il vantaggio di sicurezza?
2. Cos'è `AllowedIPs` e quali due funzioni svolge?
3. Perché WireGuard non richiede una PKI con certificati?
4. Cosa significa che gli algoritmi crittografici di WireGuard sono "fissi"? È un vantaggio o uno svantaggio?

---

*Prossimo documento: [02 — Gestione Chiavi](02_WireGuard_Chiavi.md)*
