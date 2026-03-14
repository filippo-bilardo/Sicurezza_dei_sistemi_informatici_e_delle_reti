# ES03-C — Domande di teoria: WireGuard e confronto VPN

> **Tipo**: 📖 Teoria  
> **Punteggio totale**: 70 punti  
> **Tempo**: 60–90 minuti  
> **Modalità**: risposta aperta, consultare gli appunti è consentito

---

## SEZIONE A — Architettura WireGuard (18 punti)

### A1 — 4 punti

**Descrivi cos'è WireGuard e in cosa si differenzia da OpenVPN.**

Indica: su quale layer opera, come gestisce le chiavi (PKI vs chiavi pubbliche), e almeno due vantaggi architetturali rispetto a OpenVPN.

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### A2 — 4 punti

**Cos'è il campo `AllowedIPs` in WireGuard? Descrivi le due funzioni che svolge.**

Fornisci un esempio di configurazione con `AllowedIPs = 0.0.0.0/0` e uno con `AllowedIPs = 192.168.1.0/24`, spiegando il comportamento in ciascun caso.

```
Funzione 1 (routing in uscita):
___________________________________________________________________________
___________________________________________________________________________

Funzione 2 (firewall in ingresso):
___________________________________________________________________________
___________________________________________________________________________

Esempio 0.0.0.0/0:
___________________________________________________________________________

Esempio 192.168.1.0/24:
___________________________________________________________________________
```

---

### A3 — 4 punti

**Spiega perché WireGuard non richiede una Certificate Authority (CA).**

Descrivi come due peer stabiliscono la fiducia reciproca senza CA, e quali operazioni manuali devono fare prima di connettersi.

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### A4 — 6 punti

**Analisi del file wg0.conf:**

```ini
[Interface]
PrivateKey = qNoGADRjKMwvJ3GGqfXkbvUFzYQ+8MqKGnpgEOTn7F0=
Address = 10.0.0.2/24

[Peer]
PublicKey = YamzMVRVhFxxIW+2xYbJDr4L8LDiPBqmX0L4cVFRrV4=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Rispondi:
1. Questo è un file di server o di client? Come lo dedurci?
2. Cosa indica `AllowedIPs = 0.0.0.0/0`?
3. Cosa fa `PersistentKeepalive = 25`?
4. Il file contiene una chiave che non deve mai essere condivisa. Quale?

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE B — Crittografia WireGuard (22 punti)

### B1 — 6 punti

**Descrivi la suite crittografica di WireGuard.**

Per ciascuno di questi algoritmi, indica la funzione che svolge:
- Curve25519
- ChaCha20-Poly1305
- BLAKE2s

```
Curve25519:
___________________________________________________________________________
___________________________________________________________________________

ChaCha20-Poly1305:
___________________________________________________________________________
___________________________________________________________________________

BLAKE2s:
___________________________________________________________________________
___________________________________________________________________________
```

---

### B2 — 6 punti

**Perché WireGuard ha algoritmi crittografici "fissi" invece di negoziabili come IPsec?**

Spiega vantaggi (sicurezza, semplicità) e uno svantaggio di questa scelta. Come si comporta WireGuard quando tra qualche anno ChaCha20 fosse vulnerabile?

```
Vantaggi:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Svantaggio:
___________________________________________________________________________
___________________________________________________________________________
```

---

### B3 — 4 punti

**Cos'è la `PresharedKey` in WireGuard e in quale scenario è raccomandata?**

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### B4 — 6 punti

**WireGuard garantisce Perfect Forward Secrecy (PFS). Spiega cosa significa.**

Indica ogni quanto WireGuard ruota le chiavi di sessione e cosa significa questo per la sicurezza delle comunicazioni passate.

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE C — Confronto e Scenari (30 punti)

### C1 — 10 punti

**Completa questa tabella comparativa tra IPsec, OpenVPN e WireGuard:**

| | IPsec/IKEv2 | OpenVPN | WireGuard |
|-|-------------|---------|-----------|
| Layer OSI | | | |
| Integrazione kernel Linux | | | |
| Autenticazione | | | |
| Algoritmo cifratura (default moderno) | | | |
| Righe di codice (approssimativo) | | | |
| Configurazione (semplice/media/complessa) | | | |
| Firewall friendly (porta standard) | | | |

```
Note e considerazioni aggiuntive:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### C2 — 8 punti

**Scenario di scelta:**

Un'azienda deve scegliere una VPN per 200 dipendenti in smart working. Il CTO presenta tre opzioni: IPsec/IKEv2, OpenVPN, WireGuard.

Scrivi una raccomandazione tecnica considerando:
1. Facilità di configurazione e manutenzione
2. Performance (specialmente su dispositivi mobile con CPU ARM)
3. Compatibilità con Windows, macOS, iOS, Android
4. Sicurezza (auditing del codice, algoritmi, maturità)

```
Raccomandazione:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### C3 — 6 punti

**Come si revoca l'accesso a un peer WireGuard?**

Confronta la procedura con la revoca in OpenVPN (CRL). Quale è più semplice? Quali rischi ci sono se la revoca non viene eseguita correttamente?

```
Revoca WireGuard:
___________________________________________________________________________
___________________________________________________________________________

Revoca OpenVPN:
___________________________________________________________________________
___________________________________________________________________________

Confronto e rischi:
___________________________________________________________________________
___________________________________________________________________________
```

---

### C4 — 6 punti

**Topologia hub-and-spoke vs mesh con WireGuard.**

Descrivi le differenze tra le due topologie e in quale scenario si preferisce ciascuna. Quali sono le implicazioni di configurare una topologia mesh con WireGuard rispetto a OpenVPN?

```
Hub-and-spoke:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Mesh:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

WireGuard vs OpenVPN per la mesh:
___________________________________________________________________________
___________________________________________________________________________
```

---

## 📊 Punteggio

| Sezione | Punti |
|---------|-------|
| A — Architettura WireGuard (4 domande) | 18 |
| B — Crittografia WireGuard (4 domande) | 22 |
| C — Confronto e Scenari (4 domande) | 30 |
| **Totale** | **70** |

---

*ES03-C — Sistemi e Reti | Teoria WireGuard e confronto VPN*
