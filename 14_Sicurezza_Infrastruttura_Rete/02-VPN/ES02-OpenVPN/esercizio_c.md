# ES02-C — Domande di teoria: OpenVPN, TLS e PKI

> **Tipo**: 📖 Teoria  
> **Punteggio totale**: 70 punti  
> **Tempo**: 60–90 minuti  
> **Modalità**: risposta aperta, consultare gli appunti è consentito

---

## SEZIONE A — Concetti OpenVPN (18 punti)

### A1 — 4 punti

**Cos'è OpenVPN e in cosa si differenzia da IPsec?**

Descrivi su quale layer OSI opera OpenVPN, quale protocollo di sicurezza utilizza e almeno due vantaggi rispetto a una VPN IPsec tradizionale (es. Cisco).

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### A2 — 4 punti

**Spiega la differenza tra full tunnel e split tunnel in OpenVPN.**

Per ciascuna modalità:
- Descrivi quale traffico passa attraverso il tunnel VPN
- Indica un vantaggio e uno svantaggio
- Indica quale direttiva del file di configurazione la controlla

```
Full Tunnel:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Split Tunnel:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### A3 — 4 punti

**Cos'è l'interfaccia `tun0`? Cosa succede al sistema operativo del client quando si connette a una VPN OpenVPN in full tunnel?**

Descrivi:
1. Cos'è un'interfaccia virtuale TUN
2. Quale IP riceve `tun0`
3. Come cambia la tabella di routing del client

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### A4 — 6 punti

**Confronta `tls-auth` e `tls-crypt`. Quale dei due è più sicuro e perché?**

Rispondi spiegando:
- Cosa fa ciascuna opzione
- Perché `tls-crypt` offre una protezione aggiuntiva
- Cosa significa che un osservatore non può identificare il traffico OpenVPN con `tls-crypt`

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE B — PKI e Certificati (24 punti)

### B1 — 6 punti

**Descrivi la struttura di una PKI per OpenVPN.**

Elenca i file generati da Easy-RSA, indica per ciascuno:
- Nome del file
- Se è pubblico o segreto
- Su quale macchina deve essere installato (server/client/entrambi)

```
File               | Pubblico/Segreto | Dove installare
___________________|__________________|________________
ca.crt             |                  |
ca.key             |                  |
server.crt         |                  |
server.key         |                  |
client.crt         |                  |
client.key         |                  |
dh.pem             |                  |
tc.key             |                  |
```

---

### B2 — 6 punti

**Perché OpenVPN usa un certificato per ogni client invece di uno condiviso?**

Spiega i vantaggi di questo approccio in termini di:
1. Sicurezza (cosa succede se un certificato viene compromesso)
2. Tracciabilità (audit e log)
3. Revoca (come si blocca un singolo utente senza disturbare gli altri)

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### B3 — 6 punti

**Un tecnico IT lascia l'azienda. Descrivi la procedura completa per revocargli l'accesso VPN.**

Indica i comandi Easy-RSA da eseguire, i file che cambiano e come il server OpenVPN applica la revoca.

```bash
# Comandi da eseguire:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

```
Cosa succede quando Luca tenta di connettersi dopo la revoca:
___________________________________________________________________________
___________________________________________________________________________
```

---

### B4 — 6 punti

**Analisi del file .ovpn**

Osserva questo estratto di un file `.ovpn`:

```ini
client
dev tun
proto tcp
remote vpn.azienda.com 443
redirect-gateway def1
cipher AES-256-GCM
auth SHA256
<ca> ... </ca>
<cert> ... </cert>
<key> ... </key>
<tls-crypt> ... </tls-crypt>
```

Rispondi:
1. Perché usa la porta 443 invece della 1194?
2. Cosa significa `redirect-gateway def1`?
3. Che tipo di autenticazione usa (certificato, password, o entrambi)?
4. Perché `<key>` deve essere protetto?

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE C — Sicurezza e Scenari (28 punti)

### C1 — 6 punti

**Un dipendente segnala che non riesce a connettersi alla VPN con questo errore:**

```
TLS Error: TLS handshake failed
```

Elenca almeno tre possibili cause e la procedura di diagnostica per ciascuna.

```
Causa 1: ___________________________________________________________________
Diagnostica: ______________________________________________________________

Causa 2: ___________________________________________________________________
Diagnostica: ______________________________________________________________

Causa 3: ___________________________________________________________________
Diagnostica: ______________________________________________________________
```

---

### C2 — 8 punti

**Scenario di sicurezza:**

Un attaccante intercetta il traffico di rete tra un client OpenVPN e il server e ottiene il file `.ovpn` di Mario Rossi (incluso il certificato e la chiave privata).

1. Cosa può fare l'attaccante con questi dati?
2. Come si rileva questa compromissione?
3. Quale azione immediata deve fare l'amministratore?
4. Come si previene in futuro?

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### C3 — 8 punti

**Il responsabile IT deve scegliere tra full tunnel e split tunnel per i 50 dipendenti remoti dell'azienda.**

Scrivi una raccomandazione tecnica spiegando:
1. Vantaggi e svantaggi di ciascuna opzione per l'azienda
2. Quale sceglieresti e perché (considera sicurezza, performance, privacy dipendenti, compliance)
3. Esiste una soluzione intermedia? Quale?

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### C4 — 6 punti

**Confronta OpenVPN con WireGuard** (che studierai nell'esercitazione ES03).

Basandoti su quello che sai di OpenVPN, completa questa tabella ipotizzando le caratteristiche di WireGuard:

| | OpenVPN | WireGuard |
|-|---------|-----------|
| Layer OSI | 4-7 | ? |
| Cifratura | AES-256-GCM + TLS | ? |
| Codice sorgente | ~70.000 righe | ? |
| Performance | Buona | ? |
| Gestione chiavi | PKI + certificati X.509 | ? |

```
Le tue ipotesi su WireGuard:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## 📊 Punteggio

| Sezione | Punti |
|---------|-------|
| A — Concetti OpenVPN (4 domande) | 18 |
| B — PKI e Certificati (4 domande) | 24 |
| C — Sicurezza e Scenari (4 domande) | 28 |
| **Totale** | **70** |

---

*ES02-C — Sistemi e Reti | Teoria OpenVPN, TLS e PKI*
