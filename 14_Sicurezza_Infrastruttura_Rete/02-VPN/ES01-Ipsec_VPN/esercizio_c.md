# ES01c — Domande di teoria: VPN e sicurezza delle comunicazioni

> **Tipo**: 📖 Teoria  
> **Punteggio totale**: 70 punti  
> **Tempo**: 60–90 minuti  
> **Modalità**: risposta aperta, consultare gli appunti è consentito (open book)

---

## 📋 Istruzioni

- Rispondi in modo completo ma conciso
- Usa terminologia tecnica corretta
- Per le domande che richiedono schemi, puoi usare ASCII art o descrizione testuale
- Ogni domanda riporta il punteggio massimo assegnabile

---

## SEZIONE A — Concetti fondamentali VPN (12 punti)

### Domanda A1 — 4 punti

**Cos'è una VPN (Virtual Private Network) e perché le aziende la utilizzano?**

Spiega i tre pilastri fondamentali di una VPN: tunneling (incapsulamento), cifratura
(confidenzialità) e autenticazione (identità/integrità). Descrivi uno scenario aziendale
concreto in cui l'uso di una VPN è indispensabile.

_Spazio risposta:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda A2 — 4 punti

**Qual è la differenza tra VPN Site-to-Site e VPN Remote Access (Client-to-Site)?**

Per ciascun tipo di VPN:
- Descrivi lo scenario di utilizzo tipico (chi si collega a cosa)
- Indica dove si trovano i "punti finali" del tunnel
- Fai un esempio pratico di azienda che userebbe quel tipo di VPN

_Spazio risposta:_

```
VPN Site-to-Site:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

VPN Remote Access:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda A3 — 4 punti

**Qual è la differenza tra una VPN basata su IPsec e una VPN basata su SSL/TLS
(come OpenVPN o WireGuard)?**

Considera almeno questi aspetti: livello OSI in cui operano, complessità di configurazione,
compatibilità con firewall e NAT, casi d'uso tipici. Puoi usare una tabella comparativa.

_Spazio risposta:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE B — Protocollo IPsec (16 punti)

### Domanda B1 — 4 punti

**Descrivi l'architettura IPsec: qual è la differenza tra AH e ESP?**

Per ciascun protocollo indica:
- Numero di protocollo IP
- Cosa protegge (autenticazione, integrità, cifratura)
- In quale scenario si sceglie uno rispetto all'altro

_Spazio risposta:_

```
AH (Authentication Header):
  Protocollo IP n.: ___
  Funzioni: _____________________________________________________________
  Scenario d'uso: ________________________________________________________
  ________________________________________________________________________

ESP (Encapsulating Security Payload):
  Protocollo IP n.: ___
  Funzioni: _____________________________________________________________
  Scenario d'uso: ________________________________________________________
  ________________________________________________________________________
```

---

### Domanda B2 — 4 punti

**Spiega il processo IKE (Internet Key Exchange): cosa avviene nella Phase 1 e
cosa avviene nella Phase 2?**

Descrivi per ciascuna fase:
- Obiettivo della fase
- Cosa viene negoziato / creato
- Differenza tra Main Mode e Aggressive Mode (solo per Phase 1)

_Spazio risposta:_

```
IKE Phase 1 (ISAKMP SA):
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

IKE Phase 2 (IPsec SA):
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda B3 — 4 punti

**Descrivi le due modalità operative di IPsec: Transport Mode e Tunnel Mode.**

Per ciascuna modalità:
- Descrivi cosa viene incapsulato e cosa rimane visibile
- Indica lo scenario d'uso tipico (host-to-host o gateway-to-gateway)
- Disegna uno schema ASCII dell'intestazione del pacchetto risultante

_Spazio risposta:_

```
Transport Mode:
  Uso tipico: ____________________________________________________________
  Schema pacchetto:
  [ ____________ | ____________ | ____________ ]

  Descrizione: ___________________________________________________________
  ________________________________________________________________________

Tunnel Mode:
  Uso tipico: ____________________________________________________________
  Schema pacchetto:
  [ ____________ | ____________ | ____________ | ____________ ]

  Descrizione: ___________________________________________________________
  ________________________________________________________________________
```

---

### Domanda B4 — 4 punti

**Spiega i parametri della ISAKMP policy su Cisco IOS:**

Per ciascun parametro indica cosa significa e quali valori sono possibili su Cisco IOS:
`encryption`, `hash`, `authentication`, `group`, `lifetime`

_Spazio risposta:_

```
encryption: _________________________________________________________________
  Valori Cisco: des | 3des | aes (default: ____________)
  Consigliato oggi: __________

hash: _______________________________________________________________________
  Valori Cisco: md5 | sha | sha256
  Differenza MD5 vs SHA: ____________________________________________________

authentication: _____________________________________________________________
  pre-share = _______________________________________________________________
  rsa-sig   = _______________________________________________________________

group (Diffie-Hellman): ______________________________________________________
  group 1 = __________________ (sicurezza: ❌ debole)
  group 2 = __________________ (sicurezza: ⚠️ accettabile)
  group 5 = __________________ (sicurezza: ✅ buono)
  group 14 = _________________ (sicurezza: ✅ raccomandato)

lifetime: ___________________________________________________________________
  Valore predefinito: ________________ secondi
  Cosa succede quando scade: ________________________________________________
```

---

## SEZIONE C — Tecnologie di tunneling (10 punti)

### Domanda C1 — 3 punti

**Cos'è GRE (Generic Routing Encapsulation) e in cosa si differenzia da IPsec puro?**

Indica: numero del protocollo IP usato da GRE, cosa incapsula, vantaggi e svantaggi
rispetto a IPsec, perché GRE da solo non è adatto per trasmissioni sicure su Internet.

_Spazio risposta:_

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

### Domanda C2 — 4 punti

**Spiega il concetto di GRE over IPsec: perché si combina GRE con IPsec?
Quali vantaggi offre rispetto a IPsec puro?**

Considera: supporto routing protocols, multicast, configurazione in Cisco IOS
(interfaccia Tunnel + crypto map). Fai un confronto con la soluzione IPsec puro
dell'Esercizio A.

_Spazio risposta:_

```
Perché combinare GRE e IPsec:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Vantaggi di GRE over IPsec rispetto a IPsec puro:
1. ________________________________________________________________________
2. ________________________________________________________________________
3. ________________________________________________________________________

Svantaggio principale:
___________________________________________________________________________

Esempio configurazione Cisco (interfaccia tunnel):
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda C3 — 3 punti

**Spiega il concetto di MPLS VPN e in cosa si differenzia da una VPN IPsec.**

Descrivi brevemente cosa sono le label MPLS, chi gestisce la VPN (ISP vs azienda),
e in quale scenario un'azienda sceglierebbe MPLS VPN invece di IPsec.

_Spazio risposta:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE D — Topologie VPN (10 punti)

### Domanda D1 — 2 punti

**Descrivi la topologia VPN Point-to-Point (Site-to-Site semplice).**

Quando si usa, quanti tunnel VPN ci sono, chi gestisce i router VPN.
Fai riferimento all'Esercizio A come esempio.

_Spazio risposta:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda D2 — 5 punti

**Confronta le topologie Hub-and-Spoke e Full-Mesh per una rete VPN con 5 sedi.**

Compila la tabella comparativa e rispondi alle domande:

| Caratteristica | Hub-and-Spoke | Full-Mesh |
|---------------|--------------|-----------|
| N. tunnel VPN (5 sedi) | | |
| Traffico inter-filiale | passa per _____ | ________________ |
| Latenza inter-filiale | | |
| Single Point of Failure | | |
| Complessità di gestione | | |
| Banda richiesta al router HQ | | |
| Costo (tunnel da gestire) | | |

Formula numero tunnel Full-Mesh: `N*(N-1)/2` dove N = numero di sedi

Con 5 sedi: numero tunnel Hub-and-Spoke = _____ , Full-Mesh = _____

In quale scenario sceglieresti Hub-and-Spoke? In quale Full-Mesh?

_Spazio risposta:_

```
Hub-and-Spoke scelgo quando: ________________________________________________
___________________________________________________________________________

Full-Mesh scelgo quando: ____________________________________________________
___________________________________________________________________________
```

---

### Domanda D3 — 3 punti

**Cos'è DMVPN (Dynamic Multipoint VPN)? Quali problemi risolve rispetto a
Hub-and-Spoke statico?**

Descrivi brevemente i tre componenti di DMVPN: mGRE, NHRP, IPsec.
Spiega come i nodi spoke si "trovano" dinamicamente senza configurazione statica.

_Spazio risposta:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE E — Sicurezza VPN (14 punti)

### Domanda E1 — 4 punti

**Descrivi gli algoritmi crittografici usati in IPsec e valutane la sicurezza relativa.**

Per ciascun algoritmo indica: tipo (simmetrico/asimmetrico/hash), lunghezza chiave,
stato di sicurezza attuale (sicuro/obsoleto/vulnerabile).

| Algoritmo | Tipo | Lunghezza chiave | Sicurezza attuale | Uso in IPsec |
|-----------|------|-----------------|------------------|--------------|
| DES | | | ❌ Obsoleto | |
| 3DES | | | | |
| AES-128 | | | | |
| AES-256 | | | | |
| MD5 | | | | |
| SHA-1 | | | | |
| SHA-256 | | | | |
| RSA-2048 | | | | |
| DH Group 2 | | 1024-bit | ⚠️ Debole | |
| DH Group 14 | | | ✅ Raccomandato | |

_Note aggiuntive sulla sicurezza degli algoritmi:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda E2 — 3 punti

**Cos'è il Perfect Forward Secrecy (PFS) e perché è importante nella sicurezza VPN?**

Spiega cosa succede alle sessioni precedenti se la chiave principale viene compromessa,
con e senza PFS. Come si abilita PFS in una crypto map Cisco?

_Spazio risposta:_

```
Senza PFS:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Con PFS:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

Comando Cisco per abilitare PFS nella crypto map:
crypto map VPN-MAP 10 ipsec-isakmp
 ___________________________________________________________________________
```

---

### Domanda E3 — 4 punti

**Descrivi le principali vulnerabilità di sicurezza di una VPN IPsec:**

Per ciascuna vulnerabilità indica: descrizione dell'attacco, come si manifesta,
come si previene/mitiga.

```
1. Man-in-the-Middle sull'handshake IKE:
   Descrizione: _____________________________________________________________
   Come si manifesta: _______________________________________________________
   Prevenzione: _____________________________________________________________

2. Weak Pre-Shared Key (PSK debole):
   Descrizione: _____________________________________________________________
   Come si manifesta: _______________________________________________________
   Prevenzione: _____________________________________________________________

3. Downgrade attack (policy debole accettata):
   Descrizione: _____________________________________________________________
   Come si manifesta: _______________________________________________________
   Prevenzione: _____________________________________________________________
```

---

### Domanda E4 — 3 punti

**Cos'è il VPN split tunneling? Quali sono i vantaggi e i rischi di sicurezza?**

Descrivi la differenza tra full tunneling e split tunneling. In quale scenario
un'azienda con politica di sicurezza rigida non dovrebbe usare split tunneling?

_Spazio risposta:_

```
Full tunneling:
___________________________________________________________________________
___________________________________________________________________________

Split tunneling:
___________________________________________________________________________
___________________________________________________________________________

Vantaggi split tunneling:
1. ________________________________________________________________________
2. ________________________________________________________________________

Rischi sicurezza split tunneling:
1. ________________________________________________________________________
2. ________________________________________________________________________

Quando NON usare split tunneling:
___________________________________________________________________________
___________________________________________________________________________
```

---

## SEZIONE F — Comandi e troubleshooting (8 punti)

### Domanda F1 — 3 punti

**Descrivi i principali comandi di verifica VPN su Cisco IOS e cosa mostrano.**

| Comando | Cosa mostra | Come interpretare l'output |
|---------|-------------|---------------------------|
| `show crypto isakmp sa` | | |
| `show crypto ipsec sa` | | |
| `show crypto map` | | |
| `show crypto isakmp policy` | | |
| `show crypto session` | | |
| `show ip interface Gi0/1` | | |

_Spazio note aggiuntive:_

```
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

### Domanda F2 — 2 punti

**Interpreta il seguente output di `show crypto ipsec sa` e spiega cosa significa
ogni campo evidenziato:**

```
interface: GigabitEthernet0/1
    Crypto map tag: VPN-MAP, local addr 203.0.113.2

   local  ident (addr/mask/prot/port): (192.168.1.0/255.255.255.0/0/0)   ← [A]
   remote ident (addr/mask/prot/port): (192.168.2.0/255.255.255.0/0/0)   ← [B]
   current_peer 203.0.113.6 port 500                                       ← [C]

    #pkts encaps: 47, #pkts encrypt: 47, #pkts digest: 47                 ← [D]
    #pkts decaps: 52, #pkts decrypt: 52, #pkts verify: 52                 ← [E]
    #send errors 0, #recv errors 0                                         ← [F]
```

_Spazio risposta:_

```
[A] local ident: _____________________________________________________________
___________________________________________________________________________

[B] remote ident: ____________________________________________________________
___________________________________________________________________________

[C] current_peer port 500: ___________________________________________________
___________________________________________________________________________

[D] pkts encaps/encrypt/digest: ______________________________________________
___________________________________________________________________________

[E] pkts decaps/decrypt/verify: ______________________________________________
___________________________________________________________________________

[F] send errors / recv errors: _______________________________________________
___________________________________________________________________________
```

---

### Domanda F3 — 3 punti

**Descrivi la procedura di troubleshooting VPN in 5 passi.**

Per ciascun passo indica: cosa si verifica, quale comando si usa, come interpretare
l'output e cosa fare se il passo fallisce.

_Spazio risposta:_

```
PASSO 1 — Verifica connettività IP base:
  Comando: ________________________________________________________________
  Output atteso: __________________________________________________________
  Se fallisce: ____________________________________________________________

PASSO 2 — Verifica Phase 1 (ISAKMP SA):
  Comando: ________________________________________________________________
  Output atteso: __________________________________________________________
  Se fallisce (MM_NO_STATE o vuoto): ______________________________________
  ________________________________________________________________________

PASSO 3 — Verifica Phase 2 (IPsec SA):
  Comando: ________________________________________________________________
  Output atteso: __________________________________________________________
  Se fallisce (encaps = 0): _______________________________________________
  ________________________________________________________________________

PASSO 4 — Verifica routing e ACL:
  Comandi: ________________________________________________________________
  Cosa verificare: ________________________________________________________
  ________________________________________________________________________

PASSO 5 — Debug (solo in lab!):
  Comandi: ________________________________________________________________
  ⚠️ Avvertenza: __________________________________________________________
  Come disattivare il debug: ______________________________________________
```

---

## 📊 Griglia di valutazione

| Sezione | Domande | Punti max | Punteggio ottenuto |
|---------|---------|-----------|-------------------|
| A — Concetti VPN | A1, A2, A3 | 12 pt | |
| B — IPsec | B1, B2, B3, B4 | 16 pt | |
| C — Tunneling | C1, C2, C3 | 10 pt | |
| D — Topologie | D1, D2, D3 | 10 pt | |
| E — Sicurezza | E1, E2, E3, E4 | 14 pt | |
| F — Troubleshooting | F1, F2, F3 | 8 pt | |
| **TOTALE** | **20 domande** | **70 pt** | |

### Conversione punteggio → voto decimale

| Punteggio | Voto | Giudizio |
|-----------|------|----------|
| 63–70 pt | 10 | Eccellente |
| 56–62 pt | 9 | Ottimo |
| 49–55 pt | 8 | Buono |
| 42–48 pt | 7 | Discreto |
| 35–41 pt | 6 | Sufficiente |
| 28–34 pt | 5 | Mediocre |
| 21–27 pt | 4 | Insufficiente |
| 0–20 pt | 3 | Gravemente insufficiente |

---

## 🔑 Criteri di valutazione per risposta aperta

| Livello | Descrizione | Moltiplicatore |
|---------|-------------|---------------|
| **Completo e preciso** | Tutti i concetti richiesti, terminologia corretta, esempi pertinenti | 100% dei punti |
| **Buono** | Concetti principali presenti, qualche imprecisione non sostanziale | 75–90% |
| **Sufficiente** | Concetti presenti ma incompleti o con errori minori | 50–74% |
| **Insufficiente** | Risposta parziale, concetti chiave mancanti | 25–49% |
| **Non risposto / errato** | Assente o completamente errato | 0% |
