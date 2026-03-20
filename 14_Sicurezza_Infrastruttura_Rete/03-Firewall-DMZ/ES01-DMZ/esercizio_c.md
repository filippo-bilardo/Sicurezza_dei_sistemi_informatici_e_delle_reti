# ES06-C — Verifica Scritta: DMZ e Sicurezza Perimetrale

📝 **Tipo**: Verifica scritta individuale  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 60 minuti  
📚 **Materiale consentito**: nessuno (verifica chiusa)  
🎯 **Punteggio totale**: 70 punti

---

**Cognome**: ________________________________  
**Nome**: ________________________________  
**Classe**: ________________________________  
**Data**: ________________________________

---

> ⚠️ **Istruzioni**: Rispondi a tutte le domande nello spazio fornito. Per le domande con schema da disegnare, usa diagrammi ASCII o descrizioni testuali chiare. La chiarezza e la completezza delle risposte sono valutate tanto quanto la correttezza tecnica.

---

## 📘 SEZIONE A — Concetti Fondamentali DMZ  
**Punteggio sezione: 12 punti**

---

### A.1 — Cos'è una DMZ e perché si usa? *(4 punti)*

Definisci il concetto di **DMZ (DeMilitarized Zone)** in ambito informatico. Spiega qual è il suo scopo principale e perché è necessaria in una rete aziendale che espone servizi su Internet.

Nella tua risposta indica:
- Cosa ospita la DMZ
- Cosa protegge
- Perché non basta un semplice firewall perimetrale senza DMZ

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

### A.2 — Le tre zone e i flussi di traffico *(4 punti)*

Completa la seguente tabella indicando se il flusso di traffico è **PERMESSO** ✅ o **BLOCCATO** ❌ in un'architettura DMZ standard, e spiega brevemente il motivo:

| Flusso | Direzione | Azione | Motivazione |
|--------|-----------|--------|-------------|
| Utente Internet | → Web Server DMZ (TCP 80) | | |
| Utente Internet | → PC Uffici LAN | | |
| PC Uffici LAN | → Web Server DMZ | | |
| PC Uffici LAN | → Internet | | |
| Web Server DMZ | → PC Uffici LAN | | |
| Web Server DMZ | → Internet | | |

---

### A.3 — Defense in Depth *(4 punti)*

Spiega cosa si intende per **"defense in depth"** (difesa a strati) e come la DMZ si inserisce in questa strategia. Elenca almeno **3 strati di difesa** diversi in una rete aziendale sicura, posizionando la DMZ nel contesto corretto.

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

## 📗 SEZIONE B — Architetture DMZ  
**Punteggio sezione: 14 punti**

---

### B.1 — DMZ a Singolo Firewall *(3 punti)*

Disegna uno schema testuale (ASCII) della **DMZ a singolo firewall** e completa la tabella vantaggi/svantaggi:

**Schema**:
```
[disegna qui lo schema]
```

| Aspetto | Valore |
|---------|--------|
| Numero di firewall | |
| Vantaggio principale | |
| Svantaggio principale | |
| Adatto per | |

---

### B.2 — DMZ a Doppio Firewall *(4 punti)*

Disegna lo schema della **DMZ a doppio firewall** e spiega quando è obbligatorio o altamente raccomandato usarla rispetto alla singola.

**Schema**:
```
[disegna qui lo schema]
```

Quando si usa la DMZ a doppio firewall?

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

### B.3 — Screened Subnet vs Screened Host *(3 punti)*

Spiega la differenza tra le architetture **Screened Subnet** e **Screened Host**. Qual è più sicura e perché?

| | Screened Subnet | Screened Host |
|--|----------------|--------------|
| Struttura | | |
| Numero di firewall/router | | |
| Livello di sicurezza | | |
| Caso d'uso tipico | | |

---

### B.4 — Bastion Host *(4 punti)*

Definisci cos'è un **bastion host** (o jump host). Descrivi:
- Le sue caratteristiche principali
- Perché deve essere "hardened" (irrobustito)
- Dove si posiziona tipicamente nella rete

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

## 📙 SEZIONE C — Firewall e ACL  
**Punteggio sezione: 14 punti**

---

### C.1 — Firewall Stateless vs Stateful *(4 punti)*

Spiega la differenza tra **firewall stateless** e **firewall stateful**. Per ciascuno, fornisci un esempio concreto di traffico che uno gestisce diversamente dall'altro.

| | Firewall Stateless | Firewall Stateful |
|--|-------------------|------------------|
| Come prende le decisioni | | |
| Tiene traccia delle connessioni? | | |
| Esempio: risposta TCP a una richiesta dal browser | | |
| Più sicuro per... | | |

---

### C.2 — ACL Cisco: standard vs estese *(3 punti)*

Descrivi le differenze tra **ACL standard** e **ACL estese** su Cisco IOS. Scrivi un esempio di sintassi per ciascuna tipologia:

**ACL Standard** — Cosa filtra?

_____________________________________________________________

Sintassi esempio: `access-list ______ ______ ______ ______`

**ACL Estesa** — Cosa filtra?

_____________________________________________________________

Sintassi esempio: `access-list ______ ______ ______ ______ ______ eq ______`

---

### C.3 — Ordine delle regole ACL *(3 punti)*

Spiega il principio del **"first match"** nelle ACL Cisco e il concetto di **"implicit deny all"** alla fine di ogni lista.

Considera il seguente estratto di ACL:
```
access-list 110 permit tcp any host 10.0.0.5 eq 80
access-list 110 deny   tcp any host 10.0.0.5 eq 80
access-list 110 permit ip  any any
```

**Domanda**: Se arriva un pacchetto TCP da `8.8.8.8` verso `10.0.0.5` porta `80`, cosa succede? Spiega il ragionamento regola per regola.

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

### C.4 — ACL in ingresso vs in uscita *(4 punti)*

Spiega la differenza tra applicare un'ACL **in ingresso** (`in`) e **in uscita** (`out`) su un'interfaccia di un router.

Dato il seguente scenario: il router ha due interfacce, `Gi0/0` (verso LAN) e `Gi0/1` (verso Internet). Vuoi bloccare il traffico **dalla LAN verso Internet**. Su quale interfaccia e in quale direzione applichi l'ACL? Perché?

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

## 📕 SEZIONE D — Flussi di Traffico e Policy  
**Punteggio sezione: 12 punti**

---

### D.1 — Servizi in DMZ *(4 punti)*

Completa la tabella indicando se il servizio deve stare in **DMZ**, nella **LAN interna**, o **entrambi** (con spiegazione):

| Servizio | DMZ? | LAN? | Motivazione |
|----------|------|------|-------------|
| Web server pubblico (sito aziendale) | | | |
| Database con dati clienti | | | |
| Server DNS pubblico | | | |
| Server DNS interno | | | |
| Server mail (SMTP per ricevere mail dall'esterno) | | | |
| Server Active Directory / LDAP | | | |
| Server FTP per upload file da partner esterni | | | |
| Server applicativo interno (gestionale ERP) | | | |

---

### D.2 — La regola "DMZ → LAN = DENY" *(4 punti)*

Spiega **perché** la regola che blocca il traffico dalla DMZ verso la LAN interna è considerata **fondamentale** in ogni architettura DMZ.

Descrivi uno **scenario di attacco concreto** che si verificherebbe se questa regola non fosse presente:

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

### D.3 — NAT e DMZ *(4 punti)*

I server in DMZ hanno indirizzi IP **privati**, ma devono essere raggiungibili da Internet. Spiega come il **NAT statico** risolve questo problema.

Completa l'esempio di configurazione Cisco per esporre il web server interno `192.168.100.10` all'IP pubblico `203.0.113.10`:

```cisco
Router(config)# ip nat _______ source static _____________ _____________
Router(config)# interface Gi0/1
Router(config-if)# ip nat _______
Router(config)# interface Gi0/2
Router(config-if)# ip nat _______
```

Cosa mostra il comando `show ip nat translations`?

_____________________________________________________________
_____________________________________________________________

---

## 📔 SEZIONE E — Monitoraggio e IDS/IPS  
**Punteggio sezione: 10 punti**

---

### E.1 — IDS vs IPS *(4 punti)*

Spiega la differenza tra **IDS** (Intrusion Detection System) e **IPS** (Intrusion Prevention System). Per ciascuno, indica:
- Come funziona
- Dove si posiziona nella rete
- Vantaggi e svantaggi

| | IDS | IPS |
|--|-----|-----|
| Funzione principale | | |
| Posizione nella rete | | |
| Può bloccare il traffico? | | |
| Rischio: falsi positivi | | |
| Impatto sulle performance | | |

---

### E.2 — Posizionamento IDS/IPS *(3 punti)*

In un'architettura DMZ a doppio firewall, indica **dove posizioneresti** un IDS e perché. Disegna uno schema testuale:

```
[disegna schema con posizionamento IDS/IPS]
```

Motivazione della scelta:

_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________

---

### E.3 — Cosa loggare in una DMZ *(3 punti)*

Elenca almeno **6 eventi** che devono essere registrati nei log di un sistema DMZ, spiegando perché ciascuno è importante:

| Evento da loggare | Perché è importante |
|-------------------|-------------------|
| 1. | |
| 2. | |
| 3. | |
| 4. | |
| 5. | |
| 6. | |

---

## 📒 SEZIONE F — Scenari e Troubleshooting  
**Punteggio sezione: 8 punti**

---

### F.1 — Server DMZ Compromesso *(3 punti)*

Il team di sicurezza di CorpSecure rileva che il web server in DMZ è stato **compromesso** (attacker ha ottenuto accesso shell al server). Elenca le **5 azioni immediate** da intraprendere nell'ordine corretto:

| Fase | Azione | Motivazione |
|------|--------|-------------|
| 1. Rilevazione | Analizzare i log per confermare la compromissione | Capire la portata dell'attacco |
| 2. Contenimento | ______________________________ | ______________________________ |
| 3. Eradicazione | ______________________________ | ______________________________ |
| 4. Ripristino | ______________________________ | ______________________________ |
| 5. Lesson Learned | ______________________________ | ______________________________ |

---

### F.2 — Verifica ACL funzionante *(2 punti)*

Il collega ti dice che "le ACL sembrano non funzionare". Elenca i **comandi Cisco IOS** che useresti per diagnosticare il problema:

```cisco
! Comando 1: verificare se l'ACL è applicata all'interfaccia
___________________________________

! Comando 2: vedere le regole dell'ACL e i contatori di match
___________________________________

! Comando 3: vedere il traffico che attraversa il router in tempo reale
___________________________________

! Comando 4: verificare la tabella di routing
___________________________________
```

---

### F.3 — DMZ Fisica vs DMZ Virtuale (VLAN) *(3 punti)*

Spiega la differenza tra una **DMZ fisica** (router/switch separati) e una **DMZ virtuale** basata su **VLAN**. Compila la tabella:

| Aspetto | DMZ Fisica | DMZ Virtuale (VLAN) |
|---------|-----------|---------------------|
| Hardware richiesto | Router/switch dedicati | Switch Layer 3 + trunking |
| Isolamento | | |
| Costo | | |
| Rischi specifici | | |
| Uso tipico | | |

---

## 📊 Griglia di Valutazione

| Sezione | Argomento | Punti Max | Punti Ottenuti |
|---------|-----------|-----------|----------------|
| A | Concetti fondamentali DMZ | 12 | |
| B | Architetture DMZ | 14 | |
| C | Firewall e ACL | 14 | |
| D | Flussi di traffico e policy | 12 | |
| E | Monitoraggio e IDS/IPS | 10 | |
| F | Scenari e troubleshooting | 8 | |
| **TOTALE** | | **70** | |

### Conversione Voto

| Punti | Voto (decimi) | Voto (quindicesimi) |
|-------|--------------|---------------------|
| 63–70 | 10 | 15 |
| 56–62 | 9 | 13–14 |
| 49–55 | 8 | 11–12 |
| 42–48 | 7 | 9–10 |
| 35–41 | 6 | 7–8 |
| 28–34 | 5 | 5–6 |
| < 28 | 4 o meno | < 5 |

---

**Firma studente**: ________________________  
**Firma insegnante**: ________________________  
**Voto**: _______/10  (oppure _______/15)

---

*ES06-C — Sistemi e Reti 3 | Verifica scritta DMZ e sicurezza perimetrale*
