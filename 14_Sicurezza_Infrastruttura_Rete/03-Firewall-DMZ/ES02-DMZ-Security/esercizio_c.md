# ES07-C — Verifica Teorica: Sicurezza della DMZ

> 📝 **Tipo**: Verifica scritta di teoria
> ⏱️ **Durata consigliata**: 90–120 minuti
> 📊 **Punteggio totale**: 70 punti
> 🎯 **Obiettivo**: Verificare la comprensione degli attacchi alla DMZ, delle contromisure, del monitoraggio e della risposta agli incidenti

---

**Nome e Cognome**: ___________________________________ **Classe**: ___________ **Data**: ___________

> ✏️ **Istruzioni**:
> - Rispondi in modo chiaro e conciso. Non copiare definizioni dal libro: dimostra che hai capito.
> - Per le domande che richiedono elenchi, usa punti o tabelle.
> - Per le domande su configurazioni, usa la sintassi Cisco IOS o uno pseudocodice chiaro.
> - Puoi usare schemi e disegni quando utile.
> - Non sono ammessi appunti o dispositivi elettronici.

---

## SEZIONE A — Vulnerabilità Strutturali della DMZ *(10 punti)*

---

### Domanda A1 *(3 punti)*

> Una DMZ ben progettata riduce il rischio, ma non lo elimina mai completamente.

**Spiega perché una DMZ non può mai essere considerata "sicura al 100%"**, indicando almeno **tre fattori strutturali** che rendono impossibile garantire la sicurezza totale di una DMZ, indipendentemente dalla qualità della configurazione.

_(Spazio risposta — circa 10–12 righe)_

---

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda A2 *(4 punti)*

> Un attaccante ha compromesso il server web in DMZ di un'azienda. Nelle ore successive, ottiene accesso al database interno contenente i dati di 50.000 clienti.

**Descrivi le 4 fasi di un pivot attack**, dalla compromissione iniziale del server DMZ all'accesso ai dati interni. Per ogni fase indica: cosa fa l'attaccante, quali strumenti/tecniche usa, quale segnale potrebbe rilevarlo.

| Fase | Azioni dell'attaccante | Tecniche/Strumenti | Segnale rilevabile |
|------|----------------------|-------------------|--------------------|
| **1. Compromissione DMZ** | | | |
| **2. Ricognizione interna** | | | |
| **3. Movimento laterale** | | | |
| **4. Escalation/Persistenza** | | | |

---

### Domanda A3 *(3 punti)*

> Nel 2024, molti esperti di sicurezza affermano che il "perimeter security" tradizionale è morto.

**Spiega la differenza tra il modello "perimeter security" (DMZ classica) e il modello "defense in depth"**, indicando per ciascuno:
- Assunzione di base sulla fiducia nella rete
- Cosa succede se il perimetro (DMZ) viene violato
- Come evolve nel modello Zero Trust

_(Spazio risposta — circa 8–10 righe)_

---

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

## SEZIONE B — Attacchi alla DMZ *(16 punti)*

---

### Domanda B1 *(4 punti)*

> Gli attacchi di firewall bypass sfruttano debolezze nella configurazione o nel funzionamento dei firewall per far passare traffico che dovrebbe essere bloccato.

**Descrivi tre tecniche di firewall bypass**, spiegando per ciascuna: il meccanismo tecnico, un esempio concreto e la contromisura principale.

| Tecnica | Come funziona | Esempio concreto | Contromisura |
|---------|--------------|-----------------|-------------|
| **ACL Misconfiguration** | | | |
| **IP Fragmentation Attack** | | | |
| **Covert Channel** (scegli uno: DNS/HTTP/ICMP tunneling) | | | |

---

### Domanda B2 *(4 punti)*

> Il lateral movement è la fase dell'attacco in cui l'avversario si sposta dal sistema inizialmente compromesso verso altri sistemi della rete.

**Rispondi alle seguenti domande sul lateral movement da DMZ verso LAN:**

**a)** Cosa si intende per "credential reuse" in questo contesto? Perché i server DMZ sono particolarmente vulnerabili a questo vettore? *(2 righe)*

_________________________________________________________________________________

_________________________________________________________________________________

**b)** Spiega brevemente cosa sono il **Pass-the-Hash** e il **Pass-the-Ticket**. In quale fase dell'attacco vengono tipicamente usati? *(3 righe)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

**c)** Un server web in DMZ inizia a fare una scansione delle porte verso la LAN interna. Scrivi la regola ACL Cisco che blocca questo comportamento, assumendo che:
- Subnet DMZ: `172.16.10.0/27`
- Subnet LAN: `172.16.20.0/24`
- Il traffico da bloccare è TCP verso la LAN con porte di destinazione diverse da quelle di risposta (connessioni iniziate dalla DMZ)

```cisco
ip access-list extended BLOCK-DMZ-SCAN
 ! scrivi qui la/le regole:
 _________________________________________________
 _________________________________________________
 _________________________________________________
```

---

### Domanda B3 *(4 punti)*

> Il "server hopping" (o pivot) è una tecnica in cui l'attaccante usa un server compromesso come trampolino per raggiungere altri sistemi.

**a)** Elenca **tre strumenti** comunemente usati dagli attaccanti per eseguire pivot e per ognuno descrivi come viene utilizzato in questo contesto: *(1,5 punti)*

| Strumento | Uso in un pivot attack |
|-----------|----------------------|
| **netcat** | |
| **SSH tunneling** | |
| **Metasploit (route/meterpreter)** | |

**b)** Descrivi **due indicatori di compromissione (IOC)** che i difensori possono rilevare sui log per identificare un server DMZ usato come pivot: *(1,5 punti)*

1. _______________________________________________________________________________

2. _______________________________________________________________________________

**c)** Un Intrusion Detection System (IDS) in DMZ ha rilevato questo pattern: *"Il Web Server (172.16.10.10) ha effettuato 1.247 connessioni SYN verso 172.16.20.0/24 in 45 secondi"*. Cosa indica questo? È un falso positivo possibile? *(1 punto)*

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda B4 *(4 punti)*

> Gli attacchi DDoS contro la DMZ possono rendere indisponibili i servizi pubblici dell'azienda, causando danni economici e reputazionali.

**a)** Completa la tabella comparativa tra DDoS volumetrico e DDoS applicativo: *(2 punti)*

| Caratteristica | DDoS Volumetrico | DDoS Applicativo |
|----------------|-----------------|-----------------|
| **Livello OSI target** | | |
| **Esempio di tecnica** | | |
| **Risorsa esaurita** | | |
| **Difficoltà rilevamento** | | |
| **Contromisura principale** | | |

**b)** Spiega il concetto di **attacco di amplificazione tramite DNS** ("DNS amplification"). Perché un server DNS in DMZ mal configurato può diventare complice di un attacco DDoS contro terzi? Come si previene? *(2 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

## SEZIONE C — Hardening dei Server in DMZ *(14 punti)*

---

### Domanda C1 *(3 punti)*

> "Il principio del least privilege si applica non solo agli utenti, ma anche ai processi e ai servizi."

**Spiega il principio del least privilege applicato ai processi server** (es. web server, DNS server) in una DMZ. Perché è importante che il processo del web server **non giri come root**? Cosa può fare un attaccante che ha compromesso un processo con privilegi root rispetto a uno con privilegi limitati? Fornisci un esempio concreto con comandi Linux.

_(Spazio risposta — circa 8 righe)_

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda C2 *(4 punti)*

> I server in DMZ sono tra i più critici da mantenere aggiornati, ma anche i più difficili da patchare senza interrompere il servizio.

**a)** Perché i server in DMZ sono considerati **bersagli prioritari** per gli attaccanti rispetto ai server interni? Cita almeno 3 ragioni. *(2 punti)*

1. _______________________________________________________________________________

2. _______________________________________________________________________________

3. _______________________________________________________________________________

**b)** Descrivi un ciclo di patch management per un web server in DMZ, indicando: frequenza, procedura di test prima del deploy, come minimizzare il downtime, e come verificare che la patch sia stata applicata correttamente. *(2 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda C3 *(3 punti)*

> L'"attack surface" (superficie d'attacco) di un server è l'insieme di tutti i punti attraverso cui un attaccante può tentare di entrare o estrarre dati.

**Elenca e descrivi 5 operazioni di "riduzione della superficie d'attacco"** che eseguiresti su un server web appena installato in DMZ prima di metterlo in produzione. Per ogni operazione indica lo strumento o il comando.

| # | Operazione | Strumento/Comando | Motivazione |
|---|-----------|-----------------|-------------|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

### Domanda C4 *(4 punti)*

> Un bastion host (o jump server) è un server "rafforzato" progettato per essere il punto di accesso amministrativo sicuro verso i sistemi in DMZ.

**a)** Spiega cosa è un bastion host, perché è necessario e come si inserisce nell'architettura di rete. Fai uno schema ASCII semplice che mostri il flusso di una connessione amministrativa verso un server DMZ tramite bastion host. *(2 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

```
[Admin PC LAN] → _______ → _______ → [Server DMZ]
```

**b)** Elenca 4 misure di hardening specifiche per un bastion host SSH, spiegando brevemente perché ognuna è importante: *(2 punti)*

1. _______________________________________________________________________________

2. _______________________________________________________________________________

3. _______________________________________________________________________________

4. _______________________________________________________________________________

---

## SEZIONE D — Contromisure Avanzate *(14 punti)*

---

### Domanda D1 *(4 punti)*

> Il parametro `established` nelle ACL Cisco è fondamentale per distinguere tra connessioni iniziate dall'interno e risposte a connessioni iniziate dall'esterno.

**a)** Spiega la differenza tra un firewall **stateless** e un firewall **stateful**. Perché il parametro `established` in una ACL Cisco è una forma parziale di "statefulness"? *(2 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

**b)** Considera questa situazione: un client LAN (172.16.20.10) ha aperto una sessione HTTP verso il Web Server in DMZ (172.16.10.10). Il server vuole rispondere. Completa la regola ACL sull'interfaccia DMZ per permettere **solo questa risposta** e bloccare connessioni nuove iniziate dalla DMZ: *(2 punti)*

```cisco
ip access-list extended DMZ-TO-LAN
 ! permetti risposte TCP a sessioni stabilite dalla LAN
 permit tcp ____________ ____________ ____________
 ! blocca qualsiasi connessione nuova dalla DMZ verso LAN
 deny ip ____________ ____________ log
 permit ip any any
```

---

### Domanda D2 *(4 punti)*

> La micro-segmentazione divide la rete in zone molto piccole, riducendo il "raggio d'esplosione" (blast radius) in caso di compromissione.

**a)** Disegna uno schema ASCII che confronti una **DMZ classica** (un'unica zona) con una **DMZ micro-segmentata** (web tier, app tier, data tier): *(2 punti)*

```
DMZ CLASSICA:                    DMZ MICRO-SEGMENTATA:
                                 
[Internet] → [Firewall]          [Internet] → [FW-est]
                 ↓                                ↓
           [DMZ unica]               [Web Tier /27]
           Web Server                      ↓
           App Server               [FW-mid / ACL]
           DB DMZ                         ↓
                                   [App Tier /28]
                                         ↓
                                   [FW-int / ACL]
                                         ↓
                                   [Data Tier /29]
```

*(Modifica/completa lo schema sopra con le frecce e i dettagli corretti)*

**b)** Cosa si intende per **East-West traffic filtering** in contrapposizione al North-South filtering? Perché è importante in un'architettura micro-segmentata? *(2 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda D3 *(3 punti)*

> Zero Trust Network Access (ZTNA) ribalta il paradigma tradizionale: invece di fidarsi di tutto ciò che è "dentro" la rete, non si fida di nessuno finché non viene verificato.

**Spiega il principio Zero Trust** rispondendo alle seguenti domande:

**a)** Quali sono i **5 pilastri** del modello Zero Trust? *(1 punto)*

1. ______________________________  2. ______________________________  3. ______________________________

4. ______________________________  5. ______________________________

**b)** Qual è la differenza fondamentale tra una **VPN tradizionale** e un **ZTNA (Zero Trust Network Access)**? *(1 punto)*

_________________________________________________________________________________

_________________________________________________________________________________

**c)** Come si applica il concetto Zero Trust specificamente alla DMZ? Fai un esempio concreto di come un server interno verificherebbe ogni richiesta proveniente da un server DMZ, anche legittimo. *(1 punto)*

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda D4 *(3 punti)*

> La deception technology usa "trappole" per rilevare gli attaccanti prima che raggiungano i sistemi reali.

**a)** Spiega la differenza tra **honeypot** e **honeynet**, e come si posizionano in una DMZ come sistema di early warning. *(1,5 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

**b)** Cosa sono i **canary token**? Fornisci un esempio pratico di come un canary token può rilevare un attaccante che ha compromesso un server DMZ e sta cercando credenziali. *(1,5 punti)*

_________________________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

## SEZIONE E — Monitoraggio e Rilevamento *(10 punti)*

---

### Domanda E1 *(4 punti)*

> Un SIEM (Security Information and Event Management) raccoglie log da tutta la rete e li correla per rilevare attacchi complessi.

**Descrivi come un SIEM può rilevare un pivot attack** spiegando:

**a)** Quali **fonti di log** dovrebbero essere inviate al SIEM da un'architettura DMZ (elenca almeno 5): *(1 punto)*

1. ______________________  2. ______________________  3. ______________________

4. ______________________  5. ______________________

**b)** Scrivi una **regola di correlazione** (in pseudocodice o linguaggio naturale strutturato) che rilevil'inizio di un pivot attack basandosi sui log: *(2 punti)*

```
REGOLA: "Pivot Attack Attempt"
SE:
  evento_1: _______________________________ (da quale fonte?)
  E ENTRO _____ minuti:
  evento_2: _______________________________ (da quale fonte?)
  E:
  evento_3: _______________________________ (da quale fonte?)
ALLORA:
  genera_alert(severità=CRITICA, messaggio="__________________________")
  azione_automatica: _______________________________
```

**c)** Come mai la correlazione è necessaria? Perché non basta monitorare ogni evento singolarmente? *(1 punto)*

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda E2 *(3 punti)*

> L'anomaly detection identifica comportamenti insoliti rispetto a una baseline "normale".

**Descrivi come identificare traffico anomalo da un server DMZ compromesso**:

**a)** Elenca **4 comportamenti anomali** che un Web Server in DMZ NON dovrebbe mai fare, e che potrebbero indicare una compromissione: *(2 punti)*

| # | Comportamento anomalo | Perché è sospetto |
|---|----------------------|------------------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |

**b)** Cosa si intende per "baseline" nel contesto dell'anomaly detection? Come si costruisce una baseline per un web server in DMZ? *(1 punto)*

_________________________________________________________________________________

_________________________________________________________________________________

---

### Domanda E3 *(3 punti)*

> Il threat hunting è un approccio proattivo alla sicurezza: invece di aspettare gli alert, il security analyst va attivamente alla ricerca di minacce nascoste.

**Confronta l'approccio reattivo e proattivo** alla sicurezza in DMZ:

**a)** Completa la tabella: *(1,5 punti)*

| Caratteristica | Approccio Reattivo | Approccio Proattivo (Threat Hunting) |
|----------------|-------------------|--------------------------------------|
| **Quando si agisce** | | |
| **Trigger** | | |
| **Tempo medio di rilevamento** | | |
| **Vantaggio principale** | | |
| **Svantaggio principale** | | |

**b)** Elenca **3 IOC (Indicators of Compromise)** specifici per un server DMZ che un threat hunter cercherebbe nei log, anche in assenza di alert automatici: *(1,5 punti)*

1. _______________________________________________________________________________

2. _______________________________________________________________________________

3. _______________________________________________________________________________

---

## SEZIONE F — Risposta agli Incidenti *(6 punti)*

---

### Domanda F1 *(4 punti)*

> Sono le 03:17. Il sistema di monitoraggio segnala: "Il Web Server DMZ (172.16.10.10) sta effettuando connessioni TCP in uscita verso 172.16.20.20 (Server-DB LAN) sulla porta 3306. Sono state tentate 847 connessioni negli ultimi 5 minuti, di cui 3 con handshake completato."

**Descrivi le 5 fasi di incident response (NIST SP 800-61)** con le azioni specifiche per questo scenario:

| Fase NIST | Entro quando | Azioni concrete da eseguire | Responsabile |
|-----------|-------------|----------------------------|-------------|
| **1. Preparation** *(già pre-incident)* | Pre-incident | [Cosa doveva essere preparato prima?] | CISO / Security Team |
| **2. Detection & Analysis** | T+0 → T+15 min | | |
| **3. Containment** | T+15 → T+60 min | | |
| **4. Eradication** | T+1h → T+4h | | |
| **5. Recovery** | T+4h → T+24h | | |
| **6. Post-Incident** | T+48h → T+2 settimane | | |

> 💡 *Nota: NIST SP 800-61 definisce formalmente 4 fasi; la "Post-Incident Activity" è spesso considerata la 5a o 6a. Usa la suddivisione che preferisci, purché copra tutte le attività.*

---

### Domanda F2 *(2 punti)*

> "Isolare un server compromesso" sembra semplice, ma in un ambiente di produzione può significare interrompere un servizio usato da migliaia di utenti.

**Descrivi due strategie per isolare un server DMZ compromesso senza interrompere completamente il servizio**, spiegando per ciascuna:
- Come funziona tecnicamente
- In quale scenario è applicabile
- I rischi/limitazioni

**Strategia 1**: ___________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

**Strategia 2**: ___________________________________________________________________

_________________________________________________________________________________

_________________________________________________________________________________

---

## 📊 Griglia di Valutazione

| Sezione | Domande | Punti | Punteggio ottenuto |
|---------|---------|-------|--------------------|
| A — Vulnerabilità strutturali | A1, A2, A3 | 10 | _____ / 10 |
| B — Attacchi alla DMZ | B1, B2, B3, B4 | 16 | _____ / 16 |
| C — Hardening server DMZ | C1, C2, C3, C4 | 14 | _____ / 14 |
| D — Contromisure avanzate | D1, D2, D3, D4 | 14 | _____ / 14 |
| E — Monitoraggio e rilevamento | E1, E2, E3 | 10 | _____ / 10 |
| F — Risposta agli incidenti | F1, F2 | 6 | _____ / 6 |
| **TOTALE** | | **70** | **_____ / 70** |

### Conversione Voto Decimale

| Punti | Voto |
|-------|------|
| 63–70 | 10 |
| 56–62 | 9 |
| 49–55 | 8 |
| 42–48 | 7 |
| 35–41 | 6 |
| 28–34 | 5 |
| 21–27 | 4 |
| 14–20 | 3 |
| 7–13 | 2 |
| 0–6 | 1 |

---

*ES07-C | Verifica Teorica: Sicurezza della DMZ | SISTEMI E RETI*
