# 📖 Domande Teoriche

**Tempo:** 30 minuti  
**Punteggio:** Incluso nella valutazione documentazione

---

## Istruzioni

Rispondi alle seguenti domande in modo completo e preciso. Le risposte devono dimostrare la tua comprensione teorica degli argomenti trattati nell'esercitazione.

**Formato risposte:**
- Scrivi in modo chiaro e organizzato
- Usa elenchi puntati quando appropriato
- Supporta le risposte con esempi quando possibile

---

## Sezione A: VLAN (Virtual LAN)

### Domanda 1: Vantaggi delle VLAN (4 punti)

**Perché un'azienda dovrebbe implementare le VLAN invece di utilizzare una rete flat?**

Elenca e spiega **almeno 4 vantaggi** dell'utilizzo delle VLAN, con esempi pratici riferiti allo scenario TechCorp.

**Spazio risposta:**
```
1. _____________________________________________________________
   _____________________________________________________________

2. _____________________________________________________________
   _____________________________________________________________

3. _____________________________________________________________
   _____________________________________________________________

4. _____________________________________________________________
   _____________________________________________________________
```

---

### Domanda 2: Domini di Broadcast (3 punti)

**Cosa sono i domini di broadcast e come le VLAN li influenzano?**

Spiega:
- Cos'è un dominio di broadcast
- Cosa succede senza VLAN (tutti i PC nella stessa rete)
- Come cambiano i domini di broadcast con 4 VLAN

**Spazio risposta:**
```
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________
```

---

### Domanda 3: Tipi di Porte Switch (4 punti)

**Qual è la differenza tra porta ACCESS e porta TRUNK?**

Completa la seguente tabella comparativa:

| Caratteristica | Porta ACCESS | Porta TRUNK |
|----------------|--------------|-------------|
| **Numero VLAN** | | |
| **Tagging 802.1Q** | | |
| **Dispositivi collegati** | | |
| **Comando Cisco** | | |
| **Esempio in TechCorp** | | |

---

### Domanda 4: Configurazione VLAN (3 punti)

**Nella tua configurazione, hai creato la VLAN 10 sullo Switch-Amm. Spiega cosa accadrebbe se:**

a) Dimentichi di creare la VLAN prima di assegnare una porta:
```
_________________________________________________________________
```

b) Crei la VLAN ma dimentichi il comando `switchport access vlan 10`:
```
_________________________________________________________________
```

c) Configuri la porta in modalità trunk invece di access:
```
_________________________________________________________________
```

---

## Sezione B: Subnetting

### Domanda 5: Calcolo Subnetting (5 punti)

**Spiega passo per passo come hai calcolato il subnetting per TechCorp:**

a) Quanti bit hai preso in prestito dalla porzione host?
```
_________________________________________________________________
```

b) Perché hai scelto questa subnet mask invece di una diversa?
```
_________________________________________________________________
_________________________________________________________________
```

c) Formula usata per calcolare il numero di host disponibili:
```
_________________________________________________________________
```

d) Con 62 host disponibili per subnet, quanti host "sprechiamo" per il reparto Marketing (solo 10 richiesti)?
```
_________________________________________________________________
```

e) Questa è una situazione positiva o negativa? Perché?
```
_________________________________________________________________
_________________________________________________________________
```

---

### Domanda 6: VLSM (4 punti)

**Cos'è il VLSM (Variable Length Subnet Mask)?**

a) Definizione:
```
_________________________________________________________________
_________________________________________________________________
```

b) In quale situazione sarebbe vantaggioso usare VLSM per TechCorp?
```
_________________________________________________________________
_________________________________________________________________
```

c) Proponi uno schema VLSM alternativo per TechCorp usando subnet di dimensioni diverse:
```
- Amministrazione (15 host): _____ → subnet mask _____
- Sviluppo (25 host): _____ → subnet mask _____
- Marketing (10 host): _____ → subnet mask _____
- Server (pochi host): _____ → subnet mask _____
```

---

### Domanda 7: Indirizzi Speciali (3 punti)

**Per la subnet 172.16.100.0/26:**

a) Qual è l'indirizzo di rete? _________________

b) Qual è l'indirizzo di broadcast? _________________

c) Perché questi due indirizzi non possono essere assegnati a host?
```
_________________________________________________________________
_________________________________________________________________
```

---

## Sezione C: Router-on-a-Stick

### Domanda 8: Concetto Router-on-a-Stick (4 punti)

**Perché questa tecnica si chiama "Router-on-a-Stick"?**

a) Origine del nome:
```
_________________________________________________________________
_________________________________________________________________
```

b) Disegna uno schema semplificato che mostri come funziona:
```
     [Switch con VLAN 10, 20]
              |
          (Trunk)
              |
         [Router]
           /    \
        .10    .20
     (VLAN10) (VLAN20)
```

c) Quali sono i **vantaggi** di questa tecnica?
```
1. _____________________________________________________________
2. _____________________________________________________________
```

d) Quali sono i **limiti/svantaggi**?
```
1. _____________________________________________________________
2. _____________________________________________________________
```

---

### Domanda 9: Subinterface (4 punti)

**Cosa sono le subinterface e perché le usiamo?**

a) Definizione di subinterface:
```
_________________________________________________________________
_________________________________________________________________
```

b) Nel tuo router, quante subinterface hai configurato? __________

c) Completa questo comando spiegando ogni parte:
```
interface GigabitEthernet0/0.10
  ↓
Significa: _______________________________________________________

encapsulation dot1Q 10
  ↓
Significa: _______________________________________________________

ip address 172.16.100.1 255.255.255.192
  ↓
Significa: _______________________________________________________
```

---

### Domanda 10: Flusso Traffico Inter-VLAN (5 punti)

**Traccia il percorso di un pacchetto da PC-Amm-1 (172.16.100.10) a PC-Dev-1 (172.16.100.70):**

Completa la seguente sequenza:

```
1. PC-Amm-1 invia pacchetto con:
   - IP Sorgente: _________________
   - IP Destinazione: _________________
   - MAC Destinazione: _________________  (di chi?)

2. Switch-Amm riceve su porta Fa0/1:
   - Azione: _______________________________________________________
   - Tag VLAN aggiunto: ___________

3. Pacchetto viaggia su trunk verso Router:
   - Porta switch: _________________
   - Porta router: _________________

4. Router riceve su subinterface:
   - Quale subinterface? _________________
   - Azione del router: _______________________________________________

5. Router inoltra su subinterface:
   - Quale subinterface? _________________
   - Nuovo tag VLAN: ___________

6. Pacchetto viaggia verso Switch-Dev:
   - Porta router: _________________
   - Porta switch: _________________

7. Switch-Dev inoltra a destinazione:
   - Porta switch: _________________
   - Tag rimosso: Sì / No

8. PC-Dev-1 riceve il pacchetto
```

---

## Sezione D: Standard IEEE 802.1Q

### Domanda 11: Standard 802.1Q (4 punti)

**Cos'è lo standard IEEE 802.1Q e a cosa serve?**

a) Definizione e scopo:
```
_________________________________________________________________
_________________________________________________________________
```

b) Quali informazioni contiene il tag 802.1Q? (almeno 3)
```
1. _____________________________________________________________
2. _____________________________________________________________
3. _____________________________________________________________
```

c) Di quanti byte è il tag 802.1Q e dove viene inserito nel frame Ethernet?
```
_________________________________________________________________
```

d) Frame Ethernet standard vs 802.1Q-tagged:
```
Standard (1518 byte):  [MAC Dest][MAC Src][Type][Data][FCS]

802.1Q (_____ byte):   [MAC Dest][MAC Src][______][Type][Data][FCS]
```

---

### Domanda 12: VLAN ID (3 punti)

**Il campo VID (VLAN ID) nel tag 802.1Q:**

a) Quanti bit occupa? __________

b) Range di valori possibili: da _______ a _______

c) Quali valori sono riservati e non possono essere usati?
```
- VLAN 0: ________________________________________________________
- VLAN 1: ________________________________________________________
- VLAN 4095: _____________________________________________________
```

---

### Domanda 13: Native VLAN (4 punti)

**Cos'è la Native VLAN?**

a) Definizione:
```
_________________________________________________________________
_________________________________________________________________
```

b) Valore di default: __________

c) Traffico sulla Native VLAN viaggia: ☐ Tagged  ☐ Untagged

d) Perché è importante che la Native VLAN sia uguale su entrambi i lati del trunk?
```
_________________________________________________________________
_________________________________________________________________
```

e) Quale comando useresti per cambiare la Native VLAN?
```
_________________________________________________________________
```

---

## Sezione E: Comandi e Troubleshooting

### Domanda 14: Comandi di Verifica (5 punti)

**Associa ogni comando al suo output corretto:**

| # | Comando | Output Mostra |
|---|---------|---------------|
| 1 | `show vlan brief` | A. Interfacce router con IP |
| 2 | `show interfaces trunk` | B. VLAN e porte assegnate |
| 3 | `show ip interface brief` | C. Tabella di routing |
| 4 | `show ip route` | D. Porte in modalità trunk |
| 5 | `show running-config` | E. Configurazione corrente |

**Risposte:** 1-___, 2-___, 3-___, 4-___, 5-___

---

### Domanda 15: Troubleshooting Scenario 1 (4 punti)

**Problema:** PC-Amm-1 riesce a pingare il proprio gateway (172.16.100.1) ma NON riesce a pingare PC-Dev-1 (172.16.100.70).

**Possibili cause (elencane almeno 3):**
```
1. _____________________________________________________________
2. _____________________________________________________________
3. _____________________________________________________________
```

**Quali comandi useresti per diagnosticare il problema? (almeno 3)**
```
1. _____________________________________________________________
2. _____________________________________________________________
3. _____________________________________________________________
```

---

### Domanda 16: Troubleshooting Scenario 2 (3 punti)

**Problema:** Dopo aver configurato il trunk su Switch-Amm, il comando `show interfaces trunk` non mostra la porta Gi0/1.

**Cosa potrebbe essere andato storto?**
```
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________
```

**Quale comando useresti per verificare lo stato della porta?**
```
_________________________________________________________________
```

---

### Domanda 17: Troubleshooting Scenario 3 (3 punti)

**Problema:** Il router mostra l'interfaccia GigabitEthernet0/0.10 come "down/down" nel comando `show ip interface brief`.

**Possibili cause:**
```
1. _____________________________________________________________
2. _____________________________________________________________
```

**Come risolveresti?**
```
_________________________________________________________________
_________________________________________________________________
```

---

## Sezione F: Scenari Avanzati

### Domanda 18: Espansione Rete (4 punti)

**TechCorp vuole aggiungere un nuovo reparto "Ospiti" (VLAN 50) con 8 postazioni.**

a) C'è spazio nella rete 172.16.100.0/24 per una quinta subnet /26?
```
☐ Sì  ☐ No

Spiegazione: _____________________________________________________
_________________________________________________________________
```

b) Se NO, quali soluzioni proporresti? (almeno 2)
```
1. _____________________________________________________________
2. _____________________________________________________________
```

c) Quali modifiche dovresti fare alla configurazione esistente?
```
- Switch: ________________________________________________________
- Router: ________________________________________________________
```

---

### Domanda 19: Sicurezza VLAN (4 punti)

**Per motivi di sicurezza, il reparto Amministrazione NON deve poter accedere al reparto Sviluppo.**

a) Attualmente, PC-Amm-1 può pingare PC-Dev-1?  ☐ Sì  ☐ No

b) Quale tecnologia Cisco useresti per bloccare il traffico tra queste VLAN?
```
_________________________________________________________________
```

c) Scrivi uno pseudo-comando (anche semplificato) per implementare questa policy:
```
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________
```

---

### Domanda 20: Performance (3 punti)

**Con 100 dispositivi nella VLAN Sviluppo, il link trunk verso il router potrebbe diventare un bottleneck.**

a) Perché? Spiega il problema:
```
_________________________________________________________________
_________________________________________________________________
```

b) Quale soluzione alternativa al Router-on-a-Stick risolverebbe questo problema?
```
_________________________________________________________________
_________________________________________________________________
```

c) Nomina il tipo di dispositivo necessario:
```
_________________________________________________________________
```

---

## Consegna

**Formato:** Documento Google

**Contenuto:**
- Tutte le 20 domande con risposte complete
- Formattazione chiara e leggibile
- Eventuali schemi/disegni per domande che lo richiedono

**Punteggio totale teoria:** 70 punti (contribuisce alla valutazione finale)

---

## Griglia Valutazione Teoria

| Sezione | Domande | Punti Max |
|---------|---------|-----------|
| A. VLAN | 1-4 | 14 |
| B. Subnetting | 5-7 | 12 |
| C. Router-on-a-Stick | 8-10 | 13 |
| D. IEEE 802.1Q | 11-13 | 11 |
| E. Comandi e Troubleshooting | 14-17 | 15 |
| F. Scenari Avanzati | 18-20 | 11 |
| **TOTALE** | **20 domande** | **70 punti** |

**Sufficienza:** 42/70 (60%)  
**Buono:** 52/70 (75%)  
**Ottimo:** 63/70 (90%)

---

## 💡 Suggerimenti per le Risposte

1. **Sii specifico:** Evita risposte generiche
2. **Usa terminologia corretta:** Dimostra di conoscere i termini tecnici
3. **Fornisci esempi:** Riferimenti a TechCorp rendono le risposte più concrete
4. **Spiega il "perché":** Non solo il "cosa" ma anche il "perché"
5. **Rileggi:** Controlla ortografia e completezza prima di consegnare

**Buon lavoro! 📚**
