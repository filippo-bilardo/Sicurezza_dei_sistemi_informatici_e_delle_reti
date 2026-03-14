# Subnetting

## Introduzione

Il **subnetting** è il processo di divisione di una rete IP in sottoreti (subnet) più piccole. Questa tecnica è fondamentale per:
- Ottimizzare l'utilizzo degli indirizzi IP
- Migliorare le prestazioni di rete
- Aumentare la sicurezza
- Facilitare la gestione

## Classi di Indirizzi IP (Classful Addressing)

### Classe A
- **Range**: 0.0.0.0 - 127.255.255.255
- **Subnet Mask default**: 255.0.0.0 (/8)
- **Host**: 16.777.214 (2^24 - 2)

### Classe B
- **Range**: 128.0.0.0 - 191.255.255.255
- **Subnet Mask default**: 255.255.0.0 (/16)
- **Host**: 65.534 (2^16 - 2)

### Classe C
- **Range**: 192.0.0.0 - 223.255.255.255
- **Subnet Mask default**: 255.255.255.0 (/24)
- **Host**: 254 (2^8 - 2)

## Indirizzi IP Privati (RFC 1918)

Non instradabili su Internet pubblico:

- **Classe A**: 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
- **Classe B**: 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
- **Classe C**: 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)

## Subnet Mask

La **subnet mask** determina quale parte dell'indirizzo IP identifica la rete e quale identifica l'host.

### Notazione CIDR (Classless Inter-Domain Routing)

| CIDR | Subnet Mask | Host Utilizzabili |
|------|-------------|-------------------|
| /24 | 255.255.255.0 | 254 |
| /25 | 255.255.255.128 | 126 |
| /26 | 255.255.255.192 | 62 |
| /27 | 255.255.255.224 | 30 |
| /28 | 255.255.255.240 | 14 |
| /29 | 255.255.255.248 | 6 |
| /30 | 255.255.255.252 | 2 |

## Formula di Calcolo

### Numero di Host per Subnet
```
Host utilizzabili = 2^n - 2
```
dove **n** = numero di bit per host

**-2** perché:
- 1 indirizzo = Network Address (tutti bit host a 0)
- 1 indirizzo = Broadcast Address (tutti bit host a 1)

### Numero di Subnet
```
Numero di subnet = 2^s
```
dove **s** = numero di bit presi in prestito dalla porzione host

## Processo di Subnetting

### Esempio: Dividere 192.168.10.0/24 in 5 subnet

**Step 1**: Determinare quanti bit servono
```
2^2 = 4 (insufficiente)
2^3 = 8 ✓
```
Servono **3 bit** per ottenere almeno 5 subnet.

**Step 2**: Nuova subnet mask
```
Originale: /24
Nuova: /27 (255.255.255.224)
```

**Step 3**: Calcolare dimensione
```
Host per subnet = 2^5 - 2 = 30 host
Dimensione blocco = 32
```

**Step 4**: Elencare le subnet (prime 5)

| Subnet | Network | Range Host | Broadcast | Host |
|--------|---------|------------|-----------|------|
| 1 | 192.168.10.0/27 | .1 - .30 | 192.168.10.31 | 30 |
| 2 | 192.168.10.32/27 | .33 - .62 | 192.168.10.63 | 30 |
| 3 | 192.168.10.64/27 | .65 - .94 | 192.168.10.95 | 30 |
| 4 | 192.168.10.96/27 | .97 - .126 | 192.168.10.127 | 30 |
| 5 | 192.168.10.128/27 | .129 - .158 | 192.168.10.159 | 30 |

## VLSM - Variable Length Subnet Mask

### Cos'è il VLSM?

Il **VLSM** (Variable Length Subnet Mask) è una tecnica avanzata di subnetting che permette di utilizzare **subnet mask di lunghezza diversa** all'interno della stessa rete principale.

**Vantaggi del VLSM:**
- ✅ **Ottimizzazione**: Riduce drasticamente lo spreco di indirizzi IP
- ✅ **Flessibilità**: Adatta la dimensione della subnet alle esigenze reali
- ✅ **Scalabilità**: Facilita l'espansione futura della rete
- ✅ **Efficienza**: Massimizza l'uso dello spazio di indirizzamento disponibile

**Differenza con il Subnetting Classico:**

| Aspetto | Subnetting Classico | VLSM |
|---------|---------------------|------|
| Subnet Mask | **Uguale** per tutte le subnet | **Variabile** per ogni subnet |
| Sprechi | Molti indirizzi inutilizzati | Minimi sprechi |
| Complessità | Semplice | Richiede pianificazione accurata |
| Uso | Reti uniformi | Reti con esigenze diverse |

### Quando Usare il VLSM?

**Scenario tipico:** Azienda con reparti di dimensioni diverse

- Reparto Produzione: 100 dipendenti → Serve /25 (126 host)
- Reparto Amministrazione: 50 dipendenti → Serve /26 (62 host)
- Reparto Marketing: 25 dipendenti → Serve /27 (30 host)
- Link punto-punto tra router: 2 indirizzi → Serve /30 (2 host)

Con subnetting classico (/25 per tutti) → **sprechi enormi!**  
Con VLSM → **ogni subnet dimensionata correttamente**

### Procedura Step-by-Step per VLSM

#### Esempio Pratico Completo

**Rete assegnata**: 192.168.10.0/24

**Requisiti:**
1. Sede A (Uffici): 100 host
2. Sede B (Magazzino): 50 host
3. Sede C (Laboratorio): 25 host
4. Collegamento Router-Router: 2 host
5. Rete Management: 10 host

---

#### STEP 1: Ordinare le Subnet (dalla più grande alla più piccola)

**REGOLA FONDAMENTALE:** Sempre partire dalla subnet più grande!

| Priorità | Subnet | Host Richiesti | Host Utilizzabili | Mask | Blocco |
|----------|--------|----------------|-------------------|------|--------|
| 1 | Sede A | 100 | 126 | /25 | 128 |
| 2 | Sede B | 50 | 62 | /26 | 64 |
| 3 | Sede C | 25 | 30 | /27 | 32 |
| 4 | Management | 10 | 14 | /28 | 16 |
| 5 | Router-Router | 2 | 2 | /30 | 4 |

#### STEP 2: Calcolare la Subnet Mask Necessaria

**Formula**: 2^n - 2 ≥ Host richiesti

**Esempio Sede A (100 host):**
```
2^6 - 2 = 62  ❌ Insufficiente
2^7 - 2 = 126 ✅ Sufficiente

Bit per host: 7
Bit per rete: 32 - 7 = 25
Mask: /25
```

#### STEP 3: Allocazione Sequenziale (NON sovrapporre!)

**Subnet 1 - Sede A (/25)**
```
Network:    192.168.10.0/25
Range:      192.168.10.1 - 192.168.10.126
Broadcast:  192.168.10.127
Blocco:     128 indirizzi (0-127)
```

**Subnet 2 - Sede B (/26)**
```
Network:    192.168.10.128/26
Range:      192.168.10.129 - 192.168.10.190
Broadcast:  192.168.10.191
Blocco:     64 indirizzi (128-191)
```

**Subnet 3 - Sede C (/27)**
```
Network:    192.168.10.192/27
Range:      192.168.10.193 - 192.168.10.222
Broadcast:  192.168.10.223
Blocco:     32 indirizzi (192-223)
```

**Subnet 4 - Management (/28)**
```
Network:    192.168.10.224/28
Range:      192.168.10.225 - 192.168.10.238
Broadcast:  192.168.10.239
Blocco:     16 indirizzi (224-239)
```

**Subnet 5 - Router-Router (/30)**
```
Network:    192.168.10.240/30
Range:      192.168.10.241 - 192.168.10.242
Broadcast:  192.168.10.243
Blocco:     4 indirizzi (240-243)
```

**Spazio rimanente:** 192.168.10.244 - 192.168.10.255 (12 indirizzi) → **Riservato per espansioni**

#### STEP 4: Verifica Finale

**Controllo sovrapposizioni:**
```
✅ 0-127     (Sede A)
✅ 128-191   (Sede B)
✅ 192-223   (Sede C)
✅ 224-239   (Management)
✅ 240-243   (Router-Router)
```
**Nessuna sovrapposizione!** ✓

### Schema Visivo VLSM

```
192.168.10.0/24 (256 indirizzi totali)
│
├─ 192.168.10.0/25     [Sede A - 128 IP]  ████████████████
├─ 192.168.10.128/26   [Sede B - 64 IP]   ████████
├─ 192.168.10.192/27   [Sede C - 32 IP]   ████
├─ 192.168.10.224/28   [Mgmt - 16 IP]     ██
├─ 192.168.10.240/30   [Router - 4 IP]    █
└─ 192.168.10.244-255  [Riservato - 12]   -
```

### Tabella di Confronto: Con e Senza VLSM

**SENZA VLSM** (tutte /25 = 126 host):

| Subnet | Mask | Host Richiesti | Host Allocati | **Spreco** |
|--------|------|----------------|---------------|-----------|
| Sede A | /25 | 100 | 126 | 26 (21%) |
| Sede B | /25 | 50 | 126 | **76 (60%)** ❌ |
| Sede C | /25 | 25 | 126 | **101 (80%)** ❌ |
| **TOTALE** | - | 175 | 378 | **203 (54%)** 💸 |

**CON VLSM** (mask variabili):

| Subnet | Mask | Host Richiesti | Host Allocati | **Spreco** |
|--------|------|----------------|---------------|-----------|
| Sede A | /25 | 100 | 126 | 26 (21%) |
| Sede B | /26 | 50 | 62 | 12 (19%) ✅ |
| Sede C | /27 | 25 | 30 | 5 (17%) ✅ |
| Management | /28 | 10 | 14 | 4 (29%) ✅ |
| Router | /30 | 2 | 2 | 0 (0%) ✅ |
| **TOTALE** | - | 187 | 234 | **47 (20%)** 💰 |

**Risparmio con VLSM: 156 indirizzi recuperati!**

### Errori Comuni nel VLSM

❌ **Errore 1**: Allocare prima le subnet piccole
```
Se allochi /30 a 192.168.10.0, poi /25 non entra bene!
```

✅ **Corretto**: Sempre dalla più grande alla più piccola

---

❌ **Errore 2**: Sovrapporre gli indirizzi
```
Subnet A: 192.168.10.0/26   (0-63)
Subnet B: 192.168.10.32/27  (32-63)  ← SOVRAPPOSIZIONE! ❌
```

✅ **Corretto**: Controllare che il prossimo network = precedente broadcast + 1

---

❌ **Errore 3**: Dimenticare network e broadcast
```
Host richiesti: 30
Pensare: /27 = 32 → OK
Realtà: 32 - 2 = 30 utilizzabili ✓ (appena sufficiente)
```

✅ **Corretto**: Sempre usare 2^n - 2

### Configurazione Router con VLSM

**Esempio routing statico:**

```cisco
Router(config)# ip route 192.168.10.0 255.255.255.128 10.0.0.1
Router(config)# ip route 192.168.10.128 255.255.255.192 10.0.0.2
Router(config)# ip route 192.168.10.192 255.255.255.224 10.0.0.3
Router(config)# ip route 192.168.10.224 255.255.255.240 10.0.0.4
Router(config)# ip route 192.168.10.240 255.255.255.252 10.0.0.5
```

**Nota:** Ogni subnet ha una mask diversa! Questo è VLSM.

### Protocolli di Routing e VLSM

**Protocolli che SUPPORTANO VLSM:**
- ✅ **RIPv2** (Routing Information Protocol versione 2)
- ✅ **OSPF** (Open Shortest Path First)
- ✅ **EIGRP** (Enhanced Interior Gateway Routing Protocol)
- ✅ **BGP** (Border Gateway Protocol)

**Protocolli che NON supportano VLSM:**
- ❌ **RIPv1** (versione 1 - classful)
- ❌ **IGRP** (Interior Gateway Routing Protocol - obsoleto)

**Perché?** I protocolli classful non inviano la subnet mask negli update di routing!

## Calcolo Rapido della Subnet

### Metodo della "Magia del 256"

```
Blocco = 256 - Valore ottetto subnet mask
```

**Esempio /27:**
```
Subnet mask: 255.255.255.224
Blocco = 256 - 224 = 32
Subnet: 0, 32, 64, 96, 128, 160, 192, 224
```

### Determinare a quale subnet appartiene un IP

**IP**: 192.168.10.75  
**Mask**: /27 (blocco 32)

```
75 ÷ 32 = 2.34...
Subnet = 32 × 2 = 64

Network: 192.168.10.64/27
Broadcast: 192.168.10.95
Range: 192.168.10.65 - 192.168.10.94
```

## Best Practices

1. **Pianificare in anticipo**: Stimare crescita futura
2. **Documentare**: Tenere schema di indirizzamento aggiornato
3. **Usare VLSM**: Ottimizzare utilizzo indirizzi
4. **Riservare spazio**: Mantenere subnet per espansioni
5. **Point-to-point links**: Usare /30 o /31

## Conclusioni

Il subnetting è una competenza fondamentale per:
- **Network Design**: Progettare reti efficienti
- **Troubleshooting**: Diagnosticare problemi di connettività
- **Sicurezza**: Segmentare la rete per controllo accessi
- **Ottimizzazione**: Ridurre traffico broadcast
