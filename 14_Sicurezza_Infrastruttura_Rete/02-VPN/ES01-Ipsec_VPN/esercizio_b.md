# ES08-B — Progetto autonomo: VPN Hub-and-Spoke per MultiSede S.p.A.

> **Tipo**: 🏗️ Progetto autonomo  
> **Durata stimata**: 2–3 ore  
> **Punteggio**: 50 punti base + 20 punti bonus  
> **File da consegnare**: `es08b_multisede.pkt` + relazione tecnica (schema topologia, tabelle, test)

---

## 🏢 Scenario aziendale

**MultiSede S.p.A.** è un'azienda italiana con presenza in 4 città. Il CTO ha richiesto
di progettare e implementare una soluzione VPN che colleghi tutte le sedi in modo sicuro,
garantendo che ogni filiale possa raggiungere i server della sede centrale (HQ) a Roma.

### Requisiti del cliente

> *"Vogliamo che tutti i dipendenti di Milano, Napoli e Bari possano accedere ai sistemi
> gestionali della sede di Roma in modo sicuro. Il traffico tra filiali può passare per Roma.
> Ogni sede deve avere la propria LAN separata e il tutto deve essere documentato."*
> — Marco Ferretti, CTO di MultiSede S.p.A.

---

## 🗺️ Schema topologia (da realizzare)

```
                    ┌───────────────────────────────┐
                    │        INTERNET ISP           │
                    │       (simulata in PT)        │
                    │                               │
          ┌─────────┤ Router-ISP (hub centrale WAN) ├─────────┐
          │         └──────────┬────────────────────┘         │
          │                    │                              │
   ┌──────┴────┐        ┌──────┴────┐                  ┌──────┴────┐
   │Router-Nord│        │ Router-HQ │                  │Router-Est │
   │ (Milano)  │        │  (Roma)   │                  │  (Bari)   │
   └─────┬─────┘        └─────┬─────┘                  └─────┬─────┘
         │                    │                              │
    LAN Milano            LAN Roma                       LAN Bari
    10.0.2.0/24           10.0.1.0/24                   10.0.4.0/24
                               │
                        ┌──────┴────┐
                        │Router-Sud │
                        │  (Napoli) │
                        └─────┬─────┘
                               │
                          LAN Napoli
                          10.0.3.0/24
```

> 💡 **Nota topologia**: Router-ISP è un router centrale che simula Internet.
> Ogni router di sede è collegato direttamente a Router-ISP tramite un link /30.
> I tunnel VPN sono tra Router-HQ e ciascun Router-filiale (Hub-and-Spoke).

---

## 📋 STEP 1 — Piano di indirizzamento (da completare)

### Reti LAN delle sedi

| Sede | Router | Rete LAN | Interfaccia LAN | IP Interfaccia LAN |
|------|--------|----------|-----------------|-------------------|
| Roma (HQ) | Router-HQ | 10.0.1.0/24 | Gi0/0 | 10.0.1.1 |
| Milano (Nord) | Router-Nord | 10.0.2.0/24 | Gi0/0 | 10.0.2.1 |
| Napoli (Sud) | Router-Sud | 10.0.3.0/24 | Gi0/0 | 10.0.3.1 |
| Bari (Est) | Router-Est | 10.0.4.0/24 | Gi0/0 | 10.0.4.1 |

### Reti WAN /30 — da completare

Suddividi la rete `203.0.113.0/24` in subnet /30 per ogni link WAN:

| Link | Rete /30 | IP Router-ISP | IP Router-sede | Router-sede |
|------|----------|--------------|----------------|-------------|
| ISP ↔ HQ | 203.0.113.0/30 | 203.0.113.1 | 203.0.113.2 | Router-HQ |
| ISP ↔ Nord | 203.0.113.___/30 | 203.0.113.___ | 203.0.113.___ | Router-Nord |
| ISP ↔ Sud | 203.0.113.___/30 | 203.0.113.___ | 203.0.113.___ | Router-Sud |
| ISP ↔ Est | 203.0.113.___/30 | 203.0.113.___ | 203.0.113.___ | Router-Est |

> 💡 **Suggerimento**: usa le subnet /30 consecutive: .0/30, .4/30, .8/30, .12/30
> Ogni /30 ha 4 indirizzi: rete, 2 host utilizzabili, broadcast.

### Dispositivi end-user (da completare)

Per ogni sede, configura almeno 2 PC:

| Sede | Dispositivo | IP | Gateway |
|------|------------|-----|---------|
| Roma HQ | PC-HQ1 | 10.0.1.10 | 10.0.1.1 |
| Roma HQ | PC-HQ2 | 10.0.1.11 | 10.0.1.1 |
| Roma HQ | Server-HQ | 10.0.1.100 | 10.0.1.1 |
| Milano | PC-NORD1 | 10.0.2.10 | 10.0.2.1 |
| Milano | PC-NORD2 | ___________ | _________ |
| Napoli | PC-SUD1 | ___________ | _________ |
| Napoli | PC-SUD2 | ___________ | _________ |
| Bari | PC-EST1 | ___________ | _________ |
| Bari | PC-EST2 | ___________ | _________ |

---

## 🖥️ STEP 2 — Creazione topologia in Packet Tracer

### Dispositivi richiesti

| Tipo | Modello | Quantità | Nomi |
|------|---------|----------|------|
| Router | Cisco 2901 | 5 | Router-HQ, Router-Nord, Router-Sud, Router-Est, Router-ISP |
| Switch | Cisco 2960 | 4 | Switch-HQ, Switch-Nord, Switch-Sud, Switch-Est |
| PC | PC generico | 8 | 2 per sede (+ Server-HQ opzionale) |

### Cablaggio (da eseguire)

Collega ogni router di sede all'interfaccia corrispondente di Router-ISP usando cavi
**Copper Straight-Through**. Usa le porte disponibili su Router-ISP (aggiungere moduli
NM-1FE-TX se necessario per avere abbastanza porte FastEthernet).

### ✅ Checklist STEP 2

- [ ] Tutti i dispositivi inseriti e rinominati correttamente
- [ ] Router-ISP collegato a tutti e 4 i router di sede
- [ ] Switch collegati ai rispettivi router (Gi0/0)
- [ ] PC/Server collegati agli switch
- [ ] Tutte le connessioni mostrano luci verdi

---

## ⚙️ STEP 3 — Configurazione IP base e routing

Configura gli indirizzi IP su tutte le interfacce di tutti i router e su tutti gli end-device.

### Routing richiesto

| Router | Route statica | Via (next-hop) | Scopo |
|--------|--------------|----------------|-------|
| Router-HQ | 10.0.2.0/24 | 203.0.113.1 | Raggiungi LAN Milano |
| Router-HQ | 10.0.3.0/24 | 203.0.113.1 | Raggiungi LAN Napoli |
| Router-HQ | 10.0.4.0/24 | 203.0.113.1 | Raggiungi LAN Bari |
| Router-Nord | 0.0.0.0/0 | 203.0.113.X | Default route verso ISP |
| Router-Sud | 0.0.0.0/0 | 203.0.113.X | Default route verso ISP |
| Router-Est | 0.0.0.0/0 | 203.0.113.X | Default route verso ISP |
| Router-ISP | 10.0.1.0/24 | 203.0.113.2 | Raggiungi LAN HQ |
| Router-ISP | 10.0.2.0/24 | 203.0.113.X | Raggiungi LAN Milano |
| Router-ISP | 10.0.3.0/24 | 203.0.113.X | Raggiungi LAN Napoli |
| Router-ISP | 10.0.4.0/24 | 203.0.113.X | Raggiungi LAN Bari |

> ⚠️ Le filiali comunicano tra loro SOLO passando per HQ (hub-and-spoke).
> Quindi Router-Nord non ha route diretta verso 10.0.3.0 o 10.0.4.0 —
> il traffico Nord→Sud passa per HQ: Nord → ISP → HQ → ISP → Sud.
> **Router-HQ deve avere route verso TUTTE le LAN delle filiali.**

### ✅ Checklist STEP 3

- [ ] Tutti gli IP configurati su tutte le interfacce router
- [ ] Tutti gli IP configurati su PC e Server
- [ ] Ping funzionante tra router adiacenti (e.g., Router-Nord ↔ Router-ISP)
- [ ] Ping funzionante da ogni filiale a Router-HQ (IP WAN)
- [ ] Ping funzionante tra LAN diverse PRIMA della VPN

---

## 🔒 STEP 4 — Configurazione VPN IPsec Hub-and-Spoke

Devi configurare **3 tunnel VPN separati**, tutti partenti da Router-HQ:

```
Router-HQ ══════ Tunnel VPN 1 ══════ Router-Nord (Milano)
Router-HQ ══════ Tunnel VPN 2 ══════ Router-Sud (Napoli)
Router-HQ ══════ Tunnel VPN 3 ══════ Router-Est (Bari)
```

### Parametri ISAKMP da usare (uguali per tutti i tunnel)

| Parametro | Valore |
|-----------|--------|
| Policy number | 10 |
| Encryption | AES |
| Hash | SHA |
| Authentication | pre-share |
| DH Group | 2 |
| Lifetime | 86400 |

### Chiavi PSK da usare

| Tunnel | PSK |
|--------|-----|
| HQ ↔ Nord | `HQ_NORD_SECRET` |
| HQ ↔ Sud | `HQ_SUD_SECRET` |
| HQ ↔ Est | `HQ_EST_SECRET` |

> 💡 Ogni tunnel ha una PSK diversa — in produzione questo è più sicuro
> perché compromettere una chiave non espone gli altri tunnel.

### Struttura crypto map su Router-HQ (3 entry)

```
crypto map VPN-HQ 10 ipsec-isakmp    ← Tunnel verso Nord
crypto map VPN-HQ 20 ipsec-isakmp    ← Tunnel verso Sud
crypto map VPN-HQ 30 ipsec-isakmp    ← Tunnel verso Est
```

> 💡 Una sola `crypto map` su Router-HQ con 3 entry numerate (10, 20, 30),
> applicata una sola volta sull'interfaccia WAN.

### ACL VPN-TRAFFIC per Router-HQ

```
! ACL per tunnel HQ ↔ Nord
ip access-list extended VPN-TRAFFIC-NORD
 permit ip 10.0.1.0 0.0.0.255 10.0.2.0 0.0.0.255

! ACL per tunnel HQ ↔ Sud
ip access-list extended VPN-TRAFFIC-SUD
 permit ip 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255

! ACL per tunnel HQ ↔ Est
ip access-list extended VPN-TRAFFIC-EST
 permit ip 10.0.1.0 0.0.0.255 10.0.4.0 0.0.0.255
```

### ✅ Checklist STEP 4

- [ ] ISAKMP policy configurata su tutti e 4 i router (HQ + 3 filiali)
- [ ] PSK configurate correttamente su HQ e su ogni filiale (con IP peer corretto)
- [ ] Transform-set `VPN-TRANSFORM` configurato su tutti i router
- [ ] ACL VPN-TRAFFIC configurate (speculari tra HQ e ogni filiale)
- [ ] Crypto map con 3 entry su Router-HQ
- [ ] Crypto map con 1 entry su ogni router filiale
- [ ] Crypto map applicata sull'interfaccia WAN di TUTTI i router (HQ + filiali)

---

## 🧪 STEP 5 — Test di connettività

### Attivazione dei tunnel

Esegui i ping seguenti per attivare i 3 tunnel:

```
PC-HQ1 → ping 10.0.2.10   (attiva tunnel HQ ↔ Nord)
PC-HQ1 → ping 10.0.3.10   (attiva tunnel HQ ↔ Sud)
PC-HQ1 → ping 10.0.4.10   (attiva tunnel HQ ↔ Est)
```

### Tabella test completa — da compilare

| # | Da | A | IP destinazione | Atteso | Esito | Note |
|---|----|---|----------------|--------|-------|------|
| 1 | PC-HQ1 | PC-NORD1 | 10.0.2.10 | ✅ OK | | Tunnel HQ↔Nord |
| 2 | PC-HQ1 | PC-SUD1 | 10.0.3.10 | ✅ OK | | Tunnel HQ↔Sud |
| 3 | PC-HQ1 | PC-EST1 | 10.0.4.10 | ✅ OK | | Tunnel HQ↔Est |
| 4 | PC-NORD1 | Server-HQ | 10.0.1.100 | ✅ OK | | Filiale accede server HQ |
| 5 | PC-SUD1 | Server-HQ | 10.0.1.100 | ✅ OK | | Filiale accede server HQ |
| 6 | PC-EST1 | Server-HQ | 10.0.1.100 | ✅ OK | | Filiale accede server HQ |
| 7 | PC-NORD1 | PC-SUD1 | 10.0.3.10 | ✅ OK | | Nord→Sud via HQ |
| 8 | PC-NORD1 | PC-EST1 | 10.0.4.10 | ✅ OK | | Nord→Est via HQ |
| 9 | PC-SUD1 | PC-EST1 | 10.0.4.10 | ✅ OK | | Sud→Est via HQ |
| 10 | PC-EST1 | PC-NORD1 | 10.0.2.10 | ✅ OK | | Est→Nord via HQ |

> ⚠️ **Test 7–10 (comunicazione inter-filiale)**: questo è il punto più delicato
> della topologia hub-and-spoke. Il traffico Nord→Sud deve passare attraverso HQ:
> Nord → ISP → HQ → ISP → Sud. Per far funzionare questo, Router-HQ deve avere
> la VPN attiva verso ENTRAMBE le filiali e il routing deve essere corretto.

### Verifica stato tunnel su Router-HQ

```
Router-HQ# show crypto isakmp sa
Router-HQ# show crypto ipsec sa
Router-HQ# show crypto map
```

Dovrai vedere 3 SA Phase 1 (una per ogni filiale) e 6 SA Phase 2 (2 per ogni tunnel, una per direzione).

### ✅ Checklist STEP 5

- [ ] Tutti i 10 test eseguiti e documentati nella tabella
- [ ] `show crypto isakmp sa` mostra 3 SA ACTIVE su Router-HQ
- [ ] Contatori encaps/decaps > 0 per tutti i tunnel
- [ ] Screenshot dei comandi di verifica

---

## 📄 STEP 6 — Documentazione tecnica

Prepara una breve relazione tecnica (può essere in un file .txt o .docx separato) con:

### Sezione 1 — Schema topologia

Ridisegna lo schema della rete realizzata con tutti gli indirizzi IP (puoi usare uno
strumento di disegno o ASCII art). Lo schema deve includere:
- Tutti i router con IP di ogni interfaccia
- Le reti LAN con prefisso
- I link WAN con subnet /30
- I tunnel VPN indicati (frecce tratteggiate)

### Sezione 2 — Tabella indirizzamento completa

Tabella con tutti i dispositivi, interfacce, IP, subnet mask e gateway.

### Sezione 3 — Spiegazione Hub-and-Spoke vs Full-Mesh

Rispondi alle seguenti domande (minimo 5 righe per domanda):

**Domanda 1**: Cosa significa topologia Hub-and-Spoke in una VPN?
Quali sono i vantaggi rispetto a una topologia Full-Mesh?

**Domanda 2**: In questa configurazione, se un dipendente di Milano (Nord) vuole
comunicare con un collega di Napoli (Sud), attraverso quali router passano i pacchetti?
Disegna il percorso.

**Domanda 3**: Quanti tunnel VPN sono necessari con Hub-and-Spoke (4 sedi)?
Quanti ne servirebbero con Full-Mesh (tutte le sedi collegate direttamente)?
Usa la formula: N*(N-1)/2 per Full-Mesh.

**Domanda 4**: Quali sono gli svantaggi di Hub-and-Spoke rispetto a Full-Mesh?
Pensa a: latenza, Single Point of Failure, banda sul router HQ.

### Sezione 4 — Tabella test compilata

La tabella dei 10 test con esiti reali (OK o FALLITO) e eventuali note.

### ✅ Checklist STEP 6

- [ ] Schema topologia con tutti gli IP
- [ ] Tabella indirizzamento completa
- [ ] Risposta alle 4 domande (minimo 5 righe ognuna)
- [ ] Tabella test compilata con esiti reali

---

## 💾 STEP 7 — Salvataggio e consegna

1. Salva il file PT come `es08b_multisede.pkt`
2. Prepara la relazione tecnica (anche come commenti nel file PT o file separato)
3. Esegui uno screenshot finale con tutti i tunnel attivi

### ✅ Checklist finale

- [ ] File `es08b_multisede.pkt` salvato
- [ ] Relazione tecnica completata
- [ ] Tutti i tunnel VPN funzionanti
- [ ] Screenshot finale con `show crypto isakmp sa` (3 tunnel ACTIVE)

---

## 📊 Rubrica di valutazione — 50 punti base

| Criterio | Punti | Descrizione |
|---------|-------|-------------|
| **Piano di indirizzamento** | 8 pt | Tabelle complete e corrette (LAN + WAN /30) |
| **Topologia PT** | 6 pt | Tutti i dispositivi, cablaggio corretto, IP configurati |
| **Routing base** | 6 pt | Route statiche corrette su tutti i router, ping base funzionante |
| **VPN HQ↔Nord** | 8 pt | Tunnel IPsec funzionante tra HQ e Milano |
| **VPN HQ↔Sud** | 8 pt | Tunnel IPsec funzionante tra HQ e Napoli |
| **VPN HQ↔Est** | 8 pt | Tunnel IPsec funzionante tra HQ e Bari |
| **Test connettività** | 6 pt | Tabella 10 test compilata con esiti |

### 🌟 Bonus — fino a 20 punti aggiuntivi

| Bonus | Punti | Descrizione |
|-------|-------|-------------|
| **Full-Mesh opzionale** | +8 pt | Aggiungi tunnel VPN diretti tra le filiali (6 tunnel totali anziché 3), modifica le ACL e testa la connettività diretta Nord↔Sud senza passare per HQ |
| **GRE over IPsec** | +6 pt | Sostituisci un tunnel IPsec puro con GRE over IPsec (configura un'interfaccia Tunnel0 tra HQ e una filiale, poi proteggi con IPsec). Documenta i vantaggi. |
| **Documentazione professionale** | +6 pt | Schema topologia professionale (draw.io, Visio, o simili), relazione tecnica dettagliata con spiegazione delle scelte progettuali, confronto Hub-and-Spoke vs Full-Mesh con tabella vantaggi/svantaggi |

---

## 💡 Suggerimenti per la risoluzione

### Ordine consigliato di configurazione

1. Prima configura tutto il routing base (STEP 3) e verifica i ping base
2. Poi configura VPN solo tra HQ e Nord — verifica che funzioni
3. Poi aggiungi VPN HQ ↔ Sud — verifica
4. Infine aggiungi VPN HQ ↔ Est — verifica
5. Testa la comunicazione inter-filiale (Nord→Sud via HQ)

### Trucco per la comunicazione inter-filiale (Hub-and-Spoke)

Il traffico da Nord (10.0.2.x) verso Sud (10.0.3.x) passa per HQ. Affinché funzioni:
- Router-Nord deve avere route verso 10.0.3.0/24 e 10.0.4.0/24 via ISP
- Router-HQ deve ricevere il pacchetto cifrato dal tunnel Nord, decifrarlo,
  poi cifrarlo di nuovo nel tunnel Sud e inviarlo
- Le ACL su Router-HQ devono permettere anche il traffico inter-filiale:
  aggiungere regole per 10.0.2.0/24 ↔ 10.0.3.0/24, 10.0.2.0/24 ↔ 10.0.4.0/24, ecc.

> ⚠️ Questa è la parte più complessa del progetto. Se non riesci a far funzionare
> la comunicazione inter-filiale, documenta il problema e spiega cosa hai provato.
> Viene valutato anche il metodo di troubleshooting!

### Differenza Hub-and-Spoke vs Full-Mesh

```
HUB-AND-SPOKE (questa esercitazione):        FULL-MESH (bonus):
    Nord                                         Nord
     |                                          / | \
    HQ ─── Sud               vs.          Napoli─HQ─Est
     |                                          \ | /
    Est                                          Bari

3 tunnel VPN                                 6 tunnel VPN
Traffico inter-filiale passa per HQ          Traffico diretto tra filiali
HQ = Single Point of Failure                 Più resiliente
Meno tunnel da gestire                       Più complesso da gestire
```
