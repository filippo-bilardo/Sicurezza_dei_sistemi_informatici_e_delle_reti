# A — Laboratorio Guidato: Configurazione DMZ con Singolo Firewall

🔬 **Tipo**: Laboratorio guidato  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 2–3 ore  
🛠️ **Strumento**: Cisco Packet Tracer
📁 **File da salvare**: `es06a_dmz.pkt`

---

## 📸 Riepilogo Screenshot Richiesti

| # | Step | Cosa mostrare |
|---|------|---------------|
| 📸1 | STEP 2 | Topologia completa in PT con tutti i dispositivi posizionati |
| 📸2 | STEP 2 | Connessioni fisiche (cavi) tra i dispositivi |
| 📸3 | STEP 3 | Configurazione IP di Firewall (tutte e 3 le interfacce) |
| 📸4 | STEP 4 | Tabella di routing del Firewall (`show ip route`) |
| 📸5 | STEP 5 | Web Server e DNS Server con servizi attivi |
| 📸6 | STEP 6 | CLI del Firewall con ACL configurate (`show running-config`) |
| 📸7 | STEP 7 | Ping OK: PC1 → Web Server DMZ (esito positivo) |
| 📸8 | STEP 7 | Ping BLOCCATO: Web Server DMZ → PC1 (esito negativo) |
| 📸9 | STEP 8 | Output di `show access-lists` con contatori |
| 📸10 | STEP 9 | Schermata di salvataggio file .pkt |

---

## 📋 Modalità di Consegna

Creare un documento (Google Doc) con:

1. **Copertina**: Nome, Cognome, Classe, Data
2. **Indice**: Numerato con le sezioni dell'esercitazione
3. **Screenshot**: Per ogni sezione indicata con 📸 (minimo 10)
4. **Risposte alle domande di riflessione**: Indicate con ❓
5. **Conclusioni personali**: Cosa hai imparato, difficoltà incontrate, miglioramenti possibili

**Consegna**: File PDF nominato `DMZ_Lab_[CognomeNome]_[Classe]_[Data].pdf`

---

## 🏢 Scenario

L'azienda **TechCorp S.r.l.** ha incaricato il team IT di progettare e configurare una rete con **architettura DMZ a singolo firewall**. L'azienda espone al pubblico un sito web, un server DNS e un server mail, ma vuole proteggere rigorosamente la rete interna degli uffici.

L'infrastruttura sarà configurata su un **Router Cisco 2901** che funge da firewall, con tre interfacce separate per le tre zone.

---

## 🗺️ Topologia di Rete

```
                    INTERNET (simulata)
                    203.0.113.0/30
                         │
                    ┌────┴─────┐
                    │Router-ISP│  203.0.113.1
                    └────┬─────┘
                         │ (cavo incrociato)
                         │ 203.0.113.2 (Gi0/2)
                    ┌────┴──────────────────┐
                    │     FIREWALL          │
                    │   (Router0 - 2901)    │
                    │ 192.168.100.1 (Gi0/1) │
                    │ 10.0.0.1     (Gi0/0)  │
                    └──────┬───────────┬────┘
                           │           │
                    ┌──────┴───┐  ┌────┴──────┐
                    │Switch-DMZ│  │Switch-LAN │
                    └──────┬───┘  └────┬──────┘
                           │           │
              ┌────────────┼────┐    ┌─┼──────────────┐
              │            │    │    │ │              │
         Web Server   DNS Server  Mail Server   PC1..PC4
      192.168.100.10      .11        .12      10.0.0.10..13
```

---

## 📋 STEP 1 — Piano di Indirizzamento

### 1.1 Tabella IP Completa

| Dispositivo | Interfaccia | Indirizzo IP | Subnet Mask | Gateway Default | Zona |
|-------------|-------------|--------------|-------------|-----------------|------|
| Router-ISP | Gi0/0 | 203.0.113.1 | 255.255.255.252 | — | Internet |
| **Firewall** (Router0) | **Gi0/2** | **203.0.113.2** | **255.255.255.252** | — | Internet (WAN) |
| **Firewall** (Router0) | **Gi0/1** | **192.168.100.1** | **255.255.255.224** | — | DMZ |
| **Firewall** (Router0) | **Gi0/0** | **10.0.0.1** | **255.255.255.0** | — | LAN |
| Web Server | NIC | 192.168.100.10 | 255.255.255.224 | 192.168.100.1 | DMZ |
| DNS Server | NIC | 192.168.100.11 | 255.255.255.224 | 192.168.100.1 | DMZ |
| Mail Server | NIC | 192.168.100.12 | 255.255.255.224 | 192.168.100.1 | DMZ |
| PC1 | NIC | 10.0.0.10 | 255.255.255.0 | 10.0.0.1 | LAN |
| PC2 | NIC | 10.0.0.11 | 255.255.255.0 | 10.0.0.1 | LAN |
| PC3 | NIC | 10.0.0.12 | 255.255.255.0 | 10.0.0.1 | LAN |
| PC4 | NIC | 10.0.0.13 | 255.255.255.0 | 10.0.0.1 | LAN |

### 1.2 Analisi delle Subnet

| Zona | Rete | Maschera | CIDR | Host utilizzabili | Utilizzo |
|------|------|----------|------|-------------------|---------|
| WAN/Internet | 203.0.113.0 | 255.255.255.252 | /30 | 2 | Link punto-punto verso ISP |
| DMZ | 192.168.100.0 | 255.255.255.224 | /27 | 30 | Server pubblici (web, DNS, mail) |
| LAN | 10.0.0.0 | 255.255.255.0 | /24 | 254 | PC e server interni |

> 💡 **Perché /27 per la DMZ?** Una DMZ ospita tipicamente pochi server (3–10). Una /27 offre 30 host utilizzabili: abbastanza per una DMZ aziendale media, senza sprecare indirizzi.

#### ❓ Domande di Riflessione — Subnet

**R1.1** La DMZ usa una subnet /27 (30 host utili) mentre la LAN usa /24 (254 host utili). Come mai si sono scelte maschere diverse? Cosa succederebbe se assegnassi una /24 anche alla DMZ?

**R1.2** Il link WAN tra Firewall e Router-ISP usa una /30 (solo 2 host utili). Perché si usa una /30 e non una /24 in un collegamento punto-punto? Quanti indirizzi verrebbero sprecati con una /24?

**R1.3** Confronta gli spazi di indirizzamento usati: `10.0.0.0/8` (RFC 1918 privato), `192.168.100.0/27` (privato) e `203.0.113.0/30` (TEST-NET-3, RFC 5737). Perché in produzione reale gli indirizzi WAN sarebbero diversi?

### 1.3 Flussi di Traffico Consentiti e Bloccati

| Sorgente | Destinazione | Azione | Motivazione |
|----------|-------------|--------|-------------|
| Internet | DMZ (TCP 80, 443, 53) | ✅ PERMIT | Il pubblico deve accedere ai server esposti |
| Internet | LAN | ❌ DENY | La LAN interna NON deve essere raggiungibile da Internet |
| Internet | DMZ (altri servizi) | ❌ DENY | Solo i servizi esposti sono accessibili |
| LAN | DMZ | ✅ PERMIT | I dipendenti accedono ai server interni |
| LAN | Internet | ✅ PERMIT | I dipendenti navigano su Internet |
| DMZ | LAN | ❌ DENY | **Regola critica**: se un server DMZ è compromesso, non deve poter attaccare la LAN |
| DMZ | Internet | ✅ PERMIT (established) | Risposte a connessioni iniziate dalla LAN/DMZ |

#### ❓ Domande di Riflessione — Politiche di Sicurezza

**R2.1** La regola "DMZ → LAN = DENY" è definita la più importante di tutta la configurazione. Spiega con parole tue perché un server in DMZ compromesso potrebbe diventare pericoloso se potesse raggiungere liberamente la LAN.

**R2.2** Internet può raggiungere la DMZ solo su porte specifiche (80, 443, 53, 25). Perché non si permette semplicemente tutto il traffico TCP verso la DMZ? Quali rischi comporterebbe aprire anche porte come 22 (SSH) o 3389 (RDP)?

**R2.3** La LAN può accedere sia alla DMZ che a Internet liberamente. In una politica di sicurezza più restrittiva, quali limitazioni aggiungere ai PC interni? (Pensa a social media, streaming, orari di lavoro)

---

## 🖥️ STEP 2 — Creazione Topologia in Packet Tracer

### 2.1 Dispositivi da Aggiungere

Apri Cisco Packet Tracer e aggiungi i seguenti dispositivi:

| Dispositivo | Modello PT | Quantità | Posizione consigliata |
|-------------|-----------|----------|----------------------|
| Router | Cisco 2901 | 2 | Centro-alto (ISP) e centro (Firewall) |
| Switch | Cisco 2960 | 2 | Uno per DMZ, uno per LAN |
| Server | Generic Server | 3 | Zona DMZ (sinistra) |
| PC | Generic PC | 4 | Zona LAN (destra) |

> 📸 **Screenshot 1**: Cattura la topologia con tutti i dispositivi posizionati ma ancora senza cavi.

### 2.2 Connessioni (Cablaggio)

Usa i seguenti cavi per connettere i dispositivi:

| Da | Porta | A | Porta | Tipo cavo |
|----|-------|---|-------|-----------|
| Router-ISP | Gi0/0 | Firewall (Router0) | Gi0/2 | Copper Cross-Over |
| Firewall (Router0) | Gi0/1 | Switch-DMZ | Fa0/1 | Copper Straight-Through |
| Firewall (Router0) | Gi0/0 | Switch-LAN | Fa0/1 | Copper Straight-Through |
| Switch-DMZ | Fa0/2 | Web Server | Fa0 | Copper Straight-Through |
| Switch-DMZ | Fa0/3 | DNS Server | Fa0 | Copper Straight-Through |
| Switch-DMZ | Fa0/4 | Mail Server | Fa0 | Copper Straight-Through |
| Switch-LAN | Fa0/2 | PC1 | Fa0 | Copper Straight-Through |
| Switch-LAN | Fa0/3 | PC2 | Fa0 | Copper Straight-Through |
| Switch-LAN | Fa0/4 | PC3 | Fa0 | Copper Straight-Through |
| Switch-LAN | Fa0/5 | PC4 | Fa0 | Copper Straight-Through |

> 📸 **Screenshot 2**: Cattura la topologia completa con tutti i cavi connessi (le lucine devono essere verdi).

#### ❓ Domande di Riflessione — Topologia

**R3.1** In questa topologia un singolo Router Cisco 2901 svolge sia il ruolo di **router** che di **firewall**. Quali vantaggi e svantaggi ha questa scelta rispetto all'uso di un dispositivo firewall dedicato (es. Cisco ASA)?

**R3.2** Il collegamento tra Router-ISP e Firewall usa un **cavo incrociato (cross-over)**. Perché non si usa un cavo dritto (straight-through) tra due router? In quali situazioni moderne questo non è più necessario?

**R3.3** I due switch (Switch-DMZ e Switch-LAN) sono dispositivi di livello 2. Cosa succederebbe alla sicurezza se si connettessero direttamente i server DMZ e i PC LAN allo stesso switch, senza separazione fisica?

---

## ⚙️ STEP 3 — Configurazione IP dei Dispositivi

### 3.1 Configurazione Router-ISP

Clicca su **Router-ISP** → scheda **CLI** e digita:

```cisco
Router> enable
Router# configure terminal
Router(config)# hostname Router-ISP
Router-ISP(config)# interface GigabitEthernet0/0
Router-ISP(config-if)# ip address 203.0.113.1 255.255.255.252
Router-ISP(config-if)# no shutdown
Router-ISP(config-if)# description "Link verso Firewall (WAN)"
Router-ISP(config-if)# exit
Router-ISP(config)# end
Router-ISP# write memory
```

### 3.2 Configurazione Server DMZ

Per ogni server, clicca sul dispositivo → scheda **Desktop** → **IP Configuration**:

**Web Server** (192.168.100.10):
- IP Address: `192.168.100.10`
- Subnet Mask: `255.255.255.224`
- Default Gateway: `192.168.100.1`
- DNS Server: `192.168.100.11`

**DNS Server** (192.168.100.11):
- IP Address: `192.168.100.11`
- Subnet Mask: `255.255.255.224`
- Default Gateway: `192.168.100.1`

**Mail Server** (192.168.100.12):
- IP Address: `192.168.100.12`
- Subnet Mask: `255.255.255.224`
- Default Gateway: `192.168.100.1`

### 3.3 Configurazione PC LAN

Per ogni PC → **Desktop** → **IP Configuration**:

| PC | IP | Subnet Mask | Gateway |
|----|-----|-------------|---------|
| PC1 | 10.0.0.10 | 255.255.255.0 | 10.0.0.1 |
| PC2 | 10.0.0.11 | 255.255.255.0 | 10.0.0.1 |
| PC3 | 10.0.0.12 | 255.255.255.0 | 10.0.0.1 |
| PC4 | 10.0.0.13 | 255.255.255.0 | 10.0.0.1 |

> 📸 **Screenshot 3**: Mostra la configurazione CLI del Firewall con tutte e tre le interfacce configurate (`show ip interface brief`).

#### ❓ Domande di Riflessione — Configurazione IP

**R4.1** Il comando `no shutdown` è necessario per attivare le interfacce del router. Per impostazione predefinita, le interfacce dei router Cisco sono in stato "administratively down". Perché questo comportamento predefinito è una buona pratica di sicurezza?

**R4.2** Il Web Server ha come **Default Gateway** l'IP del Firewall (`192.168.100.1`). Cosa succederebbe alla connettività del Web Server se configurassi un gateway errato, ad esempio `192.168.100.2`? Come lo diagnosticheresti?

**R4.3** I PC nella LAN hanno tutti lo stesso Default Gateway (`10.0.0.1`). Se un PC invia un pacchetto verso un IP della LAN (es. `10.0.0.11`), il pacchetto passa attraverso il gateway? Perché sì o perché no?

---

## 🔀 STEP 4 — Configurazione IP del Firewall (Router0)

Clicca su **Router0** → scheda **CLI**:

```cisco
Router> enable
Router# configure terminal
Router(config)# hostname Firewall

! === INTERFACCIA WAN (verso Internet/ISP) ===
Firewall(config)# interface GigabitEthernet0/2
Firewall(config-if)# description "WAN - Verso Internet"
Firewall(config-if)# ip address 203.0.113.2 255.255.255.252
Firewall(config-if)# no shutdown
Firewall(config-if)# exit

! === INTERFACCIA DMZ ===
Firewall(config)# interface GigabitEthernet0/1
Firewall(config-if)# description "DMZ - Server Pubblici"
Firewall(config-if)# ip address 192.168.100.1 255.255.255.224
Firewall(config-if)# no shutdown
Firewall(config-if)# exit

! === INTERFACCIA LAN ===
Firewall(config)# interface GigabitEthernet0/0
Firewall(config-if)# description "LAN - Rete Interna"
Firewall(config-if)# ip address 10.0.0.1 255.255.255.0
Firewall(config-if)# no shutdown
Firewall(config-if)# exit

! === ROUTING STATICO ===
! Rotta di default verso Internet (via Router-ISP)
Firewall(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1

Firewall(config)# end
Firewall# copy running-config startup-config
```

Verifica con:
```cisco
Firewall# show ip interface brief
Firewall# show ip route
```

L'output di `show ip interface brief` deve mostrare:
```
Interface              IP-Address      OK? Method Status   Protocol
GigabitEthernet0/0     10.0.0.1        YES manual up       up
GigabitEthernet0/1     192.168.100.1   YES manual up       up
GigabitEthernet0/2     203.0.113.2     YES manual up       up
```

> 📸 **Screenshot 4**: Output di `show ip route` sul Firewall (deve mostrare le rotte verso le 3 reti).

#### ❓ Domande di Riflessione — Firewall e Routing

**R5.1** Il comando `ip route 0.0.0.0 0.0.0.0 203.0.113.1` configura una **rotta di default** (default route). Cosa significa "0.0.0.0 0.0.0.0"? Come decide il router di usare questa rotta invece di una più specifica?

**R5.2** Esegui `show ip route` e identifica le lettere nell'output (`C` per Connected, `S` per Static, ecc.). Perché le reti `10.0.0.0/24`, `192.168.100.0/27` e `203.0.113.0/30` appaiono con la lettera `C`? Cosa significherebbe se non apparissero?

**R5.3** Il comando `copy running-config startup-config` (equivalente a `write memory`) salva la configurazione. Cosa succederebbe se non lo eseguissi e il router venisse riavviato? Qual è la differenza tra `running-config` e `startup-config`?

---

## 🌐 STEP 5 — Configurazione Web Server e DNS in DMZ

### 5.1 Web Server — Attivazione HTTP

Clicca su **Web Server** → scheda **Services**:
1. Seleziona **HTTP** nella lista a sinistra
2. Assicurati che sia **ON** (attivo)
3. Verifica che nella tab HTML ci sia una pagina di default

### 5.2 DNS Server — Configurazione Record A

Clicca su **DNS Server** → **Services** → **DNS**:
1. Attiva il servizio DNS (ON)
2. Aggiungi il seguente record:
   - Name: `www.techcorp.local`
   - Type: `A Record`
   - Address: `192.168.100.10`
3. Clicca **Add**

> 📸 **Screenshot 5**: Mostra il Web Server con HTTP attivo e il DNS Server con il record A configurato.

#### ❓ Domande di Riflessione — Servizi in DMZ

**R6.1** Hai configurato il DNS Server con un record `A` per `www.techcorp.local`. Quale tipo di record DNS useresti per mappare un dominio a un altro dominio (alias)? E per mappare un IP a un nome (ricerca inversa)?

**R6.2** Il Web Server nella DMZ serve solo HTTP (porta 80). In un ambiente reale, quali altre misure di sicurezza configureresti sul server stesso (oltre al firewall) per ridurre la superficie di attacco? Elenca almeno 3.

**R6.3** Nella configurazione attuale non è presente un **Mail Server** attivo su Packet Tracer, ma è presente nella topologia. Se dovessi abilitare il servizio SMTP, su quale porta ascolterebbe? Perché la posta in arrivo (SMTP) è nella DMZ ma la posta in uscita degli utenti interni di solito no?

---

## 🔒 STEP 6 — Configurazione ACL sul Firewall

Questa è la parte più importante dell'esercitazione. Le ACL implementano le **policy di sicurezza** della DMZ.

### 6.1 Strategia ACL

Useremo **Named ACL estese** (più leggibili e modificabili). Le applichiamo **in ingresso** (`in`) su ogni interfaccia, così il traffico viene filtrato appena entra nel firewall.

```
Gi0/2 (WAN) ──IN──► [ACL_WAN_IN]  ──► FIREWALL ──► Gi0/1 / Gi0/0
Gi0/1 (DMZ) ──IN──► [ACL_DMZ_IN]  ──► FIREWALL ──► Gi0/2 / Gi0/0
Gi0/0 (LAN) ──IN──► [ACL_LAN_IN]  ──► FIREWALL ──► Gi0/2 / Gi0/1
```

### 6.2 Comandi CLI Completi

```cisco
Firewall# configure terminal

! ================================================================
! ACL 1: TRAFFICO IN INGRESSO DALL'INTERFACCIA WAN (da Internet)
! Applicata su Gi0/2 direzione IN
! Permette solo accesso a servizi specifici in DMZ
! ================================================================
Firewall(config)# ip access-list extended ACL_WAN_IN

! Permetti HTTP (porta 80) verso qualsiasi server DMZ
Firewall(config-ext-nacl)# permit tcp any 192.168.100.0 0.0.0.31 eq 80

! Permetti HTTPS (porta 443) verso qualsiasi server DMZ
Firewall(config-ext-nacl)# permit tcp any 192.168.100.0 0.0.0.31 eq 443

! Permetti DNS UDP (porta 53) verso DNS Server in DMZ
Firewall(config-ext-nacl)# permit udp any host 192.168.100.11 eq 53

! Permetti DNS TCP (porta 53) per zone transfer
Firewall(config-ext-nacl)# permit tcp any host 192.168.100.11 eq 53

! Permetti SMTP (porta 25) verso Mail Server
Firewall(config-ext-nacl)# permit tcp any host 192.168.100.12 eq 25

! Permetti risposte a connessioni stabilite (ESTABLISHED) verso la LAN
Firewall(config-ext-nacl)# permit tcp any 10.0.0.0 0.0.0.255 established

! BLOCCA TUTTO IL RESTO da Internet (implicit deny, esplicito per log)
Firewall(config-ext-nacl)# deny ip any any
Firewall(config-ext-nacl)# exit

! ================================================================
! ACL 2: TRAFFICO IN INGRESSO DALL'INTERFACCIA DMZ
! Applicata su Gi0/1 direzione IN
! Blocca DMZ → LAN; permette DMZ → Internet solo per risposte
! ================================================================
Firewall(config)# ip access-list extended ACL_DMZ_IN

! NEGA accesso dalla DMZ alla LAN interna (REGOLA CRITICA!)
Firewall(config-ext-nacl)# deny ip 192.168.100.0 0.0.0.31 10.0.0.0 0.0.0.255

! Permetti ai server DMZ di rispondere a connessioni stabilite
Firewall(config-ext-nacl)# permit tcp 192.168.100.0 0.0.0.31 any established

! Permetti ICMP dalla DMZ (per diagnostica, opzionale)
Firewall(config-ext-nacl)# permit icmp 192.168.100.0 0.0.0.31 any

! Permetti DNS queries dal DNS Server verso Internet
Firewall(config-ext-nacl)# permit udp host 192.168.100.11 any eq 53

! Blocca tutto il resto
Firewall(config-ext-nacl)# deny ip any any
Firewall(config-ext-nacl)# exit

! ================================================================
! ACL 3: TRAFFICO IN INGRESSO DALL'INTERFACCIA LAN
! Applicata su Gi0/0 direzione IN
! La LAN può accedere a tutto (DMZ e Internet)
! ================================================================
Firewall(config)# ip access-list extended ACL_LAN_IN

! Permetti tutto il traffico dalla LAN verso DMZ
Firewall(config-ext-nacl)# permit ip 10.0.0.0 0.0.0.255 192.168.100.0 0.0.0.31

! Permetti tutto il traffico dalla LAN verso Internet
Firewall(config-ext-nacl)# permit ip 10.0.0.0 0.0.0.255 any

! Blocca tutto il resto (non dovrebbe mai scattare in questo scenario)
Firewall(config-ext-nacl)# deny ip any any
Firewall(config-ext-nacl)# exit

! ================================================================
! APPLICAZIONE ACL ALLE INTERFACCE
! ================================================================

! ACL sulla WAN: filtro in INGRESSO da Internet
Firewall(config)# interface GigabitEthernet0/2
Firewall(config-if)# ip access-group ACL_WAN_IN in
Firewall(config-if)# exit

! ACL sulla DMZ: filtro in INGRESSO dalla zona DMZ
Firewall(config)# interface GigabitEthernet0/1
Firewall(config-if)# ip access-group ACL_DMZ_IN in
Firewall(config-if)# exit

! ACL sulla LAN: filtro in INGRESSO dalla LAN
Firewall(config)# interface GigabitEthernet0/0
Firewall(config-if)# ip access-group ACL_LAN_IN in
Firewall(config-if)# exit

Firewall(config)# end
Firewall# write memory
```

> 📸 **Screenshot 6**: Output di `show running-config` sul Firewall — sezione access-list e interface.

#### ❓ Domande di Riflessione — ACL e Sicurezza

**R7.1** Le ACL di Cisco vengono applicate con `ip access-group ACL_NOME in` (direzione **in**). Cosa significherebbe applicarle con `out` (uscita)? Quale delle due direzioni è generalmente preferibile per un firewall perimetrale e perché?

**R7.2** Le ACL standard (numeri 1–99) filtrano solo per **indirizzo sorgente**, mentre le ACL estese (100–199, o named) filtrano anche per destinazione, protocollo e porta. Perché per questo scenario è obbligatorio usare ACL estese?

**R7.3** Nella `ACL_WAN_IN` c'è la regola `permit tcp any 10.0.0.0 0.0.0.255 established`. La keyword `established` verifica i flag TCP. In un attacco **TCP SYN flood**, questa regola verrebbe aggirata? Perché sì o perché no?

**R7.4** Il wildcard mask `0.0.0.31` corrisponde alla subnet `/27` (es. `192.168.100.0/27`). Come si calcola il wildcard mask partendo dalla subnet mask `255.255.255.224`? Esegui il calcolo passo-passo.

---

## ✅ STEP 7 — Verifica delle ACL (Test di Connettività)

Ora verifichiamo che le policy di sicurezza funzionino correttamente.

### 7.1 Test da Eseguire

| # | Da | A | Metodo | Esito Atteso | Motivazione |
|---|-----|---|--------|-------------|-------------|
| T1 | PC1 (10.0.0.10) | Web Server (192.168.100.10) | ping | ✅ SUCCESSO | LAN → DMZ permessa |
| T2 | PC1 (10.0.0.10) | Router-ISP (203.0.113.1) | ping | ✅ SUCCESSO | LAN → Internet permessa |
| T3 | PC1 (10.0.0.10) | DNS Server (192.168.100.11) | ping | ✅ SUCCESSO | LAN → DMZ permessa |
| T4 | Web Server (192.168.100.10) | PC1 (10.0.0.10) | ping | ❌ BLOCCATO | DMZ → LAN negata |
| T5 | Router-ISP (203.0.113.1) | PC1 (10.0.0.10) | ping | ❌ BLOCCATO | Internet → LAN negata |
| T6 | Router-ISP (203.0.113.1) | Web Server (192.168.100.10) | ping | ❌ BLOCCATO* | ICMP non permesso da ACL_WAN_IN |

> ⚠️ *Il T6 è bloccato perché l'ACL_WAN_IN permette solo TCP/UDP su porte specifiche, non ICMP generico. Questo è intenzionale: i server pubblici rispondono solo sui servizi esposti.

### 7.2 Esecuzione dei Test

**Test T1 — PC1 → Web Server (deve funzionare)**

Clicca su **PC1** → **Desktop** → **Command Prompt**:
```
C:\> ping 192.168.100.10
```
Output atteso:
```
Pinging 192.168.100.10 with 32 bytes of data:
Reply from 192.168.100.10: bytes=32 time<1ms TTL=127
Reply from 192.168.100.10: bytes=32 time<1ms TTL=127
```

**Test T2 — PC1 → Router-ISP (deve funzionare)**
```
C:\> ping 203.0.113.1
```

**Test T4 — Web Server → PC1 (deve essere bloccato)**

Clicca su **Web Server** → **Desktop** → **Command Prompt**:
```
C:\> ping 10.0.0.10
```
Output atteso:
```
Pinging 10.0.0.10 with 32 bytes of data:
Request timeout for icmp_seq 0
Request timeout for icmp_seq 1
```

> 📸 **Screenshot 7**: Test T1 — ping da PC1 a Web Server DMZ (esito positivo con 4 reply).
> 📸 **Screenshot 8**: Test T4 — ping da Web Server DMZ a PC1 (esito negativo, timeout).

#### ❓ Domande di Riflessione — Test di Connettività

**R8.1** Il test T6 (Router-ISP → Web Server) è bloccato perché `ACL_WAN_IN` non permette ICMP. Eppure in un sito web reale, gli amministratori spesso vogliono poter fare ping al server dal proprio ufficio remoto. Come modificheresti l'ACL per permettere ICMP **solo da un IP specifico** dell'amministratore (es. `198.51.100.5`)?

**R8.2** Quando esegui un ping, il pacchetto percorre un cammino **andata e ritorno** (ICMP Echo Request + Echo Reply). Per il test T1 (PC1 → Web Server), attraverso quali ACL passa il pacchetto di **andata**? E quello di **ritorno**? Traccia il percorso completo interfaccia per interfaccia.

**R8.3** Il risultato del test T4 è "Request timeout". Ci sono almeno due possibili ragioni per questo messaggio in Packet Tracer: (a) il pacchetto viene bloccato dall'ACL, oppure (b) la rete non è raggiungibile. Come potresti distinguere i due casi usando `show access-lists` con i contatori?

---

## 📊 STEP 8 — Analisi con show access-lists

### 8.1 Visualizzazione Contatori ACL

Dopo aver eseguito i test, visualizza i contatori delle ACL sul Firewall:

```cisco
Firewall# show access-lists
```

Output tipico (i numeri di match aumentano ad ogni test):
```
Extended IP access list ACL_WAN_IN
    10 permit tcp any 192.168.100.0 0.0.0.31 eq 80 (0 matches)
    20 permit tcp any 192.168.100.0 0.0.0.31 eq 443 (0 matches)
    30 permit udp any host 192.168.100.11 eq 53 (0 matches)
    40 permit tcp any host 192.168.100.11 eq 53 (0 matches)
    50 permit tcp any host 192.168.100.12 eq 25 (0 matches)
    60 permit tcp any 10.0.0.0 0.0.0.255 established (0 matches)
    70 deny ip any any (X matches)      ← contatore deve essere > 0 dopo i test
Extended IP access list ACL_DMZ_IN
    10 deny ip 192.168.100.0 0.0.0.31 10.0.0.0 0.0.0.255 (X matches)
    20 permit tcp 192.168.100.0 0.0.0.31 any established (0 matches)
    ...
Extended IP access list ACL_LAN_IN
    10 permit ip 10.0.0.0 0.0.0.255 192.168.100.0 0.0.0.31 (X matches)
    20 permit ip 10.0.0.0 0.0.0.255 any (X matches)
    ...
```

```cisco
Firewall# show ip interface GigabitEthernet0/1
```
Verifica che l'ACL sia applicata:
```
  Inbound  access list is ACL_DMZ_IN
  Outbound access list is not set
```

> 📸 **Screenshot 9**: Output completo di `show access-lists` con i contatori dei match.

#### ❓ Domande di Riflessione — Analisi ACL

**R9.1** Osserva i contatori di `show access-lists` dopo aver eseguito tutti i test. Quale ACL ha il contatore più alto nella regola `deny`? A quale test corrisponde? Cosa ci dicono questi numeri sull'attività di rete?

**R9.2** La voce `deny ip any any` alla fine di ogni ACL è esplicita, ma in realtà Cisco IOS ha già un **implicit deny** alla fine di ogni ACL. Perché è comunque consigliabile inserire la regola di deny esplicita? (Suggerimento: pensa ai contatori e ai log)

**R9.3** Se un amministratore vuole aggiungere una nuova regola per permettere il traffico SSH (porta 22) dalla LAN verso il Web Server DMZ, in quale ACL deve inserirla e in quale posizione? Scrivi il comando Cisco IOS corretto.

---

## 💾 STEP 9 — Salvataggio del File

```cisco
Firewall# write memory
Building configuration...
[OK]
```

Salva il file Packet Tracer:
1. **File** → **Save As**
2. Nome file: `es06a_dmz.pkt`
3. Salva nella cartella dell'esercitazione

> 📸 **Screenshot 10**: Schermata di salvataggio con il nome file `es06a_dmz.pkt` visibile.

---

## 🔧 Troubleshooting

### Problema: il ping da PC1 a Web Server non funziona

**Sintomo**: Request timeout anche per T1 (che dovrebbe funzionare).

**Possibili cause e soluzioni**:

| Causa | Come verificare | Soluzione |
|-------|----------------|-----------|
| Interfacce Firewall DOWN | `show ip interface brief` | `no shutdown` su ogni interfaccia |
| IP errato sul Web Server | Controlla la config IP del server | Riconfigura l'IP |
| ACL applicata nel verso sbagliato | `show ip interface` | Rimuovi con `no ip access-group` e riapplica |
| ACL_LAN_IN troppo restrittiva | `show access-lists` + contatori | Controlla le regole deny prima del permit |

### Problema: Web Server → PC1 funziona (ma non dovrebbe!)

**Soluzione**: Verifica che `ACL_DMZ_IN` sia applicata **in ingresso** (`in`) su `Gi0/1`:
```cisco
Firewall# show ip interface GigabitEthernet0/1
```
Deve mostrare: `Inbound access list is ACL_DMZ_IN`

Se non è applicata:
```cisco
Firewall(config)# interface GigabitEthernet0/1
Firewall(config-if)# ip access-group ACL_DMZ_IN in
```

### Problema: errore "Invalid input detected" durante la configurazione ACL

**Causa**: Errore di sintassi. Le ACL estese di Cisco sono sensibili alla sintassi.

**Verifica**: Controlla di usare:
- `host` prima di un singolo IP: `permit tcp any host 192.168.100.10 eq 80`
- Wildcard corretta per una rete: `0.0.0.31` per /27 (non `0.0.0.224`)

---

## 📝 Note Tecniche

### Limitazione: ACL Stateless in Cisco IOS

⚠️ Le ACL di Cisco IOS standard sono **stateless**: non tengono traccia delle connessioni. La keyword `established` funziona solo per TCP (controlla il flag ACK/RST), ma **non per UDP o ICMP**.

In un vero ambiente di produzione si usano:
- **Firewall stateful** (Cisco ASA, pfSense, iptables con conntrack)
- **Zone-Based Policy Firewall** (ZPF) su Cisco IOS
- **CBAC** (Context-Based Access Control) per tracciare sessioni UDP

### Differenza tra ACL e Firewall reale

| Caratteristica | ACL Cisco IOS | Firewall Stateful |
|----------------|--------------|-------------------|
| Tracciamento connessioni | ❌ No (solo TCP established) | ✅ Sì |
| Ispezione applicativa (L7) | ❌ No | ✅ (NGFW) |
| Performance | ✅ Alta | Variabile |
| Complessità config | Bassa | Media/Alta |
| Uso tipico | Router, switch L3 | Perimetro aziendale |

### La Regola Aurea: DMZ → LAN = DENY

La regola `deny ip 192.168.100.0 0.0.0.31 10.0.0.0 0.0.0.255` in `ACL_DMZ_IN` è la più importante dell'intera configurazione. Senza di essa, un attaccante che compromette il web server può:
1. Usare il server come **pivot** per attaccare la LAN
2. Eseguire **lateral movement** verso database e file server
3. Esfiltrare dati sensibili attraverso il server compromesso

---

## ✅ Checklist Finale

Prima di consegnare, verifica:

- [ ] Topologia completa con tutti i dispositivi e cavi
- [ ] Tutti gli IP configurati correttamente (verifica con `show ip interface brief`)
- [ ] Routing funzionante (verifica con `show ip route`)
- [ ] Tutte e 3 le ACL configurate (`show access-lists`)
- [ ] ACL applicate alle interfacce corrette nel verso corretto
- [ ] Test T1, T2, T3 superati (ping OK)
- [ ] Test T4, T5 superati (ping bloccato)
- [ ] 10 screenshot catturati e salvati
- [ ] File `es06a_dmz.pkt` salvato
- [ ] Tutte le domande di riflessione (R1.1–R9.3) risposte nel documento di consegna

---

## 🧠 Domande di Riepilogo Finali

❓ Rispondi a queste domande nelle **conclusioni** del documento di consegna:

**C1 — Architettura**  
Spiega con parole tue la differenza tra una rete **senza DMZ** (solo LAN + Internet) e una rete **con DMZ**. Quali attacchi vengono mitigati dall'introduzione della DMZ?

**C2 — Difesa in profondità**  
Il principio di "Defense in Depth" (difesa a strati) prevede che la sicurezza non sia affidata a un unico meccanismo. In questa topologia, quali altri strati di sicurezza aggiungere oltre alle ACL sul firewall perimetrale? Elenca almeno 3 misure complementari.

**C3 — Scenario di attacco**  
Un attaccante riesce a compromettere il Web Server nella DMZ sfruttando una vulnerabilità in Apache. Descrivi step-by-step cosa potrebbe fare l'attaccante **con** la configurazione attuale e cosa riuscirebbe a fare **senza** le ACL di protezione verso la LAN.

**C4 — Confronto con soluzioni reali**  
Questa simulazione usa un router Cisco con ACL stateless. In un'azienda reale si userebbero firewall come pfSense, Cisco ASA o FortiGate. Ricerca una differenza chiave tra le ACL stateless di IOS e un firewall stateful e spiega perché quella differenza è importante per la sicurezza.

**C5 — Riflessione personale**  
Descrivi in almeno 150 parole: cosa hai imparato di nuovo in questa esercitazione, quale passaggio ti ha messo in difficoltà e come lo hai risolto, e cosa implementeresti diversamente se dovessi progettare questa rete per una vera azienda.

---

*ES06-A — Sistemi e Reti 3 | Laboratorio guidato DMZ singolo firewall*
