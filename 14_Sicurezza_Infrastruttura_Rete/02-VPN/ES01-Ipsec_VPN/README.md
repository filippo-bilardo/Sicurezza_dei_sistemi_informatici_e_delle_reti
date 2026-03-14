# Ipsec VPN: Configurazione di Tunnel VPN con Router Cisco

> **Materia**: Sistemi e Reti — Classe 5ª  
> **Argomento**: Virtual Private Network (VPN) con router Cisco 2901 in Cisco Packet Tracer  
> **Durata stimata**: 3–4 ore (esercizio A), 4–6 ore (esercizio B)

---

## 🌐 Introduzione

Una **VPN (Virtual Private Network)** permette di collegare reti geograficamente distanti attraverso Internet in modo sicuro, come se fossero sulla stessa rete locale. Immagina un "tunnel privato" scavato attraverso la rete pubblica: i dati viaggiano cifrati, protetti da occhi indiscreti, anche se fisicamente passano per infrastrutture condivise.

Le VPN sono una tecnologia fondamentale nelle reti aziendali moderne:
- Le **sedi di un'azienda** distribuite sul territorio comunicano in modo sicuro
- I **dipendenti in smart working** si connettono alla rete aziendale da casa
- I **dati sensibili** (database, sistemi gestionali, comunicazioni interne) sono protetti durante il transito

Questa esercitazione copre la configurazione di tunnel **VPN Site-to-Site IPsec** e **GRE** su router **Cisco 2901** in **Cisco Packet Tracer**, con attenzione alla comprensione teorica dei meccanismi crittografici coinvolti.

---

## 🎯 Competenze Coperte

| # | Competenza | Livello |
|---|-----------|---------|
| 1 | Configurazione tunnel GRE (Generic Routing Encapsulation) tra due router Cisco | ⭐⭐ |
| 2 | Configurazione VPN Site-to-Site IPsec con IKEv1 (Phase 1 + Phase 2) | ⭐⭐⭐ |
| 3 | Definizione delle Crypto ACL per il traffico interessante | ⭐⭐ |
| 4 | Applicazione della Crypto Map all'interfaccia WAN | ⭐⭐ |
| 5 | Verifica tunnel con `show crypto isakmp sa`, `show crypto ipsec sa`, `show interface tunnel` | ⭐⭐ |
| 6 | Routing attraverso il tunnel VPN (statico e dinamico) | ⭐⭐⭐ |
| 7 | Differenza tra GRE, IPsec puro e GRE over IPsec | ⭐⭐⭐ |
| 8 | Troubleshooting VPN con comandi debug Cisco IOS | ⭐⭐⭐ |

---

## 📚 Guide Teoriche

Prima di iniziare gli esercizi, studia le guide nella cartella `docs/`:

| # | File | Argomento | Priorità |
|---|------|-----------|----------|
| 1 | [`docs/01_VPN_Concetti.md`](docs/01_VPN_Concetti.md) | Concetti VPN: tipi, tunneling, sicurezza | 📖 Prima di tutto |
| 2 | [`docs/02_IPsec.md`](docs/02_IPsec.md) | Protocollo IPsec: AH, ESP, IKE, SA, modalità | 📖 Prima degli esercizi A/B |
| 3 | [`docs/03_GRE_Tunnel.md`](docs/03_GRE_Tunnel.md) | GRE Tunnel: configurazione e GRE over IPsec | 📖 Prima dell'esercizio B |
| 4 | [`docs/04_Configurazione_VPN_Cisco.md`](docs/04_Configurazione_VPN_Cisco.md) | Guida pratica comandi Cisco IOS VPN | 🔧 Riferimento durante lab |
| 5 | [`docs/05_VPN_Troubleshooting.md`](docs/05_VPN_Troubleshooting.md) | Troubleshooting VPN: verifica stato, debug, soluzioni | 🛠️ Quando qualcosa non funziona |

---

## 🏋️ Esercizi

| Esercizio | File | Tipo | Difficoltà | Punti |
|-----------|------|------|------------|-------|
| **A** | [`esercizio_a.md`](esercizio_a.md) | Laboratorio guidato — VPN IPsec Site-to-Site Roma↔Milano | ⭐⭐⭐ | /100 |
| **B** | [`esercizio_b.md`](esercizio_b.md) | Progetto autonomo — VPN Hub-and-Spoke a 3 sedi GlobalNet | ⭐⭐⭐⭐ | /100 + bonus |
| **C** | [`esercizio_c.md`](esercizio_c.md) | Teoria — 20 domande su VPN, IPsec, GRE, troubleshooting | ⭐⭐ | /70 |

---

## 🗂️ Struttura Cartelle

```
ES01-Ipsec_VPN/
├── README.md                          ← Questo file
├── esercizio_a.md                     ← Lab guidato: VPN IPsec Site-to-Site
├── esercizio_b.md                     ← Progetto autonomo: VPN Multi-sede
├── esercizio_c.md                     ← Domande di teoria
├── docs/
│   ├── 01_VPN_Concetti.md             ← Teoria: cos'è una VPN, tipi
│   ├── 02_IPsec.md                    ← Teoria: protocollo IPsec completo
│   ├── 03_GRE_Tunnel.md               ← Teoria: GRE e GRE over IPsec
│   ├── 04_Configurazione_VPN_Cisco.md ← Pratica: comandi Cisco IOS (copia-incolla)
│   └── 04_VPN_Troubleshooting.md      ← Pratica: verifica stato e risoluzione problemi
└── img/                               ← Screenshot degli esercizi
    ├── es08a_*.png                    ← Screenshot esercizio A
    └── es08b_*.png                    ← Screenshot esercizio B
```

---

## 🔧 Software Richiesto

- **Cisco Packet Tracer** 8.x o superiore (consigliato 8.2+)
- Router modello **Cisco 2901** (supporta IPsec con IKEv1 in PT)
- Switch modello **Cisco 2960**

> ⚠️ **Nota PT**: Packet Tracer supporta IPsec Site-to-Site con **IKEv1** e **GRE tunnel**.  
> Non supporta: IKEv2, SSL VPN, DMVPN avanzato, VTI completo.

---

## 🔑 Concetti Chiave da Ricordare

| Concetto | Descrizione breve |
|---------|-------------------|
| **IPsec** | Suite di protocolli per comunicazioni IP sicure (cifratura + autenticazione) |
| **IKE Phase 1** | Negoziazione ISAKMP SA — stabilisce canale sicuro per la negoziazione |
| **IKE Phase 2** | Negoziazione IPsec SA — stabilisce il tunnel per i dati |
| **ESP** | Encapsulating Security Payload — cifra E autentica i dati |
| **AH** | Authentication Header — solo autenticazione, nessuna cifratura |
| **GRE** | Generic Routing Encapsulation — tunnel senza cifratura, supporta multicast |
| **Crypto ACL** | Access-list che definisce quale traffico entra nel tunnel VPN |
| **Crypto Map** | Associa ACL, peer, transform-set e si applica all'interfaccia |
| **Pre-shared Key** | Chiave condivisa per autenticare i due endpoint del tunnel |
| **DH Group** | Diffie-Hellman group — per lo scambio sicuro delle chiavi |

---

## 📋 Sequenza di Studio Consigliata

```
1. Leggi docs/01_VPN_Concetti.md              →  Comprendi cos'è una VPN
2. Leggi docs/02_IPsec.md                     →  Studia il protocollo IPsec
3. Leggi docs/04_Configurazione_VPN_Cisco.md  →  Riferimento comandi (tieni aperto durante il lab)
4. Esegui esercizio_a.md                      →  Lab guidato passo-passo
5. Leggi docs/03_GRE_Tunnel.md                →  Studia GRE
6. Esegui esercizio_b.md                      →  Progetto autonomo
7. Rispondi esercizio_c.md                    →  Verifica teoria
   (usa docs/04_VPN_Troubleshooting.md se hai problemi durante i lab)
```

---

*ES08 — Sistemi e Reti | Versione 1.0 | Cisco Packet Tracer 8.x*
