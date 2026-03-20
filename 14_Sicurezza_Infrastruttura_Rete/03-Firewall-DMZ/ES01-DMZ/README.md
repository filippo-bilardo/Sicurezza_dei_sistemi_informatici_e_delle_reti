# ES06 — DMZ: Progettazione e Configurazione di una Rete Perimetrale

🛡️ **Livello**: Scuola Superiore — Classe 4ª/5ª | **Materia**: Sistemi e Reti  
🔥 **Argomento**: DMZ (DeMilitarized Zone) — Sicurezza Perimetrale  
⏱️ **Durata stimata**: 4–6 ore (laboratorio + teoria)

---

## 📌 Introduzione

La **DMZ (DeMilitarized Zone)** è una rete perimetrale che si interpone tra Internet e la rete interna aziendale, ospitando i server pubblici (web, mail, DNS) e **limitando il danno** in caso di compromissione.

Il nome deriva dalla terminologia militare: una zona cuscinetto tra due fronti nemici, dove nessuna delle due parti ha pieno controllo. In informatica, la DMZ è la zona dove vivono i servizi esposti al mondo esterno, **separati e isolati** dalla rete interna dove risiedono i dati sensibili dell'azienda.

```
                    ┌─────────────────────────────────────────────┐
  INTERNET          │              FIREWALL                       │
  (rete ostile) ────┤   ┌──────────────────┐   ┌───────────────┐  │
                    │   │       DMZ        │   │  LAN INTERNA  │  │
                    │   │  Web Server      │   │  PC Uffici    │  │
                    │   │  DNS Server      │   │  Server DB    │  │
                    │   │  Mail Server     │   │  File Server  │  │
                    │   └──────────────────┘   └───────────────┘  │
                    └─────────────────────────────────────────────┘
```

**Perché è fondamentale**: senza DMZ, un attaccante che compromette il web server ha accesso diretto alla rete interna. Con la DMZ, anche se il server viene bucato, la LAN rimane protetta grazie alle regole del firewall.

È uno degli strumenti fondamentali della **sicurezza di rete moderna** e un argomento ricorrente negli esami di maturità tecnica (indirizzo Informatica e Telecomunicazioni).

---

## 🎯 Competenze Coperte

Al termine di questa esercitazione lo studente sarà in grado di:

| # | Competenza |
|---|------------|
| 1 | Progettare una topologia DMZ a **singolo firewall** con 3 zone separate |
| 2 | Progettare una topologia DMZ a **doppio firewall** per ambienti ad alta sicurezza |
| 3 | Eseguire il **subnetting** per le 3 zone (Internet/WAN, DMZ, LAN) con maschere appropriate |
| 4 | Configurare **ACL estese** su router Cisco per implementare le policy di sicurezza tra zone |
| 5 | Applicare le regole di accesso: Internet→DMZ, LAN→DMZ, LAN→Internet, DMZ→LAN (bloccata) |
| 6 | Verificare la corretta applicazione delle policy con **ping**, **traceroute** e `show access-lists` |
| 7 | Spiegare i concetti di **firewall stateless vs stateful**, IDS/IPS e NAT in contesto DMZ |
| 8 | Comprendere la **defense in depth** come strategia di sicurezza a strati |

---

## 📚 Guide Teoriche

Le seguenti guide in `docs/` forniscono tutto il background teorico necessario. Si consiglia di leggerle **prima** di affrontare gli esercizi.

| # | File | Argomento | Prerequisito per |
|---|------|-----------|-----------------|
| 1 | [01_DMZ_Concetti.md](docs/01_DMZ_Concetti.md) | Cos'è la DMZ, architetture, defense in depth | Tutti gli esercizi |
| 2 | [02_Firewall_ACL.md](docs/02_Firewall_ACL.md) | Firewall, ACL Cisco standard ed estese, wildcard | Esercizio A, B |
| 3 | [03_NAT_PAT_DMZ.md](docs/03_NAT_PAT_DMZ.md) | NAT statico, PAT, port forwarding in DMZ | Esercizio B |
| 4 | [04_IDS_IPS_Monitoraggio.md](docs/04_IDS_IPS_Monitoraggio.md) | IDS, IPS, SIEM, monitoraggio e incident response | Esercizio C |

---

## 🗂️ Esercizi

| Esercizio | Tipo | Titolo | Difficoltà | Durata |
|-----------|------|--------|------------|--------|
| [A](esercizio_a.md) | 🔬 Laboratorio guidato | Configurazione DMZ con singolo firewall in Cisco Packet Tracer | ⭐⭐⭐ | 2–3 ore |
| [B](esercizio_b.md) | 🏗️ Progetto autonomo | Progettazione DMZ a doppio firewall per CorpSecure S.p.A. | ⭐⭐⭐⭐ | 2–3 ore |
| [C](esercizio_c.md) | 📝 Verifica scritta | 20 domande di teoria su DMZ e sicurezza perimetrale | ⭐⭐⭐ | 1 ora |

---

## 🗃️ Struttura Cartelle

```
ES06-DMZ/
│
├── README.md                    ← Questa pagina
│
├── esercizio_a.md               ← Lab guidato: DMZ singolo firewall in PT
├── esercizio_b.md               ← Progetto: DMZ doppio firewall
├── esercizio_c.md               ← Verifica scritta (20 domande teoria)
│
├── docs/
│   ├── 01_DMZ_Concetti.md       ← Teoria: DMZ, architetture, defense in depth
│   ├── 02_Firewall_ACL.md       ← Teoria: Firewall, ACL Cisco, wildcard mask
│   ├── 03_NAT_PAT_DMZ.md        ← Teoria: NAT statico, PAT, port forwarding
│   └── 04_IDS_IPS_Monitoraggio.md ← Teoria: IDS/IPS, SIEM, incident response
│
└── img/                         ← Screenshot Packet Tracer (da inserire)
    └── (es06a_screenshot_01.png, ...)
```

---

## ⚠️ Prerequisiti

Prima di iniziare questa esercitazione è necessario avere:
- Conoscenza base di **Cisco Packet Tracer** (aggiungere dispositivi, configurare IP)
- Conoscenza del **subnetting** e delle maschere di rete
- Conoscenza base dei comandi **Cisco IOS** (`enable`, `configure terminal`, `interface`, ecc.)
- Aver completato le esercitazioni precedenti (ES01–ES05) o equivalenti

---

## 💡 Suggerimento per l'Insegnante

L'esercizio A è pensato per essere svolto in coppia (pair programming), con uno studente che digita i comandi e l'altro che consulta la documentazione teorica. L'esercizio B può essere assegnato come progetto individuale o di gruppo. L'esercizio C è ideale come verifica scritta individuale da 1 ora.

---

*ES06 — Sistemi e Reti 3 | Materiale didattico*
