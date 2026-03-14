# 01 — VLAN: Virtual Local Area Network

> **Materia**: Sistemi e Reti — Classe 5ª  
> **Parte**: 14 — Sicurezza dell'Infrastruttura di Rete

---

## 📖 Guide Teoriche

| # | File | Argomento |
|---|------|-----------|
| 01 | [VLAN e 802.1Q](01_vlan_e_8021q.md) | Cos'è una VLAN, standard IEEE 802.1Q, trunk port |
| 02 | [Configurazione delle VLAN](02_configurazione_vlan.md) | Comandi Cisco IOS per creare e gestire VLAN |
| 03 | [VTP e Inter-VLAN Routing](03_vtp_e_intervlan_routing.md) | VLAN Trunking Protocol, Router-on-a-Stick, SVI |
| 04 | [VLAN e Sicurezza](04_vlan_e_sicurezza.md) | VLAN hopping, PVLAN, port security, best practice |

---

## 🏋️ Esercitazioni

### ES01 — Progetto VLAN con Cisco Packet Tracer

> Progetta e configura una rete aziendale con VLAN, trunk, inter-VLAN routing e subnetting.

| File | Descrizione |
|------|-------------|
| [ES01-Progetto_VLAN/README.md](ES01-Progetto_VLAN/README.md) | Introduzione, competenze, sequenza di studio |
| [docs/01_VLAN.md](ES01-Progetto_VLAN/docs/01_VLAN.md) | VLAN — concetti e configurazione |
| [docs/02_Inter-VLAN_Routing.md](ES01-Progetto_VLAN/docs/02_Inter-VLAN_Routing.md) | Inter-VLAN Routing — Router-on-a-Stick e SVI |
| [docs/03_Subnetting.md](ES01-Progetto_VLAN/docs/03_Subnetting.md) | Subnetting — piano di indirizzamento |
| [docs/04_IEEE_802.1Q.md](ES01-Progetto_VLAN/docs/04_IEEE_802.1Q.md) | IEEE 802.1Q — VLAN tagging |
| [configs/Piano_Indirizzamento.md](ES01-Progetto_VLAN/configs/Piano_Indirizzamento.md) | Piano di indirizzamento IP completo |
| [configs/Router0.txt](ES01-Progetto_VLAN/configs/Router0.txt) | Configurazione Router0 |
| [configs/Router1.txt](ES01-Progetto_VLAN/configs/Router1.txt) | Configurazione Router1 |
| [configs/Switch0.txt](ES01-Progetto_VLAN/configs/Switch0.txt) | Configurazione Switch0 |
| [configs/Switch1.txt](ES01-Progetto_VLAN/configs/Switch1.txt) | Configurazione Switch1 |
| [esercizio_a.md](ES01-Progetto_VLAN/esercizio_a.md) | 🔬 Lab guidato — Topologia VLAN con Inter-VLAN Routing |
| [esercizio_b.md](ES01-Progetto_VLAN/esercizio_b.md) | 🏗️ Progetto autonomo — Rete aziendale TechCorp |
| [esercizio_c.md](ES01-Progetto_VLAN/esercizio_c.md) | 📖 Teoria — Domande su VLAN, 802.1Q, routing |

---

## 🗂️ Struttura Cartella

```
01-VLAN/
├── README.md                          ← Questo file
│
├── 01_vlan_e_8021q.md                 ← Guida: VLAN e standard 802.1Q
├── 02_configurazione_vlan.md          ← Guida: configurazione Cisco IOS
├── 03_vtp_e_intervlan_routing.md      ← Guida: VTP e inter-VLAN routing
├── 04_vlan_e_sicurezza.md             ← Guida: sicurezza VLAN
│
└── ES01-Progetto_VLAN/                ← Esercitazione VLAN (Cisco PT)
    ├── README.md
    ├── docs/
    │   ├── 01_VLAN.md
    │   ├── 02_Inter-VLAN_Routing.md
    │   ├── 03_Subnetting.md
    │   └── 04_IEEE_802.1Q.md
    ├── configs/
    │   ├── Piano_Indirizzamento.md
    │   ├── Router0.txt
    │   ├── Router1.txt
    │   ├── Switch0.txt
    │   └── Switch1.txt
    ├── esercizio_a.md
    ├── esercizio_b.md
    └── esercizio_c.md
```

---

## 🔑 Concetti Chiave

| Concetto | Descrizione breve |
|---------|-------------------|
| **VLAN** | Segmentazione logica della LAN — isola il traffico broadcast |
| **802.1Q** | Standard IEEE per il tagging delle VLAN sulle trunk port |
| **Trunk port** | Porta che trasporta traffico di più VLAN (tag 802.1Q) |
| **Access port** | Porta assegnata a una sola VLAN (senza tag) |
| **Native VLAN** | VLAN non taggata su una trunk — fonte di attacchi VLAN hopping |
| **VTP** | VLAN Trunking Protocol — propagazione automatica delle VLAN |
| **Router-on-a-Stick** | Inter-VLAN routing tramite subinterface su un singolo link trunk |
| **SVI** | Switch Virtual Interface — inter-VLAN routing su Layer 3 switch |
| **VLAN hopping** | Attacco che sfrutta double tagging o trunk negotiation per saltare VLAN |
| **Port security** | Limita i MAC address ammessi su una porta per prevenire accessi non autorizzati |

---

*Parte 14 — Sicurezza dell'Infrastruttura di Rete | Sistemi e Reti 5ª*
