# ES01 — Progetto VLAN: Configurazione Rete con Inter-VLAN Routing

![Topologia di rete](img/image1.png)

## Introduzione

In questa esercitazione si affronta la progettazione e configurazione di una rete locale segmentata tramite **VLAN (Virtual Local Area Network)**. La rete principale `192.168.10.0/24` viene suddivisa in **5 sottoreti** usando il subnetting con maschera `/27`, e la comunicazione tra i segmenti è realizzata tramite la tecnica **Router-on-a-Stick** con due router Cisco 2901 interconnessi via GigabitEthernet.

L'esercitazione copre le seguenti competenze:
- Subnetting e calcolo del piano di indirizzamento
- Configurazione di VLAN su switch Cisco 2960
- Routing inter-VLAN con subinterface (dot1Q)
- Verifica della connettività e troubleshooting di rete

---

## 📚 Guide Teoriche

Nella cartella [`docs/`](docs/) sono disponibili le guide di riferimento sugli argomenti trattati:

| # | Guida | Argomento |
|---|-------|-----------|
| 1 | [01_VLAN.md](docs/01_VLAN.md) | Cos'è una VLAN, tipi, comandi Cisco, troubleshooting |
| 2 | [02_Inter-VLAN_Routing.md](docs/02_Inter-VLAN_Routing.md) | Router-on-a-Stick, subinterface, encapsulation dot1Q |
| 3 | [03_Subnetting.md](docs/03_Subnetting.md) | Subnetting, VLSM, calcolo subnet e broadcast |
| 4 | [04_IEEE_802.1Q.md](docs/04_IEEE_802.1Q.md) | Standard 802.1Q, struttura del tag, native VLAN |

---

## 🗂️ Esercizi

Nella cartella [`esercizi/`](esercizi/) sono presenti tre esercitazioni di difficoltà crescente:

| # | Esercizio | Descrizione | Tipo |
|---|-----------|-------------|------|
| A | [esercizio_a.md](esercizio_a.md) | Configurazione guidata della topologia VLAN2 in Cisco Packet Tracer (9 step con screenshot) | Laboratorio pratico |
| B | [esercizio_b.md](esercizio_b.md) | Progettazione autonoma della rete aziendale TechCorp con 4 VLAN su rete `172.16.100.0/24` | Progetto autonomo |
| C | [esercizio_c.md](esercizio_c.md) | 20 domande di teoria su VLAN, subnetting, Router-on-a-Stick, 802.1Q e troubleshooting | Verifica teorica |

---

## 📁 Struttura del Progetto

```
ES01-Progetto_VLAN/
├── README.md               ← questo file
├── esercizio_a.md          ← laboratorio guidato (Packet Tracer)
├── esercizio_b.md          ← progetto autonomo (TechCorp)
├── esercizio_c.md          ← domande di teoria (20 domande)
├── img/
│   └── image1.png          ← schema topologia di riferimento
├── docs/                   ← guide teoriche
│   ├── 01_VLAN.md
│   ├── 02_Inter-VLAN_Routing.md
│   ├── 03_Subnetting.md
│   └── 04_IEEE_802.1Q.md
└── configs/                ← configurazioni complete dei dispositivi
    ├── Router0.txt
    ├── Router1.txt
    ├── Switch0.txt
    ├── Switch1.txt
    └── Piano_Indirizzamento.md
```
