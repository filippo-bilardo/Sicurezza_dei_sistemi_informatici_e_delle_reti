# ES07 — Sicurezza della DMZ: Attacchi e Contromisure Avanzate

> 🏫 **Livello**: Scuola Superiore — 4ª/5ª classe (Informatica / Sistemi e Reti)
> 📚 **Modulo**: Sicurezza delle Reti — Architetture Perimetrali
> ⏱️ **Durata stimata**: 8–12 ore (laboratorio + teoria + progetto)
> 🎯 **Prerequisiti**: ES01–ES06, conoscenza base di ACL Cisco, concetti di DMZ

---

## 🎯 Introduzione

Una **DMZ mal configurata** non è una difesa — è una testa di ponte.

Molte organizzazioni considerano la DMZ come un "confine sicuro" tra Internet e la LAN interna. Questa percezione è **pericolosamente errata**: un singolo server DMZ compromesso, in assenza di contromisure adeguate, diventa la base di lancio perfetta per attaccare l'intera rete interna attraverso tecniche di **pivot attack** e **lateral movement**.

In questa esercitazione analizziamo:
- Come un attaccante sfrutta un server DMZ compromesso per raggiungere la LAN
- Perché le ACL permissive (errore comune) rendono inutile la DMZ
- Le contromisure avanzate: firewall stateful, IPS, micro-segmentazione, Zero Trust
- Come rispondere a un incidente in ambiente DMZ senza interrompere i servizi

> ⚠️ **Nota**: Tutte le tecniche di attacco descritte sono presentate a scopo **esclusivamente didattico** per comprendere come difendersi. L'utilizzo su sistemi reali senza autorizzazione è illegale.

---

## 🧠 Competenze Sviluppate

| # | Competenza | Livello |
|---|-----------|---------|
| 1 | Analisi di attacchi pivot e lateral movement da DMZ verso LAN | ⭐⭐⭐ |
| 2 | Progettazione e configurazione ACL anti-bypass su router Cisco | ⭐⭐⭐ |
| 3 | Hardening avanzato di server in zona DMZ | ⭐⭐⭐ |
| 4 | Micro-segmentazione e architettura doppia DMZ | ⭐⭐⭐⭐ |
| 5 | Principi Zero Trust applicati alla DMZ | ⭐⭐⭐⭐ |
| 6 | IDS/IPS: rilevamento intrusioni su traffico DMZ | ⭐⭐⭐ |
| 7 | Incident response per compromissione server DMZ | ⭐⭐⭐⭐ |
| 8 | Analisi rischio residuo post-contromisure | ⭐⭐⭐⭐ |

---

## 📚 Guide Teoriche

| File | Argomento | Pagine stimate | Prerequisiti |
|------|-----------|---------------|-------------|
| [`docs/01_Attacchi_DMZ.md`](docs/01_Attacchi_DMZ.md) | Attacchi alla DMZ: pivot, bypass, lateral movement, DDoS | ~12 | Concetti di rete base |
| [`docs/02_Hardening_DMZ.md`](docs/02_Hardening_DMZ.md) | Hardening OS, Web Server, DNS, Mail, Bastion Host, Patch Management | ~14 | Linux base, servizi di rete |
| [`docs/03_Micro_Segmentazione_ZeroTrust.md`](docs/03_Micro_Segmentazione_ZeroTrust.md) | Micro-segmentazione, Zero Trust, SDP, Deception Technology | ~12 | ACL, VLAN |
| [`docs/04_Incident_Response_DMZ.md`](docs/04_Incident_Response_DMZ.md) | Incident Response NIST, playbook pivot attack, containment | ~12 | Tutto il modulo |

---

## 🛠️ Esercizi

| Esercizio | Tipo | Argomento | Durata | Strumenti |
|-----------|------|-----------|--------|-----------|
| [**ES-A**](esercizio_a.md) | 🔬 Laboratorio guidato | Simulazione attacco pivot DMZ→LAN + contromisure ACL in Packet Tracer | 3–4 ore | Cisco Packet Tracer |
| [**ES-B**](esercizio_b.md) | 🏗️ Progetto autonomo | Riprogettazione architettura sicurezza FortressNet S.r.l. con doppia DMZ | 4–5 ore | PT + documentazione |
| [**ES-C**](esercizio_c.md) | 📝 Verifica teorica | 20 domande sulla sicurezza DMZ (70 punti) | 1–2 ore | Solo carta |

---

## 📁 Struttura del Progetto

```
ES07-DMZ-Security/
│
├── README.md                          ← Questo file
│
├── esercizio_a.md                     ← Lab guidato: pivot attack + ACL in PT
├── esercizio_b.md                     ← Progetto: architettura FortressNet
├── esercizio_c.md                     ← 20 domande teoriche (70 pt)
│
├── docs/
│   ├── 01_Attacchi_DMZ.md             ← Teoria: attacchi pivot, bypass, DDoS
│   ├── 02_Hardening_DMZ.md            ← Teoria: hardening server e OS
│   ├── 03_Micro_Segmentazione_ZeroTrust.md  ← Teoria: ZT, micro-seg, honeypot
│   └── 04_Incident_Response_DMZ.md    ← Teoria: IR NIST, playbook, metriche
│
└── img/                               ← Screenshot Packet Tracer (da inserire)
    ├── es07a_screenshot_01.png        ← Topologia completa PT
    ├── es07a_screenshot_02.png        ← Cablaggio e interfacce
    ├── ...
    └── es07a_screenshot_10.png        ← File .pkt salvato
```

---

## 🔗 Collegamento con le Altre Esercitazioni

| Esercitazione | Argomento | Collegamento con ES07 |
|--------------|-----------|----------------------|
| ES01 | Fondamenti TCP/IP e subnetting | Piano di indirizzamento DMZ |
| ES02 | VLAN e switching | Micro-segmentazione DMZ |
| ES03 | DNS Security | Hardening DNS in DMZ, DNS tunneling |
| ES04 | Firewall e ACL base | ACL anti-pivot, regole ESTABLISHED |
| ES05 | HTTP Security / WAF | Web server DMZ hardening, WAF |
| ES06 | Architettura DMZ base | Questo esercizio ne estende la sicurezza |

---

## ⚠️ Note per il Docente

- L'**esercizio A** richiede Cisco Packet Tracer ≥ 8.x; alcune funzionalità IPS non sono disponibili in PT (vedi note nell'esercizio)
- L'**esercizio B** può essere svolto in gruppo (2–3 studenti) come progetto multi-sessione
- L'**esercizio C** è adatto come **simulazione di seconda prova** per l'esame di maturità
- La doppia DMZ dell'esercizio B è un concetto avanzato: raccomandato solo per 5ª classe o studenti con ottima base

---

*ES07 — Sicurezza della DMZ | SISTEMI E RETI | © Materiale didattico open-source*
