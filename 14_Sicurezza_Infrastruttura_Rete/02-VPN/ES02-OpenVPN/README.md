# ES02 — OpenVPN: Configurazione VPN SSL su Linux

> **Materia**: Sistemi e Reti — Classe 5ª  
> **Argomento**: VPN con OpenVPN su server Linux (Ubuntu Server)  
> **Durata stimata**: 3–4 ore (esercizio A), 4–5 ore (esercizio B)

---

## 🌐 Introduzione

**OpenVPN** è la soluzione VPN open source più diffusa al mondo. A differenza di IPsec — che opera a livello rete ed è integrato nel kernel — OpenVPN funziona a livello applicativo, usando **TLS** per cifrare il canale. Questo lo rende estremamente flessibile: funziona su UDP o TCP, attraversa quasi tutti i firewall (porta 443), ed è disponibile su ogni sistema operativo.

In questa esercitazione configurerai un server OpenVPN su **Ubuntu Server** e collegherai client Linux e Windows, simulando un accesso remoto aziendale reale (scenario *Remote Access VPN* o "Road Warrior").

> ⚠️ **Ambiente di laboratorio**: gli esercizi usano **macchine virtuali Linux** (VirtualBox o VMware) anziché Cisco Packet Tracer, poiché OpenVPN gira su sistemi operativi reali.

---

## 🎯 Competenze Coperte

| # | Competenza | Livello |
|---|-----------|---------|
| 1 | Installazione e configurazione di un server OpenVPN su Ubuntu | ⭐⭐ |
| 2 | Creazione di una PKI (CA, certificati server e client) con Easy-RSA | ⭐⭐⭐ |
| 3 | Configurazione del tunnel TLS (tls-crypt, cipher AES-256-GCM) | ⭐⭐⭐ |
| 4 | Configurazione IP forwarding e NAT (iptables) sul server | ⭐⭐ |
| 5 | Connessione di un client Linux e Windows al server VPN | ⭐⭐ |
| 6 | Verifica del tunnel: IP assegnato, routing, traffico cifrato | ⭐⭐ |
| 7 | Differenza tra full tunnel e split tunnel | ⭐⭐⭐ |
| 8 | Revoca di un certificato client (CRL) | ⭐⭐⭐ |

---

## 📚 Guide Teoriche

| # | File | Argomento | Priorità |
|---|------|-----------|----------|
| 1 | [`docs/01_SSL_VPN_Concetti.md`](docs/01_SSL_VPN_Concetti.md) | Differenze SSL VPN vs IPsec, layer OSI, porte | 📖 Prima di tutto |
| 2 | [`docs/02_PKI_Certificati.md`](docs/02_PKI_Certificati.md) | PKI, CA, certificati X.509, Easy-RSA | 📖 Prima degli esercizi |
| 3 | [`docs/03_OpenVPN_Config.md`](docs/03_OpenVPN_Config.md) | Guida comandi OpenVPN: server.conf, client.ovpn | 🔧 Riferimento durante lab |
| 4 | [`docs/04_Troubleshooting.md`](docs/04_Troubleshooting.md) | Diagnosi errori TLS, routing, DNS leak | 🛠️ Quando qualcosa non funziona |

---

## 🏋️ Esercizi

| Esercizio | File | Tipo | Difficoltà | Punti |
|-----------|------|------|------------|-------|
| **A** | [`esercizio_a.md`](esercizio_a.md) | Laboratorio guidato — Server OpenVPN Road Warrior | ⭐⭐⭐ | /100 |
| **B** | [`esercizio_b.md`](esercizio_b.md) | Progetto autonomo — VPN Site-to-Site con OpenVPN | ⭐⭐⭐⭐ | /100 + bonus |
| **C** | [`esercizio_c.md`](esercizio_c.md) | Teoria — 20 domande su OpenVPN, TLS, PKI, sicurezza | ⭐⭐ | /70 |

---

## 🗂️ Struttura Cartelle

```
ES02-OpenVPN/
├── README.md                          ← Questo file
├── esercizio_a.md                     ← Lab guidato: server OpenVPN + client road warrior
├── esercizio_b.md                     ← Progetto autonomo: VPN site-to-site
├── esercizio_c.md                     ← Domande di teoria
├── docs/
│   ├── 01_SSL_VPN_Concetti.md         ← Teoria: SSL VPN, TLS, confronto con IPsec
│   ├── 02_PKI_Certificati.md          ← Teoria: PKI, CA, Easy-RSA
│   ├── 03_OpenVPN_Config.md           ← Pratica: configurazione server e client
│   └── 04_Troubleshooting.md         ← Pratica: diagnosi e risoluzione problemi
└── img/                               ← Screenshot degli esercizi
```

---

## 🔧 Software Richiesto

- **VirtualBox** 7.x o **VMware Workstation** 17+
- **Ubuntu Server 22.04 LTS** (server VPN)
- **Ubuntu Desktop 22.04** o **Windows 10/11** (client)
- Connessione di rete in modalità **Host-Only + NAT** (per simulare LAN + Internet)

---

## 🔑 Concetti Chiave da Ricordare

| Concetto | Descrizione breve |
|---------|-------------------|
| **TLS** | Transport Layer Security — protocollo che cifra il canale OpenVPN |
| **PKI** | Public Key Infrastructure — sistema di certificati per autenticazione |
| **CA** | Certificate Authority — emette e firma i certificati |
| **tls-crypt** | Chiave pre-condivisa che cifra anche il canale di controllo TLS |
| **tun** | Interfaccia virtuale Layer 3 (routing) — usata da OpenVPN in modalità tunnel |
| **tap** | Interfaccia virtuale Layer 2 (bridging) — usata per bridging Ethernet |
| **Full tunnel** | Tutto il traffico del client passa per la VPN (0.0.0.0/0) |
| **Split tunnel** | Solo il traffico verso la rete aziendale passa per la VPN |
| **CRL** | Certificate Revocation List — lista certificati revocati (client bloccati) |
| **AES-256-GCM** | Algoritmo di cifratura AEAD usato da OpenVPN per i dati |

---

## 📋 Sequenza di Studio Consigliata

```
1. Leggi docs/01_SSL_VPN_Concetti.md    →  Comprendi SSL VPN e confronto con IPsec
2. Leggi docs/02_PKI_Certificati.md     →  Studia PKI e certificati
3. Leggi docs/03_OpenVPN_Config.md      →  Tieni aperto come riferimento durante il lab
4. Esegui esercizio_a.md               →  Lab guidato passo-passo
5. Esegui esercizio_b.md               →  Progetto autonomo site-to-site
6. Rispondi esercizio_c.md             →  Verifica teoria
   (usa docs/04_Troubleshooting.md se hai problemi durante i lab)
```

---

*ES02 — Sistemi e Reti | Versione 1.0 | Ubuntu Server 22.04 LTS*
