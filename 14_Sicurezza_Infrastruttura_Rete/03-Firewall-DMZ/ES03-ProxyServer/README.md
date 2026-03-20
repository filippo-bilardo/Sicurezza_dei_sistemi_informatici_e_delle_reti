# ES03 — Proxy Server: Configurazione e Sicurezza

🛡️ **Livello**: Scuola Superiore — Classe 4ª/5ª | **Materia**: Sistemi e Reti  
🔥 **Argomento**: Proxy Server — Filtraggio Web e Cache  
⏱️ **Durata stimata**: 4–6 ore (laboratorio + teoria)

---

## 📌 Introduzione

Un **Proxy Server** è un intermediario che si posiziona tra i client della rete interna e Internet, gestendo le richieste HTTP/HTTPS. I proxy offrono molteplici vantaggi:

- **Filtraggio contenuti**: blocco di siti malevoli, categorie inappropriate (social, streaming)
- **Caching**: memorizzazione delle risposte per ridurre banda e latenza
- **Anonimato/Privacy**: mascheramento dell'IP reale dei client
- **Logging e audit**: tracciamento completo dell'attività web degli utenti
- **Protezione malware**: scansione antivirus su file scaricati
- **Bandwidth shaping**: prioritizzazione del traffico aziendale

```
Senza Proxy:
[PC Client] ────────────> Internet (connessione diretta)
     ↑ IP reale esposto, nessun controllo

Con Proxy:
[PC Client] ───> [Proxy Server] ───> Internet
     ↑ 10.0.0.10    ↑ 192.168.1.50 (IP proxy verso Internet)
                    │
                    └─ Filtra, logga, cachea
```

**Perché è fondamentale**: in ambienti aziendali e scolastici, il proxy è lo strumento principale per:
- Garantire conformità alle policy di utilizzo accettabile (AUP)
- Prevenire infezioni malware tramite download
- Ridurre i costi di banda Internet (grazie al caching)
- Produrre audit trail per compliance (GDPR, normative settoriali)

È un componente essenziale della sicurezza di rete moderna e argomento frequente negli esami di maturità tecnica.

---

## 🎯 Competenze Coperte

Al termine di questa esercitazione lo studente sarà in grado di:

| # | Competenza |
|---|------------|
| 1 | Spiegare la differenza tra **forward proxy** e **reverse proxy** |
| 2 | Comprendere i concetti di **transparent proxy** vs **explicit proxy** |
| 3 | Installare e configurare **Squid Proxy** su Linux |
| 4 | Configurare i client per utilizzare il proxy (manuale e WPAD) |
| 5 | Implementare **blacklist/whitelist** per filtraggio URL |
| 6 | Configurare l'**autenticazione utente** (Basic, NTLM, LDAP) |
| 7 | Analizzare i **log di accesso** per audit e troubleshooting |
| 8 | Configurare il **caching** per ottimizzare la banda |
| 9 | Implementare **SSL/TLS interception** (HTTPS inspection) |
| 10 | Integrare il proxy con firewall e policy di sicurezza di rete |

---

## 📚 Guide Teoriche

Le seguenti guide in `docs/` forniscono tutto il background teorico necessario. Si consiglia di leggerle **prima** di affrontare gli esercizi.

| # | File | Argomento | Prerequisito per |
|---|------|-----------|-----------------|
| 1 | [01_Proxy_Concetti.md](docs/01_Proxy_Concetti.md) | Cos'è un proxy, forward/reverse, transparent/explicit | Tutti gli esercizi |
| 2 | [02_Squid_Installazione.md](docs/02_Squid_Installazione.md) | Installazione e configurazione base Squid | Esercizio A, B |
| 3 | [03_Filtraggio_ACL.md](docs/03_Filtraggio_ACL.md) | ACL Squid, blacklist, whitelist, categorie | Esercizio A, B |
| 4 | [04_Autenticazione.md](docs/04_Autenticazione.md) | Autenticazione proxy (Basic, NTLM, LDAP) | Esercizio B |
| 5 | [05_HTTPS_Inspection.md](docs/05_HTTPS_Inspection.md) | SSL Bumping, certificati, privacy | Esercizio C |
| 6 | [06_Cache_Performance.md](docs/06_Cache_Performance.md) | Caching, hit ratio, ottimizzazione banda | Esercizio B |

---

## 🗂️ Esercizi

| Esercizio | Tipo | Titolo | Difficoltà | Durata |
|-----------|------|--------|------------|--------|
| [A](esercizio_a.md) | 🔬 Laboratorio guidato | Configurazione Squid Proxy di base con filtraggio | ⭐⭐⭐ | 2–3 ore |
| [B](esercizio_b.md) | 🏗️ Progetto autonomo | Proxy aziendale con autenticazione e cache | ⭐⭐⭐⭐ | 2–3 ore |
| [C](esercizio_c.md) | 📝 Verifica scritta | 20 domande di teoria su proxy server e sicurezza | ⭐⭐⭐ | 1 ora |

---

## 🗃️ Struttura Cartelle

```
ES03-ProxyServer/
│
├── README.md                    ← Questa pagina
│
├── esercizio_a.md               ← Lab guidato: Squid base + filtraggio
├── esercizio_b.md               ← Progetto: Proxy enterprise con auth
├── esercizio_c.md               ← Verifica scritta (20 domande teoria)
│
├── docs/
│   ├── 01_Proxy_Concetti.md       ← Teoria: Forward/reverse proxy, transparent
│   ├── 02_Squid_Installazione.md  ← Teoria: Installazione Squid su Linux
│   ├── 03_Filtraggio_ACL.md       ← Teoria: ACL Squid, blacklist/whitelist
│   ├── 04_Autenticazione.md       ← Teoria: Autenticazione utenti
│   ├── 05_HTTPS_Inspection.md     ← Teoria: SSL Bumping, certificati
│   └── 06_Cache_Performance.md    ← Teoria: Caching, ottimizzazione
│
└── img/                         ← Screenshot lab (da inserire)
    └── (es03a_screenshot_01.png, ...)
```

---

## ⚠️ Prerequisiti

Prima di iniziare questa esercitazione è necessario avere:
- Conoscenza base di **Linux** (comandi bash, gestione servizi systemd)
- Conoscenza base di **networking** (IP, gateway, DNS)
- Conoscenza dei **protocolli HTTP/HTTPS**
- Accesso a macchine virtuali o container (VirtualBox, VMware, Docker)
- (Opzionale) Conoscenza base di Active Directory per esercizio autenticazione

---

## 💡 Suggerimento per l'Insegnante

L'esercizio A è pensato per essere svolto in coppia, con configurazione guidata step-by-step. L'esercizio B può essere assegnato come progetto di gruppo (2-3 studenti) o individuale per studenti avanzati. L'esercizio C è ideale come verifica scritta individuale da 1 ora. 

Si consiglia di preparare VM preconfigurate con Ubuntu Server per velocizzare il setup iniziale e concentrarsi sulla configurazione Squid.

---

*ES03 — Sistemi e Reti 3 | Materiale didattico*
