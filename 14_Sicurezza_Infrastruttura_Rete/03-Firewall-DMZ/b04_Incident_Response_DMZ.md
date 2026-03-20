# 04 — Incident Response per Incidenti in DMZ

> 📚 **Guida teorica** | Livello: 4ª–5ª superiore
> 🔗 Prerequisiti: Tutta la guida ES07, nozioni di log e monitoraggio
> ⏱️ Tempo di lettura: ~28 minuti
> 📖 Riferimento normativo: NIST SP 800-61 Rev. 2

---

## 🚨 Rilevamento di un Incidente in DMZ

### Segnali di Compromissione

Prima ancora che il SIEM lanci un alert, ci sono spesso **segnali precoci** che qualcosa non va in DMZ:

| Categoria | Segnale | Livello di urgenza |
|-----------|---------|-------------------|
| **Traffico anomalo** | Un web server genera traffico verso la LAN su porte insolite | 🔴 CRITICO |
| **Connessioni insolite** | Il server si connette a IP esterni mai visti (C2 potenziale) | 🔴 CRITICO |
| **Port scan** | Un server DMZ invia SYN a centinaia di porte verso la LAN | 🔴 CRITICO |
| **Processi insoliti** | Processi non previsti in esecuzione (es. `nc`, `wget`, `curl` su un web server) | 🔴 CRITICO |
| **Picchi di CPU/Rete** | Utilizzo CPU o banda insolitamente alto a ore strane | 🟡 ALTO |
| **Tentativi di autenticazione** | Decine di login falliti su SSH da IP esterni | 🟡 ALTO |
| **Modifica file** | File di sistema o file web modificati in orari non lavorativi | 🟡 ALTO |
| **Nuovi account** | Account non previsti creati sul sistema | 🔴 CRITICO |
| **Log mancanti** | Un server che non invia più log al SIEM (forse qualcuno li ha bloccati) | 🟡 ALTO |

### IOC (Indicators of Compromise) per Server DMZ

Un **IOC** è una prova tecnica che indica la compromissione di un sistema. Per i server DMZ, gli IOC più rilevanti sono:

**IOC di rete**:
```
- Traffico DNS verso domini non standard (DNS tunneling)
- Richieste HTTP/HTTPS verso IP con bassa reputazione
- Connessioni in uscita su porte non standard (es. HTTP su porta 4444 → C2)
- Alta frequenza di richieste SYN verso subnet interne
- Traffico verso la LAN interna che normalmente non dovrebbe esistere
```

**IOC di sistema (log del server)**:
```
- File .php, .asp, .jsp appena creati in directory web (web shell)
- Esecuzione di comandi di sistema da processi web (es. Apache che esegue "id", "whoami")
- Accessi SSH da IP mai visti
- Modifica di /etc/passwd, /etc/shadow, /etc/crontab
- Creazione di task pianificati (cron job) non autorizzati
- Download di file binari (wget, curl) da server web
```

**IOC SIEM — Pattern di correlazione**:
```
ALERT: "Web server esegue comandi di sistema" =
  source: web-server-process-log
  pattern: Apache/Nginx genera processo figlio con argomenti /bin/sh, /bin/bash, cmd.exe

ALERT: "Pivot attempt" =
  source: firewall-log
  event: web-server-ip → LAN-subnet: TCP SYN su porte diverse da quelle consentite
```

---

## 📋 Le 6 Fasi di Incident Response (NIST SP 800-61)

Il NIST SP 800-61 "Computer Security Incident Handling Guide" è la guida di riferimento per la risposta agli incidenti. Definisce un ciclo di vita dell'incidente:

```
    ┌─────────────────────────────────────────────┐
    │                                             │
    ▼                                             │
[1. PREPARATION]                                  │
Essere pronti prima che accada                    │
    │                                             │
    ▼                                             │
[2. DETECTION & ANALYSIS]                         │
Rilevare e capire cosa sta succedendo             │
    │                                             │
    ▼                                             │
[3. CONTAINMENT]                                  │
Fermare la diffusione del danno                   │
    │                                             │
    ▼                                             │
[4. ERADICATION]                                  │
Rimuovere la minaccia                             │
    │                                             │
    ▼                                             │
[5. RECOVERY]                                     │
Ripristinare il servizio                          │
    │                                             │
    ▼                                             │
[6. POST-INCIDENT ACTIVITY]                       │
Imparare dall'incidente                           │
    │                                             │
    └─────────────────────────────────────────────┘
          (le lezioni migliorano la Preparation)
```

### Fase 1 — Preparation (Pre-Incidente)

La preparazione avviene **prima** che si verifichi un incidente. La risposta è tanto più efficace quanto più è stata preparata in anticipo.

**Attività di preparazione per la DMZ**:

| Attività | Dettaglio | Responsabile |
|----------|-----------|-------------|
| **CSIRT costituito** | Team di risposta definito con ruoli chiari (Incident Manager, Analyst, Communication Lead) | CISO |
| **Runbook documentati** | Procedure specifiche per ogni tipo di incidente (pivot attack, DDoS, web shell) | Security Team |
| **Strumenti pronti** | Forensic toolkit, log collector, backup testato, contatti ISP | IT Operations |
| **Baseline stabilita** | "Come appare il traffico normale?" — senza baseline non si riconosce l'anomalia | Security Monitoring |
| **Comunicazione definita** | Chi avvisare, quando, in quale ordine (management, DPO, autorità) | Legal + CISO |
| **Backup verificato** | Il backup dei server DMZ è aggiornato e testato (restore verificato) | IT Operations |
| **Accessi isolamento preparati** | Regole ACL di emergenza già pronte (basta applicarle) | Network Team |

### Fase 2 — Detection & Analysis

**Obiettivo**: Capire se si tratta davvero di un incidente, qual è la sua portata, e classificarne la gravità.

**Triage iniziale** (primi 15 minuti):

```
Alert ricevuto dal SIEM → Analista di sicurezza risponde:

1. È un falso positivo? 
   → Controlla la baseline: questo comportamento è mai avvenuto prima?
   → Se il web server fa ping verso la LAN ogni lunedì per backup → normale
   → Se fa port scan a 1000 porte → NON normale

2. Qual è la portata?
   → Quanti sistemi sono coinvolti?
   → Il traffico anomalo va solo verso un IP o verso tutta la LAN?
   → Ci sono altri server DMZ che mostrano comportamenti simili?

3. Qual è la gravità?
   → Classificazione: Low / Medium / High / Critical
   → Fattori: dati sensibili esposti? Impatto su servizi? Violazione GDPR?

4. Raccolta evidence (NON modificare nulla ancora!):
   → Snapshot della memoria del server (se possibile)
   → Copia dei log attuali
   → pcap (packet capture) del traffico anomalo
   → Screenshot del SIEM
```

**Raccolta evidence — Ordine di volatilità (dalla più alla meno volatile)**:

```
1. Contenuto della RAM (perde dati allo spegnimento → catturare PRIMO)
2. Tabelle di routing, ARP cache, connessioni attive
3. Log temporanei in /tmp
4. Processi in esecuzione (ps aux, netstat)
5. File aperti (lsof)
6. Log di sistema (/var/log/)
7. File su disco (web shell, modifiche)
8. Backup e dati archiviati (meno volatili)
```

### Fase 3 — Containment (Contenimento)

**Obiettivo**: Fermare la diffusione del danno **senza distruggere le prove** e, se possibile, **senza interrompere il servizio**.

**Strategie di contenimento per la DMZ**:

#### Opzione A — Isolamento ACL (preferita, mantenimento servizio)

```cisco
! REGOLA DI EMERGENZA — Applica IMMEDIATAMENTE
! Isola il server compromesso bloccando tutto il suo traffico in uscita
! ma mantieni gli altri server DMZ operativi

ip access-list extended EMERGENCY-ISOLATE-WEBSERVER
 ! Blocca TUTTO in uscita dal web server compromesso
 deny ip host 172.16.10.10 any log
 ! Ma mantieni altri server raggiungibili
 permit tcp any host 172.16.10.11 eq 53   ! DNS pubblico
 permit tcp any host 172.16.10.12 eq 25   ! Mail server
 deny ip any any log

! Applica sull'interfaccia DMZ
interface GigabitEthernet0/1
 ip access-group EMERGENCY-ISOLATE-WEBSERVER in
```

**Vantaggio**: Gli altri server DMZ continuano a funzionare. Il servizio web è temporaneamente down ma il danno è limitato.

#### Opzione B — VLAN Quarantena

```
Sposta il server compromesso in una VLAN quarantena isolata:

VLAN 10 (DMZ normale) → VLAN 99 (Quarantena)

VLAN 99:
- Nessuna connessione verso la LAN
- Nessuna connessione verso altri server DMZ
- Accesso solo dal team di security (per analisi forense)
- Tutti i log inviati al SIEM
```

**Vantaggio**: Il server è completamente isolato ma ancora acceso (per analisi forense).

#### Opzione C — Null Route

```cisco
! Null route: tutto il traffico verso/da il server finisce nel "nulla"
ip route 172.16.10.10 255.255.255.255 Null0

! Il server non è più raggiungibile né può raggiungere nessuno
! Rapido da implementare in emergenza
```

**Quando usare cosa**:

| Situazione | Strategia consigliata |
|-----------|----------------------|
| Attacco in corso, evidenza certa | Opzione A (ACL isolamento) — immediato |
| Server critico, no certezza | Opzione A con monitoring intensificato |
| Analisi forense richiesta | Opzione B (VLAN quarantena) — server attivo |
| Emergenza massima, tutto compromesso | Opzione C (null route) + notify team |

### Fase 4 — Eradication (Rimozione della Minaccia)

**Obiettivo**: Eliminare completamente la presenza dell'attaccante dal sistema compromesso.

**Ordine delle operazioni**:

```
1. ANALISI FORENSE (prima di toccare nulla)
   → Crea una copia bit-per-bit del disco (forensic image)
   → dd if=/dev/sda of=/backup/forensic-image-$(date +%Y%m%d).img
   → Calcola hash: sha256sum /dev/sda

2. IDENTIFICAZIONE VETTORE
   → Come è entrato l'attaccante?
   → Analizza access log del web server
   → Cerca web shell (file .php recenti in directory web)
   → find /var/www/html -name "*.php" -newer /etc/passwd -ls

3. SCOPE CHECK — altri server compromessi?
   → Controlla log di accesso di TUTTI i server DMZ nel periodo sospetto
   → Cerca lo stesso IP dell'attaccante in tutti i log
   → Verifica se il server compromesso ha effettuato connessioni verso altri server

4. RIMOZIONE MALWARE
   → Rimuovi web shell trovate
   → Chiudi eventuali backdoor (cron job, account creati)
   → Cambia TUTTE le password del sistema e dei servizi
   → Verifica chiavi SSH autorizzate: cat /root/.ssh/authorized_keys

5. PATCHING
   → Identifica la vulnerabilità sfruttata
   → Applica la patch
   → Verifica con vulnerability scanner
```

### Fase 5 — Recovery (Ripristino)

**Obiettivo**: Ripristinare il servizio in modo sicuro, con hardening aggiuntivo.

**Opzioni di ripristino**:

```
Opzione A (consigliata): Rebuild da zero
→ Distruggi la VM/istanza compromessa
→ Rideploy da immagine aurea (golden image) pulita
→ Restaura solo i dati (non i binari) da backup
→ Applica hardening completo + patch
→ Test funzionale
→ Monitoring intensificato per 2 settimane

Opzione B: Restore da backup
→ Restore da backup precedente alla compromissione
→ Identifica il punto preciso nel tempo (prima dell'incidente)
→ Applica tutte le patch successive al backup
→ Verifica integrità del backup (il backup stesso potrebbe essere compromesso se abbastanza vecchio!)

Opzione C: Pulizia in-place (sconsigliata per incidenti gravi)
→ Rimuovi malware manualmente
→ Patcha la vulnerabilità
→ Rischio: backdoor non trovate
```

**Timeline di recovery tipica per server DMZ**:

| Attività | Durata stimata |
|----------|---------------|
| Forensic image del server | 30–60 minuti |
| Analisi forense iniziale | 2–4 ore |
| Rebuild / restore server | 1–2 ore |
| Configurazione e hardening | 2–3 ore |
| Test funzionali | 30–60 minuti |
| Return to operations | — |
| **Totale minimo** | **~8 ore** |

### Fase 6 — Post-Incident Activity

**Obiettivo**: Imparare dall'incidente per evitare che si ripeta.

**Attività**:

```
1. LESSONS LEARNED MEETING (entro 1 settimana)
   Partecipanti: tutto il team coinvolto
   Domande chiave:
   - Cosa è successo esattamente?
   - Come è stata rilevata la compromissione? (e perché non prima?)
   - Le procedure di risposta hanno funzionato?
   - Cosa cambieremmo?

2. AGGIORNAMENTO RUNBOOK
   - Aggiorna le procedure in base a ciò che non ha funzionato
   - Aggiungi le nuove regole di correlazione SIEM
   - Aggiorna la lista degli IOC

3. ROOT CAUSE ANALYSIS
   - Qual è la causa radice? (vulnerabilità non patchata? configurazione errata?)
   - Come si previene in futuro?

4. REPORT PER IL MANAGEMENT
   - Executive summary (non tecnico)
   - Timeline dell'incidente
   - Impatto (dati esposti? downtime? costo stimato?)
   - Azioni correttive intraprese
   - Rischio residuo

5. NOTIFICHE OBBLIGATORIE (GDPR)
   - Se dati personali sono stati esposti:
     → Notifica all'Autorità Garante entro 72 ore dall'incidente
     → Notifica agli interessati (utenti/clienti) se c'è rischio elevato
```

---

## 🔕 Containment senza Downtime

Il dilemma più difficile della risposta agli incidenti in DMZ: **isolare il server compromesso mantenendo il servizio**.

### Strategie Specifiche

**1. Load Balancer Redirect**
```
PRIMA DELL'INCIDENTE:
[Internet] → [Load Balancer] → [Web-01: 172.16.10.10] ← compromesso!
                             → [Web-02: 172.16.10.11]

DURANTE L'INCIDENTE:
→ Rimuovi Web-01 dal pool del load balancer
→ Tutto il traffico va su Web-02
→ Web-01 viene isolato per analisi

REQUISITO: architettura load-balanced (almeno 2 istanze)
```

**2. DNS Failover**
```
→ Modifica il record DNS: www.azienda.it punta a IP alternativo
→ Il vecchio server (compromesso) non riceve più traffico legittimo
→ TTL basso necessario (es. 300 secondi) per propagazione rapida

RISCHIO: se TTL era alto (es. 86400), ci vuole fino a 24h per propagarsi
```

**3. ACL Granulare (solo traffico attivo)**
```cisco
! Blocca solo traffico nuovo verso la LAN, mantieni connessioni esistenti
! (approccio meno aggressivo)
ip access-list extended PARTIAL-ISOLATE
 ! Blocca connessioni NUOVE dalla DMZ verso LAN
 deny tcp 172.16.10.10 0.0.0.0 172.16.20.0 0.0.0.255 syn log
 ! Permetti risposte a connessioni esistenti verso Internet (servizio web)
 permit tcp any host 172.16.10.10 established
 ! Blocca tutto il resto dal server compromesso
 deny ip host 172.16.10.10 any log
 permit ip any any
```

### Quando è Accettabile lo Spegnimento Immediato

| Situazione | Azione consigliata |
|-----------|-------------------|
| Ransomware in propagazione attiva | ❌ Spegni immediatamente |
| Esfiltrazione dati in corso | ❌ Blocca connessione di rete, poi forense |
| Il server è un honeypot/non critico | ✅ Mantieni attivo per raccogliere informazioni sull'attaccante |
| Servizio critico con alta disponibilità | 🔄 Failover prima, poi isola |
| Incerto / analisi in corso | 🔄 Isolamento rete, mantieni acceso per forense |

---

## 💬 Comunicazione durante l'Incidente

### Chi Avvisare e Quando

```
                    INCIDENTE CONFERMATO
                           │
               ┌───────────┼───────────┐
               │           │           │
            T+1h         T+4h        T+72h
               │           │           │
        ┌──────▼──┐   ┌────▼────┐  ┌──▼────────┐
        │ INTERNO │   │ LEGALE  │  │ GARANTE   │
        │         │   │         │  │ PRIVACY   │
        │ CISO    │   │ DPO     │  │ (se dati  │
        │ CTO     │   │ CEO     │  │  personali│
        │ IT Team │   │ Avvocato│  │  esposti) │
        └─────────┘   └─────────┘  └───────────┘

T+24h se necessario: CLIENTI/UTENTI (se dati loro esposti)
T+24h se necessario: STAMPA (solo tramite ufficio comunicazione)
```

### Regole di Comunicazione Esterna

> ⚠️ **Non comunicare mai** con la stampa o con i clienti in modo improvvisato. Ogni comunicazione esterna deve essere approvata dalla direzione e dal legale.

**Cosa comunicare ai clienti** (se applicabile):
1. Cosa è successo (in termini semplici, senza dettagli tecnici che aiutino futuri attaccanti)
2. Quali dati potrebbero essere stati esposti
3. Cosa sta facendo l'azienda per risolvere
4. Cosa devono fare gli utenti (es. cambiare password)
5. Contatto per domande

---

## 📖 Playbook: Pivot Attack DMZ → LAN

Questo playbook è il riferimento operativo per gestire un attacco pivot confermato o sospetto.

```
╔══════════════════════════════════════════════════════════════════╗
║  PLAYBOOK: PIVOT ATTACK DMZ → LAN                               ║
║  Trigger: server DMZ genera traffico verso LAN su porte insolite ║
╚══════════════════════════════════════════════════════════════════╝

PASSO 1 — CONFERMA (T+0, max 10 minuti)
─────────────────────────────────────────
□ Verifica il log del firewall:
  show access-lists → cerca matches su regole DMZ→LAN
  
□ Verifica connessioni attive dal server sospetto:
  (se hai accesso) netstat -antp | grep 172.16.20

□ Controlla su SIEM: altri eventi correlati nelle ultime 24h?
  - tentativi SSH falliti sul server DMZ
  - nuovi processi avviati dal web server
  - modifica file in directory web

□ Classifica: CONFERMATO / SOSPETTO / FALSO POSITIVO
  → Se falso positivo: documenta e chiudi
  → Se confermato o sospetto: continua al Passo 2

PASSO 2 — BLOCCO IMMEDIATO (T+10, max 5 minuti)
─────────────────────────────────────────────────
□ Applica regola ACL di emergenza sul firewall:
  
  ip access-list extended EMERGENCY-BLOCK
   deny ip host [IP-server-compromesso] 172.16.20.0 0.0.0.255 log
   permit ip any any
  
  interface GigabitEthernet0/1
   ip access-group EMERGENCY-BLOCK in

□ Verifica che il blocco funzioni:
  show access-lists EMERGENCY-BLOCK → contatori aumentano
  
□ Notifica il CISO e avvia il protocollo di IR

PASSO 3 — RACCOLTA LOG (T+15, max 30 minuti)
──────────────────────────────────────────────
□ Esporta i log del firewall relativi alle ultime 48h
□ Esporta i log del server compromesso (/var/log/apache2/, auth.log, syslog)
□ Cattura stato di rete del server: ss -antp > /tmp/network-state.txt
□ Lista processi: ps auxf > /tmp/process-list.txt
□ Connessioni attive: cat /proc/net/tcp >> /tmp/network-state.txt
□ File recentemente modificati: find /var/www -newer /etc/passwd -ls > /tmp/recent-files.txt
□ Calcola hash di tutti i file .php: find /var/www -name "*.php" -exec sha256sum {} \;

PASSO 4 — ANALISI VETTORE DI INGRESSO (T+45, ~2 ore)
──────────────────────────────────────────────────────
□ Analizza access log web server per richieste sospette:
  grep -E "shell\.php|cmd=|exec=|system\(|eval\(" /var/log/apache2/access.log
  
□ Cerca web shell:
  find /var/www -name "*.php" -newer /etc/passwd -exec cat {} \; | grep -E "system|exec|shell"
  
□ Analizza auth.log per accessi SSH non autorizzati:
  grep "Accepted" /var/log/auth.log
  grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
  
□ Identifica il CVE sfruttato (se possibile)
□ Verifica se la patch era disponibile

PASSO 5 — SCOPE: ALTRI SERVER COMPROMESSI? (T+45 parallelo)
─────────────────────────────────────────────────────────────
□ Controlla i log di TUTTI gli altri server DMZ per lo stesso IP attaccante
□ Verifica se il server compromesso ha fatto connessioni verso altri server DMZ:
  grep "[IP-attaccante]" /var/log/server-dns/access.log
  grep "[IP-attaccante]" /var/log/mail/access.log
  
□ Se altri server risultano compromessi: ripeti Passi 2-4 per ognuno
□ Verifica se qualche sistema LAN mostra segni di accesso non autorizzato:
  Cerca nel SIEM: login da IP della DMZ su sistemi LAN

PASSO 6 — ERADICATION E RESTORE (T+3h+)
──────────────────────────────────────────
□ Crea forensic image del server compromesso:
  dd if=/dev/sda of=/backup/forensic-$(hostname)-$(date +%Y%m%d).img bs=4M
  sha256sum /dev/sda > /backup/forensic-$(hostname)-$(date +%Y%m%d).sha256
  
□ Rideploy il server da golden image pulita (preferito) OR restore da backup
□ Applica patch per la vulnerabilità sfruttata
□ Esegui hardening aggiuntivo (checklist doc 02)
□ Test funzionale completo
□ Rimuovi la regola ACL di emergenza (sostituisci con regole permanenti corrette)
□ Return to operations con monitoring intensificato

PASSO 7 — ROOT CAUSE ANALYSIS (T+24h+)
─────────────────────────────────────────
□ Documenta la timeline completa dell'incidente
□ Identifica la causa radice (vulnerabilità non patchata? misconfiguration? errore umano?)
□ Identifica cosa ha permesso la persistenza non rilevata
□ Proponi cambiamenti architetturali per prevenire simili incidenti
□ Aggiorna questo playbook con le lezioni apprese
□ Redigi report per il management
```

---

## 📊 Metriche Post-Incidente

Misurare le performance della risposta agli incidenti permette di migliorare nel tempo:

| Metrica | Definizione | Formula | Obiettivo |
|---------|-------------|---------|-----------|
| **MTTD** | Mean Time To Detect | Tempo da compromissione a rilevamento | < 1 ora per incidenti DMZ |
| **MTTR** | Mean Time To Respond | Tempo da rilevamento a containment | < 30 minuti |
| **MTTRS** | Mean Time To Restore Service | Tempo da containment a servizio ripristinato | < 8 ore |
| **Dwell Time** | Tempo in cui l'attaccante è rimasto non rilevato | Data compromissione – data rilevamento | → 0 (minimizzare) |

**Costo stimato dell'incidente**:
```
Costo totale =  Downtime del servizio (€/ora × ore)
              + Costo lavoro IR team (ore × tariffa oraria)
              + Costo rebuild/restore
              + Costo forense esterno (se coinvolto)
              + Costo notifiche GDPR (legale, comunicazione)
              + Danno reputazionale (difficile da quantificare)
              + Eventuale multa Garante (fino al 4% del fatturato annuo)
```

---

## 📊 Tabella Riepilogativa: Tipo Incidente → Risposta

| Tipo Incidente | Segnali Principali | Containment Immediato | Priorità IR |
|----------------|-------------------|----------------------|-------------|
| **Web Shell trovata** | File .php sospetto in dir web; esecuzione comandi OS da processo web | Blocco ACL server; VLAN quarantena | 🔴 CRITICO |
| **Pivot Attack** | Traffico server DMZ → LAN; port scan interno | Blocco ACL (deny src:server-DMZ dst:LAN) | 🔴 CRITICO |
| **DDoS su Web Server** | Alto volume traffico in ingresso; web server irraggiungibile | Contatta ISP; abilita scrubbing; rate limiting | 🔴 CRITICO |
| **Brute Force SSH** | Decine di auth failure su SSH da stesso IP | Blocca IP sorgente; abilita fail2ban | 🟡 ALTO |
| **DNS Amplification abuse** | Alto traffico UDP:53 in uscita; IP esterni segnalano spam | Abilita RRL; verifica config recursion | 🟡 ALTO |
| **Mail Server Open Relay** | Log mostrano invio email per conto di domini terzi | Blocca SMTP in uscita eccetto per domini autorizzati | 🟡 ALTO |
| **Log tampering** | Server smette di inviare log al SIEM; log locali cancellati | Assume compromissione totale → isolamento immediato | 🔴 CRITICO |
| **Certificate Compromise** | Certificato SSL del server usato su domini non autorizzati | Revoca certificato (CRL/OCSP); richiedi nuovo | 🟡 ALTO |

---

## 🧪 Punti di Riflessione

> 💬 **Domanda 1**: Un incidente viene rilevato 11 giorni dopo la compromissione (il "dwell time" è di 11 giorni). Cosa avrebbe permesso di ridurre questo tempo a meno di 1 ora?

> 💬 **Domanda 2**: Il CISO vuole spegnere immediatamente il server compromesso per "fermare il danno". Tu, come analista forense, sei contrario. Quali argomenti porti? Quando invece hai torto e il CISO ha ragione?

> 💬 **Domanda 3**: Dopo un incidente con violazione di dati personali, il management vuole aspettare 2 settimane prima di notificare il Garante "per capire meglio l'entità del danno". Qual è la tua risposta dal punto di vista normativo?

---

*04 — Incident Response per la DMZ | Guida Teorica ES07 | SISTEMI E RETI*
