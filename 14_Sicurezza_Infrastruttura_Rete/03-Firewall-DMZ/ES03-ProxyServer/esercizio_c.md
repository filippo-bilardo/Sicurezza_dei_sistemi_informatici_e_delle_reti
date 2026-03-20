# C — Verifica Scritta: Proxy Server e Sicurezza Web

📝 **Tipo**: Verifica scritta  
⭐ **Difficoltà**: ⭐⭐⭐ (Intermedio)  
⏱️ **Durata**: 1 ora  
📄 **Modalità**: Carta e penna / Computer  

---

## 📌 Istruzioni

- Tempo massimo: **60 minuti**
- Risposte aperte: max 5-6 righe ciascuna
- Valutazione: 20 domande × 0,5 punti = **10/10**
- Sufficienza: **6/10** (12 risposte corrette)
- Consultazione materiale: **NON permessa**

---

## Sezione 1: Concetti Fondamentali (6 domande)

### Domanda 1
**Cos'è un proxy server e quali sono i suoi tre vantaggi principali in ambito aziendale?**

---

### Domanda 2
**Spiega la differenza tra forward proxy e reverse proxy. Fornisci un esempio d'uso per ciascuno.**

---

### Domanda 3
**Qual è la differenza tra transparent proxy e explicit proxy? In quale scenario è preferibile l'uno o l'altro?**

---

### Domanda 4
**Descrivi il ruolo del proxy nel modello OSI. A quale livello opera tipicamente?**

---

### Domanda 5
**Cosa significa "SSL inspection" o "SSL bumping" in un proxy? Perché può essere considerato controverso dal punto di vista della privacy?**

---

### Domanda 6
**Elenca 3 rischi di sicurezza che un proxy può mitigare e spiega come.**

---

## Sezione 2: Configurazione Squid (6 domande)

### Domanda 7
**Nel file `squid.conf`, qual è la differenza tra le seguenti ACL?**

```bash
acl localnet src 10.0.0.0/8
acl SSL_ports port 443
acl Safe_ports port 80
```

---

### Domanda 8
**Spiega l'ordine di valutazione delle regole `http_access` in Squid. Perché è importante posizionare le whitelist prima delle blacklist?**

---

### Domanda 9
**Interpreta questa riga di log di Squid:**

```
1678900123.456   234 10.1.1.50 TCP_MISS/200 15678 GET http://www.example.com/ mario DIRECT/93.184.216.34 text/html
```

Spiega il significato di: TCP_MISS, 200, 15678, DIRECT.

---

### Domanda 10
**Scrivi la configurazione Squid per bloccare Facebook e Instagram solo durante l'orario lavorativo (lun-ven 9:00-18:00) per il gruppo "dipendenti", ma permetterle sempre per il gruppo "dirigenti".**

---

### Domanda 11
**Cosa indica un "cache hit ratio" del 35%? Come si può migliorare questo valore?**

---

### Domanda 12
**Quale comando useresti per visualizzare in tempo reale le richieste che passano attraverso Squid? E per vedere le statistiche della cache?**

---

## Sezione 3: Autenticazione e ACL (4 domande)

### Domanda 13
**Descrivi 3 metodi di autenticazione supportati da Squid (es. Basic, NTLM, LDAP). Qual è il più sicuro e perché?**

---

### Domanda 14
**Osserva questa configurazione:**

```bash
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm "Proxy Aziendale"
acl authenticated proxy_auth REQUIRED
http_access deny !authenticated
```

**Cosa succede se un utente prova ad accedere senza credenziali?**

---

### Domanda 15
**Come si crea un file password per Squid usando `htpasswd`? Scrivi il comando per aggiungere l'utente "mario" con password "Sicura123".**

---

### Domanda 16
**Spiega la differenza tra queste due ACL:**

```bash
acl gruppo_it proxy_auth it_tech1 it_tech2 it_admin
acl gruppo_admin proxy_auth_regex ^admin_
```

---

## Sezione 4: Cache e Performance (2 domande)

### Domanda 17
**Spiega cosa sono i "refresh patterns" in Squid e fornisci un esempio di configurazione per cachare le immagini (JPG, PNG) per 7 giorni.**

---

### Domanda 18
**Qual è la differenza tra `cache_mem` e `cache_dir` nella configurazione Squid? Quando un oggetto viene memorizzato in RAM vs disco?**

---

## Sezione 5: Casi Pratici (2 domande)

### Domanda 19
**Scenario:** Gli studenti di una scuola lamentano che YouTube è lento durante l'orario scolastico. Il proxy ha un cache hit ratio del 15%. Proponi 3 soluzioni per migliorare la situazione, spiegando pro e contro di ciascuna.

---

### Domanda 20
**Scenario:** Nei log del proxy Squid noti 10.000 richieste in 1 minuto da un singolo IP (10.1.1.55) verso domini random (es. `asdf123.xyz`, `qwerty456.top`). Cosa potrebbe indicare questo comportamento? Quali azioni immediate prenderesti?

---

## Griglia di Valutazione

| Punteggio | Voto | Valutazione |
|-----------|------|-------------|
| 19-20 | 10 | Eccellente |
| 17-18 | 9 | Ottimo |
| 15-16 | 8 | Distinto |
| 13-14 | 7 | Buono |
| 12 | 6 | Sufficiente |
| 10-11 | 5 | Insufficiente |
| < 10 | ≤ 4 | Gravemente insufficiente |

---

## Soluzioni (Solo per Docenti)

<details>
<summary>Clicca per espandere soluzioni</summary>

### Soluzione D1
Intermediario tra client e server. Vantaggi: filtraggio contenuti, caching (riduzione banda), logging/audit.

### Soluzione D2
Forward proxy: client → proxy → Internet (uso aziendale per filtrare). Reverse proxy: Internet → proxy → server interno (bilanciamento carico, protezione server).

### Soluzione D3
Transparent: client non sa del proxy, redirect automatico. Explicit: client configurato manualmente. Transparent per semplicità utente, explicit per maggior controllo.

### Soluzione D4
Livello 7 (Applicazione) - analizza HTTP/HTTPS. Può operare anche a livello 4 (Trasporto) per proxy generico TCP/UDP.

### Soluzione D5
Proxy intercetta traffico HTTPS, decrittografa, ispeziona, ri-crittografa. Controverso perché viola privacy end-to-end, MITM "legale".

### Soluzione D6
Malware download (scansiona file), phishing (blocca URL malevoli), data exfiltration (monitora upload anomali).

### Soluzione D7
localnet: ACL per subnet sorgente. SSL_ports: ACL per porte SSL/TLS. Safe_ports: porte permesse (HTTP/HTTPS/FTP).

### Soluzione D8
Valutazione top-down, prima regola che matcha vince. Whitelist prima per permettere eccezioni prima del blocco generale.

### Soluzione D9
TCP_MISS: non in cache, fetch da server. 200: HTTP OK. 15678: byte trasferiti. DIRECT: connessione diretta (no parent proxy).

### Soluzione D10
```bash
acl social dstdomain .facebook.com .instagram.com
acl orario_lavoro time MTWHF 09:00-18:00
acl dipendenti proxy_auth_regex ^dip_
acl dirigenti proxy_auth_regex ^dir_
http_access allow dirigenti social
http_access deny dipendenti social orario_lavoro
```

### Soluzione D11
35% richieste servite da cache. Migliorare: refresh pattern aggressivi, cache_dir più grande, ignore_client_no_cache on.

### Soluzione D12
Real-time: `tail -f /var/log/squid/access.log`. Statistiche: `squidclient mgr:info`.

### Soluzione D13
Basic (htpasswd, plain text Base64), NTLM (Active Directory), LDAP (directory aziendale). Più sicuro: LDAP/NTLM su TLS.

### Soluzione D14
Browser mostra popup "407 Proxy Authentication Required". Utente inserisce credenziali.

### Soluzione D15
`sudo htpasswd /etc/squid/passwords mario` poi inserire password quando richiesto.

### Soluzione D16
Prima ACL: lista esplicita utenti. Seconda ACL: regex, tutti gli utenti che iniziano con "admin_".

### Soluzione D17
Regole per quanto tempo cachare oggetti.
```bash
refresh_pattern -i \.(jpg|png)$ 10080 90% 10080
# 10080 min = 7 giorni
```

### Soluzione D18
cache_mem: RAM per hot objects (accesso veloce). cache_dir: disco per tutti gli oggetti. RAM per oggetti piccoli/frequenti, disco per grandi.

### Soluzione D19
1. Bandwidth limiting su YouTube (pro: equità, contro: video buffer)
2. Aumentare cache_dir (pro: più hit, contro: più disco)
3. Bloccare streaming in orario (pro: risolve, contro: lamentele studenti)

### Soluzione D20
Possibile malware DGA (Domain Generation Algorithm) che cerca C2. Azioni: bloccare IP 10.1.1.55, isolare host, scansione antivirus, analisi forense.

</details>

---

*Esercizio C — ES03 Proxy Server | Sistemi e Reti 3*
