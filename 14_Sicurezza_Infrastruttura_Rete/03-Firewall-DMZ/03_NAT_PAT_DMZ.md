# 03 — NAT/PAT in Relazione alla DMZ

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: NAT statico, PAT, port forwarding — rendere i server DMZ raggiungibili da Internet

---

## 1. Il Problema: IP Privati vs IP Pubblici

I server in DMZ hanno **indirizzi IP privati** (es. `192.168.100.10` per il web server). Ma Internet non instrada indirizzi privati — sono riservati a reti locali e non sono unici globalmente.

**Come fa allora un utente su Internet a raggiungere `www.esempio.it` se il server ha un IP privato?**

La risposta è il **NAT** (Network Address Translation): un meccanismo che traduce gli indirizzi IP privati in indirizzi pubblici (e viceversa) al confine della rete, tipicamente sul router/firewall perimetrale.

```
                 IP PRIVATO               IP PUBBLICO
                 192.168.100.10           203.0.113.10
                      │                       │
Web Server ─────[FIREWALL/NAT]──── Internet ──── Utente
  (DMZ)        (traduzione)                     (8.8.8.8)

L'utente vede: 203.0.113.10
Il server ha: 192.168.100.10
Il NAT fa la traduzione in modo trasparente
```

---

## 2. Tipi di NAT

### 2.1 NAT Statico (Static NAT — 1:1)

Il **NAT statico** crea una mappatura **fissa e bidirezionale** tra un IP privato e un IP pubblico. È usato per i server che devono essere raggiungibili da Internet con un indirizzo pubblico dedicato.

```
IP Privato         ←→        IP Pubblico
192.168.100.10     ←→        203.0.113.10   (Web Server)
192.168.100.11     ←→        203.0.113.11   (DNS Server)
192.168.100.12     ←→        203.0.113.12   (Mail Server)
```

**Caratteristiche**:
- Una sola mappatura: 1 IP privato → 1 IP pubblico
- Bidirezionale: gli utenti Internet possono raggiungere il server **e** il server può iniziare connessioni verso Internet con il suo IP pubblico
- Richiede un IP pubblico per ogni server esposto

**Configurazione Cisco IOS**:
```cisco
! Mappatura statica: 192.168.100.10 (privato) ↔ 203.0.113.10 (pubblico)
ip nat inside source static 192.168.100.10 203.0.113.10

! Mappatura per il DNS server
ip nat inside source static 192.168.100.11 203.0.113.11

! Mappatura per il mail server
ip nat inside source static 192.168.100.12 203.0.113.12

! Indicazione delle interfacce inside/outside
interface GigabitEthernet0/2   ! verso Internet (WAN)
 ip nat outside

interface GigabitEthernet0/1   ! verso DMZ
 ip nat inside

interface GigabitEthernet0/0   ! verso LAN
 ip nat inside
```

### 2.2 NAT Dinamico

Il **NAT dinamico** traduce un pool di indirizzi privati in un pool di indirizzi pubblici. Meno usato oggi, perché PAT è più efficiente.

### 2.3 PAT / NAT con Overload (Port Address Translation)

Il **PAT** (Port Address Translation) — chiamato anche NAT con overload — permette a **molti dispositivi con IP privati** di condividere **un solo IP pubblico**, usando le porte TCP/UDP per distinguere le connessioni.

È il meccanismo usato da qualsiasi router casalingo: tutti i PC di casa condividono un solo IP pubblico.

```
IP Privato + Porta Sorgente     →    IP Pubblico + Porta Tradotta
10.0.0.10:49152                 →    203.0.113.2:1024
10.0.0.11:49153                 →    203.0.113.2:1025
10.0.0.12:49154                 →    203.0.113.2:1026
```

**Configurazione Cisco IOS**:
```cisco
! Definisce la lista degli IP interni da tradurre
access-list 1 permit 10.0.0.0 0.0.0.255

! Abilita PAT sull'interfaccia WAN (overload = PAT)
ip nat inside source list 1 interface GigabitEthernet0/2 overload

interface GigabitEthernet0/2
 ip nat outside

interface GigabitEthernet0/0
 ip nat inside
```

---

## 3. Port Forwarding

Il **port forwarding** (o **Static PAT**) è una variante del NAT statico che traduce **porta per porta**, invece che IP per IP. È utile quando hai **un solo IP pubblico** ma vuoi esporre più servizi su server diversi.

```
203.0.113.2:80   →  192.168.100.10:80   (Web Server)
203.0.113.2:25   →  192.168.100.12:25   (Mail Server)
203.0.113.2:53   →  192.168.100.11:53   (DNS Server)
```

Tutti e tre i server sono raggiungibili dall'esterno tramite lo stesso IP pubblico, ma su porte diverse.

**Configurazione Cisco IOS (Static PAT)**:
```cisco
! Porta 80 sull'IP pubblico → Web Server interno porta 80
ip nat inside source static tcp 192.168.100.10 80 203.0.113.2 80

! Porta 443 sull'IP pubblico → Web Server interno porta 443
ip nat inside source static tcp 192.168.100.10 443 203.0.113.2 443

! Porta 25 → Mail Server
ip nat inside source static tcp 192.168.100.12 25 203.0.113.2 25

! Porta 53 UDP → DNS Server
ip nat inside source static udp 192.168.100.11 53 203.0.113.2 53
```

---

## 4. DMZ Host nel Router Casalingo vs DMZ Professionale

I router casalinghi hanno una funzione chiamata "DMZ host" — non confonderla con una vera DMZ professionale!

| Caratteristica | DMZ Casalinga (router) | DMZ Professionale |
|----------------|----------------------|-------------------|
| Significato | Un host riceve TUTTO il traffico non filtrato | Zona di rete separata con regole specifiche |
| Sicurezza | ❌ Molto bassa (nessun filtro!) | ✅ Alta (ACL/firewall specifiche) |
| Isolamento dalla LAN | ❌ Nessuno | ✅ Completo |
| Uso tipico | Gaming, server temporaneo | Produzione aziendale |
| Complessità | Bassa | Alta |

La "DMZ" dei router casalinghi è in realtà un **port forwarding totale** — tutti i pacchetti non gestiti da altre regole vengono inoltrati a quell'host. È comoda ma pericolosa.

---

## 5. Configurazione Completa NAT + ACL + DMZ

Ecco una configurazione realistica che combina NAT statico per i server DMZ e PAT per la LAN interna:

```cisco
! ============================================================
! CONFIGURAZIONE NAT COMPLETA PER SCENARIO DMZ
! 
! WAN: 203.0.113.2/30  (Gi0/2)
! DMZ: 192.168.100.1/27 (Gi0/1)  
! LAN: 10.0.0.1/24 (Gi0/0)
! IP pubblici server: 203.0.113.10, .11, .12
! ============================================================

! --- NAT STATICO per server DMZ ---
! Web Server: IP privato 192.168.100.10 → IP pubblico 203.0.113.10
ip nat inside source static 192.168.100.10 203.0.113.10

! DNS Server: IP privato 192.168.100.11 → IP pubblico 203.0.113.11
ip nat inside source static 192.168.100.11 203.0.113.11

! Mail Server: IP privato 192.168.100.12 → IP pubblico 203.0.113.12
ip nat inside source static 192.168.100.12 203.0.113.12

! --- PAT per la LAN interna (condivisione IP WAN) ---
! ACL che identifica i client LAN
access-list 100 permit ip 10.0.0.0 0.0.0.255 any

! PAT con overload sull'interfaccia WAN
ip nat inside source list 100 interface GigabitEthernet0/2 overload

! --- Configurazione interfacce ---
interface GigabitEthernet0/2
 description "WAN - Verso Internet"
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 no shutdown

interface GigabitEthernet0/1
 description "DMZ - Server Pubblici"
 ip address 192.168.100.1 255.255.255.224
 ip nat inside
 no shutdown

interface GigabitEthernet0/0
 description "LAN - Rete Interna"
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
 no shutdown
```

---

## 6. Ordine di Applicazione: NAT e ACL

Un punto spesso fonte di confusione: in che ordine vengono applicati NAT e ACL?

### 6.1 Traffico in Ingresso (inbound)

```
Pacchetto in arrivo su Gi0/2 (WAN, outside):
  1. ACL in ingresso (ip access-group ACL_WAN_IN in)
     → Il pacchetto viene esaminato con l'IP PUBBLICO di destinazione
  2. NAT (destiantion NAT: IP pubblico → IP privato)
  3. Routing decision
  4. ACL in uscita sull'interfaccia di destinazione
```

> ⚠️ **Importante**: Per il traffico in ingresso (da Internet verso i server), l'ACL sull'interfaccia outside viene applicata **PRIMA** del NAT. Quindi nelle ACL WAN IN devi usare **l'IP privato** del server o l'IP pubblico? Dipende dalla versione IOS e dalla configurazione.

**In Cisco IOS standard**: l'ACL `in` su un'interfaccia `outside` viene controllata sull'IP **pubblico** (prima della traduzione). L'ACL `out` sull'interfaccia `inside` viene controllata sull'IP **privato** (dopo la traduzione).

### 6.2 Traffico in Uscita (outbound)

```
Pacchetto in uscita dalla LAN:
  1. ACL in ingresso su Gi0/0 (ip access-group ACL_LAN_IN in)
     → Esaminato con IP privato sorgente
  2. Routing decision
  3. NAT (source NAT: IP privato → IP pubblico)
  4. ACL in uscita su Gi0/2 (se presente)
     → Esaminato con IP pubblico sorgente
```

**Regola pratica per Packet Tracer**: In PT, le ACL funzionano nel modo più intuitivo — applica le ACL sulle interfacce in ingresso e usa gli IP privati nelle regole. Il NAT viene gestito separatamente.

---

## 7. Verifica NAT

```cisco
! Mostra la tabella delle traduzioni NAT attive
show ip nat translations

! Mostra le statistiche NAT (numero traduzioni, hit, miss)
show ip nat statistics

! Debug in tempo reale (usa con cautela!)
debug ip nat
```

**Esempio output `show ip nat translations`**:
```
Pro  Inside global       Inside local        Outside local       Outside global
tcp  203.0.113.10:80     192.168.100.10:80   8.8.8.8:52341       8.8.8.8:52341
---  203.0.113.10        192.168.100.10      ---                 ---
tcp  10.0.0.10:1024      203.0.113.2:1024   93.184.216.34:80    93.184.216.34:80
```

Interpretazione:
- Riga 1: connessione HTTP dall'esterno (8.8.8.8) verso il web server in DMZ
- Riga 2: NAT statico Web Server (sempre presente)
- Riga 3: PC della LAN (10.0.0.10) naviga su Internet tramite PAT

---

## 8. Problemi Comuni NAT + DMZ

### Problema 1: Il server DMZ non è raggiungibile da Internet

**Causa possibile**: ACL_WAN_IN blocca il traffico prima che il NAT lo traduca.

**Soluzione**: Verifica che nella ACL sull'interfaccia WAN (outside) la destinazione corrisponda all'IP **che il router vede in quel punto** (dipende da IOS). In Packet Tracer, usa l'IP privato nella ACL sull'interfaccia inside.

### Problema 2: I PC della LAN non navigano

**Causa possibile**: ACL_LAN_IN blocca il traffico, oppure PAT non è configurato.

**Verifica**:
```cisco
show ip nat translations
show access-lists
```

### Problema 3: "NAT Loop" — il server DMZ non riesce a raggiungere se stesso tramite l'IP pubblico

**Spiegazione**: Il server DMZ (192.168.100.10) tenta di connettersi a `203.0.113.10` (il suo IP pubblico) — questo crea un loop nel NAT.

**Soluzione**: Configura un **DNS split-horizon** — il DNS interno risponde con l'IP privato per i client interni, mentre il DNS pubblico risponde con l'IP pubblico per i client Internet. Argomento avanzato, non richiesto per questa esercitazione.

---

## 9. Riepilogo Comandi NAT

| Comando | Funzione |
|---------|----------|
| `ip nat inside source static [priv] [pub]` | NAT statico 1:1 |
| `ip nat inside source static tcp [priv] [port] [pub] [port]` | Port forwarding TCP |
| `ip nat inside source static udp [priv] [port] [pub] [port]` | Port forwarding UDP |
| `ip nat inside source list [acl] interface [if] overload` | PAT |
| `ip nat inside` | Marca interfaccia come "inside" |
| `ip nat outside` | Marca interfaccia come "outside" |
| `show ip nat translations` | Mostra tabella traduzioni attive |
| `show ip nat statistics` | Statistiche NAT |
| `debug ip nat` | Debug in tempo reale |
| `clear ip nat translation *` | Cancella tutte le traduzioni dinamiche |

---

*Guida 03/04 — ES06 — Sistemi e Reti 3*
