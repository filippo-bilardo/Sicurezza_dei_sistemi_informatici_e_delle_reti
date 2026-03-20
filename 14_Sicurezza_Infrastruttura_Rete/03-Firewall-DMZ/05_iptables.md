# 05 — iptables: Firewall su Linux

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: iptables — architettura, tabelle, catene, regole, NAT, configurazione DMZ su Linux

---

## 1. Cos'è iptables

**iptables** è il frontend storico del framework **Netfilter** integrato nel kernel Linux. Permette di definire regole per filtrare, modificare e reindirizzare i pacchetti di rete.

> 🔁 **iptables vs nftables**: da Linux 4.18+, `nftables` è il successore moderno di iptables. Su distribuzioni recenti (Debian 10+, Ubuntu 20.04+) `iptables` è spesso un alias di `nftables`. La sintassi che impariamo è comunque valida e vastamente diffusa.

```
Pacchetto in arrivo
        ↓
  ┌─────────────┐
  │  Netfilter  │  ← kernel Linux (gestisce tutti i pacchetti)
  │  (iptables) │
  └──────┬──────┘
         ↓
  Decisione: ACCEPT / DROP / REJECT / MASQUERADE / ...
```

---

## 2. Architettura: Tabelle e Catene

iptables organizza le regole in **tabelle**, ciascuna con le proprie **catene**.

### 2.1 Le Tabelle principali

| Tabella | Scopo | Catene disponibili |
|---------|-------|--------------------|
| **filter** | Filtraggio pacchetti (firewall) — **la più usata** | INPUT, OUTPUT, FORWARD |
| **nat** | Network Address Translation | PREROUTING, POSTROUTING, OUTPUT |
| **mangle** | Modifica campi pacchetto (TTL, TOS, mark) | PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING |
| **raw** | Bypass connection tracking | PREROUTING, OUTPUT |

### 2.2 Le Catene (Chains)

Una **catena** è una lista ordinata di regole. Ogni pacchetto attraversa le catene in base al percorso che compie:

```
  RETE ESTERNA
       ↓
  PREROUTING (nat)        ← modifica destinazione prima del routing
       ↓
  ┌────┴──────────────────────────────┐
  │   Decisione di routing (kernel)   │
  └───┬─────────────────┬─────────────┘
      ↓                 ↓
  INPUT (filter)    FORWARD (filter)     ← pacchetti per il sistema locale vs inoltrati
      ↓                 ↓
  Processo locale   POSTROUTING (nat)    ← modifica sorgente dopo il routing
      ↓                 ↓
  OUTPUT (filter)   RETE ESTERNA
      ↓
  POSTROUTING (nat)
       ↓
  RETE ESTERNA
```

| Catena | Traffico che attraversa |
|--------|------------------------|
| **INPUT** | Pacchetti **destinati al sistema** locale |
| **OUTPUT** | Pacchetti **generati dal sistema** locale |
| **FORWARD** | Pacchetti che **transitano** attraverso il sistema (routing/NAT) |
| **PREROUTING** | Tutti i pacchetti in arrivo, **prima** della decisione di routing |
| **POSTROUTING** | Tutti i pacchetti in uscita, **dopo** la decisione di routing |

---

## 3. Sintassi di base

```bash
iptables [-t TABELLA] COMANDO CATENA [OPZIONI] -j TARGET
```

| Parte | Valori comuni | Significato |
|-------|--------------|-------------|
| `-t TABELLA` | `filter`, `nat`, `mangle` | Tabella (default: `filter`) |
| `COMANDO` | `-A`, `-I`, `-D`, `-L`, `-F` | Azione sulla catena |
| `CATENA` | `INPUT`, `OUTPUT`, `FORWARD` | Catena target |
| `-j TARGET` | `ACCEPT`, `DROP`, `REJECT`, `LOG` | Cosa fare col pacchetto |

### 3.1 Comandi principali

| Comando | Significato |
|---------|-------------|
| `-A CATENA` | **Append** — aggiunge regola in fondo alla catena |
| `-I CATENA [N]` | **Insert** — inserisce regola in posizione N (default: 1 = in cima) |
| `-D CATENA N` | **Delete** — elimina la regola numero N |
| `-F [CATENA]` | **Flush** — elimina tutte le regole (della catena o di tutte) |
| `-L [CATENA]` | **List** — elenca le regole |
| `-P CATENA TARGET` | **Policy** — imposta la policy di default della catena |
| `-n` | Mostra IP e porte in formato numerico (senza DNS lookup) |
| `-v` | Verbose — mostra contatori pacchetti/byte |
| `--line-numbers` | Mostra il numero di riga delle regole |

### 3.2 Opzioni di matching

| Opzione | Esempio | Significato |
|---------|---------|-------------|
| `-s IP[/mask]` | `-s 192.168.1.0/24` | IP sorgente |
| `-d IP[/mask]` | `-d 10.0.0.5` | IP destinazione |
| `-p PROTO` | `-p tcp` | Protocollo (`tcp`, `udp`, `icmp`) |
| `--sport PORTA` | `--sport 1024:65535` | Porta sorgente (o range) |
| `--dport PORTA` | `--dport 80` | Porta destinazione |
| `-i IFACE` | `-i eth0` | Interfaccia in ingresso |
| `-o IFACE` | `-o eth1` | Interfaccia in uscita |
| `! OPZIONE` | `! -s 10.0.0.0/8` | Negazione |
| `-m state --state STATI` | `--state ESTABLISHED,RELATED` | Connection tracking |

### 3.3 Target (azioni)

| Target | Significato |
|--------|-------------|
| `ACCEPT` | Lascia passare il pacchetto |
| `DROP` | Scarta il pacchetto silenziosamente (nessuna risposta) |
| `REJECT` | Scarta e invia un messaggio di errore ICMP |
| `LOG` | Registra il pacchetto nel syslog (poi continua con le regole) |
| `MASQUERADE` | NAT dinamico — sostituisce IP sorgente con IP uscita (per DHCP) |
| `SNAT --to-source IP` | NAT statico — sostituisce IP sorgente con IP specificato |
| `DNAT --to-destination IP:PORTA` | Redirige traffico verso IP:porta interno (port forwarding) |

---

## 4. Connection Tracking (–m state)

Il modulo `state` abilita il **firewall stateful** su Linux. Traccia lo stato delle connessioni:

| Stato | Significato |
|-------|-------------|
| `NEW` | Primo pacchetto di una nuova connessione |
| `ESTABLISHED` | Pacchetto che appartiene a una connessione già stabilita |
| `RELATED` | Pacchetto correlato a una connessione esistente (es. FTP data, ICMP error) |
| `INVALID` | Pacchetto che non corrisponde a nessuna connessione nota — quasi sempre da scartare |

### Esempio classico — permetti solo traffico stabilito in ingresso

```bash
# Permetti risposte a connessioni già stabilite (traffico in ingresso)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permetti nuove connessioni solo su porte specifiche
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# Blocca tutto il resto
iptables -P INPUT DROP
```

---

## 5. Configurazione Firewall per DMZ

### 5.1 Scenario tipico

```
INTERNET          FIREWALL LINUX           LAN interna
203.0.113.1  ←→  eth0 | eth1 | eth2  ←→  192.168.1.0/24
                       ↕
                   eth2 (DMZ)
                  172.16.0.0/24
                  (Web, Mail server)
```

| Interfaccia | Zona | Rete |
|-------------|------|------|
| `eth0` | Internet (WAN) | 203.0.113.2/30 |
| `eth1` | LAN interna | 192.168.1.1/24 |
| `eth2` | DMZ | 172.16.0.1/24 |

### 5.2 Abilitare IP forwarding

Il kernel Linux **non inoltra pacchetti tra interfacce** per default.

```bash
# Temporaneo (perso al riavvio)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Permanente — modifica /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
```

### 5.3 Script completo firewall DMZ

```bash
#!/bin/bash
# Firewall Linux con DMZ — policy di default DROP

# ── Interfacce ──────────────────────────────────────────
WAN="eth0"
LAN="eth1"
DMZ="eth2"
WAN_IP="203.0.113.2"

# ── Reset ────────────────────────────────────────────────
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# ── Policy di default: DROP tutto ───────────────────────
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # sistema locale può comunicare liberamente

# ── Loopback sempre permesso ─────────────────────────────
iptables -A INPUT -i lo -j ACCEPT

# ── Traffico già stabilito (stateful) ───────────────────
iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ── SSH di gestione (solo da LAN) ───────────────────────
iptables -A INPUT -i $LAN -p tcp --dport 22 -m state --state NEW -j ACCEPT

# ── LAN → Internet (full access) ────────────────────────
iptables -A FORWARD -i $LAN -o $WAN -m state --state NEW -j ACCEPT

# ── LAN → DMZ (accesso completo ai server) ──────────────
iptables -A FORWARD -i $LAN -o $DMZ -m state --state NEW -j ACCEPT

# ── DMZ → Internet (aggiornamenti server) ───────────────
iptables -A FORWARD -i $DMZ -o $WAN -p tcp -m multiport --dports 80,443 -m state --state NEW -j ACCEPT

# ── Internet → DMZ: solo porte pubbliche ─────────────────
iptables -A FORWARD -i $WAN -o $DMZ -p tcp --dport 80  -m state --state NEW -j ACCEPT
iptables -A FORWARD -i $WAN -o $DMZ -p tcp --dport 443 -m state --state NEW -j ACCEPT
iptables -A FORWARD -i $WAN -o $DMZ -p tcp --dport 25  -m state --state NEW -j ACCEPT  # SMTP

# ── DMZ → LAN: VIETATO (isolamento DMZ) ─────────────────
# (nessuna regola FORWARD DMZ→LAN = DROP per policy)

# ── Internet → LAN: VIETATO ──────────────────────────────
# (nessuna regola FORWARD WAN→LAN = DROP per policy)

# ── NAT / MASQUERADE per LAN e DMZ verso Internet ───────
iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE

# ── LOG pacchetti droppati (opzionale, debug) ────────────
iptables -A INPUT   -j LOG --log-prefix "[FW-DROP-IN] "   --log-level 4
iptables -A FORWARD -j LOG --log-prefix "[FW-DROP-FWD] "  --log-level 4
```

### 5.4 Matrice delle policy DMZ

| Sorgente → Destinazione | Permesso | Note |
|------------------------|----------|------|
| Internet → DMZ (80/443/25) | ✅ | Server pubblici raggiungibili |
| Internet → LAN | ❌ | Rete interna non esposta |
| LAN → Internet | ✅ | Navigazione dipendenti |
| LAN → DMZ | ✅ | Amministrazione server |
| DMZ → LAN | ❌ | Isolamento — server compromesso non raggiunge LAN |
| DMZ → Internet (80/443) | ✅ | Solo aggiornamenti |

---

## 6. NAT con iptables

### 6.1 MASQUERADE — NAT dinamico (IP variabile, DHCP)

```bash
# Tutti i pacchetti in uscita da eth0 vengono nattati con l'IP corrente di eth0
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 6.2 SNAT — NAT statico (IP fisso)

```bash
# Più efficiente di MASQUERADE quando l'IP WAN è fisso
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 203.0.113.2
```

### 6.3 DNAT — Port forwarding (server in DMZ)

```bash
# Redirige il traffico su porta 80 dal WAN al server web in DMZ
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
  -j DNAT --to-destination 172.16.0.10:80

# Redirige HTTPS
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 \
  -j DNAT --to-destination 172.16.0.10:443

# Redirige SSH su porta 2222 esterna → porta 22 interna
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 2222 \
  -j DNAT --to-destination 172.16.0.20:22
```

---

## 7. Persistenza delle regole

Le regole iptables **non sopravvivono al riavvio** per default.

### Su Debian/Ubuntu

```bash
# Installa il pacchetto
apt install iptables-persistent

# Salva le regole correnti
netfilter-persistent save
# (salva in /etc/iptables/rules.v4 e rules.v6)

# Ricarica manualmente
netfilter-persistent reload
```

### Salvataggio e ripristino manuale

```bash
# Salva
iptables-save > /etc/iptables/rules.v4

# Ripristina
iptables-restore < /etc/iptables/rules.v4
```

---

## 8. Comandi di verifica

```bash
# Mostra tutte le regole della tabella filter con numeri di riga
iptables -L -n -v --line-numbers

# Mostra solo la catena FORWARD
iptables -L FORWARD -n -v

# Mostra regole NAT
iptables -t nat -L -n -v

# Mostra regole come comandi (utile per scriptare)
iptables-save

# Traccia un pacchetto in tempo reale (richiede modulo LOG o TRACE)
iptables -t raw -A PREROUTING -s 203.0.113.1 -j TRACE
dmesg | grep TRACE
```

---

## 9. Confronto iptables vs ACL Cisco

| Caratteristica | iptables (Linux) | ACL Cisco IOS |
|----------------|-----------------|---------------|
| **Tipo** | Stateful (con `-m state`) | Stateless (ACL base) |
| **Dove si applica** | Sul sistema Linux stesso | Sull'interfaccia del router |
| **NAT** | Integrato (tabella nat) | Richiede `ip nat` separato |
| **Persistenza** | Non automatica (serve `iptables-persistent`) | Salvata con `write memory` |
| **Logging** | Target `LOG` → syslog | `log` keyword → syslog |
| **Flessibilità** | Molto alta | Media |
| **Curva apprendimento** | Alta | Media |
| **Uso tipico** | Firewall Linux, router software, DMZ | Router/switch aziendali |

---

## 10. Riepilogo rapido — regole più usate

```bash
# Permetti SSH in ingresso
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Permetti HTTP e HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m state --state NEW -j ACCEPT

# Permetti ping
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Blocca un IP specifico
iptables -A INPUT -s 10.0.0.5 -j DROP

# Permetti forwarding LAN→WAN con NAT
iptables -A FORWARD -i eth1 -o eth0 -m state --state NEW -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Reset completo (attenzione: rimuove tutte le regole!)
iptables -F && iptables -X && iptables -t nat -F
```

---

*Guida 05 — ES06 DMZ | Sistemi e Reti 3*
