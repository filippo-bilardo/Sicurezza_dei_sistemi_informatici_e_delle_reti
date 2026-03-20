# 06 — nftables: Il Nuovo Firewall Linux

📚 **Guida teorica** | Sistemi e Reti 3  
🎯 **Argomento**: nftables — architettura, tabelle, catene, regole, NAT, migrazione da iptables

---

## 1. Cos'è nftables

**nftables** è il successore ufficiale di iptables, integrato nel kernel Linux dalla versione **3.13** (2014) e diventato il default su Debian 10+, Ubuntu 20.04+, RHEL 8+.

### Perché nftables sostituisce iptables?

| Problema di iptables | Soluzione in nftables |
|---------------------|-----------------------|
| Regole separate per IPv4 e IPv6 (`iptables` + `ip6tables`) | Un unico strumento gestisce entrambi |
| Tabelle separate per ogni protocollo (filter, nat, mangle…) | Tabelle e catene definite dall'utente |
| Nessun raggruppamento (ogni regola è indipendente) | **Set** e **map** per raggruppare IP/porte |
| Codice kernel molto complesso (~100.000 righe) | Architettura VM più pulita (~10.000 righe) |
| Performance con molte regole lineare O(n) | Set/map con lookup O(1) via hash/rbtree |
| Ogni modulo separato (`-m state`, `-m multiport`…) | Tutto nativo nel linguaggio delle regole |

> 💡 Su distribuzioni moderne, il comando `iptables` è spesso un **wrapper** che traduce le regole iptables in nftables. Per vedere quale backend è in uso: `iptables --version` (cerca "nf_tables" o "legacy").

---

## 2. Architettura: Famiglie, Tabelle, Catene

nftables usa una gerarchia: **famiglia → tabella → catena → regola**.

### 2.1 Famiglie (address families)

| Famiglia | Traffico gestito |
|----------|-----------------|
| `ip` | Solo IPv4 |
| `ip6` | Solo IPv6 |
| `inet` | IPv4 **e** IPv6 insieme — il più usato |
| `arp` | Pacchetti ARP |
| `bridge` | Traffico bridge (Layer 2) |
| `netdev` | Pacchetti in ingresso prima di qualsiasi elaborazione |

### 2.2 Tabelle

Le tabelle in nftables sono **create dall'utente** — non esistono tabelle predefinite come in iptables. Ogni tabella appartiene a una famiglia.

```
nft add table inet firewall       ← tabella "firewall" per IPv4+IPv6
nft add table ip nat              ← tabella "nat" solo per IPv4
```

### 2.3 Catene

Anche le catene sono **create dall'utente**. Per agganciare una catena al percorso dei pacchetti (come INPUT/FORWARD/OUTPUT di iptables) occorre specificare `type`, `hook` e `priority`.

```
nft add chain inet firewall input { \
    type filter hook input priority 0 ; \
    policy drop ; \
}
```

| Parametro | Valori comuni | Significato |
|-----------|--------------|-------------|
| `type` | `filter`, `nat`, `route` | Tipo di catena |
| `hook` | `prerouting`, `input`, `forward`, `output`, `postrouting` | Punto di aggancio nel percorso pacchetti |
| `priority` | `0` (filter), `-100` (conntrack), `100` (NAT) | Ordine di elaborazione (basso = prima) |
| `policy` | `accept`, `drop` | Comportamento di default |

---

## 3. Sintassi delle regole

```
nft add rule FAMIGLIA TABELLA CATENA [MATCH...] AZIONE
```

### 3.1 Esempi di matching

```bash
# Per protocollo e porta
ip protocol tcp
tcp dport 80
tcp dport { 80, 443 }          # set inline
tcp dport 1024-65535            # range

# Per indirizzo IP
ip saddr 192.168.1.0/24
ip daddr 10.0.0.5
ip saddr != 10.0.0.0/8         # negazione

# Per interfaccia
iifname "eth0"                  # interfaccia ingresso
oifname "eth1"                  # interfaccia uscita

# Connection tracking
ct state new
ct state { established, related }
ct state invalid

# Protocollo ICMP
icmp type echo-request
```

### 3.2 Azioni (verdetti)

| Azione | Significato |
|--------|-------------|
| `accept` | Lascia passare il pacchetto |
| `drop` | Scarta silenziosamente |
| `reject` | Scarta con messaggio ICMP |
| `reject with tcp reset` | Scarta con TCP RST |
| `log` | Registra nel syslog |
| `counter` | Conta pacchetti/byte (spesso combinato) |
| `masquerade` | NAT dinamico (POSTROUTING) |
| `snat to IP` | NAT statico sorgente |
| `dnat to IP:PORTA` | Port forwarding |
| `jump CATENA` | Salta a un'altra catena |

---

## 4. Set e Map — la potenza di nftables

### 4.1 Set — gruppi di indirizzi o porte

I **set** permettono di raggruppare IP, reti o porte e usarli nelle regole. Il lookup è O(1) (hash).

```bash
# Definisce un set di IP bloccati
nft add set inet firewall blacklist { type ipv4_addr ; }
nft add element inet firewall blacklist { 10.0.0.5, 10.0.0.6, 1.2.3.4 }

# Usa il set nella regola
nft add rule inet firewall input ip saddr @blacklist drop

# Set di porte permesse
nft add set inet firewall allowed_ports { type inet_service ; }
nft add element inet firewall allowed_ports { 22, 80, 443 }
nft add rule inet firewall input tcp dport @allowed_ports accept
```

### 4.2 Set con intervalli (flags interval)

```bash
# Set di sottoreti
nft add set inet firewall lan_nets { type ipv4_addr ; flags interval ; }
nft add element inet firewall lan_nets { 192.168.0.0/16, 10.0.0.0/8 }
```

---

## 5. Configurazione Firewall per DMZ

### 5.1 Scenario

```
INTERNET          FIREWALL LINUX           LAN interna
203.0.113.2  ←→  eth0 | eth1 | eth2  ←→  192.168.1.0/24
                       ↕
                   eth2 (DMZ)
                  172.16.0.0/24
```

### 5.2 Script completo nftables per DMZ

```bash
#!/usr/sbin/nft -f
# Firewall nftables con DMZ — policy DROP

# ── Reset ────────────────────────────────────────────────
flush ruleset

# ── Tabella filtro IPv4+IPv6 ─────────────────────────────
table inet firewall {

    # ── Catena INPUT (traffico verso il firewall) ─────────
    chain input {
        type filter hook input priority 0 ;
        policy drop ;

        # Loopback sempre permesso
        iifname "lo" accept

        # Traffico già stabilito
        ct state { established, related } accept

        # Scarta traffico invalido
        ct state invalid drop

        # SSH di gestione solo da LAN
        iifname "eth1" tcp dport 22 ct state new accept

        # Ping (opzionale)
        icmp type echo-request accept
    }

    # ── Catena FORWARD (traffico inoltrato) ───────────────
    chain forward {
        type filter hook forward priority 0 ;
        policy drop ;

        # Traffico già stabilito
        ct state { established, related } accept

        # LAN → Internet (accesso completo)
        iifname "eth1" oifname "eth0" ct state new accept

        # LAN → DMZ (accesso completo ai server)
        iifname "eth1" oifname "eth2" ct state new accept

        # Internet → DMZ: solo porte pubbliche
        iifname "eth0" oifname "eth2" tcp dport { 80, 443 } ct state new accept
        iifname "eth0" oifname "eth2" tcp dport 25          ct state new accept

        # DMZ → Internet: solo aggiornamenti
        iifname "eth2" oifname "eth0" tcp dport { 80, 443 } ct state new accept

        # DMZ → LAN: VIETATO (isolamento DMZ)
        # Internet → LAN: VIETATO
        # (nessuna regola = DROP per policy)

        # Log pacchetti scartati (debug)
        log prefix "[FW-DROP-FWD] " level warn counter drop
    }

    # ── Catena OUTPUT (traffico generato dal firewall) ────
    chain output {
        type filter hook output priority 0 ;
        policy accept ;
    }
}

# ── Tabella NAT ───────────────────────────────────────────
table ip nat {

    chain prerouting {
        type nat hook prerouting priority -100 ;

        # Port forwarding: HTTP verso server web in DMZ
        iifname "eth0" tcp dport 80  dnat to 172.16.0.10:80
        iifname "eth0" tcp dport 443 dnat to 172.16.0.10:443

        # Port forwarding: SMTP verso mail server in DMZ
        iifname "eth0" tcp dport 25  dnat to 172.16.0.20:25
    }

    chain postrouting {
        type nat hook postrouting priority 100 ;

        # Masquerade per LAN e DMZ verso Internet
        oifname "eth0" masquerade
    }
}
```

---

## 6. Gestione tramite CLI

### 6.1 Operazioni comuni

```bash
# Mostra il ruleset completo
nft list ruleset

# Mostra una singola tabella
nft list table inet firewall

# Mostra una singola catena con contatori
nft list chain inet firewall forward

# Aggiunge una regola (append)
nft add rule inet firewall input tcp dport 8080 accept

# Inserisce una regola in cima (handle 0)
nft insert rule inet firewall input tcp dport 8080 accept

# Elimina una regola per handle
nft list chain inet firewall input -a   # mostra gli handle
nft delete rule inet firewall input handle 5

# Reset di tutti i contatori
nft reset counters

# Flush completo (attenzione: rimuove tutto!)
nft flush ruleset
```

### 6.2 Caricare un file di regole

```bash
# Carica il ruleset da file
nft -f /etc/nftables.conf

# Verifica la sintassi senza applicare
nft -c -f /etc/nftables.conf
```

---

## 7. Persistenza

Su distribuzioni moderne nftables si integra con **systemd**:

```bash
# Abilita nftables all'avvio
systemctl enable nftables
systemctl start nftables

# Il file di configurazione principale
cat /etc/nftables.conf

# Salva il ruleset corrente nel file di configurazione
nft list ruleset > /etc/nftables.conf

# Ricarica
systemctl reload nftables
```

---

## 8. Migrazione da iptables a nftables

Strumenti di migrazione automatica inclusi nel pacchetto `iptables`:

```bash
# Traduce regole iptables-save in formato nftables
iptables-save | iptables-restore-translate -f /etc/nftables.conf

# Singola regola
iptables-translate -A INPUT -p tcp --dport 22 -j ACCEPT
# output: nft add rule ip filter INPUT tcp dport 22 counter accept
```

---

## 9. Confronto nftables vs iptables

| Caratteristica | iptables | nftables |
|----------------|----------|----------|
| **IPv4 + IPv6** | Due comandi separati | Un unico strumento (`inet`) |
| **Tabelle** | Fisse (filter, nat, mangle) | Definite dall'utente |
| **Set/Map** | Nessun supporto nativo | ✅ Nativo — O(1) lookup |
| **Performance con molte regole** | Lineare O(n) | O(1) con set/map |
| **Sintassi** | Opzioni `-A`, `-j`, `-m`… | Linguaggio più leggibile |
| **File di configurazione** | Script bash | File dichiarativo `.conf` |
| **Supporto kernel** | Da sempre | Da kernel 3.13 (2014) |
| **Default su** | CentOS 7, vecchie distro | Debian 10+, Ubuntu 20.04+, RHEL 8+ |
| **Compatibilità iptables** | — | Layer di compatibilità `iptables-nft` |

---

## 10. Riepilogo rapido — regole più usate

```bash
# Permetti SSH
nft add rule inet firewall input tcp dport 22 ct state new accept

# Permetti HTTP e HTTPS
nft add rule inet firewall input tcp dport { 80, 443 } ct state new accept

# Permetti ping
nft add rule inet firewall input icmp type echo-request accept

# Blocca un IP
nft add rule inet firewall input ip saddr 10.0.0.5 drop

# Forwarding LAN→WAN con NAT
nft add rule inet firewall forward iifname "eth1" oifname "eth0" ct state new accept
nft add rule ip nat postrouting oifname "eth0" masquerade

# Mostra tutto
nft list ruleset
```

---

*Guida 06 — ES06 DMZ | Sistemi e Reti 3*
