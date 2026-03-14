# ES03-B — Progetto autonomo: Rete VPN mesh a 3 peer

> **Tipo**: 🚀 Progetto autonomo  
> **Durata stimata**: 3–5 ore  
> **Punteggio**: 100 punti + bonus  
> **File da consegnare**: screenshot + file di configurazione + `relazione.md`

---

## 🌐 Scenario

L'azienda **TechItalia S.r.l.** ha tre sedi:
- **Milano** (sede centrale) — funge da hub VPN
- **Roma** (filiale) — si connette a Milano e a Torino
- **Torino** (filiale) — si connette a Milano e a Roma

Invece della tradizionale topologia hub-and-spoke (tutto passa per il centro), si vuole creare una **rete mesh**: ogni sede può comunicare direttamente con le altre senza passare dal server centrale.

---

## 🗺️ Topologia Mesh

```
        Milano (hub)
        wg0: 10.10.0.1
           /         \
          /           \
Roma               Torino
wg0: 10.10.0.2     wg0: 10.10.0.3

Ogni peer conosce gli altri due → comunicazione diretta senza hub
```

### Indirizzamento

| Sede | VM | WAN (Host-Only) | VPN (wg0) | LAN interna |
|------|----|-----------------|-----------|-------------|
| Milano (server) | `wg-milano` | 192.168.56.1 | 10.10.0.1/24 | 10.1.0.0/24 |
| Roma | `wg-roma` | 192.168.56.2 | 10.10.0.2/24 | 10.2.0.0/24 |
| Torino | `wg-torino` | 192.168.56.3 | 10.10.0.3/24 | 10.3.0.0/24 |

---

## 📋 Requisiti

### Requisito 1 — Generazione Chiavi (15 punti)

Genera le coppie di chiavi su **ciascuna** delle tre VM:

```bash
# Su ogni VM
wg genkey | sudo tee /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
sudo chmod 600 /etc/wireguard/private.key /etc/wireguard/wg0.conf
```

Crea una tabella di scambio chiavi:

| VM | PrivateKey (tenere) | PublicKey (condividere) |
|----|---------------------|------------------------|
| Milano | `[generata]` | `[annotare]` |
| Roma | `[generata]` | `[annotare]` |
| Torino | `[generata]` | `[annotare]` |

### Requisito 2 — Configurazione Milano (Hub) (25 punti)

Milano conosce entrambi i peer (Roma e Torino):

```ini
# /etc/wireguard/wg0.conf — MILANO

[Interface]
PrivateKey = <PRIV_MILANO>
Address = 10.10.0.1/24
ListenPort = 51820
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; \
           iptables -A FORWARD -o %i -j ACCEPT; \
           iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; \
           sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -D FORWARD -i %i -j ACCEPT; \
           iptables -D FORWARD -o %i -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Roma
PublicKey = <PUB_ROMA>
AllowedIPs = 10.10.0.2/32, 10.2.0.0/24
Endpoint = 192.168.56.2:51820
PersistentKeepalive = 25

[Peer]
# Torino
PublicKey = <PUB_TORINO>
AllowedIPs = 10.10.0.3/32, 10.3.0.0/24
Endpoint = 192.168.56.3:51820
PersistentKeepalive = 25
```

### Requisito 3 — Configurazione Roma e Torino (25 punti)

Ogni filiale deve conoscere **sia Milano che l'altra filiale** per la comunicazione mesh.

Scrivi autonomamente il `wg0.conf` per Roma e Torino, includendo:
- La propria `PrivateKey` e `Address`
- La sezione `[Peer]` per Milano (con `Endpoint`)
- La sezione `[Peer]` per l'altra filiale (Roma → Torino, Torino → Roma)

> 💡 **Nota sulla comunicazione mesh**: per permettere a Roma di comunicare direttamente con Torino, la sezione `[Peer]` di Torino in Roma deve avere `Endpoint = 192.168.56.3:51820` e `AllowedIPs = 10.10.0.3/32, 10.3.0.0/24`.

### Requisito 4 — Verifica Connettività Mesh (20 punti)

Dopo aver attivato WireGuard su tutti e tre i peer:

```bash
# Su Milano: verificare che entrambi i peer abbiano fatto handshake
sudo wg show

# Da Roma: ping diretto a Torino (senza passare per Milano!)
ping -c 3 10.10.0.3
ping -c 3 10.3.0.1   # IP LAN Torino (se simulata)

# Da Torino: ping diretto a Roma
ping -c 3 10.10.0.2

# Verificare il routing: il traffico Roma→Torino va direttamente?
traceroute 10.10.0.3   # Da Roma: non deve passare per 10.10.0.1 (Milano)
```

### Requisito 5 — Relazione Tecnica (15 punti)

Scrivi `relazione.md` con:
- Schema ASCII della topologia mesh implementata
- Tabella delle chiavi pubbliche scambiate
- Confronto hub-and-spoke vs mesh (vantaggi, svantaggi, scenari d'uso)
- Differenze di configurazione rispetto all'esercizio A (road warrior)

---

## 🌟 Bonus (fino a +20 punti)

### Bonus A — PresharedKey tra peer (+10)

Aggiungi una `PresharedKey` tra ogni coppia di peer per protezione post-quantum:

```bash
# Generare una PSK per la coppia Milano-Roma
wg genpsk > psk_milano_roma.key

# Aggiungere alla sezione [Peer] di entrambi:
# PresharedKey = <contenuto psk_milano_roma.key>
```

### Bonus B — Script di setup automatico (+10)

Scrivi uno script `setup_wireguard.sh` che:
1. Installa WireGuard
2. Genera le chiavi
3. Crea il file `wg0.conf` a partire da parametri in input (IP, chiave pubblica del peer)
4. Attiva il tunnel

---

## 📊 Punteggio

| Requisito | Punti |
|-----------|-------|
| 1 — Generazione e tabella chiavi | 15 |
| 2 — Configurazione Milano | 25 |
| 3 — Configurazione Roma e Torino | 25 |
| 4 — Verifica connettività mesh | 20 |
| 5 — Relazione tecnica | 15 |
| **Totale** | **100** |
| Bonus A — PresharedKey | +10 |
| Bonus B — Script setup | +10 |

---

*ES03-B — Sistemi e Reti | Progetto autonomo WireGuard Mesh*
