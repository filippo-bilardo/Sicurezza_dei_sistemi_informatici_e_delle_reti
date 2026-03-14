# ES02-B — Progetto autonomo: VPN multi-client con revoca certificati

> **Tipo**: 🚀 Progetto autonomo  
> **Durata stimata**: 4–6 ore  
> **Punteggio**: 100 punti + bonus  
> **File da consegnare**: screenshot + file di configurazione + `relazione.md`

---

## 🌐 Scenario

L'azienda **TechItalia S.r.l.** ha assunto tre nuovi tecnici remoti. Il responsabile IT deve:

1. Configurare un server OpenVPN che supporti **tre client simultanei**
2. Implementare la **separazione degli accessi**: solo alcuni client raggiungono determinati server
3. **Revocare** il certificato di un tecnico che ha lasciato l'azienda
4. Implementare il **full tunnel** per un client e lo **split tunnel** per un altro

---

## 🗺️ Topologia

```
                              SERVER OpenVPN
                             192.168.56.1 (WAN)
                             10.0.0.1 (LAN Aziendale)
                             10.8.0.1 (VPN gateway)
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
         tun: 10.8.0.2         tun: 10.8.0.3        tun: 10.8.0.4
         Client Mario            Client Anna           Client Luca
         (full tunnel)          (split tunnel)        (da revocare)
```

### Subnetting VPN per client specifici (bonus)

Usando `client-config-dir`, ogni client riceve route specifiche:

```
Mario  → accede a: 10.0.0.0/24 (tutta la LAN)
Anna   → accede a: 10.0.1.0/24 (solo server applicativi)
Luca   → certificato revocato (non si connette)
```

---

## 📋 Requisiti

### Requisito 1 — Multi-client (20 punti)

Configura il server per supportare tre client:
- `mario-rossi` — Tecnico senior, accesso completo alla LAN
- `anna-verdi` — Tecnico junior, accesso limitato
- `luca-bianchi` — Ex-tecnico (certificato da revocare)

Genera i tre certificati con Easy-RSA e i relativi file `.ovpn`.

### Requisito 2 — Client Config Directory (25 punti)

Implementa configurazioni per-client usando `client-config-dir`:

```bash
# Nel server.conf aggiungere:
client-config-dir /etc/openvpn/ccd
```

```bash
sudo mkdir /etc/openvpn/ccd

# File /etc/openvpn/ccd/mario-rossi
# (il nome deve corrispondere al Common Name del certificato)
sudo nano /etc/openvpn/ccd/mario-rossi
```

```ini
# Contenuto /etc/openvpn/ccd/mario-rossi
# IP fisso per Mario
ifconfig-push 10.8.0.10 10.8.0.9
# Accesso a tutta la LAN
push "route 10.0.0.0 255.255.0.0"
```

```bash
sudo nano /etc/openvpn/ccd/anna-verdi
```

```ini
# Contenuto /etc/openvpn/ccd/anna-verdi
# IP fisso per Anna
ifconfig-push 10.8.0.20 10.8.0.19
# Solo accesso ai server applicativi (subnet limitata)
push "route 10.0.1.0 255.255.255.0"
```

### Requisito 3 — Full Tunnel vs Split Tunnel (20 punti)

Nel profilo `.ovpn` di Mario, abilitare il **full tunnel**:

```ini
# mario-rossi.ovpn — aggiungere:
redirect-gateway def1
```

Nel profilo di Anna, usare **split tunnel** (non aggiungere `redirect-gateway`).

Verifica e documenta la differenza con:
```bash
# Su Mario: verificare che 0.0.0.0/0 punti a tun0
ip route show | head -5

# Su Anna: verificare che il gateway di default sia ancora quello casalingo
ip route show | head -5
```

### Requisito 4 — Revoca Certificato Luca (20 punti)

```bash
# Sul server
cd ~/openvpn-pki

# Revocare il certificato
./easyrsa revoke luca-bianchi

# Generare la CRL aggiornata
./easyrsa gen-crl

# Copiare la CRL nella directory OpenVPN
sudo cp pki/crl.pem /etc/openvpn/server/

# Verificare che server.conf contenga:
grep crl-verify /etc/openvpn/server/server.conf
# Se non c'è, aggiungere:
echo "crl-verify /etc/openvpn/server/crl.pem" | sudo tee -a /etc/openvpn/server/server.conf

# Riavviare per applicare
sudo systemctl restart openvpn-server@server
```

**Verifica**: prova a connetterti con il profilo di Luca → deve fallire con errore di certificato revocato.

### Requisito 5 — Relazione Tecnica (15 punti)

Scrivi un file `relazione.md` con:
- Schema della topologia implementata (ASCII art)
- Descrizione delle scelte di configurazione
- Differenza osservata tra full tunnel e split tunnel (con screenshot delle route)
- Procedura di revoca e verifica

---

## 🌟 Bonus (fino a +20 punti)

### Bonus A — Autenticazione username+password (+10)

Aggiungi l'autenticazione username/password **in aggiunta** ai certificati (double factor):

```bash
# Nel server.conf
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
```

```bash
# Nel client.ovpn
auth-user-pass
```

### Bonus B — Script di monitoraggio connessioni (+10)

Scrivi uno script bash `monitor_vpn.sh` che:
- Legga il `status.log` ogni 30 secondi
- Mostri i client connessi con IP e byte trasferiti
- Invii un log in `/var/log/vpn_monitor.log`

---

## 📊 Punteggio

| Requisito | Punti |
|-----------|-------|
| 1 — Multi-client (3 certificati, 3 profili .ovpn) | 20 |
| 2 — Client Config Directory (IP fissi, route per-client) | 25 |
| 3 — Full tunnel vs split tunnel (verifica con screenshot) | 20 |
| 4 — Revoca certificato Luca (CRL, verifica blocco) | 20 |
| 5 — Relazione tecnica | 15 |
| **Totale** | **100** |
| Bonus A — Auth username+password | +10 |
| Bonus B — Script monitoraggio | +10 |

---

*ES02-B — Sistemi e Reti | Progetto autonomo OpenVPN*
