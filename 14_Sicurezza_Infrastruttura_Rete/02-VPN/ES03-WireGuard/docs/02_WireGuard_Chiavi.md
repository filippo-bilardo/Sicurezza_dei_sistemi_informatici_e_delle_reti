# WireGuard — Gestione delle Chiavi

> **ES03 — WireGuard** | Documento teorico 02

---

## Generazione Chiavi

Ogni peer WireGuard ha una **coppia di chiavi asimmetriche** (privata + pubblica). La chiave pubblica si deriva matematicamente dalla privata, ma non è possibile fare il contrario.

```bash
# Generare una chiave privata
wg genkey | tee privatekey | wg pubkey > publickey

# Verificare il risultato
cat privatekey   # Es: qNoGADRjKMwvJ3GGqfXkbvUFzYQ+8MqKGnpgEOTn7F0=
cat publickey    # Es: YamzMVRVhFxxIW+2xYbJDr4L8LDiPBqmX0L4cVFRrV4=
```

Le chiavi WireGuard sono **base64 di 32 byte** — molto più corte di un certificato X.509.

### Chiave Pre-condivisa (PresharedKey) — Opzionale

È possibile aggiungere una chiave simmetrica **per coppia di peer**, che viene combinata con lo scambio Curve25519. Questo aggiunge un livello di protezione contro i computer quantistici:

```bash
wg genpsk > presharedkey
```

---

## Scambio delle Chiavi Pubbliche

A differenza di OpenVPN (dove la CA firma i certificati), in WireGuard le chiavi pubbliche si scambiano **manualmente** (o tramite automazione):

```
Server genera: priv_S, pub_S
Client genera: priv_C, pub_C

Server riceve: pub_C (il client invia la sua pubblica al server)
Client riceve: pub_S (il server invia la sua pubblica al client)

Nessuna terza parte (CA) necessaria!
```

**Come scambiare le chiavi in pratica:**
- Per laboratorio: copia manuale (ssh, scp, copia-incolla)
- In produzione: sistemi automatici come Ansible, Puppet, o portali self-service

---

## Sicurezza nella Gestione delle Chiavi

### Cosa fare

```
✅ Generare le chiavi sul dispositivo che le userà (non generare per conto di altri)
✅ Tenere la PrivateKey in un file con permessi 600 (solo root può leggere)
✅ Fare backup sicuro delle chiavi (encrypted)
✅ Usare PresharedKey per protezione post-quantum su dati sensibili
✅ Ruotare periodicamente le chiavi (ogni anno o in caso di sospetta compromissione)
```

### Cosa non fare

```
❌ Inviare la chiave privata via email o chat
❌ Mettere la PrivateKey in un repository Git
❌ Usare la stessa coppia di chiavi su più dispositivi
❌ Lasciare le chiavi leggibili da tutti (chmod 644)
```

### Proteggere il file di configurazione

```bash
# Il file wg0.conf contiene la PrivateKey — deve essere leggibile solo da root
sudo chmod 600 /etc/wireguard/wg0.conf
sudo chown root:root /etc/wireguard/wg0.conf
```

---

## Revocare l'Accesso di un Peer

In WireGuard non esiste una CRL come in OpenVPN. Per bloccare un peer:

```bash
# Rimuovere il peer dalla configurazione del server
sudo wg set wg0 peer PUBLIC_KEY_CLIENT --remove

# Oppure rimuovere la sezione [Peer] da /etc/wireguard/wg0.conf
# e ricaricare la configurazione
sudo wg syncconf wg0 <(wg-quick strip wg0)
```

Il peer non potrà più comunicare con il server perché la sua chiave pubblica non è più nella lista dei peer autorizzati.

> 💡 **Semplicità rispetto a OpenVPN**: niente CRL da generare, niente `crl.pem` da aggiornare. Basta rimuovere la riga con la chiave pubblica.

---

## Domande di Riepilogo

1. Qual è la differenza tra chiave privata e chiave pubblica in WireGuard? Quale si può condividere?
2. Come si blocca un peer che non deve più accedere alla VPN? Come si differenzia da OpenVPN?
3. A cosa serve la `PresharedKey`? In quale scenario è raccomandata?
4. Perché la chiave privata non deve mai essere inviata via email?

---

*Prossimo documento: [03 — Configurazione WireGuard](03_WireGuard_Config.md)*
