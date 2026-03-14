# SSL VPN e OpenVPN — Concetti

> **ES02 — OpenVPN** | Documento teorico 01

---

## Cos'è una SSL VPN

Una **SSL VPN** utilizza il protocollo **TLS** (Transport Layer Security) per creare un tunnel sicuro tra client e server. TLS è lo stesso protocollo che protegge HTTPS — quindi una SSL VPN può passare attraverso quasi tutti i firewall e proxy aziendali senza problemi.

**OpenVPN** è l'implementazione SSL VPN open source più diffusa: ogni anno milioni di server e client la usano in tutto il mondo.

---

## Confronto: OpenVPN vs IPsec

| Caratteristica | OpenVPN | IPsec/IKEv2 |
|----------------|---------|-------------|
| **Layer OSI** | 4–7 (applicativo) | 3 (rete) |
| **Porta usata** | UDP 1194 o TCP 443 | UDP 500 + 4500 (NAT-T) |
| **Firewall friendly** | ✅ Molto (porta 443) | ⚠️ Meno (ESP proto 50) |
| **Installazione** | Software su qualsiasi OS | Integrato nel kernel |
| **Performance** | Buona (userspace) | Alta (kernel) |
| **Configurazione** | File di testo semplice | Complessa (IKE policies) |
| **Autenticazione** | Certificati X.509, PSK, user+pass | Certificati, PSK |
| **Standard** | Protocollo proprietario OpenVPN | Standard IETF |

---

## Architettura OpenVPN

```
Client (laptop dipendente)            Server OpenVPN (gateway aziendale)
        |                                         |
        | --- [TLS Handshake] ------------------> |
        | <-- [Certificato Server] -------------- |
        | --- [Certificato Client] -------------> |
        |                                         |
        | ===== [Canale controllo TLS] ========== |
        |                                         |
        | --- [Push/Pull opzioni VPN] ----------> |
        | <-- [IP: 10.8.0.2, route 192.168.1.0] - |
        |                                         |
        | ===== [Tunnel dati AES-256-GCM] ======> |
                   (traffico aziendale)
```

### Interfaccia tun0

Quando OpenVPN si connette, crea un'**interfaccia virtuale** sul client:

```
PRIMA della VPN:
eth0: 192.168.100.5   (IP casalingo o dell'hotspot)
Gateway: 192.168.100.1 → tutto il traffico esce da eth0

DOPO la connessione VPN (full tunnel):
eth0: 192.168.100.5   (rimane, usata per il tunnel fisico)
tun0: 10.8.0.2        (IP assegnato dal server VPN)
Gateway: 0.0.0.0/0 → tun0  (TUTTO il traffico passa per la VPN)
```

---

## Tipi di VPN OpenVPN

### Remote Access (Road Warrior)
Un singolo utente si collega al server VPN aziendale da qualsiasi rete.

```
[Laptop dipendente] ──── Internet ──── [Server OpenVPN] ──── [LAN Aziendale]
  IP: qualsiasi          tunnel TLS      10.8.0.1              192.168.1.0/24
  VPN IP: 10.8.0.2
```

**Uso tipico:** smart working, accesso a risorse aziendali da casa.

### Site-to-Site
Due sedi aziendali collegate in modo permanente tramite tunnel OpenVPN.

```
[LAN Sede A] ── [Server OpenVPN A] ══ tunnel ══ [Client OpenVPN B] ── [LAN Sede B]
192.168.1.0/24     10.8.0.1                          10.8.0.2          192.168.2.0/24
```

---

## Full Tunnel vs Split Tunnel

### Full Tunnel (`push "redirect-gateway def1"`)
**Tutto** il traffico del client (incluso internet) passa dalla VPN.

```
YouTube, Gmail, Facebook → tun0 → Server VPN → Internet
Risorse aziendali        → tun0 → Server VPN → LAN
```

✅ Massima sicurezza (tutto il traffico è protetto e filtrato dall'azienda)  
❌ Più lento (tutto passa dal server VPN)  
❌ Il server VPN vede tutto il traffico internet del dipendente

### Split Tunnel (solo route aziendali)
Solo il traffico verso la rete aziendale passa dalla VPN, internet è diretto.

```
YouTube, Gmail, Facebook → eth0 → Internet diretto
Risorse aziendali        → tun0 → Server VPN → LAN
```

✅ Più veloce (internet non passa dal VPN)  
❌ Minor controllo sul traffico del dipendente  
❌ Rischio DNS leak (risoluzione DNS fuori dalla VPN)

---

## Sicurezza del Canale

### tls-auth vs tls-crypt

**`tls-auth`**: aggiunge un HMAC su ogni pacchetto OpenVPN. Protegge contro port scanning e DoS sul server.

**`tls-crypt`** (raccomandato, OpenVPN 2.4+): **cifra e autentica** il canale di controllo TLS. Un osservatore esterno non può nemmeno identificare che il traffico è OpenVPN.

```
Con tls-auth:   [Pacchetto OpenVPN visibile] + [HMAC]
Con tls-crypt:  [Tutto cifrato — non identificabile come OpenVPN]
```

### Suite crittografica

```ini
# Configurazione moderna raccomandata
cipher AES-256-GCM          # Cifratura AEAD (cifra + autentica)
auth SHA256                 # Hash per l'integrità
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
tls-version-min 1.2         # Minimo TLS 1.2
```

---

## Domande di Riepilogo

1. Su quale porta usa OpenVPN di default? Perché può usare la porta 443?
2. Qual è la differenza tra full tunnel e split tunnel?
3. Perché `tls-crypt` è più sicuro di `tls-auth`?
4. Cosa fa l'interfaccia `tun0` nel sistema operativo del client?

---

*Prossimo documento: [02 — PKI e Certificati con Easy-RSA](02_PKI_Certificati.md)*
