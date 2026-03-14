# Capitolo 09 - Modelli di Accesso Remoto Sicuro

> **PARTE 14 - SICUREZZA DELL'INFRASTRUTTURA DI RETE**  
> **Capitolo 09 — VPN e Accesso Remoto Sicuro**

---

## Introduzione

L'accesso remoto sicuro è evoluto significativamente oltre il semplice tunnel VPN. L'adozione massiva del cloud, il lavoro distribuito e l'aumento degli attacchi ai gateway VPN hanno spinto verso modelli architetturali più granulari e resilienti. Questa guida analizza i principali modelli — da quelli classici a Zero Trust — e fornisce criteri per scegliere l'approccio più adatto al proprio contesto.

### Obiettivi di Apprendimento
- Conoscere i modelli di accesso remoto dal tradizionale al moderno
- Comprendere il paradigma Zero Trust e la sua applicazione pratica
- Analizzare ZTNA, SASE e altri modelli cloud-native
- Valutare i criteri di scelta in base al contesto aziendale
- Progettare un'architettura di accesso remoto sicuro multi-layer

---

## Evoluzione Storica

```
Anni '90       Anni '00         Anni '10          Anni '20+
   |               |                |                  |
   ▼               ▼                ▼                  ▼
Dial-up        IPsec VPN        SSL VPN            Zero Trust /
Modem          Site-to-Site     Remote Access      ZTNA / SASE
(PSTN)         (Hardware)       (Software)         (Cloud-native)
               
Perimetro netto →→→→→→→→→→→ Perimetro dissolto →→→→→→→→→ No perimetro
"Castle & Moat"                                         "Never Trust, Always Verify"
```

---

## Modello 1: VPN Tradizionale (Network-Centric)

### Architettura

```
Internet
    |
[Firewall perimetrale]
    |
[VPN Gateway / Concentratore]
    |
[Rete Aziendale Flat]
    ├── Server applicativi
    ├── File server
    ├── Database
    └── Stampanti / IoT
```

### Caratteristiche

- **Fiducia implicita:** una volta autenticato, l'utente accede all'intera rete (o a subnet ampie)
- **Modello "castle and moat":** perimetro netto, tutto dentro è fidato
- **Scalabilità limitata:** il gateway VPN è un single point of failure e collo di bottiglia
- **Visibilità ridotta:** traffico nel tunnel non ispezionato (o ispezionato solo all'uscita)

### Limiti Evidenziati dagli Attacchi Recenti

Gli attacchi ransomware degli ultimi anni hanno sfruttato esattamente questo modello:
1. Credenziali VPN compromesse (phishing, credential stuffing)
2. Accesso alla rete interna con movimenti laterali liberi
3. Propagazione ransomware su tutta la rete

---

## Modello 2: VPN con Segmentazione (Network-Centric Migliorato)

### Architettura

```
Internet
    |
[Firewall perimetrale]
    |
[VPN Gateway]
    |
[Firewall interno / NAC]
    |
    ├── VLAN Finance    (solo team Finance)
    ├── VLAN Dev        (solo sviluppatori)
    ├── VLAN Operations (solo ops/sysadmin)
    └── VLAN Servers    (solo da VLAN autorizzate)
```

### Miglioramenti vs Modello 1

- La VPN assegna l'utente alla VLAN/segmento appropriato in base all'identità
- I movimenti laterali sono limitati dalle regole firewall tra VLAN
- NAC (Network Access Control) può verificare la postura del dispositivo prima dell'accesso

### Implementazione con OpenVPN

```ini
# server.conf - assegnare subnet diverse per gruppo
client-config-dir /etc/openvpn/ccd/

# File /etc/openvpn/ccd/mario.rossi (utente Finance)
ifconfig-push 10.8.1.5 10.8.1.6
push "route 192.168.10.0 255.255.255.0"  # Solo VLAN Finance

# File /etc/openvpn/ccd/dev.team (utenti Dev)
ifconfig-push 10.8.2.5 10.8.2.6
push "route 192.168.20.0 255.255.255.0"  # Solo VLAN Dev
```

---

## Modello 3: Zero Trust Network Access (ZTNA)

### Principi Zero Trust (NIST SP 800-207)

Il paradigma **Zero Trust** si basa su:

```
"Never trust, always verify"

Principi fondamentali:
1. Verificare esplicitamente → Autenticare e autorizzare ogni richiesta
                               (identità, dispositivo, posizione, comportamento)
2. Minimo privilegio        → Accesso just-in-time, just-enough-access
3. Assume breach            → Progettare come se la rete fosse già compromessa
                               (micro-segmentazione, cifratura end-to-end)
```

### Architettura ZTNA

```
Utente remoto                    ZTNA Control Plane
     |                                  |
     |---[1. Richiesta accesso]-------->|
     |<--[2. Verifica identità+device]--|  (IdP: AD, Okta, Azure AD)
     |---[3. Device posture check]----->|  (MDM, EDR status, patch level)
     |<--[4. Token di accesso]----------|
     |                                  |
     |---[5. Connessione app-specifica]->|--[App Connector]--[App interna]
     |         (non all'intera rete)     |   (micro-tunnel)
```

**Differenza chiave rispetto alla VPN:**
- L'utente non entra mai nella rete interna
- Accede a **singole applicazioni** tramite un proxy/connector
- La rete interna rimane invisibile al client

### Componenti ZTNA

| Componente | Funzione |
|------------|----------|
| **Identity Provider (IdP)** | Autenticazione utente (SSO, MFA) |
| **Policy Engine** | Decisione di accesso basata su contesto |
| **Device Trust** | Verifica postura del dispositivo |
| **App Connector** | Agente installato vicino all'applicazione |
| **ZTNA Gateway/Broker** | Proxy tra utente e applicazione |

### Prodotti ZTNA

| Prodotto | Vendor | Modello |
|----------|--------|---------|
| Zscaler Private Access (ZPA) | Zscaler | Cloud-hosted |
| Cloudflare Access | Cloudflare | Cloud-hosted |
| BeyondCorp Enterprise | Google | Cloud-hosted |
| Prisma Access | Palo Alto | Cloud-hosted |
| Twingate | Twingate | Cloud-hosted |
| Tailscale | Tailscale | WireGuard-based, cloud control plane |

---

## Modello 4: SASE (Secure Access Service Edge)

**SASE** (pronunciato "sassy") combina funzionalità di rete WAN con servizi di sicurezza erogati dal cloud, come definito da Gartner nel 2019.

### Componenti SASE

```
SASE = SD-WAN + Security Stack cloud-delivered

Security Stack:
  ├── ZTNA (Zero Trust Network Access)
  ├── SWG (Secure Web Gateway) — filtraggio web
  ├── CASB (Cloud Access Security Broker) — sicurezza SaaS
  ├── FWaaS (Firewall as a Service)
  └── DLP (Data Loss Prevention)
```

```
Utente (ovunque)
    |
    ↓
[SASE PoP - Point of Presence] (edge cloud vicino all'utente)
    ├── Ispezione traffico (SSL inspection, AV, sandbox)
    ├── Applicazione policy Zero Trust
    ├── Accesso ottimizzato a SaaS (Microsoft 365, Salesforce)
    └── Tunnel sicuro verso risorse on-premise
```

### SASE vs VPN Tradizionale

| | VPN Tradizionale | SASE |
|-|-----------------|------|
| Routing traffico | Hub & spoke (tutto al datacenter) | Direct-to-cloud ottimizzato |
| Sicurezza perimetro | On-premise | Cloud distribuita |
| Scalabilità | Limitata (HW gateway) | Elastica |
| Visibilità | Parziale | Full stack inspection |
| Gestione | Complessa (multi-vendor) | Piattaforma unificata |
| Costo | HW + manutenzione | Subscription |

---

## Modello 5: Privileged Access Workstation (PAW) + Bastion Host

Per l'accesso amministrativo a sistemi critici, il modello VPN tradizionale non è sufficiente. Si usano architetture dedicate:

### Bastion Host / Jump Server

```
Admin remoto
    |
    |---[VPN / SSH]--→ [Bastion Host / Jump Server]
                              |
                              |---[SSH/RDP]--→ [Server produzione]
                              |---[SSH/RDP]--→ [Database server]
                              |---[SSH/RDP]--→ [Firewall management]
```

**Caratteristiche:**
- Il bastion host è l'**unico** punto di ingresso per l'accesso amministrativo
- Logging completo di tutte le sessioni (session recording)
- MFA obbligatorio per l'accesso al bastion
- I server di produzione non sono direttamente raggiungibili dall'esterno

### Implementazione con SSH ProxyJump

```bash
# Accedere a server interno tramite bastion
ssh -J admin@bastion.azienda.com utente@server-interno.lan

# Configurazione ~/.ssh/config
Host bastion
    HostName bastion.azienda.com
    User admin
    IdentityFile ~/.ssh/bastion_key

Host server-interno
    HostName 192.168.1.50
    User root
    ProxyJump bastion
    IdentityFile ~/.ssh/prod_key
```

### PAM (Privileged Access Management)

Per ambienti enterprise, soluzioni PAM come **CyberArk**, **HashiCorp Vault**, **BeyondTrust** aggiungono:
- Credential vaulting (password casuali e rotanti per gli account privilegiati)
- Session recording e audit trail
- Approvazione workflow per accessi critici (just-in-time access)
- Integrazione con SIEM per alerting

---

## Confronto dei Modelli

### Matrice di Scelta

```
                    Sicurezza
                    (alta)
                       ↑
            ZTNA/SASE  │  PAW + PAM
                       │
  Complessità ←────────┼──────────→ Semplicità
                       │
         VPN           │  SSH Tunnel
         Segmentata    │  (singola app)
                       ↓
                    Sicurezza
                    (base)
```

| Scenario | Modello Consigliato |
|----------|---------------------|
| PMI, team piccolo, budget limitato | VPN + segmentazione VLAN |
| Enterprise con workforce distribuita | ZTNA o SASE |
| Accesso amministrativo a sistemi critici | Bastion Host + PAM |
| Cloud-first, nessun datacenter on-prem | ZTNA cloud-native |
| Compliance stringente (PCI, HIPAA) | PAM + ZTNA + logging completo |
| BYOD con dispositivi non gestiti | ZTNA (no accesso rete, solo app) |
| Connessione sede-sede (site-to-site) | IPsec o WireGuard |

---

## Progettazione di un'Architettura Ibrida

Un'architettura reale combina più modelli:

```
                           Internet
                              |
              ┌───────────────┼───────────────────┐
              |               |                   |
       [ZTNA Gateway]   [VPN Gateway]      [Bastion Host]
              |               |                   |
       App-specific     Site-to-site         Admin access
       remote workers   branch offices       (privileged)
              |               |                   |
              └───────────────┼───────────────────┘
                              |
                    [Firewall interno + IDS]
                              |
              ┌───────────────┼───────────────────┐
              |               |                   |
         [VLAN Users]   [VLAN Servers]      [VLAN Admin]
         192.168.10/24  192.168.20/24       192.168.30/24
```

### Checklist Progettazione

```
Identità e Autenticazione:
  ☐ MFA obbligatorio per tutti gli accessi remoti
  ☐ SSO integrato (ridurre password fatigue)
  ☐ Conditional Access (blocca accesso da Paesi anomali)

Dispositivi:
  ☐ Device trust / MDM enrollment per dispositivi aziendali
  ☐ Policy BYOD separata (ZTNA preferito su VPN)
  ☐ Verifica patch level prima dell'accesso

Rete:
  ☐ Segmentazione per funzione (VLAN / micro-segmentazione)
  ☐ Principio del minimo privilegio sulle route
  ☐ Ispezione traffico interno (east-west)

Visibilità:
  ☐ Logging centralizzato (SIEM)
  ☐ Alerting su anomalie (orari insoliti, volume dati, geo)
  ☐ Session recording per accessi privilegiati

Continuità:
  ☐ Ridondanza del gateway VPN/ZTNA
  ☐ Piano di risposta agli incidenti per compromissione VPN
  ☐ Test di accesso remoto periodici
```

---

## Domande di Verifica

1. **Descrivi il modello "castle and moat" delle VPN tradizionali. Perché è diventato inadeguato con la diffusione del cloud e del lavoro remoto?**

2. **Quali sono i tre principi fondamentali del paradigma Zero Trust secondo NIST SP 800-207? Come si differenzia da un accesso VPN tradizionale?**

3. **Spiega la differenza architetturale tra VPN e ZTNA nel modo in cui l'utente accede alle applicazioni. Perché ZTNA è considerato più sicuro in caso di compromissione del dispositivo?**

4. **Cos'è un Bastion Host? Perché è preferibile all'accesso VPN diretto per la gestione amministrativa di server di produzione?**

5. **Descrivi l'architettura SASE. Quali componenti di sicurezza integra e quali vantaggi offre rispetto a una soluzione VPN on-premise per un'azienda con workforce distribuita?**

6. **Un'azienda ha 500 dipendenti, 3 sedi e usa principalmente SaaS (Microsoft 365, Salesforce, SAP cloud). Quale modello di accesso remoto consiglieresti? Motiva la scelta.**

7. **Come si configura un accesso SSH tramite bastion host con `ProxyJump`? Quali log vengono prodotti sul bastion e qual è il loro valore ai fini di un audit?**

---

## Riferimenti

### Standard e Framework
- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) — Zero Trust Architecture
- [NIST SP 800-77r1](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) — Guide to IPsec VPNs
- [Gartner — SASE Definition](https://www.gartner.com/en/information-technology/glossary/secure-access-service-edge-sase)

### Documentazione Prodotti
- [Tailscale Documentation](https://tailscale.com/kb/) — WireGuard-based ZTNA
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- [HashiCorp Vault](https://developer.hashicorp.com/vault/docs) — Secrets management e PAM

### Libri e Paper
- "Zero Trust Networks" — Evan Gilman, Doug Barth (O'Reilly)
- "BeyondCorp: A New Approach to Enterprise Security" — Google (research paper)
- "NIST Zero Trust Architecture" — SP 800-207

---

**Sezione Precedente**: [08 - Normativa e Implicazioni Legali](./08_normativa_implicazioni_legali.md)  
**Indice**: [Indice](../README.md)
