# 02 — VPN: Virtual Private Network

> **Materia**: Sistemi e Reti — Classe 5ª  
> **Parte**: 14 — Sicurezza dell'Infrastruttura di Rete

---

## 📖 Guide Teoriche

| # | File | Argomento |
|---|------|-----------|
| 01 | [Le VPN](01_le_vpn.md) | Cos'è una VPN, tipi, tunneling, scenari d'uso |
| 02 | [SSL VPN](02_ssl_vpn.md) | SSL/TLS VPN, architettura, confronto con IPsec |
| 03 | [IPsec VPN](03_ipsec_vpn.md) | Protocollo IPsec: AH, ESP, IKE, SA, modalità |
| 04 | [OpenVPN](04_openvpn.md) | OpenVPN: PKI, configurazione, TUN/TAP |
| 05 | [WireGuard](05_wireguard.md) | WireGuard: architettura, crittografia, peer |
| 06 | [Split Tunneling](06_split_tunneling.md) | Full tunnel vs split tunnel, policy, DNS |
| 07 | [VPN Kill Switch e DNS Leak](07_vpn_kill_switch_e_dns_leak.md) | Protezione perdita di connessione e perdita DNS |
| 08 | [Normativa e Implicazioni Legali](08_normativa_implicazioni_legali.md) | GDPR, normativa europea, uso lecito delle VPN |
| 09 | [Modelli di Accesso Remoto Sicuro](09_modelli_accesso_remoto_sicuro.md) | Remote access, Zero Trust, ZTNA, SASE |

---

## 🏋️ Esercitazioni

### ES01 — IPsec VPN con Cisco Packet Tracer

> Configura tunnel VPN Site-to-Site IPsec e GRE su router Cisco 2901.

| File | Descrizione |
|------|-------------|
| [ES01-Ipsec_VPN/README.md](ES01-Ipsec_VPN/README.md) | Introduzione, competenze, sequenza di studio |
| [docs/01_VPN_Concetti.md](ES01-Ipsec_VPN/docs/01_VPN_Concetti.md) | Concetti VPN: tipi, tunneling, sicurezza |
| [docs/02_IPsec.md](ES01-Ipsec_VPN/docs/02_IPsec.md) | Protocollo IPsec completo |
| [docs/03_GRE_Tunneling.md](ES01-Ipsec_VPN/docs/03_GRE_Tunneling.md) | GRE Tunnel e GRE over IPsec |
| [docs/04_Configurazione_VPN_Cisco.md](ES01-Ipsec_VPN/docs/04_Configurazione_VPN_Cisco.md) | Comandi Cisco IOS — riferimento pratico |
| [docs/05_VPN_Troubleshooting.md](ES01-Ipsec_VPN/docs/05_VPN_Troubleshooting.md) | Troubleshooting: verifica stato, debug |
| [esercizio_a.md](ES01-Ipsec_VPN/esercizio_a.md) | 🔬 Lab guidato — VPN IPsec Site-to-Site Roma↔Milano |
| [esercizio_b.md](ES01-Ipsec_VPN/esercizio_b.md) | 🏗️ Progetto autonomo — VPN Hub-and-Spoke MultiSede |
| [esercizio_c.md](ES01-Ipsec_VPN/esercizio_c.md) | 📖 Teoria — VPN, IPsec, GRE, troubleshooting |

---

### ES02 — OpenVPN su Linux

> Installa e configura un server OpenVPN con PKI su Ubuntu Server.

| File | Descrizione |
|------|-------------|
| [ES02-OpenVPN/README.md](ES02-OpenVPN/README.md) | Introduzione, competenze, sequenza di studio |
| [docs/01_SSL_VPN_Concetti.md](ES02-OpenVPN/docs/01_SSL_VPN_Concetti.md) | SSL VPN, TUN vs TAP, full/split tunnel, confronto |
| [docs/02_PKI_Certificati.md](ES02-OpenVPN/docs/02_PKI_Certificati.md) | PKI, CA, Easy-RSA, revoca CRL |
| [docs/03_OpenVPN_Config.md](ES02-OpenVPN/docs/03_OpenVPN_Config.md) | server.conf, iptables NAT, client.ovpn |
| [docs/04_Troubleshooting.md](ES02-OpenVPN/docs/04_Troubleshooting.md) | Errori TLS, routing, disconnessioni |
| [esercizio_a.md](ES02-OpenVPN/esercizio_a.md) | 🔬 Lab guidato — Server OpenVPN Road Warrior |
| [esercizio_b.md](ES02-OpenVPN/esercizio_b.md) | 🏗️ Progetto autonomo — VPN multi-client con revoca certificati |
| [esercizio_c.md](ES02-OpenVPN/esercizio_c.md) | 📖 Teoria — OpenVPN, TLS e PKI |

---

### ES03 — WireGuard su Linux

> Configura una VPN WireGuard moderna, dalle coppie di chiavi alla rete mesh.

| File | Descrizione |
|------|-------------|
| [ES03-WireGuard/README.md](ES03-WireGuard/README.md) | Introduzione, competenze, sequenza di studio |
| [docs/01_WireGuard_Concetti.md](ES03-WireGuard/docs/01_WireGuard_Concetti.md) | Architettura peer-to-peer, crittografia (Curve25519/ChaCha20) |
| [docs/02_WireGuard_Chiavi.md](ES03-WireGuard/docs/02_WireGuard_Chiavi.md) | Generazione chiavi, scambio pubbliche, revoca peer |
| [docs/03_WireGuard_Config.md](ES03-WireGuard/docs/03_WireGuard_Config.md) | wg0.conf, wg-quick, full/split tunnel, comandi verifica |
| [docs/04_Troubleshooting.md](ES03-WireGuard/docs/04_Troubleshooting.md) | Handshake fallito, routing, checklist |
| [esercizio_a.md](ES03-WireGuard/esercizio_a.md) | 🔬 Lab guidato — Server WireGuard Road Warrior |
| [esercizio_b.md](ES03-WireGuard/esercizio_b.md) | 🏗️ Progetto autonomo — Rete VPN mesh a 3 peer |
| [esercizio_c.md](ES03-WireGuard/esercizio_c.md) | 📖 Teoria — WireGuard e confronto VPN |

---

## 🗂️ Struttura Cartella

```
02-VPN/
├── README.md                          ← Questo file
│
├── 01_le_vpn.md                       ← Guida: cos'è una VPN
├── 02_ssl_vpn.md                      ← Guida: SSL VPN
├── 03_ipsec_vpn.md                    ← Guida: IPsec VPN
├── 04_openvpn.md                      ← Guida: OpenVPN
├── 05_wireguard.md                    ← Guida: WireGuard
├── 06_split_tunneling.md              ← Guida: split tunneling
├── 07_vpn_kill_switch_e_dns_leak.md   ← Guida: kill switch e DNS leak
├── 08_normativa_implicazioni_legali.md← Guida: normativa e legale
├── 09_modelli_accesso_remoto_sicuro.md← Guida: Zero Trust, ZTNA, SASE
│
├── ES01-Ipsec_VPN/                    ← Esercitazione IPsec (Cisco PT)
│   ├── README.md
│   ├── docs/
│   ├── esercizio_a.md
│   ├── esercizio_b.md
│   └── esercizio_c.md
│
├── ES02-OpenVPN/                      ← Esercitazione OpenVPN (Linux)
│   ├── README.md
│   ├── docs/
│   ├── esercizio_a.md
│   ├── esercizio_b.md
│   └── esercizio_c.md
│
└── ES03-WireGuard/                    ← Esercitazione WireGuard (Linux)
    ├── README.md
    ├── docs/
    ├── esercizio_a.md
    ├── esercizio_b.md
    └── esercizio_c.md
```

---

## 🔑 Confronto Rapido tra Protocolli VPN

| Protocollo | Layer OSI | Porta | Crittografia | Facilità | Caso d'uso tipico |
|-----------|-----------|-------|--------------|----------|-------------------|
| **IPsec** | L3 | UDP 500/4500 | AES, 3DES | ⭐⭐ | Site-to-site enterprise, router Cisco |
| **OpenVPN** | L4/L7 | UDP/TCP 1194 o 443 | AES-GCM, ChaCha20 | ⭐⭐⭐ | Remote access, alta compatibilità firewall |
| **WireGuard** | L3 | UDP (libero) | ChaCha20-Poly1305 | ⭐⭐⭐⭐ | Performance, mobile, configurazione semplice |

---

*Parte 14 — Sicurezza dell'Infrastruttura di Rete | Sistemi e Reti 5ª*
