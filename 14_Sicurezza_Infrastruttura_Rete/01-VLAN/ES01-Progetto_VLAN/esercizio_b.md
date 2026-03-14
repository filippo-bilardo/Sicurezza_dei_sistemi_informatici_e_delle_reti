# Esercitazione VLAN - Rete Aziendale TechCorp

**Tempo stimato:** 3-4 ore  
**Difficoltà:** ⭐⭐⭐ (Intermedia)  
**Modalità:** Individuale

---

## 📋 Scenario

Sei il network engineer di **TechCorp**, un'azienda che deve ristrutturare la propria rete implementando VLAN e inter-VLAN routing per migliorare sicurezza e prestazioni.

### Requisiti

**Reparti:** Amministrazione (VLAN10), Sviluppo (VLAN20), Marketing (VLAN30), Server (VLAN40)  
**Hardware:** 1x Router 2901, 2x Switch 2960, 6x PC, 1x Server  
**Rete:** 172.16.100.0/24 da suddividere in 4 subnet

---

## 📝 STEP dell'Esercitazione

### STEP 1: Subnetting (30 min)
Calcola 4 subnet /26 e compila piano di indirizzamento completo.

### STEP 2: Topologia Packet Tracer (20 min)
Costruisci topologia con dispositivi e cavi secondo lo schema fornito.

### STEP 3: Configurazione IP (15 min)
Configura IP statico su tutti i PC e server.

### STEP 4: Configurazione Switch (40 min)
Crea VLAN, configura trunk e porte access.

### STEP 5: Configurazione Router (30 min)
Implementa Router-on-a-Stick con 4 subinterface.

### STEP 6: Test Connettività (30 min)
Esegui test ping, traceroute e compila tabella verifiche.

---

## 📦 Consegna Finale

**File da consegnare (ZIP):**
1. Piano_Indirizzamento.pdf
2. Cognome_Nome_TechCorp.pkt
3. Config_Router.txt
4. Config_Switch-Amm.txt
5. Config_Switch-Dev.txt
6. Test_Connettivita.pdf

**Nome:** `Cognome_Nome_VLAN_TechCorp.zip`  
**Scadenza:** _______________

---

## ⚖️ Valutazione

| Criterio | Peso | Punti |
|----------|------|-------|
| Subnetting | 20% | /20 |
| Topologia PT | 10% | /10 |
| Config Switch | 20% | /20 |
| Config Router | 20% | /20 |
| Test | 20% | /20 |
| Documentazione | 10% | /10 |
| **TOTALE** | **100%** | **/100** |

**Teoria:** 70 punti aggiuntivi (valutazione separata)  
**Bonus:** +10 punti per ACL, description, ecc.

---

## 📚 Risorse

- `/docs/` - Guide teoriche complete
- `/configs/` - Esempi configurazioni
- `Guida_Packet_Tracer.md` - Tutorial PT step-by-step
- **`Domande_Teoria.md`** - 20 domande teoriche dettagliate

---

## 🎯 Istruzioni Dettagliate

### STEP 1: Subnetting

**Calcola:**
- Subnet mask necessaria per 4 subnet
- Network, broadcast, range per ogni subnet
- Piano indirizzamento completo per tutti i dispositivi

**Tabella da completare:**

| Subnet | VLAN | Network | Broadcast | Range | Host |
|--------|------|---------|-----------|-------|------|
| 1 | 10 | ? | ? | ? | ? |
| 2 | 20 | ? | ? | ? | ? |
| 3 | 30 | ? | ? | ? | ? |
| 4 | 40 | ? | ? | ? | ? |

---

### STEP 2: Topologia

**Dispositivi e collegamenti:**
```
         [Router-TechCorp]
           /            \
    (Gi0/0)            (Gi0/1)
         /                \
  [Switch-Amm]        [Switch-Dev]
    /      \          /    |    \
PC-Amm-1  PC-Amm-2  PC-Dev... Server
```

**Salva come:** `Cognome_Nome_TechCorp.pkt`

---

### STEP 3: Configurazione IP

Configura IP statico su ogni PC/Server secondo il piano di indirizzamento:
- IP Address
- Subnet Mask: 255.255.255.192
- Default Gateway

---

### STEP 4: Switch

**Switch-Amm:**
- Crea VLAN 10
- Trunk Gi0/1 → Router
- Access Fa0/1-2 → PC VLAN10

**Switch-Dev:**
- Crea VLAN 20, 30, 40
- Trunk Gi0/1 → Router
- Access Fa0/1-5 → PC/Server nelle rispettive VLAN

---

### STEP 5: Router

**Configura 4 subinterface:**
- Gi0/0.10 → VLAN10 (Amministrazione)
- Gi0/1.20 → VLAN20 (Sviluppo)
- Gi0/1.30 → VLAN30 (Marketing)
- Gi0/1.40 → VLAN40 (Server)

**Ogni subinterface:**
```cisco
interface GigabitEthernet0/X.XX
encapsulation dot1Q XX
ip address [gateway] 255.255.255.192
```

---

### STEP 6: Test

**Esegui e documenta:**
- Ping al gateway da ogni PC
- Ping intra-VLAN
- Ping inter-VLAN
- Ping al server da tutti
- Traceroute cross-VLAN

**Compila tabella con risultati e screenshot**

---

### STEP 7: Teoria

**📖 IMPORTANTE:** Consulta il file **`Domande_Teoria.md`** per:
- 20 domande teoriche dettagliate
- Suddivise in 6 sezioni
- Spazi per le risposte
- Griglia di valutazione

**Sezioni:**
- A. VLAN (4 domande)
- B. Subnetting (3 domande)
- C. Router-on-a-Stick (3 domande)
- D. IEEE 802.1Q (3 domande)
- E. Comandi e Troubleshooting (4 domande)
- F. Scenari Avanzati (3 domande)

**Consegna:** `Risposte_Teoria.pdf` (70 punti)

---

## 💡 Suggerimenti

✅ Completa STEP 1 con precisione (base per tutto)  
✅ Salva frequentemente (`write memory`)  
✅ Testa dopo ogni configurazione  
✅ Documenta con screenshot  
✅ Consulta guide in `/docs/`  
✅ Rispondi con cura alle domande teoriche  

**Buon lavoro! 🚀**
