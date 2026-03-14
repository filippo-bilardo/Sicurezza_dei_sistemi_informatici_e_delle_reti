# Piano di Indirizzamento Completo - VLAN2

## Schema Subnetting

Rete base: **192.168.10.0/24**  
Suddivisione: **5 sottoreti /27** (255.255.255.224)  
Host per subnet: **30 utilizzabili**

---

## Tabella Riepilogativa Completa

| Dispositivo | Interfaccia | IP | Mask | Gateway | VLAN | Subnet |
|-------------|-------------|-----|------|---------|------|--------|
| **Router0** | Serial0/0/0 | 192.168.10.129 | /27 | - | - | subnet5 |
| **Router0** | Gi0/0.10 | 192.168.10.1 | /27 | - | 10 | subnet1 |
| **Router0** | Gi0/0.20 | 192.168.10.33 | /27 | - | 20 | subnet2 |
| **Router1** | Serial0/0/0 | 192.168.10.130 | /27 | - | - | subnet5 |
| **Router1** | Gi0/0.10 | 192.168.10.65 | /27 | - | 10 | subnet3 |
| **Router1** | Gi0/0.20 | 192.168.10.97 | /27 | - | 20 | subnet4 |
| **PC0** | Fa0 | 192.168.10.10 | /27 | 192.168.10.1 | 10 | subnet1 |
| **PC1** | Fa0 | 192.168.10.42 | /27 | 192.168.10.33 | 20 | subnet2 |
| **PC2** | Fa0 | 192.168.10.74 | /27 | 192.168.10.65 | 10 | subnet3 |
| **PC3** | Fa0 | 192.168.10.106 | /27 | 192.168.10.97 | 20 | subnet4 |
| **Server0** | Fa0 | 192.168.10.75 | /27 | 192.168.10.65 | 10 | subnet3 |

---

## Dettaglio Subnet

### Subnet 1 - VLAN 10 (192.168.10.0/27)
- Network: 192.168.10.0
- Range: 192.168.10.1 - 192.168.10.30
- Broadcast: 192.168.10.31
- Gateway: 192.168.10.1 (Router0)
- Dispositivi: PC0

### Subnet 2 - VLAN 20 (192.168.10.32/27)
- Network: 192.168.10.32
- Range: 192.168.10.33 - 192.168.10.62
- Broadcast: 192.168.10.63
- Gateway: 192.168.10.33 (Router0)
- Dispositivi: PC1

### Subnet 3 - VLAN 10 (192.168.10.64/27)
- Network: 192.168.10.64
- Range: 192.168.10.65 - 192.168.10.94
- Broadcast: 192.168.10.95
- Gateway: 192.168.10.65 (Router1)
- Dispositivi: PC2, Server0

### Subnet 4 - VLAN 20 (192.168.10.96/27)
- Network: 192.168.10.96
- Range: 192.168.10.97 - 192.168.10.126
- Broadcast: 192.168.10.127
- Gateway: 192.168.10.97 (Router1)
- Dispositivi: PC3

### Subnet 5 - Backbone (192.168.10.128/27)
- Network: 192.168.10.128
- Range: 192.168.10.129 - 192.168.10.158
- Broadcast: 192.168.10.159
- Dispositivi: Router0, Router1
