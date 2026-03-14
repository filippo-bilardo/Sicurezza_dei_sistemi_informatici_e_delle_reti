# Inter-VLAN Routing

## Introduzione

L'**Inter-VLAN Routing** è il processo che permette la comunicazione tra dispositivi appartenenti a VLAN diverse. Poiché le VLAN sono domini di broadcast separati, è necessario un dispositivo di Layer 3 (router o switch Layer 3) per instradare il traffico tra di esse.

## Perché serve l'Inter-VLAN Routing?

### Isolamento VLAN
- Le VLAN creano segmenti di rete logicamente separati
- I dispositivi in VLAN diverse non possono comunicare direttamente
- Anche se sono sullo stesso switch fisico!

### Esempi pratici:
- Un PC in VLAN 10 (Amministrazione) deve accedere a un server in VLAN 20 (Server)
- Un utente in VLAN Ospiti deve raggiungere Internet tramite gateway in VLAN Management
- Condivisione risorse tra reparti in VLAN diverse

## Metodi di Inter-VLAN Routing

### 1. Router con Interfacce Multiple (Legacy)

**Architettura:**
```
[Switch] --VLAN10--> [Router Fa0/0] 192.168.10.1
         --VLAN20--> [Router Fa0/1] 192.168.20.1
```

**Caratteristiche:**
- Una porta fisica del router per ogni VLAN
- Semplice ma poco scalabile
- Spreco di porte router e switch
- Raramente usato oggi

### 2. Router-on-a-Stick (Più Comune)

**Architettura:**
```
[Switch] --TRUNK--> [Router Gi0/0]
                      ├─ .10 (VLAN 10)
                      └─ .20 (VLAN 20)
```

**Caratteristiche:**
- Una sola interfaccia fisica del router
- Subinterface logiche per ogni VLAN
- Porta trunk tra switch e router
- Tagging 802.1Q
- Soluzione economica e flessibile

**Vantaggi:**
✓ Richiede solo una porta fisica
✓ Facile aggiungere nuove VLAN
✓ Configurazione centralizzata

**Svantaggi:**
✗ Bottleneck sul singolo link
✗ Tutto il traffico passa per quella porta

### 3. Switch Layer 3 (Multilayer Switch)

**Architettura:**
```
[Switch L3] con routing integrato
  ├─ VLAN 10: SVI 192.168.10.1
  ├─ VLAN 20: SVI 192.168.20.1
  └─ VLAN 30: SVI 192.168.30.1
```

**Caratteristiche:**
- Switching e routing sullo stesso dispositivo
- SVI (Switch Virtual Interface) per ogni VLAN
- Routing hardware ad alte prestazioni
- Soluzione enterprise

## Router-on-a-Stick: Configurazione Dettagliata

### Configurazione Switch

```cisco
enable
configure terminal

! Creazione VLAN
vlan 10
name AMMINISTRAZIONE
vlan 20
name VENDITE
exit

! Configurazione porte access
interface FastEthernet0/1
switchport mode access
switchport access vlan 10

! Configurazione porta TRUNK verso router
interface GigabitEthernet0/1
switchport mode trunk
switchport trunk allowed vlan 10,20
no shutdown

end
write memory
```

### Configurazione Router (Router-on-a-Stick)

```cisco
enable
configure terminal

! Subinterface per VLAN 10
interface GigabitEthernet0/0.10
encapsulation dot1Q 10
ip address 192.168.10.1 255.255.255.0

! Subinterface per VLAN 20
interface GigabitEthernet0/0.20
encapsulation dot1Q 20
ip address 192.168.20.1 255.255.255.0

! Attivazione interfaccia fisica
interface GigabitEthernet0/0
no shutdown

end
write memory
```

## Funzionamento dell'Inter-VLAN Routing

**Esempio: PC1 (VLAN 10) → PC2 (VLAN 20)**

1. **PC1** invia pacchetto con destinazione gateway (192.168.10.1)
2. **Switch** aggiunge tag 802.1Q (VLAN 10) e inoltra su trunk
3. **Router** riceve su subinterface Gi0/0.10
4. **Router** effettua routing verso VLAN 20
5. **Router** inoltra su subinterface Gi0/0.20 con tag VLAN 20
6. **Switch** rimuove tag e inoltra su porta access VLAN 20
7. **PC2** riceve il pacchetto

## Comandi di Verifica

### Verifica Subinterface Router
```cisco
show ip interface brief
```

### Verifica Routing Table
```cisco
show ip route
```

### Verifica Trunk su Switch
```cisco
show interfaces trunk
```

### Test Connettività
```cisco
ping 192.168.10.10
ping 192.168.20.10
```

## Troubleshooting

### Problema: PC non comunica tra VLAN

**Verifiche:**
1. Controllare trunk: `show interfaces trunk`
2. Verificare subinterface: `show ip interface brief`
3. Controllare gateway sui PC
4. Verificare routing table: `show ip route`
5. Test ping dal router verso entrambe le VLAN

### Best Practices

1. **Usare VLAN native diversa da 1**
2. **Documentare le subinterface** con description
3. **Limitare VLAN su trunk** solo a quelle necessarie
4. **Monitorare utilizzo banda** sul link trunk
5. **Implementare ACL** per controllo traffico inter-VLAN

## Conclusioni

L'Inter-VLAN Routing è essenziale per permettere comunicazione controllata tra VLAN mantenendo i benefici della segmentazione di rete.
