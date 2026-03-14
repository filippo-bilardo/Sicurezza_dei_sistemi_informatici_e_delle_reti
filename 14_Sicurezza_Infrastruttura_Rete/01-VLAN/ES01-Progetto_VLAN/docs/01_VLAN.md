# VLAN - Virtual Local Area Network

## Introduzione

Una **VLAN (Virtual Local Area Network)** è una rete locale virtuale che permette di segmentare logicamente una rete fisica in più reti logiche indipendenti, anche se i dispositivi sono collegati allo stesso switch fisico.

## Perché usare le VLAN?

### Vantaggi principali:

1. **Sicurezza**: Isolamento del traffico tra diversi reparti/gruppi
2. **Prestazioni**: Riduzione del dominio di broadcast
3. **Flessibilità**: Spostamento logico di utenti senza modifiche fisiche
4. **Organizzazione**: Raggruppamento logico indipendente dalla posizione fisica
5. **Gestione**: Semplificazione dell'amministrazione di rete

## Domini di Broadcast

Senza VLAN, tutti i dispositivi connessi a uno switch fanno parte dello stesso dominio di broadcast:
- Ogni broadcast raggiunge tutti i dispositivi
- Maggior traffico di rete
- Problemi di sicurezza e privacy

Con le VLAN:
- Ogni VLAN è un dominio di broadcast separato
- Il traffico broadcast rimane confinato nella VLAN
- Migliori prestazioni e sicurezza

## Tipi di VLAN

### 1. VLAN di Default (VLAN 1)
- Presente su tutti gli switch Cisco
- Non può essere eliminata
- Tutte le porte sono in VLAN 1 di default

### 2. VLAN Dati
- Utilizzate per il traffico utente
- Separate per reparto, funzione, o gruppo
- Esempi: VLAN 10 (Amministrazione), VLAN 20 (Vendite)

### 3. VLAN Nativa
- Utilizzata per il traffico untagged sui trunk
- Di default è VLAN 1
- Può essere modificata per sicurezza

### 4. VLAN Voce
- Dedicate al traffico VoIP
- QoS (Quality of Service) prioritario
- Esempio: VLAN 100 per telefoni IP

### 5. VLAN Management
- Utilizzata per gestire gli switch
- Esempio: VLAN 99 per accesso amministrativo

## Identificazione VLAN: Standard 802.1Q

Lo standard **IEEE 802.1Q** definisce il meccanismo di tagging delle VLAN:

### Frame Ethernet Standard (senza tag)
```
| Dest MAC | Source MAC | Type | Data | FCS |
```

### Frame 802.1Q (con tag VLAN)
```
| Dest MAC | Source MAC | [802.1Q TAG] | Type | Data | FCS |
```

**Tag 802.1Q (4 byte):**
- **TPID** (16 bit): Tag Protocol Identifier = 0x8100
- **PRI** (3 bit): Priority (QoS)
- **CFI** (1 bit): Canonical Format Indicator
- **VID** (12 bit): VLAN Identifier (0-4095)

### VLAN ID Range
- **0**: Riservato
- **1**: VLAN di default
- **2-1001**: VLAN normali (standard range)
- **1002-1005**: Riservate per Token Ring e FDDI
- **1006-4094**: VLAN estese (extended range)
- **4095**: Riservato

## Porte Switch

### Access Port
- Appartiene a una sola VLAN
- Traffico untagged (senza tag 802.1Q)
- Collegamento a dispositivi finali (PC, stampanti, server)

**Configurazione:**
```cisco
interface FastEthernet0/1
switchport mode access
switchport access vlan 10
```

### Trunk Port
- Trasporta traffico di più VLAN
- Traffico tagged con 802.1Q
- Collegamento tra switch o tra switch e router

**Configurazione:**
```cisco
interface GigabitEthernet0/1
switchport mode trunk
switchport trunk allowed vlan 10,20,30
switchport trunk native vlan 99
```

## Configurazione VLAN su Switch Cisco

### Creazione VLAN
```cisco
! Accesso alla modalità privilegiata
enable

! Modalità configurazione globale
configure terminal

! Creazione VLAN 10
vlan 10
name AMMINISTRAZIONE
exit

! Creazione VLAN 20
vlan 20
name VENDITE
exit
```

### Assegnazione Porte Access
```cisco
! Assegnazione porta a VLAN 10
interface FastEthernet0/5
switchport mode access
switchport access vlan 10
description PC Amministrazione
no shutdown
exit

! Assegnazione porta a VLAN 20
interface FastEthernet0/8
switchport mode access
switchport access vlan 20
description PC Vendite
no shutdown
exit
```

### Configurazione Porta Trunk
```cisco
interface GigabitEthernet0/1
switchport mode trunk
switchport trunk allowed vlan 10,20
switchport trunk native vlan 99
description Trunk verso Router
no shutdown
exit
```

### Salvataggio Configurazione
```cisco
end
write memory
! oppure
copy running-config startup-config
```

## Spiegazione Dettagliata dei Comandi

### Comandi di Configurazione Globale

#### `enable`
**Descrizione:** Accede alla modalità privilegiata (EXEC privilegiato)
```cisco
Switch> enable
Switch#
```
- Prompt cambia da `>` a `#`
- Richiede password se configurata
- Permette accesso ai comandi di configurazione

#### `configure terminal`
**Descrizione:** Entra in modalità configurazione globale
```cisco
Switch# configure terminal
Switch(config)#
```
- Abbreviazione: `conf t`
- Permette di modificare la configurazione dello switch
- Tutti i comandi di configurazione partono da qui

### Comandi Creazione e Gestione VLAN

#### `vlan [numero]`
**Descrizione:** Crea una VLAN o entra in modalità configurazione VLAN
```cisco
Switch(config)# vlan 10
Switch(config-vlan)#
```
- **Range valido:** 1-4094 (1-1001 per switch base)
- Se la VLAN non esiste, la crea automaticamente
- Se esiste, entra in modalità modifica
- **Prompt:** `(config-vlan)#`

#### `name [nome-vlan]`
**Descrizione:** Assegna un nome descrittivo alla VLAN
```cisco
Switch(config-vlan)# name AMMINISTRAZIONE
```
- Nome massimo: 32 caratteri
- Opzionale ma **fortemente raccomandato**
- Facilita identificazione e troubleshooting
- Senza nome, appare come "VLAN00XX"

### Comandi Configurazione Interfaccia

#### `interface [tipo][numero]`
**Descrizione:** Seleziona un'interfaccia da configurare
```cisco
Switch(config)# interface FastEthernet0/5
Switch(config-if)#
```
- **Tipi comuni:**
  - `FastEthernet` (Fa) - 100 Mbps
  - `GigabitEthernet` (Gi) - 1000 Mbps
- **Formato numero:** `modulo/porta` o `porta`
- **Prompt:** `(config-if)#`

**Range di interfacce:**
```cisco
Switch(config)# interface range FastEthernet0/5-10
Switch(config-if-range)#
```
- Configura più porte contemporaneamente
- Risparmia tempo per configurazioni identiche

#### `switchport mode access`
**Descrizione:** Configura la porta in modalità access (dispositivi finali)
```cisco
Switch(config-if)# switchport mode access
```
- **Funzione:** Porta appartiene a una sola VLAN
- Rimuove tag 802.1Q dai frame in uscita
- Aggiunge tag 802.1Q ai frame in entrata
- **Uso:** PC, stampanti, server, telefoni IP

#### `switchport access vlan [numero]`
**Descrizione:** Assegna la porta a una VLAN specifica
```cisco
Switch(config-if)# switchport access vlan 10
```
- **Pre-requisito:** La VLAN deve esistere (o viene creata automaticamente)
- Default: VLAN 1
- **Effetto immediato:** Il traffico viene isolato nella VLAN specificata

#### `switchport mode trunk`
**Descrizione:** Configura la porta in modalità trunk (collegamenti switch-switch o switch-router)
```cisco
Switch(config-if)# switchport mode trunk
```
- **Funzione:** Trasporta traffico di multiple VLAN
- Aggiunge tag 802.1Q a tutti i frame (eccetto native VLAN)
- **Uso:** Inter-switch link (ISL), collegamenti a router

#### `switchport trunk allowed vlan [lista]`
**Descrizione:** Specifica quali VLAN possono transitare sul trunk
```cisco
Switch(config-if)# switchport trunk allowed vlan 10,20,30
```
- **Formato lista:**
  - Singole: `10,20,30`
  - Range: `10-30`
  - Mix: `10,20-30,40`
- **Best practice:** Limitare solo alle VLAN necessarie (sicurezza)
- **Default:** Tutte le VLAN (1-4094)

**Altri comandi trunk:**
```cisco
! Aggiungere VLAN senza rimuovere esistenti
switchport trunk allowed vlan add 40,50

! Rimuovere VLAN specifiche
switchport trunk allowed vlan remove 30

! Permettere tutte le VLAN (sconsigliato)
switchport trunk allowed vlan all
```

#### `switchport trunk native vlan [numero]`
**Descrizione:** Configura la VLAN nativa (traffico untagged sul trunk)
```cisco
Switch(config-if)# switchport trunk native vlan 99
```
- **Funzione:** Traffico senza tag 802.1Q
- **Default:** VLAN 1
- **IMPORTANTE:** Deve essere uguale su entrambi i lati del trunk!
- **Sicurezza:** Cambiare da VLAN 1 a una VLAN dedicata inutilizzata

#### `description [testo]`
**Descrizione:** Aggiunge una descrizione all'interfaccia
```cisco
Switch(config-if)# description Collegamento PC Amministrazione
```
- Massimo: 240 caratteri
- **Visibile con:** `show interfaces status`, `show running-config`
- **Best practice:** Sempre documentare le connessioni!

#### `no shutdown`
**Descrizione:** Attiva l'interfaccia (amministrativamente up)
```cisco
Switch(config-if)# no shutdown
```
- **Abbreviazione:** `no shut`
- Le interfacce sono shutdown di default (alcuni switch)
- **Output:** `%LINK-5-CHANGED: Interface Fa0/5, changed state to up`
- **Contrario:** `shutdown` disabilita la porta

#### `exit`
**Descrizione:** Esce dal livello corrente di configurazione
```cisco
Switch(config-if)# exit
Switch(config)#
```
- Torna al livello precedente
- Da `(config-if)#` → `(config)#`
- Da `(config)#` → `#`

#### `end`
**Descrizione:** Esce completamente dalla configurazione
```cisco
Switch(config-if)# end
Switch#
```
- Scorciatoia: `Ctrl+Z`
- Torna direttamente a modalità EXEC privilegiato
- Da qualsiasi livello di configurazione

### Comandi Salvataggio Configurazione

#### `write memory`
**Descrizione:** Salva la configurazione corrente (running-config) nella memoria permanente (startup-config)
```cisco
Switch# write memory
Building configuration...
[OK]
```
- **Abbreviazione:** `wr` o `wr mem`
- **Equivalente:** `copy running-config startup-config`
- **CRITICO:** Senza questo comando, le modifiche vanno perse al riavvio!

#### `copy running-config startup-config`
**Descrizione:** Copia la configurazione corrente nella configurazione di avvio
```cisco
Switch# copy running-config startup-config
Destination filename [startup-config]? [Enter]
Building configuration...
[OK]
```
- **Abbreviazione:** `copy run start`
- Più verboso di `write memory` ma più esplicito
- Richiede conferma (premere Enter)

## Comandi di Verifica

### `show vlan brief`
**Descrizione:** Mostra un riepilogo delle VLAN configurate
```cisco
Switch# show vlan brief
```

**Output:**
```
VLAN Name                             Status    Ports
---- -------------------------------- --------- ------------------------
1    default                          active    Fa0/1, Fa0/2
10   AMMINISTRAZIONE                  active    Fa0/5, Fa0/6
20   VENDITE                          active    Fa0/8, Fa0/9
```

**Colonne:**
- **VLAN**: Numero VLAN
- **Name**: Nome assegnato
- **Status**: `active` (usata) o `act/unsup` (non supportata)
- **Ports**: Porte assegnate a quella VLAN

**Uso:** Prima verifica dopo configurazione VLAN

### `show vlan id [numero]`
**Descrizione:** Mostra dettagli completi di una VLAN specifica
```cisco
Switch# show vlan id 10
```

**Output:**
```
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
10   AMMINISTRAZIONE                  active    Fa0/5, Fa0/6

VLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2
---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------
10   enet  100010     1500  -      -      -        -    -        0      0

Remote SPAN VLAN
----------------
Disabled
```

**Informazioni aggiuntive:**
- **Type**: `enet` (Ethernet), `fddi`, `token-ring`
- **SAID**: Security Association ID
- **MTU**: Maximum Transmission Unit (1500 byte default)

### `show interfaces trunk`
**Descrizione:** Visualizza informazioni sulle porte trunk
```cisco
Switch# show interfaces trunk
```

**Output:**
```
Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/1       10,20

Port        Vlans allowed and active in management domain
Gi0/1       10,20

Port        Vlans in spanning tree forwarding state and not pruned
Gi0/1       10,20
```

**Sezioni:**
1. **Informazioni generali:**
   - Mode: `on`, `auto`, `desirable`
   - Encapsulation: `802.1q` (o ISL su vecchi switch)
   - Native VLAN

2. **VLAN allowed:** VLAN configurate con `allowed vlan`
3. **VLAN active:** VLAN che esistono E sono permesse
4. **VLAN forwarding:** VLAN in forwarding state (STP)

**Troubleshooting:** Verifica che VLAN siano allowed e active

### `show running-config interface [interfaccia]`
**Descrizione:** Mostra la configurazione corrente di un'interfaccia specifica
```cisco
Switch# show running-config interface FastEthernet0/5
```

**Output:**
```
Building configuration...

Current configuration : 120 bytes
!
interface FastEthernet0/5
 description PC Amministrazione
 switchport access vlan 10
 switchport mode access
end
```

**Uso:**
- Verifica configurazione dettagliata
- Controllo descrizioni
- Debugging problemi di configurazione

**Abbreviazione:** `show run int Fa0/5`

### `show interfaces status`
**Descrizione:** Mostra lo stato di tutte le interfacce
```cisco
Switch# show interfaces status
```

**Output:**
```
Port      Name               Status       Vlan       Duplex  Speed Type
Fa0/1                        notconnect   1          auto    auto  10/100BaseTX
Fa0/5     PC Amministrazione connected    10         a-full  a-100 10/100BaseTX
Fa0/8     PC Vendite         connected    20         a-full  a-100 10/100BaseTX
Gi0/1     Trunk verso Router connected    trunk      a-full  a-1000 10/100/1000BaseTX
```

**Colonne:**
- **Port**: Nome interfaccia
- **Name**: Descrizione (`description`)
- **Status**: `connected`, `notconnect`, `disabled`, `err-disabled`
- **Vlan**: VLAN assegnata (o "trunk")
- **Duplex**: `full`, `half`, `auto` (a-full = auto-negotiated full)
- **Speed**: 10, 100, 1000 Mbps
- **Type**: Tipo di porta fisica

**Uso:** Visione d'insieme rapida dello switch

### `show interfaces [interfaccia] switchport`
**Descrizione:** Mostra informazioni dettagliate switchport
```cisco
Switch# show interfaces FastEthernet0/5 switchport
```

**Output:**
```
Name: Fa0/5
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 10 (AMMINISTRAZIONE)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
```

**Informazioni chiave:**
- **Administrative Mode**: Configurato (`access` o `trunk`)
- **Operational Mode**: Modalità effettiva
- **Access Mode VLAN**: VLAN assegnata
- **Negotiation**: DTP (Dynamic Trunking Protocol) abilitato/disabilitato

### `show mac address-table`
**Descrizione:** Mostra la tabella MAC dello switch
```cisco
Switch# show mac address-table
```

**Output:**
```
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0001.C7A1.2B45    DYNAMIC     Fa0/5
  20    0002.1634.AB21    DYNAMIC     Fa0/8
  All    0100.0CCC.CCCC    STATIC      CPU
```

**Filtrare per VLAN:**
```cisco
Switch# show mac address-table vlan 10
```

**Filtrare per interfaccia:**
```cisco
Switch# show mac address-table interface Fa0/5
```

**Uso:** Verificare apprendimento indirizzi MAC e associazione VLAN-porta

### Comandi di Troubleshooting Avanzati

#### `show vtp status`
**Descrizione:** Mostra stato VTP (VLAN Trunking Protocol)
```cisco
Switch# show vtp status
VTP Version                     : 2
Configuration Revision          : 5
Maximum VLANs supported locally : 255
Number of existing VLANs        : 7
VTP Operating Mode              : Server
VTP Domain Name                 : AZIENDA
```

**Mode VTP:**
- **Server**: Può creare/modificare/eliminare VLAN
- **Client**: Solo riceve VLAN da server
- **Transparent**: Non partecipa a VTP

#### `show spanning-tree`
**Descrizione:** Mostra informazioni Spanning Tree Protocol
```cisco
Switch# show spanning-tree brief
```

**Uso:** Verificare porte in forwarding/blocking per VLAN

#### `debug sw-vlan vtp events`
**Descrizione:** Debug eventi VTP in tempo reale
```cisco
Switch# debug sw-vlan vtp events
```
⚠️ **ATTENZIONE:** Usare con cautela in produzione!

**Disabilitare:**
```cisco
Switch# no debug all
Switch# undebug all
```

## Best Practices

1. **Non usare VLAN 1**: Creare VLAN personalizzate per sicurezza
2. **VLAN Native separata**: Usare una VLAN diversa da 1 per il trunk native
3. **Documentazione**: Mantenere documentazione aggiornata delle VLAN
4. **Naming convention**: Usare nomi descrittivi per le VLAN
5. **Limitare VLAN sui trunk**: Specificare solo le VLAN necessarie
6. **VLAN Management dedicata**: Separare il traffico di gestione
7. **Disabilitare porte inutilizzate**: Mettere in VLAN isolata o shutdown

## Troubleshooting

### Problemi comuni:

**PC non comunica con gateway:**
- Verificare che PC e gateway siano nella stessa VLAN
- Controllare assegnazione porta: `show vlan brief`
- Verificare stato porta: `show interfaces status`

**Traffico non passa tra switch:**
- Verificare configurazione trunk: `show interfaces trunk`
- Controllare VLAN allowed sul trunk
- Verificare native VLAN su entrambi gli switch

**VLAN non visibile:**
- Verificare creazione VLAN: `show vlan brief`
- Controllare VTP mode (se usato)
- Verificare range VLAN (normale vs esteso)

## Conclusioni

Le VLAN sono uno strumento fondamentale per:
- Migliorare la sicurezza della rete
- Ottimizzare le prestazioni
- Semplificare la gestione
- Aumentare la flessibilità dell'infrastruttura

La corretta implementazione delle VLAN richiede pianificazione e documentazione accurata, ma porta benefici significativi in termini di sicurezza, prestazioni e manutenibilità della rete.
