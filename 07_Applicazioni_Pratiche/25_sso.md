# Single Sign-On (SSO)

## 1. Introduzione

Il **Single Sign-On (SSO)** è una tecnica di autenticazione che consente a un utente di accedere a più applicazioni o servizi informatici effettuando **una sola autenticazione**. Una volta autenticato, l’utente può spostarsi tra sistemi diversi senza dover reinserire le credenziali.

Il SSO nasce dall’esigenza di migliorare l’esperienza utente e, allo stesso tempo, aumentare il livello di sicurezza riducendo la proliferazione di password.

---

## 2. Problemi dell’autenticazione tradizionale

Nel modello classico, ogni applicazione gestisce autonomamente:

* utenti
* password
* sessioni

Questo approccio presenta diversi limiti:

* molteplicità di credenziali per lo stesso utente
* password deboli o riutilizzate
* difficoltà di gestione centralizzata
* maggiore superficie di attacco

Il SSO risolve questi problemi introducendo un **sistema di autenticazione centralizzato**.

---

## 3. Concetto di Single Sign-On

Il SSO si basa sulla separazione dei ruoli:

* **Identity Provider (IdP)**: autentica l’utente
* **Service Provider (SP)**: fornisce il servizio e si fida dell’IdP

L’utente comunica le proprie credenziali **solo all’IdP**, mai direttamente alle applicazioni.

---

## 4. Architettura generale del SSO

### Attori coinvolti

1. **Utente**
2. **Identity Provider (IdP)**
3. **Service Provider (SP)**

### Flusso logico

1. L’utente accede a un servizio
2. Il servizio reindirizza l’utente verso l’IdP
3. L’utente si autentica presso l’IdP
4. L’IdP rilascia una prova di autenticazione (token o asserzione)
5. Il servizio crea una sessione locale

---

## 5. Tipologie di Single Sign-On

### 5.1 SSO locale

* Tutte le applicazioni appartengono allo stesso dominio
* Tipico di ambienti aziendali o intranet

### 5.2 SSO federato

* Coinvolge domini e organizzazioni diverse
* Basato su standard condivisi
* Tipico dei servizi cloud e della Pubblica Amministrazione

---

## 6. Tecnologie per il SSO

### 6.1 SAML 2.0

Standard XML per l’autenticazione federata.

**Caratteristiche:**

* asserzioni firmate digitalmente
* scambio basato su redirect HTTP
* elevato livello di sicurezza

**Esempi di utilizzo:**

* SPID
* sistemi enterprise

---

### 6.2 OpenID Connect (OIDC)

Protocollo di autenticazione costruito sopra OAuth 2.0.

**Caratteristiche:**

* utilizza token JWT
* API-friendly
* ampiamente adottato

**Esempi di utilizzo:**

* Login con Google
* Login con Microsoft

---

### 6.3 Kerberos

Sistema di autenticazione basato su ticket.

**Caratteristiche:**

* nessuna trasmissione della password
* autenticazione trasparente

**Esempi di utilizzo:**

* Active Directory

---

## 7. SSO e OAuth 2.0

OAuth 2.0 **non è un sistema di autenticazione**, ma di autorizzazione. Tuttavia, combinato con OpenID Connect, consente di realizzare soluzioni di SSO moderne e sicure.

---

## 8. Vantaggi del Single Sign-On

* miglior esperienza utente
* riduzione del numero di password
* gestione centralizzata della sicurezza
* maggiore controllo degli accessi

---

## 9. Svantaggi e rischi

* single point of failure
* elevato impatto in caso di compromissione dell’IdP
* maggiore complessità architetturale

---

## 10. Esempi pratici

* **SPID**: SSO federato basato su SAML 2.0
* **Google Sign-In**: SSO basato su OpenID Connect
* **Active Directory**: SSO aziendale con Kerberos

---

## 11. Confronto tra le principali tecnologie

| Tecnologia | Standard     | Ambito          | Modernità |
| ---------- | ------------ | --------------- | --------- |
| SAML 2.0   | XML          | Enterprise / PA | Media     |
| OIDC       | JSON / JWT   | Web / Cloud     | Alta      |
| Kerberos   | Proprietario | Reti aziendali  | Media     |

---

## 12. Riepilogo

Il Single Sign-On è un elemento chiave delle moderne architetture di sicurezza. La scelta della tecnologia dipende dal contesto applicativo, dal livello di sicurezza richiesto e dall’ecosistema di riferimento.

---

## 13. Domande di autovalutazione

1. Cos’è il Single Sign-On?
2. Qual è il ruolo dell’Identity Provider?
3. Quali differenze esistono tra SAML e OpenID Connect?
4. Perché OAuth 2.0 da solo non realizza un SSO?

---

## 14. Esercizi proposti

1. Disegnare il diagramma di flusso di un login SSO.
2. Confrontare SSO tradizionale e federato.
3. Analizzare un caso reale di login con Google o SPID.
