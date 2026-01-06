# Capitolo 51 - Progetti Guidati

> **Corso**: Sistemi e Reti 3  
> **Parte**: 13 - Progetti e Casi di Studio  
> **Autore**: Prof. Filippo Bilardo

---

## Progetto 1: Secure Password Manager

### Obiettivo

Creare un password manager locale con cifratura AES-GCM.

### Specifiche

- Cifratura AES-256-GCM
- Master password con Argon2
- Storage JSON cifrato
- CLI interface

### Implementazione

```python
import json
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

class PasswordManager:
    """Password manager con cifratura"""
    
    def __init__(self, vault_file='vault.enc'):
        self.vault_file = vault_file
        self.vault = {}
        self.cipher = None
    
    def derive_key(self, master_password, salt):
        """Deriva chiave da master password"""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        return kdf.derive(master_password.encode())
    
    def unlock(self, master_password):
        """Sblocca vault"""
        if not os.path.exists(self.vault_file):
            # Nuovo vault
            salt = os.urandom(16)
            key = self.derive_key(master_password, salt)
            self.cipher = AESGCM(key)
            self.salt = salt
            self.save_vault()
            print("✅ Nuovo vault creato")
            return True
        
        # Carica vault esistente
        with open(self.vault_file, 'rb') as f:
            data = f.read()
        
        # Primi 16 byte = salt
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        # Deriva chiave
        key = self.derive_key(master_password, salt)
        self.cipher = AESGCM(key)
        self.salt = salt
        
        try:
            # Decifra vault
            plaintext = self.cipher.decrypt(nonce, ciphertext, b"")
            self.vault = json.loads(plaintext.decode())
            print("✅ Vault sbloccato")
            return True
        except:
            print("❌ Master password errata")
            return False
    
    def save_vault(self):
        """Salva vault cifrato"""
        if self.cipher is None:
            print("❌ Vault non sbloccato")
            return
        
        # Serializza vault
        plaintext = json.dumps(self.vault).encode()
        
        # Cifra
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, plaintext, b"")
        
        # Salva: salt + nonce + ciphertext
        with open(self.vault_file, 'wb') as f:
            f.write(self.salt + nonce + ciphertext)
        
        print("💾 Vault salvato")
    
    def add_password(self, service, username, password):
        """Aggiungi password"""
        self.vault[service] = {
            'username': username,
            'password': password
        }
        self.save_vault()
        print(f"✅ Aggiunta password per {service}")
    
    def get_password(self, service):
        """Recupera password"""
        if service in self.vault:
            entry = self.vault[service]
            print(f"\n📝 {service}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {entry['password']}")
            return entry
        else:
            print(f"❌ Servizio '{service}' non trovato")
            return None
    
    def list_services(self):
        """Lista servizi"""
        if not self.vault:
            print("📭 Vault vuoto")
            return
        
        print("\n📋 Servizi salvati:")
        for service in sorted(self.vault.keys()):
            print(f"   - {service}")
    
    def delete_password(self, service):
        """Elimina password"""
        if service in self.vault:
            del self.vault[service]
            self.save_vault()
            print(f"🗑️  Eliminata password per {service}")
        else:
            print(f"❌ Servizio '{service}' non trovato")

def main():
    """CLI Password Manager"""
    pm = PasswordManager()
    
    # Master password
    master = getpass.getpass("Master password: ")
    
    if not pm.unlock(master):
        return
    
    # Menu
    while True:
        print("\n" + "="*40)
        print("PASSWORD MANAGER")
        print("="*40)
        print("1. Aggiungi password")
        print("2. Recupera password")
        print("3. Lista servizi")
        print("4. Elimina password")
        print("5. Esci")
        
        choice = input("\nScelta: ").strip()
        
        if choice == '1':
            service = input("Servizio: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            pm.add_password(service, username, password)
        
        elif choice == '2':
            service = input("Servizio: ")
            pm.get_password(service)
        
        elif choice == '3':
            pm.list_services()
        
        elif choice == '4':
            service = input("Servizio: ")
            pm.delete_password(service)
        
        elif choice == '5':
            print("👋 Arrivederci!")
            break

if __name__ == '__main__':
    main()
```

### Test

```bash
python password_manager.py
# Master password: ********
# ✅ Nuovo vault creato
# 
# 1. Aggiungi password
# Servizio: Gmail
# Username: user@gmail.com
# Password: ********
# ✅ Aggiunta password per Gmail
```

---

## Progetto 2: Secure File Sharing

### Obiettivo

Sistema per condividere file cifrati tra utenti.

### Architettura

```
Alice                           Bob
  │                              │
  ├─ Genera chiave AES          │
  ├─ Cifra file                 │
  ├─ Cifra chiave AES con       │
  │  chiave pubblica Bob        │
  └─ Invia: file.enc + key.enc  │
                                 │
                                 ├─ Decifra chiave AES
                                 ├─ Decifra file
                                 └─ ✅ File decifrato
```

### Implementazione

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class SecureFileSharing:
    """Sistema condivisione file sicuri"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self, private_key_file, public_key_file):
        """Genera coppia chiavi RSA"""
        # Genera chiave privata
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # Salva chiave privata
        with open(private_key_file, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Salva chiave pubblica
        with open(public_key_file, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print(f"✅ Chiavi generate:")
        print(f"   Privata: {private_key_file}")
        print(f"   Pubblica: {public_key_file}")
    
    def load_private_key(self, key_file):
        """Carica chiave privata"""
        with open(key_file, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    
    def load_public_key(self, key_file):
        """Carica chiave pubblica"""
        with open(key_file, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def encrypt_file(self, input_file, output_file, recipient_public_key_file):
        """Cifra file per destinatario"""
        # Carica chiave pubblica destinatario
        with open(recipient_public_key_file, 'rb') as f:
            recipient_key = serialization.load_pem_public_key(f.read())
        
        # 1. Genera chiave AES random
        aes_key = AESGCM.generate_key(bit_length=256)
        cipher = AESGCM(aes_key)
        
        # 2. Cifra file con AES
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext, b"")
        
        # 3. Cifra chiave AES con RSA
        encrypted_key = recipient_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Salva: encrypted_key_size(4) + encrypted_key + nonce(12) + ciphertext
        with open(output_file, 'wb') as f:
            f.write(len(encrypted_key).to_bytes(4, 'big'))
            f.write(encrypted_key)
            f.write(nonce)
            f.write(ciphertext)
        
        print(f"✅ File cifrato: {output_file}")
        print(f"   Dimensione originale: {len(plaintext)} byte")
        print(f"   Dimensione cifrata: {os.path.getsize(output_file)} byte")
    
    def decrypt_file(self, input_file, output_file):
        """Decifra file"""
        if self.private_key is None:
            print("❌ Carica prima la chiave privata")
            return
        
        # Leggi file cifrato
        with open(input_file, 'rb') as f:
            # Leggi encrypted_key
            key_size = int.from_bytes(f.read(4), 'big')
            encrypted_key = f.read(key_size)
            
            # Leggi nonce e ciphertext
            nonce = f.read(12)
            ciphertext = f.read()
        
        # 1. Decifra chiave AES con RSA
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Decifra file con AES
        cipher = AESGCM(aes_key)
        plaintext = cipher.decrypt(nonce, ciphertext, b"")
        
        # 3. Salva file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"✅ File decifrato: {output_file}")

# Test
sfs = SecureFileSharing()

# Alice genera chiavi
sfs.generate_keypair('alice_private.pem', 'alice_public.pem')

# Bob genera chiavi
sfs_bob = SecureFileSharing()
sfs_bob.generate_keypair('bob_private.pem', 'bob_public.pem')

# Alice cifra file per Bob
sfs.encrypt_file('document.txt', 'document.enc', 'bob_public.pem')

# Bob decifra file
sfs_bob.load_private_key('bob_private.pem')
sfs_bob.decrypt_file('document.enc', 'document_decrypted.txt')
```

---

## Progetto 3: Blockchain Semplificata

### Obiettivo

Implementare blockchain base con proof-of-work.

### Implementazione

```python
import hashlib
import time
import json

class Block:
    """Blocco blockchain"""
    
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calcola hash blocco"""
        block_string = json.dumps({
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty):
        """Mining con proof-of-work"""
        target = '0' * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        print(f"⛏️  Blocco minato: {self.hash}")

class Blockchain:
    """Blockchain semplificata"""
    
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []
        self.mining_reward = 10
    
    def create_genesis_block(self):
        """Crea blocco genesi"""
        return Block(0, ["Genesis Block"], time.time(), "0")
    
    def get_latest_block(self):
        """Ottieni ultimo blocco"""
        return self.chain[-1]
    
    def mine_pending_transactions(self, miner_address):
        """Mina transazioni pending"""
        block = Block(
            len(self.chain),
            self.pending_transactions,
            time.time(),
            self.get_latest_block().hash
        )
        
        block.mine_block(self.difficulty)
        self.chain.append(block)
        
        # Reward per miner
        self.pending_transactions = [
            f"Reward: {self.mining_reward} → {miner_address}"
        ]
    
    def create_transaction(self, sender, recipient, amount):
        """Crea transazione"""
        transaction = f"{sender} → {recipient}: {amount}"
        self.pending_transactions.append(transaction)
    
    def is_chain_valid(self):
        """Verifica integrità blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verifica hash
            if current.hash != current.calculate_hash():
                print(f"❌ Blocco {i}: hash invalido")
                return False
            
            # Verifica link
            if current.previous_hash != previous.hash:
                print(f"❌ Blocco {i}: link invalido")
                return False
            
            # Verifica proof-of-work
            if not current.hash.startswith('0' * self.difficulty):
                print(f"❌ Blocco {i}: proof-of-work invalido")
                return False
        
        return True
    
    def print_chain(self):
        """Stampa blockchain"""
        print("\n" + "="*60)
        print("BLOCKCHAIN")
        print("="*60)
        
        for block in self.chain:
            print(f"\nBlocco #{block.index}")
            print(f"Timestamp: {time.ctime(block.timestamp)}")
            print(f"Transazioni: {block.transactions}")
            print(f"Previous Hash: {block.previous_hash[:16]}...")
            print(f"Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")

# Test
bc = Blockchain(difficulty=4)

# Transazioni
bc.create_transaction("Alice", "Bob", 50)
bc.create_transaction("Bob", "Charlie", 25)

# Mining
print("\n⛏️  Mining blocco 1...")
bc.mine_pending_transactions("Miner1")

# Altre transazioni
bc.create_transaction("Charlie", "Alice", 10)

print("\n⛏️  Mining blocco 2...")
bc.mine_pending_transactions("Miner1")

# Stampa blockchain
bc.print_chain()

# Verifica integrità
print(f"\n✅ Blockchain valida: {bc.is_chain_valid()}")

# Tentativo modifica (attacco)
print("\n🔴 Tentativo modifica blocco 1...")
bc.chain[1].transactions.append("FRAUD: Eve → Eve: 1000000")
bc.chain[1].hash = bc.chain[1].calculate_hash()

print(f"❌ Blockchain valida: {bc.is_chain_valid()}")
```

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 50](../PARTE_12_Laboratori/50_laboratorio_sicurezza_di_rete_e_malware.md)
- **Successivo**: [Capitolo 52 - Casi di Studio](52_casi_di_studio.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

**Nota**: Questi progetti sono didattici. In produzione usa librerie mature e testate.
