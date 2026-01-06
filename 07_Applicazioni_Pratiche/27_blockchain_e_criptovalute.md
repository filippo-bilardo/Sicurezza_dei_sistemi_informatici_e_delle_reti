# Capitolo 27 - Blockchain e Criptovalute

> **Corso**: Sistemi e Reti 3  
> **Parte**: 7 - Applicazioni Pratiche  
> **Autore**: Prof. Filippo Bilardo

---

## Introduzione

**Blockchain**: Registro distribuito immutabile basato su crittografia.

**Applicazioni**:
- Bitcoin, Ethereum (criptovalute)
- Smart contracts
- Supply chain tracking
- Digital identity
- NFT (Non-Fungible Tokens)

### Componenti Crittografici

1. **Hash**: SHA-256, Keccak-256
2. **Firme digitali**: ECDSA, EdDSA
3. **Merkle Trees**: Verifica efficiente transazioni
4. **Proof-of-Work**: Consenso decentralizzato
5. **Key derivation**: Wallet HD (BIP32/39)

---

## Hash Chains

**Hash chain**: Lista concatenata tramite hash.

```
Block 0          Block 1          Block 2
┌─────────┐      ┌─────────┐      ┌─────────┐
│ Data: X │      │ Data: Y │      │ Data: Z │
│ Hash: A │──────│ Prev: A │──────│ Prev: B │
└─────────┘      │ Hash: B │      │ Hash: C │
                 └─────────┘      └─────────┘

✅ Immutabilità: Modifica Block 1 → cambia hash B
                 → invalida Block 2 e successivi!
```

### Implementazione

```python
import hashlib
import json
from datetime import datetime

class Block:
    """Blocco blockchain"""
    
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calcola hash SHA-256 del blocco"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def __repr__(self):
        return f"Block(#{self.index}, hash={self.hash[:8]}...)"

class Blockchain:
    """Blockchain semplice"""
    
    def __init__(self):
        self.chain = [self.create_genesis_block()]
    
    def create_genesis_block(self):
        """Blocco genesi (primo blocco)"""
        return Block(0, "Genesis Block", "0")
    
    def get_latest_block(self):
        """Ultimo blocco"""
        return self.chain[-1]
    
    def add_block(self, data):
        """Aggiungi blocco"""
        previous_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=previous_block.hash
        )
        self.chain.append(new_block)
        return new_block
    
    def is_valid(self):
        """Verifica integrità chain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verifica hash blocco
            if current.hash != current.calculate_hash():
                print(f"❌ Block {i}: hash corrotto")
                return False
            
            # Verifica link precedente
            if current.previous_hash != previous.hash:
                print(f"❌ Block {i}: link rotto")
                return False
        
        return True

# Test
print("=== Blockchain Demo ===\n")

bc = Blockchain()

# Aggiungi blocchi
bc.add_block("Alice → Bob: 10 BTC")
bc.add_block("Bob → Charlie: 5 BTC")
bc.add_block("Charlie → Alice: 3 BTC")

# Visualizza
for block in bc.chain:
    print(f"{block}")
    print(f"  Data: {block.data}")
    print(f"  Previous: {block.previous_hash[:8]}...")
    print()

# Verifica
print(f"✅ Chain valid: {bc.is_valid()}")

# Tentativo modifica
print("\n--- Tentativo modifica Block #1 ---")
bc.chain[1].data = "Alice → Bob: 1000 BTC"  # ❌ Hacking!
print(f"❌ Chain valid: {bc.is_valid()}")
```

---

## Merkle Trees

**Merkle Tree**: Albero binario di hash per verifica efficiente.

```
        Root Hash (R)
       /             \
    H(AB)           H(CD)
    /   \           /   \
  H(A) H(B)       H(C) H(D)
   |    |          |    |
  Tx A Tx B      Tx C  Tx D

✅ Verificare Tx C:
   - Serve solo: H(D), H(AB), Root
   - O(log n) invece di O(n)
```

### Implementazione

```python
class MerkleTree:
    """Merkle Tree per transazioni"""
    
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree()
    
    def hash(self, data):
        """Hash SHA-256"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def build_tree(self):
        """Costruisci albero bottom-up"""
        # Leaf nodes
        current_level = [self.hash(tx) for tx in self.transactions]
        
        # Se numero dispari, duplica ultimo
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])
        
        # Risali albero
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                
                # Hash concatenato
                combined = self.hash(left + right)
                next_level.append(combined)
            
            # Se livello dispari, duplica ultimo
            if len(next_level) % 2 == 1 and len(next_level) > 1:
                next_level.append(next_level[-1])
            
            current_level = next_level
        
        return current_level[0]
    
    def get_proof(self, tx_index):
        """Ottieni proof per transazione (Merkle proof)"""
        proof = []
        current_level = [self.hash(tx) for tx in self.transactions]
        
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])
        
        index = tx_index
        
        while len(current_level) > 1:
            # Sibling hash
            if index % 2 == 0:
                # Nodo sinistro → prendi destro
                sibling = current_level[index + 1]
                proof.append(('right', sibling))
            else:
                # Nodo destro → prendi sinistro
                sibling = current_level[index - 1]
                proof.append(('left', sibling))
            
            # Prossimo livello
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = self.hash(current_level[i] + current_level[i+1])
                next_level.append(combined)
            
            if len(next_level) % 2 == 1 and len(next_level) > 1:
                next_level.append(next_level[-1])
            
            current_level = next_level
            index //= 2
        
        return proof
    
    def verify_proof(self, tx, tx_index, proof):
        """Verifica Merkle proof"""
        # Hash transazione
        current_hash = self.hash(tx)
        
        # Risali albero con proof
        for direction, sibling_hash in proof:
            if direction == 'right':
                current_hash = self.hash(current_hash + sibling_hash)
            else:
                current_hash = self.hash(sibling_hash + current_hash)
        
        # Confronta con root
        return current_hash == self.root

# Test
print("\n=== Merkle Tree Demo ===\n")

transactions = [
    "Alice → Bob: 10 BTC",
    "Bob → Charlie: 5 BTC",
    "Charlie → Dave: 3 BTC",
    "Dave → Alice: 2 BTC"
]

tree = MerkleTree(transactions)
print(f"Merkle Root: {tree.root}\n")

# Verifica transazione #2
tx_index = 2
proof = tree.get_proof(tx_index)

print(f"Proof for Tx #{tx_index}:")
for i, (direction, hash_val) in enumerate(proof):
    print(f"  {i+1}. {direction}: {hash_val[:16]}...")

# Verifica
valid = tree.verify_proof(transactions[tx_index], tx_index, proof)
print(f"\n✅ Proof valid: {valid}")

# Verifica con transazione falsa
fake_tx = "Charlie → Dave: 1000 BTC"
valid_fake = tree.verify_proof(fake_tx, tx_index, proof)
print(f"❌ Fake tx valid: {valid_fake}")
```

---

## Proof of Work (Mining)

**PoW**: Trova nonce tale che `hash(block) < target`.

```python
class ProofOfWorkBlock(Block):
    """Blocco con Proof of Work"""
    
    def __init__(self, index, data, previous_hash, difficulty=4):
        self.index = index
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce = 0
        self.hash = self.mine_block()
    
    def calculate_hash(self):
        """Hash con nonce"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self):
        """Mining: trova nonce con leading zeros"""
        target = '0' * self.difficulty
        
        print(f"⛏️  Mining block #{self.index}...")
        start_time = datetime.now()
        
        while True:
            hash_result = self.calculate_hash()
            
            if hash_result[:self.difficulty] == target:
                elapsed = (datetime.now() - start_time).total_seconds()
                print(f"✅ Block mined! Nonce: {self.nonce}, Time: {elapsed:.2f}s")
                print(f"   Hash: {hash_result}\n")
                return hash_result
            
            self.nonce += 1

# Test Mining
print("\n=== Proof of Work Demo ===\n")

# Difficulty 4 = hash deve iniziare con 0000
genesis = Block(0, "Genesis", "0")
block1 = ProofOfWorkBlock(1, "Alice → Bob: 10 BTC", genesis.hash, difficulty=4)

# Prova difficoltà maggiore
block2 = ProofOfWorkBlock(2, "Bob → Charlie: 5 BTC", block1.hash, difficulty=5)

print(f"Difficulty 4: ~{2**16} hash calcolati")
print(f"Difficulty 5: ~{2**20} hash calcolati")
```

### Bitcoin Mining Simulation

```python
import time

def bitcoin_mining_simulation(difficulty=5, max_attempts=1000000):
    """Simula mining Bitcoin"""
    
    # Block header components
    version = 1
    prev_block = "0" * 64
    merkle_root = hashlib.sha256(b"transactions").hexdigest()
    timestamp = int(time.time())
    bits = difficulty
    
    print(f"=== Bitcoin Mining (Difficulty {difficulty}) ===\n")
    
    target = '0' * difficulty
    nonce = 0
    start = time.time()
    
    while nonce < max_attempts:
        # Block header
        header = f"{version}{prev_block}{merkle_root}{timestamp}{bits}{nonce}"
        
        # Double SHA-256 (Bitcoin uses)
        hash1 = hashlib.sha256(header.encode()).digest()
        hash2 = hashlib.sha256(hash1).hexdigest()
        
        if hash2[:difficulty] == target:
            elapsed = time.time() - start
            hashrate = nonce / elapsed
            
            print(f"✅ Block found!")
            print(f"   Nonce: {nonce}")
            print(f"   Hash: {hash2}")
            print(f"   Time: {elapsed:.2f}s")
            print(f"   Hashrate: {hashrate:.0f} H/s")
            
            # Bitcoin network hashrate: ~400 EH/s (400 * 10^18)
            btc_time = 2**difficulty / 400e18
            print(f"\n   Bitcoin network would solve in: {btc_time:.9f}s")
            
            return hash2, nonce
        
        nonce += 1
        
        if nonce % 100000 == 0:
            print(f"   Tried {nonce:,} hashes...")
    
    print(f"❌ No solution found in {max_attempts:,} attempts")
    return None, nonce

# Test
bitcoin_mining_simulation(difficulty=5)
```

---

## Wallet Crittografico

### Chiavi Private/Pubbliche

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import base58

class BitcoinWallet:
    """Wallet Bitcoin semplificato"""
    
    def __init__(self):
        # Genera chiave privata (secp256k1 - Bitcoin curve)
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
    
    def get_address(self):
        """Genera indirizzo Bitcoin"""
        # 1. Public key bytes
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # 2. SHA-256
        sha256 = hashlib.sha256(public_bytes).digest()
        
        # 3. RIPEMD-160
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        # 4. Add version byte (0x00 for mainnet)
        versioned = b'\x00' + ripemd160
        
        # 5. Double SHA-256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        
        # 6. Base58 encoding
        address = base58.b58encode(versioned + checksum)
        
        return address.decode()
    
    def sign_transaction(self, transaction):
        """Firma transazione"""
        signature = self.private_key.sign(
            transaction.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def verify_signature(self, transaction, signature):
        """Verifica firma"""
        try:
            self.public_key.verify(
                signature,
                transaction.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

# Test
print("\n=== Bitcoin Wallet Demo ===\n")

alice_wallet = BitcoinWallet()
bob_wallet = BitcoinWallet()

alice_address = alice_wallet.get_address()
bob_address = bob_wallet.get_address()

print(f"Alice address: {alice_address}")
print(f"Bob address: {bob_address}")

# Transazione
tx = f"Alice sends 10 BTC to {bob_address}"
signature = alice_wallet.sign_transaction(tx)

print(f"\nTransaction: {tx}")
print(f"Signature: {signature.hex()[:40]}...")

# Verifica
valid = alice_wallet.verify_signature(tx, signature)
print(f"✅ Signature valid: {valid}")
```

### HD Wallet (BIP32/39)

**Hierarchical Deterministic Wallet**: Da seed → infinite chiavi.

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets

class HDWallet:
    """HD Wallet (BIP32 simplified)"""
    
    def __init__(self, mnemonic=None):
        if mnemonic:
            self.mnemonic = mnemonic
        else:
            # Genera 12 parole (128 bit entropy)
            self.mnemonic = self.generate_mnemonic()
        
        self.seed = self.mnemonic_to_seed(self.mnemonic)
    
    def generate_mnemonic(self):
        """Genera mnemonic phrase (simplified)"""
        # BIP39 wordlist (qui simplified)
        wordlist = ['abandon', 'ability', 'able', 'about', 'above', 'absent']
        
        # 128 bit random
        entropy = secrets.token_bytes(16)
        
        # Converte in indici wordlist
        words = []
        for byte in entropy[:12]:
            words.append(wordlist[byte % len(wordlist)])
        
        return ' '.join(words)
    
    def mnemonic_to_seed(self, mnemonic, passphrase=''):
        """Deriva seed da mnemonic (PBKDF2)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=('mnemonic' + passphrase).encode(),
            iterations=2048
        )
        return kdf.derive(mnemonic.encode())
    
    def derive_child_key(self, index):
        """Deriva chiave figlia (simplified)"""
        # In BIP32 reale: usa HMAC-SHA512, hardened derivation, etc.
        child_seed = hashlib.sha256(self.seed + index.to_bytes(4, 'big')).digest()
        
        # Genera chiave privata da seed
        private_key = ec.derive_private_key(
            int.from_bytes(child_seed, 'big'),
            ec.SECP256K1()
        )
        
        return private_key

# Test
print("\n=== HD Wallet Demo ===\n")

hd_wallet = HDWallet()
print(f"Mnemonic: {hd_wallet.mnemonic}")
print(f"Seed: {hd_wallet.seed.hex()[:40]}...\n")

# Deriva multiple chiavi
print("Derived addresses:")
for i in range(5):
    child_key = hd_wallet.derive_child_key(i)
    wallet = BitcoinWallet()
    wallet.private_key = child_key
    wallet.public_key = child_key.public_key()
    
    address = wallet.get_address()
    print(f"  m/0/{i}: {address}")

print("\n✅ Da 1 seed → infinite chiavi!")
print("✅ Backup solo mnemonic → recupera tutto!")
```

---

## Smart Contracts

**Smart Contract**: Codice su blockchain, esecuzione automatica.

```python
class SmartContract:
    """Smart contract semplificato (Ethereum-like)"""
    
    def __init__(self, code, storage=None):
        self.code = code
        self.storage = storage or {}
        self.balance = 0
    
    def execute(self, function, *args, sender=None, value=0):
        """Esegui funzione contract"""
        # Simula ambiente EVM
        context = {
            'storage': self.storage,
            'sender': sender,
            'value': value,
            'balance': self.balance
        }
        
        # Esegui funzione
        if function in self.code:
            result = self.code[function](context, *args)
            
            # Update balance
            self.balance += value
            
            return result
        else:
            raise ValueError(f"Function {function} not found")

# Esempio: Simple Token Contract
def token_contract():
    """Crea token ERC-20 semplificato"""
    
    def init(ctx):
        """Costruttore"""
        ctx['storage']['total_supply'] = 1000000
        ctx['storage']['balances'] = {}
        ctx['storage']['owner'] = ctx['sender']
        ctx['storage']['balances'][ctx['sender']] = ctx['storage']['total_supply']
    
    def balance_of(ctx, address):
        """Ottieni balance"""
        return ctx['storage']['balances'].get(address, 0)
    
    def transfer(ctx, to, amount):
        """Trasferisci token"""
        sender = ctx['sender']
        
        # Check balance
        if ctx['storage']['balances'].get(sender, 0) < amount:
            raise ValueError("Insufficient balance")
        
        # Transfer
        ctx['storage']['balances'][sender] -= amount
        ctx['storage']['balances'][to] = ctx['storage']['balances'].get(to, 0) + amount
        
        return True
    
    return {
        'init': init,
        'balanceOf': balance_of,
        'transfer': transfer
    }

# Deploy & Test
print("\n=== Smart Contract Demo ===\n")

# Deploy contract
contract = SmartContract(token_contract())

# Init (deploy)
contract.execute('init', sender='0xALICE')
print(f"✅ Contract deployed")
print(f"   Total supply: {contract.storage['total_supply']}")

# Check balance
balance = contract.execute('balanceOf', '0xALICE')
print(f"   Alice balance: {balance}")

# Transfer
contract.execute('transfer', '0xBOB', 100, sender='0xALICE')
print(f"\n✅ Transfer executed: Alice → Bob (100 tokens)")

# Check balances
alice_bal = contract.execute('balanceOf', '0xALICE')
bob_bal = contract.execute('balanceOf', '0xBOB')

print(f"   Alice: {alice_bal}")
print(f"   Bob: {bob_bal}")
```

### Solidity Example (Ethereum)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleToken {
    string public name = "MyToken";
    string public symbol = "MTK";
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    constructor(uint256 _totalSupply) {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        
        emit Transfer(msg.sender, _to, _value);
        
        return true;
    }
}
```

---

## Sicurezza Blockchain

### Attacchi Comuni

#### 1. 51% Attack

Controllo >50% hashrate → può reverse transazioni.

```python
def simulate_51_attack():
    """Simula 51% attack"""
    
    # Network: 100 nodi, 51 attaccanti
    honest_nodes = 49
    attacker_nodes = 51
    
    # Probabilità attaccante trova blocco per primo
    p_attacker = attacker_nodes / (honest_nodes + attacker_nodes)
    
    print(f"\n=== 51% Attack Simulation ===")
    print(f"Attacker hashrate: {p_attacker*100:.0f}%")
    print(f"Probability attacker mines next block: {p_attacker:.2f}")
    print(f"✅ Attacker can reverse transactions and double-spend!")
```

#### 2. Double Spend

Spendi stessi BTC 2 volte.

```
1. Alice → Bob: 10 BTC (attendi conferma)
2. Alice → Charlie: stesso 10 BTC (su fork)
3. Fork con >51% → diventa main chain
4. Bob perde soldi!
```

**Mitigazione**: Attendi 6 conferme (1 ora).

#### 3. Smart Contract Vulnerabilities

```solidity
// ❌ VULNERABILE: Reentrancy Attack
contract Vulnerable {
    mapping(address => uint) balances;
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        
        // ❌ Chiama prima di aggiornare stato!
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] = 0;  // Troppo tardi!
    }
}

// ✅ SICURO: Checks-Effects-Interactions
contract Secure {
    mapping(address => uint) balances;
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        
        // ✅ Aggiorna stato PRIMA
        balances[msg.sender] = 0;
        
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}
```

---

## Best Practices

### ✅ Blockchain Development

| Aspetto | Best Practice |
|---------|---------------|
| **Keys** | HD wallet, hardware wallet |
| **Storage** | Cold storage per grandi somme |
| **Transactions** | Attendi 6+ conferme |
| **Smart Contracts** | Audit, formal verification |
| **Privacy** | Mixer, CoinJoin, Monero |
| **Gas** | Ottimizza contratti |

### ❌ Errori Comuni

```
❌ Riuso indirizzi (privacy)
❌ Private key su dispositivo online
❌ Smart contract senza audit
❌ Overflow/underflow integer
❌ Reentrancy attacks
❌ Front-running vulnerabilities
```

---

## Confronto Blockchain

| Blockchain | Consensus | TPS | Smart Contracts | Privacy |
|------------|-----------|-----|-----------------|---------|
| **Bitcoin** | PoW (SHA-256) | 7 | ❌ Limited | Pseudonimo |
| **Ethereum** | PoS (Eth2) | 30 | ✅ Full (Solidity) | Pseudonimo |
| **Solana** | PoH + PoS | 65,000 | ✅ (Rust) | Pseudonimo |
| **Monero** | PoW (RandomX) | ~1700 | ❌ | ✅ Privacy |
| **Cardano** | PoS (Ouroboros) | 250 | ✅ (Plutus) | Pseudonimo |

---

## 🔗 Collegamenti

- **Precedente**: [Capitolo 26 - Crittografia nelle Comunicazioni](26_crittografia_nelle_comunicazioni.md)
- **Indice**: [Torna all'indice](../00_INDICE.md)

---

## 📚 Riferimenti

- Bitcoin Whitepaper (Satoshi Nakamoto)
- Ethereum Yellow Paper
- BIP32: Hierarchical Deterministic Wallets
- BIP39: Mnemonic Phrases
- Solidity Documentation
- Mastering Bitcoin (Andreas Antonopoulos)

**Nota**: Blockchain combina crittografia, distributed systems e game theory. La crittografia garantisce immutabilità e ownership!
