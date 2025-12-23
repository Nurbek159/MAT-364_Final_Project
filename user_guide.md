# CryptoVault User Guide

A practical guide to using CryptoVault's cryptographic modules and features.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Crypto Module](#core-crypto-module)
3. [Authentication Module](#authentication-module)
4. [Secure Messaging Module](#secure-messaging-module)
5. [File Encryption Module](#file-encryption-module)
6. [Blockchain Module](#blockchain-module)
7. [Event Logging Module](#event-logging-module)
8. [CLI Examples](#cli-examples)

---

## Getting Started

### Prerequisites

```powershell
# Navigate to project directory
cd MAT-364_Final_Project

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Navigate to cryptovault
cd cryptovault
```

### Interactive Python Shell

```powershell
# Start Python interactive shell
python
```

---

## Core Crypto Module

### SHA-256 Hashing

```python
from src.core_crypto.sha256 import sha256, sha256_hex

# Hash bytes and get raw bytes result
hash_bytes = sha256(b"Hello, World!")
print(f"Hash (bytes): {hash_bytes.hex()}")

# Hash and get hex string directly
hash_hex = sha256_hex(b"Hello, World!")
print(f"Hash (hex): {hash_hex}")

# Hash a file
with open("document.txt", "rb") as f:
    file_hash = sha256_hex(f.read())
print(f"File hash: {file_hash}")
```

**Output:**
```
Hash (hex): dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

### Merkle Tree

```python
from src.core_crypto.merkle import MerkleTree

# Create a Merkle tree from transaction data
transactions = [
    b"Alice sends 10 to Bob",
    b"Bob sends 5 to Charlie",
    b"Charlie sends 3 to Dave",
    b"Dave sends 1 to Eve"
]

tree = MerkleTree(transactions)

# Get the Merkle root
print(f"Merkle Root: {tree.root_hex}")

# Generate a proof for transaction at index 1
proof = tree.get_proof(1)
print(f"Proof for tx[1]: {proof}")

# Verify the proof
is_valid = tree.verify_proof(
    leaf=transactions[1],
    index=1,
    proof=proof,
    root=tree.root
)
print(f"Proof valid: {is_valid}")
```

### AES Key Schedule

```python
from src.core_crypto.aes_key_schedule import aes256_key_expansion
import os

# Generate a random 256-bit key
key = os.urandom(32)

# Expand key to round keys
round_keys = aes256_key_expansion(key)

print(f"Number of round keys: {len(round_keys)}")  # 15 for AES-256
print(f"First round key: {round_keys[0].hex()}")
```

### LFSR Stream Cipher

```python
from src.core_crypto.lfsr_cipher import LFSR, LFSRCipher

# Create LFSR with maximal-length taps
lfsr = LFSR.from_size(seed=0xACE1, size=16)

# Generate keystream bytes
keystream = lfsr.generate_bytes(10)
print(f"Keystream: {keystream.hex()}")

# Encrypt/decrypt with LFSR cipher
cipher = LFSRCipher(seed=12345, size=32)
plaintext = b"Secret message!"
ciphertext = cipher.encrypt(plaintext)

# Reset and decrypt
cipher.reset()
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted.decode()}")
```

### RSA Math

```python
from src.core_crypto.rsa_math import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    rsa_sign, rsa_verify, is_probably_prime_miller_rabin
)

# Check if a number is prime
print(f"Is 104729 prime? {is_probably_prime_miller_rabin(104729)}")

# Generate RSA keypair (small for demo, use 2048+ in production)
public_key, private_key = generate_rsa_keypair(bits=512)
print(f"Public key (e, n): e={public_key[0]}, n has {public_key[1].bit_length()} bits")

# Encrypt a small number
message = 42
ciphertext = rsa_encrypt(message, public_key)
decrypted = rsa_decrypt(ciphertext, private_key)
print(f"Decrypted: {decrypted}")

# Sign and verify
signature = rsa_sign(message, private_key)
is_valid = rsa_verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")
```

---

## Authentication Module

### Password Hashing

```python
from src.auth.registration import PasswordHasher_, validate_password_strength

# Validate password strength
result = validate_password_strength("MySecureP@ss123!")
print(f"Password valid: {result['valid']}")
print(f"Password score: {result['score']}/100")
if not result['valid']:
    print(f"Errors: {result['errors']}")

# Hash a password
hasher = PasswordHasher_()
password_hash = hasher.hash_password("MySecureP@ss123!")
print(f"Hash: {password_hash[:50]}...")

# Verify password
is_correct = hasher.verify_password("MySecureP@ss123!", password_hash)
print(f"Password correct: {is_correct}")

is_wrong = hasher.verify_password("WrongPassword!", password_hash)
print(f"Wrong password accepted: {is_wrong}")
```

### User Registration

```python
from src.auth.registration import UserRegistration

# Create registration handler
registration = UserRegistration()

# Register a new user
result = registration.register_user(
    username="alice",
    password="SecureP@ss123!",
    email="alice@example.com"
)
print(f"Registration success: {result['success']}")
print(f"User ID: {result.get('user_id', 'N/A')}")

# Try duplicate registration
result2 = registration.register_user("alice", "AnotherP@ss123!")
print(f"Duplicate allowed: {result2['success']}")  # False
print(f"Message: {result2['message']}")
```

### Login with Rate Limiting

```python
from src.auth.registration import UserRegistration
from src.auth.login import LoginManager, RateLimiter

# Setup
registration = UserRegistration()
registration.register_user("bob", "SecureP@ss123!")

# Create login manager with user store
login_mgr = LoginManager(user_store=registration._users)

# Successful login
result = login_mgr.login("bob", "SecureP@ss123!")
print(f"Login success: {result['success']}")
if result['success']:
    print(f"Session ID: {result['session_id']}")
    print(f"Token: {result['token'][:20]}...")

# Failed login
result = login_mgr.login("bob", "WrongPassword!")
print(f"Wrong password accepted: {result['success']}")

# Rate limiting demo
rate_limiter = RateLimiter(max_attempts=3, lockout_duration=60)
for i in range(4):
    rate_limiter.record_attempt("attacker_ip", success=False)
    locked, remaining = rate_limiter.is_locked_out("attacker_ip")
    print(f"Attempt {i+1}: Locked={locked}, Remaining={remaining}s")
```

### TOTP Two-Factor Authentication

```python
from src.auth.totp import TOTPGenerator, TOTPManager, generate_secret

# Generate TOTP for a user
totp = TOTPGenerator(
    issuer="CryptoVault",
    account_name="alice@example.com"
)

# Get the secret (share with authenticator app)
print(f"Secret (Base32): {totp.secret_base32}")

# Get provisioning URI for QR code
uri = totp.get_provisioning_uri()
print(f"Provisioning URI: {uri}")

# Generate current code
code = totp.generate()
print(f"Current TOTP code: {code}")

# Verify code
is_valid = totp.verify(code)
print(f"Code valid: {is_valid}")

# Wrong code
is_valid = totp.verify("000000")
print(f"Wrong code accepted: {is_valid}")

# Using TOTP Manager for multiple users
manager = TOTPManager(issuer="CryptoVault")

# Create secret for user enrollment
secret_b32, uri = manager.create_secret("user123", "user@example.com")
print(f"Enrollment URI: {uri}")

# User enters code from authenticator app
# success, secret = manager.confirm_enrollment("user123", "123456")
```

---

## Secure Messaging Module

### Key Exchange and Encryption

```python
from src.messaging.secure_channel import (
    KeyPair, SecureChannel, ECDHKeyExchange, 
    AESGCMCipher, ECDSASigner, hkdf_derive_key
)

# === Low-Level: ECDH Key Exchange ===
alice_ecdh = ECDHKeyExchange()
bob_ecdh = ECDHKeyExchange()

# Exchange public keys and derive shared secret
alice_secret = alice_ecdh.derive_shared_secret_from_bytes(bob_ecdh.public_bytes)
bob_secret = bob_ecdh.derive_shared_secret_from_bytes(alice_ecdh.public_bytes)
print(f"Secrets match: {alice_secret == bob_secret}")

# Derive encryption key using HKDF
session_key = hkdf_derive_key(alice_secret, info=b"chat_session")
print(f"Session key: {session_key.hex()}")

# === Low-Level: AES-GCM Encryption ===
cipher = AESGCMCipher(session_key)
nonce, ciphertext, tag = cipher.encrypt(b"Hello, Bob!")
print(f"Ciphertext: {ciphertext.hex()}")

plaintext = cipher.decrypt(nonce, ciphertext, tag)
print(f"Decrypted: {plaintext.decode()}")

# === Low-Level: ECDSA Signatures ===
alice_keys = KeyPair.generate()
signer = ECDSASigner(alice_keys)

message = b"Important message"
signature = signer.sign(message)
print(f"Signature: {signature.hex()[:40]}...")

is_valid = signer.verify(message, signature, alice_keys.public_key)
print(f"Signature valid: {is_valid}")
```

### High-Level Secure Channel

```python
from src.messaging.secure_channel import SecureChannel, KeyPair

# Create identities for Alice and Bob
alice_keys = KeyPair.generate()
bob_keys = KeyPair.generate()

# Create secure channels
alice_channel = SecureChannel(alice_keys)
bob_channel = SecureChannel(bob_keys)

# Establish shared session
alice_channel.establish(bob_channel.public_key)
bob_channel.establish(alice_channel.public_key)

# Alice sends encrypted message to Bob
message = b"Hey Bob, this is encrypted!"
encrypted = alice_channel.encrypt_message(message)
print(f"Encrypted message created")

# Bob decrypts message from Alice
decrypted = bob_channel.decrypt_message(encrypted, alice_channel.public_key)
print(f"Bob received: {decrypted.decode()}")

# Bob replies to Alice
reply = b"Got it, Alice!"
encrypted_reply = bob_channel.encrypt_message(reply)
decrypted_reply = alice_channel.decrypt_message(encrypted_reply, bob_channel.public_key)
print(f"Alice received: {decrypted_reply.decode()}")
```

---

## File Encryption Module

### Encrypt and Decrypt Files

```python
from src.files.file_crypto import encrypt_file, decrypt_file, FileEncryptor
import os
import tempfile

# Create a test file
with tempfile.TemporaryDirectory() as tmpdir:
    # Create original file
    original_path = os.path.join(tmpdir, "secret.txt")
    encrypted_path = os.path.join(tmpdir, "secret.enc")
    decrypted_path = os.path.join(tmpdir, "secret_decrypted.txt")
    
    with open(original_path, "w") as f:
        f.write("This is my secret document!\n" * 100)
    
    # Encrypt file
    encrypt_file(original_path, encrypted_path, "MyStrongPassword123!")
    print(f"File encrypted: {encrypted_path}")
    
    # Check file sizes
    orig_size = os.path.getsize(original_path)
    enc_size = os.path.getsize(encrypted_path)
    print(f"Original: {orig_size} bytes, Encrypted: {enc_size} bytes")
    
    # Decrypt file
    decrypt_file(encrypted_path, decrypted_path, "MyStrongPassword123!")
    print(f"File decrypted: {decrypted_path}")
    
    # Verify content
    with open(decrypted_path, "r") as f:
        content = f.read()
    print(f"Content matches: {content.startswith('This is my secret')}")
```

### Using FileEncryptor Class

```python
from src.files.file_crypto import FileEncryptor
import tempfile
import os

with tempfile.TemporaryDirectory() as tmpdir:
    # Create encryptor with password
    encryptor = FileEncryptor("MySecurePassword123!")
    
    # Create test file
    input_path = os.path.join(tmpdir, "data.bin")
    with open(input_path, "wb") as f:
        f.write(os.urandom(1024 * 100))  # 100 KB random data
    
    # Encrypt
    enc_path = os.path.join(tmpdir, "data.enc")
    encryptor.encrypt_file(input_path, enc_path)
    
    # Get file info
    info = encryptor.get_file_info(enc_path)
    print(f"Encrypted file info:")
    print(f"  Original size: {info.get('original_size', 'N/A')}")
    print(f"  Encrypted size: {info.get('encrypted_size', 'N/A')}")
    
    # Decrypt
    dec_path = os.path.join(tmpdir, "data_dec.bin")
    encryptor.decrypt_file(enc_path, dec_path)
    
    # Verify
    with open(input_path, "rb") as f1, open(dec_path, "rb") as f2:
        print(f"Files match: {f1.read() == f2.read()}")
```

### Detecting Tampering

```python
from src.files.file_crypto import encrypt_file, decrypt_file
import tempfile
import os

with tempfile.TemporaryDirectory() as tmpdir:
    original = os.path.join(tmpdir, "original.txt")
    encrypted = os.path.join(tmpdir, "encrypted.enc")
    
    # Create and encrypt
    with open(original, "w") as f:
        f.write("Sensitive data")
    encrypt_file(original, encrypted, "password123")
    
    # Tamper with encrypted file
    with open(encrypted, "r+b") as f:
        f.seek(100)  # Seek to middle
        f.write(b"TAMPERED")
    
    # Try to decrypt
    try:
        decrypt_file(encrypted, os.path.join(tmpdir, "out.txt"), "password123")
        print("Decryption succeeded (should not happen)")
    except Exception as e:
        print(f"Tampering detected: {type(e).__name__}")
```

---

## Blockchain Module

### Creating a Blockchain

```python
from src.blockchain.ledger import Blockchain, Block

# Create blockchain with difficulty 4 (4 leading zero bits)
chain = Blockchain(difficulty=4)

# Add transactions
chain.add_transaction("Alice sends 50 coins to Bob")
chain.add_transaction("Bob sends 25 coins to Charlie")
chain.add_transaction("Charlie sends 10 coins to Dave")

# Mine pending transactions
print("Mining block...")
chain.mine_pending_transactions()
print(f"Block mined! Chain length: {chain.length}")

# Add more transactions and mine
chain.add_transaction("Dave sends 5 coins to Eve")
chain.mine_pending_transactions()
print(f"Chain length: {chain.length}")

# Validate chain
is_valid = chain.is_valid()
print(f"Chain valid: {is_valid}")
```

### Inspecting Blocks

```python
from src.blockchain.ledger import Blockchain

chain = Blockchain(difficulty=4)
chain.add_transaction("Transaction 1")
chain.add_transaction("Transaction 2")
chain.mine_pending_transactions()

# Get block by index
block = chain.get_block(1)  # Block after genesis
print(f"Block #{block.index}")
print(f"  Timestamp: {block.timestamp}")
print(f"  Transactions: {len(block.transactions)}")
print(f"  Merkle Root: {block.merkle_root[:16]}...")
print(f"  Previous Hash: {block.previous_hash[:16]}...")
print(f"  Hash: {block.hash[:16]}...")
print(f"  Nonce: {block.nonce}")
```

### Merkle Proofs in Blockchain

```python
from src.blockchain.ledger import Blockchain

chain = Blockchain(difficulty=4)
chain.add_transaction("TX1: Alice -> Bob")
chain.add_transaction("TX2: Bob -> Charlie")
chain.add_transaction("TX3: Charlie -> Dave")
chain.mine_pending_transactions()

# Get proof for a transaction
tx = "TX2: Bob -> Charlie"
proof = chain.get_transaction_proof(1, tx)  # Block 1, transaction TX2
print(f"Merkle proof: {proof}")

# Verify transaction is in block
is_included = chain.verify_transaction(1, tx, proof)
print(f"Transaction verified: {is_included}")

# Try with wrong transaction
is_fake = chain.verify_transaction(1, "FAKE TX", proof)
print(f"Fake transaction accepted: {is_fake}")
```

### Chain Serialization

```python
from src.blockchain.ledger import Blockchain
import json

# Create and populate chain
chain = Blockchain(difficulty=4)
chain.add_transaction("TX1")
chain.mine_pending_transactions()

# Serialize to JSON
chain_data = chain.to_dict()
json_str = json.dumps(chain_data, indent=2)
print(f"Chain JSON (first 200 chars):\n{json_str[:200]}...")

# Deserialize
loaded_chain = Blockchain.from_dict(chain_data)
print(f"Loaded chain valid: {loaded_chain.is_valid()}")
```

---

## Event Logging Module

### Blockchain-Based Audit Logging

```python
from src.integration.event_logger import EventLogger, EventType

# Create event logger with auto-mining disabled for demo
logger = EventLogger(difficulty=4, auto_mine=False)

# Log various events
logger.log_login("alice", success=True, ip_address="192.168.1.100")
logger.log_login("bob", success=False, ip_address="10.0.0.50")
logger.log_totp("alice", success=True)
logger.log_file_encrypt("alice", file_hash="abc123...", file_size=1024)
logger.log_message_send("alice", "bob", message_hash="def456...")

# Mine all pending events
logger.mine_events()
print(f"Events mined into blockchain")

# Verify integrity
is_valid = logger.verify_integrity()
print(f"Audit trail valid: {is_valid}")

# Get all events
events = logger.get_all_events()
print(f"\nAudit Log ({len(events)} events):")
for event in events:
    print(f"  [{event.event_type.name}] User: {event.user_hash[:8]}... at {event.timestamp}")
```

### Privacy-Preserving User Hashes

```python
from src.integration.event_logger import get_user_hash, EventLogger

# User IDs are hashed for privacy
user_hash = get_user_hash("alice")
print(f"alice -> {user_hash[:16]}...")

# Same user always gets same hash
user_hash2 = get_user_hash("alice")
print(f"Consistent: {user_hash == user_hash2}")

# Different users get different hashes
bob_hash = get_user_hash("bob")
print(f"bob -> {bob_hash[:16]}...")
print(f"Different: {user_hash != bob_hash}")
```

### Querying Events

```python
from src.integration.event_logger import EventLogger, EventType

logger = EventLogger(difficulty=4, auto_mine=True)

# Log some events
logger.log_login("alice", success=True)
logger.log_login("alice", success=True)
logger.log_file_encrypt("alice", "hash1", 100)
logger.log_login("bob", success=False)

# Get events by type
login_events = logger.get_events_by_type(EventType.LOGIN_SUCCESS)
print(f"Successful logins: {len(login_events)}")

# Get events by user
alice_events = logger.get_events_by_user("alice")
print(f"Alice's events: {len(alice_events)}")

# Get blockchain info
chain = logger.get_blockchain()
print(f"Blockchain length: {chain.length}")
```

---

## CLI Examples

### Running Tests

```powershell
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_auth.py

# Run specific test class
pytest tests/test_core_crypto.py::TestSHA256

# Run specific test
pytest tests/test_auth.py::TestPasswordHashing::test_hash_password

# Run with coverage
coverage run -m pytest
coverage report
coverage html  # Generate HTML report
```

### Quick Crypto Operations

```powershell
# Hash a string
python -c "from src.core_crypto.sha256 import sha256_hex; print(sha256_hex(b'Hello'))"

# Generate TOTP code
python -c "from src.auth.totp import TOTPGenerator; t=TOTPGenerator(); print(t.generate())"

# Check password strength
python -c "from src.auth.registration import validate_password_strength; print(validate_password_strength('Test123!'))"
```

### Interactive Demo Script

Create `demo.py`:

```python
#!/usr/bin/env python
"""Interactive CryptoVault Demo"""

from src.core_crypto.sha256 import sha256_hex
from src.core_crypto.merkle import MerkleTree
from src.auth.registration import UserRegistration, PasswordHasher_
from src.auth.totp import TOTPGenerator
from src.messaging.secure_channel import SecureChannel, KeyPair
from src.files.file_crypto import encrypt_file, decrypt_file
from src.blockchain.ledger import Blockchain

def main():
    print("=" * 60)
    print("CryptoVault Demo")
    print("=" * 60)
    
    # 1. SHA-256
    print("\n[1] SHA-256 Hashing")
    msg = b"Hello, CryptoVault!"
    print(f"    Message: {msg.decode()}")
    print(f"    SHA-256: {sha256_hex(msg)}")
    
    # 2. Merkle Tree
    print("\n[2] Merkle Tree")
    txs = [b"TX1", b"TX2", b"TX3", b"TX4"]
    tree = MerkleTree(txs)
    print(f"    Transactions: {[t.decode() for t in txs]}")
    print(f"    Merkle Root: {tree.root_hex[:32]}...")
    
    # 3. Password Hashing
    print("\n[3] Password Hashing (Argon2id)")
    hasher = PasswordHasher_()
    pw_hash = hasher.hash_password("DemoP@ssword123!")
    print(f"    Password: DemoP@ssword123!")
    print(f"    Hash: {pw_hash[:50]}...")
    
    # 4. TOTP
    print("\n[4] TOTP 2FA")
    totp = TOTPGenerator()
    print(f"    Secret: {totp.secret_base32}")
    print(f"    Current Code: {totp.generate()}")
    
    # 5. Secure Messaging
    print("\n[5] Secure Messaging")
    alice = SecureChannel(KeyPair.generate())
    bob = SecureChannel(KeyPair.generate())
    alice.establish(bob.public_key)
    bob.establish(alice.public_key)
    
    msg = b"Secret message from Alice!"
    enc = alice.encrypt_message(msg)
    dec = bob.decrypt_message(enc, alice.public_key)
    print(f"    Original: {msg.decode()}")
    print(f"    Decrypted: {dec.decode()}")
    
    # 6. Blockchain
    print("\n[6] Blockchain")
    chain = Blockchain(difficulty=4)
    chain.add_transaction("Demo transaction")
    chain.mine_pending_transactions()
    print(f"    Chain length: {chain.length}")
    print(f"    Chain valid: {chain.is_valid()}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")

if __name__ == "__main__":
    main()
```

Run with:
```powershell
python demo.py
```

---

## Troubleshooting

### Common Issues

**Import Error: No module named 'src'**
```powershell
# Make sure you're in the cryptovault directory
cd cryptovault
python -c "from src.core_crypto.sha256 import sha256_hex; print('OK')"
```

**Password too weak error**
```python
# Password must have: 8+ chars, uppercase, lowercase, digit, special char
# Good: "MySecureP@ss123!"
# Bad: "password", "12345678", "Password1"
```

**TOTP code not working**
```python
# Check clock synchronization
import time
print(f"Current time: {time.time()}")
# TOTP is time-sensitive, ensure system clock is accurate
```

**File decryption fails**
```python
# Possible causes:
# 1. Wrong password
# 2. File was tampered with
# 3. Corrupted encrypted file
```
