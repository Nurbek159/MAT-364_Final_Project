# CryptoVault

A comprehensive cryptography project implementing secure authentication, messaging, file encryption, and blockchain-based audit logging.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Dependencies](#dependencies)
- [Run Instructions](#run-instructions)
- [Testing](#testing)
- [Team Roles & Responsibilities](#team-roles--responsibilities)
- [Peer Evaluation](#peer-evaluation)

---

## Overview

CryptoVault is a MAT-364 Final Project demonstrating practical cryptographic implementations including:
- Custom SHA-256 implementation from scratch
- Merkle tree with proof generation/verification
- AES-256 key schedule (Rijndael)
- LFSR stream cipher
- RSA math primitives with Miller-Rabin primality testing

## Features

### Module 1: Authentication System
**Complete user authentication with multi-factor security**

- **Argon2id Password Hashing**
  - Memory-hard password hashing (64 MB, 3 iterations, 4 threads)
  - Automatic salt generation using CSPRNG
  - Protection against GPU and side-channel attacks
  
- **Password Strength Validation**
  - Minimum 8 characters (configurable)
  - Requires uppercase, lowercase, digits, and special characters
  - Password strength scoring (0-100)
  - Prevents weak passwords at registration

- **Rate-Limited Login**
  - Maximum 5 failed attempts before lockout
  - 5-minute lockout duration
  - IP-based and username-based rate limiting
  - Prevents brute-force attacks

- **TOTP Two-Factor Authentication (RFC 6238)**
  - Time-based one-time passwords
  - QR code generation for authenticator apps (Google Authenticator, Authy)
  - Time drift tolerance (±30 seconds)
  - Secure secret generation and storage

- **Session Management**
  - HMAC-SHA256 authenticated session tokens
  - Configurable session expiration (default: 1 hour)
  - Constant-time token verification
  - Automatic session cleanup

### Module 2: Secure Messaging
**End-to-end encrypted communication with perfect forward secrecy**

- **ECDH Key Exchange (P-256)**
  - Elliptic Curve Diffie-Hellman on SECP256R1 curve
  - Ephemeral key pairs for each session
  - Shared secret derivation (32 bytes)

- **HKDF Key Derivation**
  - HMAC-based Key Derivation Function (RFC 5869)
  - Context-specific key derivation
  - Salted key generation

- **AES-256-GCM Encryption**
  - Authenticated encryption with associated data
  - Unique 96-bit nonce per message
  - 128-bit authentication tag
  - Protection against tampering

- **ECDSA Digital Signatures**
  - P-256 elliptic curve signatures
  - Signs SHA-256 hash of ciphertext (not plaintext)
  - Non-repudiation guarantee
  - Signature verification before decryption

- **Perfect Forward Secrecy**
  - Ephemeral ECDH keys per message
  - Compromised long-term keys don't affect past messages
  - One-shot API for PFS messaging

### Module 3: File Encryption System
**Secure file storage with streaming encryption**

- **PBKDF2 Key Derivation**
  - 100,000 iterations minimum (configurable)
  - SHA-256 based key stretching
  - Unique 256-bit salt per file
  - Protection against password brute-force

- **File Encryption Key (FEK) Architecture**
  - Random 256-bit FEK per file
  - FEK encrypted with password-derived master key (KEK)
  - Key wrapping using AES-GCM
  - Enables key rotation without re-encrypting files

- **Streaming Encryption**
  - Chunked encryption for large files (1 MB chunks default)
  - Memory-efficient (doesn't load entire file)
  - Supports files of any size
  - Unique nonce per chunk

- **Integrity Verification**
  - SHA-256 hash of original file stored in header
  - HMAC-SHA256 over entire encrypted file
  - **Verification BEFORE decryption** (prevents malicious decryption)
  - Tamper detection with clear error messages

- **File Format**
  - Custom header with magic bytes ("CVLT")
  - Version field for future compatibility
  - Metadata encryption support ready

### Module 4: Blockchain Audit Ledger
**Immutable audit trail for security events**

- **Block Structure**
  - Previous block hash (SHA-256 double hash)
  - Merkle root of all transactions
  - Timestamp and nonce
  - Block hash meeting difficulty target

- **Merkle Tree Integration**
  - Custom Merkle tree implementation
  - Transaction inclusion proofs
  - Proof verification
  - Handles odd number of transactions

- **Proof of Work Consensus**
  - Adjustable difficulty (leading zero bits)
  - Double SHA-256 hashing (Bitcoin-style)
  - Nonce search algorithm
  - Chain validation

- **Chain Integrity**
  - Full chain validation
  - Block-by-block verification
  - Hash chaining verification
  - Immutable blocks (frozen dataclass)

### Integration Module: Event Logger
**Blockchain-based security audit logging**

- **Privacy-Preserving Logging**
  - SHA-256 hashing of usernames
  - IP address hashing
  - No plaintext sensitive data in blockchain

- **Event Types**
  - Authentication events (login, logout, TOTP)
  - File operations (encrypt, decrypt, integrity checks)
  - Messaging events (send, receive, key exchange)
  - System events (startup, shutdown)

- **Automatic Mining**
  - Configurable batch size (default: 10 events)
  - Automatic block mining when batch full
  - Manual mining API available

- **Query Capabilities**
  - Filter events by user (hashed)
  - Filter events by type
  - Get recent events
  - Full audit log export/import

---

## Project Structure

```
cryptovault/
├── src/
│   ├── core_crypto/          # From-scratch implementations
│   │   ├── sha256.py         # SHA-256 hash function
│   │   ├── merkle.py         # Merkle tree
│   │   ├── aes_key_schedule.py  # AES-256 key expansion
│   │   ├── lfsr_cipher.py    # LFSR stream cipher
│   │   └── rsa_math.py       # RSA primitives
│   ├── auth/                 # Authentication module
│   │   ├── registration.py   # User registration, password hashing
│   │   ├── login.py          # Login, rate limiting, sessions
│   │   └── totp.py           # TOTP implementation
│   ├── messaging/            # Secure messaging module
│   │   └── secure_channel.py # ECDH, AES-GCM, ECDSA
│   ├── files/                # File encryption module
│   │   └── file_crypto.py    # File encryption/decryption
│   ├── blockchain/           # Blockchain module
│   │   └── ledger.py         # Blockchain, PoW, validation
│   └── integration/          # Integration module
│       └── event_logger.py   # Blockchain-based audit logging
├── tests/                    # Test suite
│   ├── test_core_crypto.py   # Core crypto tests
│   ├── test_auth.py          # Authentication tests
│   ├── test_messaging.py     # Messaging tests
│   ├── test_files.py         # File encryption tests
│   ├── test_blockchain.py    # Blockchain tests
│   ├── test_integration.py   # Integration tests
│   └── test_security.py      # Security tests
├── pytest.ini                # Pytest configuration
└── README.md                 # This file
```

---

## Setup

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```powershell
   git clone https://github.com/your-repo/MAT-364_Final_Project.git
   cd MAT-364_Final_Project
   ```

2. **Create a virtual environment**
   ```powershell
   python -m venv venv
   ```

3. **Activate the virtual environment**
   
   Windows (PowerShell):
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
   
   Windows (CMD):
   ```cmd
   .\venv\Scripts\activate.bat
   ```
   
   Linux/macOS:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```powershell
   pip install -r requirements.txt
   ```

   Or install individually:
   ```powershell
   pip install cryptography pyotp argon2-cffi bcrypt pytest coverage qrcode
   ```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | ≥41.0.0 | ECDH, AES-GCM, ECDSA, HKDF |
| `pyotp` | ≥2.9.0 | TOTP reference implementation |
| `argon2-cffi` | ≥23.1.0 | Argon2id password hashing |
| `bcrypt` | ≥4.1.0 | Backup password hashing |
| `pytest` | ≥8.0.0 | Testing framework |
| `coverage` | ≥7.4.0 | Code coverage analysis |
| `qrcode` | ≥7.4.0 | QR code generation for TOTP |

### requirements.txt
```
cryptography>=41.0.0
pyotp>=2.9.0
argon2-cffi>=23.1.0
bcrypt>=4.1.0
pytest>=8.0.0
coverage>=7.4.0
qrcode>=7.4.0
```

---

## Run Instructions

### Running the Tests

Navigate to the cryptovault directory and run:

```powershell
cd cryptovault

# Activate virtual environment
..\venv\Scripts\Activate.ps1

# Run all tests
pytest

# Run tests with verbose output
pytest -v

# Run specific test file
pytest tests/test_auth.py -v

# Run specific test class
pytest tests/test_core_crypto.py::TestSHA256 -v
```

### Running with Coverage

```powershell
# Run tests with coverage
coverage run -m pytest

# View coverage report
coverage report

# Generate HTML coverage report
coverage html
```

### Example Usage

```python
# SHA-256 Hashing
from src.core_crypto.sha256 import sha256_hex
hash_value = sha256_hex(b"Hello, World!")
print(f"SHA-256: {hash_value}")

# Merkle Tree
from src.core_crypto.merkle import MerkleTree
tree = MerkleTree([b"tx1", b"tx2", b"tx3"])
proof = tree.get_proof(0)
print(f"Merkle Root: {tree.root_hex}")

# Password Hashing
from src.auth.registration import PasswordHasher_
hasher = PasswordHasher_()
hash_str = hasher.hash_password("SecureP@ss123!")
verified = hasher.verify_password("SecureP@ss123!", hash_str)

# TOTP
from src.auth.totp import TOTPGenerator
totp = TOTPGenerator()
code = totp.generate()
print(f"TOTP Code: {code}")

# Secure Channel
from src.messaging.secure_channel import SecureChannel, KeyPair
alice_keys = KeyPair.generate()
bob_keys = KeyPair.generate()

alice = SecureChannel(alice_keys)
bob = SecureChannel(bob_keys)

alice.establish(bob.public_key)
bob.establish(alice.public_key)

encrypted = alice.encrypt_message(b"Secret message")
decrypted = bob.decrypt_message(encrypted, alice.public_key)

# File Encryption
from src.files.file_crypto import encrypt_file, decrypt_file
encrypt_file("secret.txt", "secret.enc", "password123")
decrypt_file("secret.enc", "decrypted.txt", "password123")

# Blockchain
from src.blockchain.ledger import Blockchain
chain = Blockchain(difficulty=4)
chain.add_transaction("Alice sends 10 to Bob")
chain.mine_pending_transactions()
print(f"Chain valid: {chain.is_valid()}")
```

---

## Testing

### Test Coverage Summary

| Module | Coverage |
|--------|----------|
| Core Crypto | 53-81% |
| Authentication | 50-63% |
| Messaging | 51% |
| File Encryption | 67% |
| Blockchain | 60% |
| **Overall** | **71%** |

### Test Categories

- **Unit Tests**: Individual function/class testing
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Invalid input handling
  - Wrong TOTP codes
  - Modified ciphertext
  - Invalid Merkle proofs
  - Forged signatures

---

## Team Roles & Responsibilities

### Team Members

| Name | Student ID | GitHub | Roles |
|------|------------|--------|-------|
| Nurbek Sagimbayev | 220107034 | Nurbek159 | B, C |
| Alan Auezkhanov | 220107093 | alanauezkhanov | A |

### Role A: Authentication & Security Lead
- Design and implement authentication module
- Implement password hashing and TOTP
- Ensure secure coding practices across project
- Write security analysis document
- Review code for vulnerabilities

### Role B: Cryptography & Messaging Lead
- Implement core crypto library (from scratch parts)
- Design and implement messaging module
- Implement key exchange and signatures
- Handle file encryption module
- Ensure proper key management

### Role C: Blockchain & Integration Lead
- Design and implement blockchain module
- Create Merkle tree implementation
- Integrate all modules together

---

## Peer Evaluation

After submission, each team member will submit a confidential peer evaluation:

### Nurbek Sagimbayev (Roles B, C)
```
Team Member: Nurbek Sagimbayev, Alan Auezkhanov
Contribution Level: [1-5]
Areas Contributed:
  [x] Authentication
  [x] Messaging
  [x] File Encryption
  [x] Blockchain
  [x] Testing
  [x] Documentation
Comments: Implemented core crypto library (SHA-256, Merkle tree, AES key schedule, 
LFSR cipher, RSA math). Designed and implemented secure messaging module with ECDH, 
AES-GCM, and ECDSA. Built blockchain module with PoW and chain validation. 
Handled file encryption module. Integrated all modules together.
```

### Alan Auezkhanov (Role A)
```
Team Member: Alan Auezkhanov
Contribution Level: [1-5]
Areas Contributed:
  [x] Authentication
  [ ] Messaging
  [ ] File Encryption
  [ ] Blockchain
  [x] Testing
  [x] Documentation
Comments: Designed and implemented authentication module including password hashing 
(Argon2id) and TOTP two-factor authentication. Ensured secure coding practices 
across the project. Reviewed code for vulnerabilities. Contributed to security 
testing and documentation.
```

---

## License

This project was created for educational purposes as part of MAT-364 coursework.

---

## Acknowledgments

- Course: MAT-364 Cryptography
- Semester: Fall 2025
