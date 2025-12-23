# CryptoVault Security Analysis

## Threat Model

This document provides a comprehensive security analysis of the CryptoVault system, identifying assets, potential threats, attack vectors, implemented mitigations, and known limitations.

---

## Table of Contents

1. [Assets](#assets)
2. [Threat Actors](#threat-actors)
3. [Attack Vectors](#attack-vectors)
4. [Mitigations](#mitigations)
5. [Known Limitations](#known-limitations)
6. [Security Recommendations](#security-recommendations)

---

## Assets

### Primary Assets

| Asset | Description | Sensitivity | Location |
|-------|-------------|-------------|----------|
| **User Credentials** | Passwords hashed with Argon2id | Critical | User store (memory/database) |
| **TOTP Secrets** | 20-byte shared secrets for 2FA | Critical | User store |
| **Session Tokens** | HMAC-SHA256 authenticated tokens | High | Server memory |
| **Private Keys** | ECDSA/ECDH private keys (P-256) | Critical | Memory (ephemeral) |
| **Encrypted Files** | User files encrypted with AES-256-GCM | High | File system |
| **File Encryption Keys** | Random 256-bit FEKs wrapped with master key | Critical | Encrypted file headers |
| **Plaintext Messages** | Decrypted user communications | High | Memory (transient) |
| **Blockchain Ledger** | Immutable audit log of security events | Medium | Memory/disk |

### Secondary Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Master Keys** | PBKDF2-derived keys from passwords | Critical |
| **Shared Secrets** | ECDH-derived session keys | Critical |
| **Merkle Proofs** | Transaction inclusion proofs | Low |
| **User Metadata** | Usernames, email addresses | Medium |
| **Audit Events** | Login attempts, file operations | Medium |

---

## Threat Actors

### 1. External Attackers

| Actor | Motivation | Capabilities | Target Assets |
|-------|------------|--------------|---------------|
| **Script Kiddies** | Curiosity, vandalism | Automated tools, public exploits | Weak passwords, unpatched systems |
| **Cybercriminals** | Financial gain | Moderate technical skills, botnets | User credentials, encrypted files |
| **Nation-State Actors** | Espionage, surveillance | Advanced persistent threats, zero-days | All assets, cryptographic keys |

### 2. Insider Threats

| Actor | Motivation | Capabilities | Target Assets |
|-------|------------|--------------|---------------|
| **Malicious Admin** | Data theft, sabotage | System access, log manipulation | All stored data |
| **Compromised User** | Account takeover | Valid credentials | Own data, shared resources |

### 3. Passive Adversaries

| Actor | Motivation | Capabilities | Target Assets |
|-------|------------|--------------|---------------|
| **Network Eavesdropper** | Data interception | Network monitoring | Messages in transit |
| **Storage Analyst** | Forensic recovery | Disk access | Encrypted files, deleted data |

---

## Attack Vectors

### A. Authentication Attacks

#### A1. Brute Force Password Attack
```
Threat:     Attacker attempts many password guesses
Target:     User credentials
Likelihood: HIGH
Impact:     Account compromise
```

**Attack Flow:**
```
Attacker ──▶ Login Endpoint ──▶ Repeated password guesses
                                       │
                                       ▼
                               Account Access (if successful)
```

#### A2. Credential Stuffing
```
Threat:     Using leaked credentials from other breaches
Target:     User accounts
Likelihood: HIGH
Impact:     Account takeover
```

#### A3. TOTP Replay Attack
```
Threat:     Reusing a valid TOTP code within time window
Target:     2FA bypass
Likelihood: MEDIUM
Impact:     Second factor bypass
```

#### A4. TOTP Brute Force
```
Threat:     Guessing 6-digit TOTP codes (1M combinations)
Target:     2FA bypass
Likelihood: LOW (with rate limiting)
Impact:     Second factor bypass
```

---

### B. Cryptographic Attacks

#### B1. Ciphertext Manipulation
```
Threat:     Modifying encrypted data to alter plaintext
Target:     Encrypted messages, files
Likelihood: LOW (mitigated by GCM)
Impact:     Data corruption, injection
```

**Attack Flow:**
```
Attacker ──▶ Intercept Ciphertext ──▶ Modify bytes
                                            │
                                            ▼
                                    Send to victim
                                            │
                                            ▼
                               ❌ GCM Authentication Fails
```

#### B2. Key Extraction
```
Threat:     Extracting cryptographic keys from memory
Target:     Private keys, session keys
Likelihood: LOW (requires system access)
Impact:     Complete security compromise
```

#### B3. Padding Oracle Attack
```
Threat:     Exploiting padding validation for decryption
Target:     Encrypted data
Likelihood: N/A (GCM mode, no padding)
Impact:     N/A
```

#### B4. Timing Side-Channel
```
Threat:     Measuring operation timing to leak secrets
Target:     Password comparison, key operations
Likelihood: LOW (mitigated)
Impact:     Credential or key disclosure
```

---

### C. Protocol Attacks

#### C1. Man-in-the-Middle (MITM)
```
Threat:     Intercepting key exchange to decrypt messages
Target:     Secure channel establishment
Likelihood: MEDIUM (without key verification)
Impact:     Message interception, modification
```

**Attack Flow:**
```
Alice ◀──────────────▶ Attacker ◀──────────────▶ Bob
        (fake Bob)              (fake Alice)
```

#### C2. Replay Attack
```
Threat:     Re-sending captured encrypted messages
Target:     Message integrity
Likelihood: LOW (nonces prevent replay)
Impact:     Duplicate actions
```

#### C3. Session Hijacking
```
Threat:     Stealing session tokens
Target:     Authenticated sessions
Likelihood: MEDIUM (depends on transport)
Impact:     Account access
```

---

### D. Data Integrity Attacks

#### D1. Blockchain Tampering
```
Threat:     Modifying historical audit records
Target:     Blockchain ledger
Likelihood: LOW (PoW + hash chaining)
Impact:     Audit trail corruption
```

#### D2. Merkle Proof Forgery
```
Threat:     Creating false inclusion proofs
Target:     Transaction verification
Likelihood: VERY LOW
Impact:     False transaction validation
```

#### D3. File Tampering
```
Threat:     Modifying encrypted files
Target:     Encrypted file integrity
Likelihood: LOW (HMAC verification)
Impact:     Data corruption detection failure
```

---

### E. Denial of Service

#### E1. Resource Exhaustion
```
Threat:     Overwhelming system with requests
Target:     System availability
Likelihood: MEDIUM
Impact:     Service unavailability
```

#### E2. Argon2 Amplification
```
Threat:     Forcing expensive password hashing
Target:     CPU resources
Likelihood: MEDIUM
Impact:     Performance degradation
```

---

## Mitigations

### Authentication Mitigations

| Attack | Mitigation | Implementation |
|--------|------------|----------------|
| **Brute Force** | Rate limiting with lockout | `RateLimiter` class: 5 attempts, 5-minute lockout |
| **Brute Force** | Strong password hashing | Argon2id with memory-hard parameters |
| **Credential Stuffing** | Password strength validation | Minimum 8 chars, mixed case, digits, symbols |
| **TOTP Replay** | Time-based expiration | 30-second time step with ±1 drift tolerance |
| **TOTP Brute Force** | Rate limiting | Same rate limiter applies to TOTP |
| **Weak Passwords** | Password scoring | Score 0-100 with requirement enforcement |

### Cryptographic Mitigations

| Attack | Mitigation | Implementation |
|--------|------------|----------------|
| **Ciphertext Manipulation** | Authenticated encryption | AES-256-GCM with 128-bit auth tag |
| **Key Extraction** | Ephemeral keys | ECDH keys generated per session |
| **Timing Attacks** | Constant-time comparison | `secure_compare()` using `hmac.compare_digest` |
| **Weak Randomness** | Secure random generation | `secrets` module for all random values |
| **Key Derivation** | Strong KDF | PBKDF2 with 100,000 iterations |

### Protocol Mitigations

| Attack | Mitigation | Implementation |
|--------|------------|----------------|
| **MITM** | Key exchange authentication | ECDSA signatures on key exchange |
| **Replay** | Unique nonces | 96-bit random nonces per message |
| **Session Hijacking** | Token binding | HMAC-SHA256 token verification |
| **Forward Secrecy** | Ephemeral ECDH | New key pair per secure channel |

### Data Integrity Mitigations

| Attack | Mitigation | Implementation |
|--------|------------|----------------|
| **Blockchain Tampering** | Hash chaining | SHA-256 linking blocks |
| **Blockchain Tampering** | Proof of Work | Difficulty-based mining |
| **Merkle Forgery** | Cryptographic proofs | SHA-256 Merkle tree |
| **File Tampering** | HMAC verification | HMAC-SHA256 on file contents |

### Implementation Details

```python
# Rate Limiting Configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes
ATTEMPT_WINDOW_SECONDS = 300

# Argon2id Parameters
ARGON2_CONFIG = {
    'time_cost': 3,
    'memory_cost': 65536,  # 64 MB
    'parallelism': 4,
    'hash_len': 32,
    'salt_len': 16,
}

# PBKDF2 Configuration
PBKDF2_ITERATIONS = 100000

# AES-GCM Configuration
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits
GCM_TAG_SIZE = 16  # 128 bits
```

---

## Known Limitations

### 1. No Persistent Key Storage
```
Limitation: Private keys exist only in memory
Impact:     Keys lost on program termination
Risk Level: Medium
Workaround: Implement secure key storage (HSM, encrypted keystore)
```

### 2. No Transport Layer Security
```
Limitation: No TLS/SSL implementation
Impact:     Network eavesdropping possible
Risk Level: High (for network deployment)
Workaround: Deploy behind TLS-terminating proxy
```

### 3. In-Memory User Store
```
Limitation: User data not persisted to disk
Impact:     Data lost on restart
Risk Level: Medium
Workaround: Implement database backend with encryption at rest
```

### 4. No Key Revocation
```
Limitation: No mechanism to revoke compromised keys
Impact:     Compromised keys remain valid
Risk Level: Medium
Workaround: Implement key revocation list (CRL) or OCSP
```

### 5. Single-Node Blockchain
```
Limitation: Blockchain runs on single node
Impact:     No Byzantine fault tolerance
Risk Level: Low (audit log only)
Workaround: Implement distributed consensus
```

### 6. No Forward Secrecy for Files
```
Limitation: File encryption uses password-derived key
Impact:     Password compromise exposes all files
Risk Level: Medium
Workaround: Implement key rotation, per-file random keys
```

### 7. TOTP Time Synchronization
```
Limitation: Requires synchronized clocks
Impact:     Clock drift causes authentication failures
Risk Level: Low
Workaround: Use NTP, increase drift tolerance window
```

### 8. No Protection Against Physical Access
```
Limitation: No secure enclave or TPM integration
Impact:     Physical access enables key extraction
Risk Level: High (for high-security environments)
Workaround: Use hardware security modules (HSM)
```

### 9. Limited Audit Log Privacy
```
Limitation: Event metadata visible (timestamps, types)
Impact:     Behavioral analysis possible
Risk Level: Low
Workaround: Implement encrypted audit logs
```

### 10. No Rate Limiting Persistence
```
Limitation: Rate limit state lost on restart
Impact:     Attacker can restart attack after service restart
Risk Level: Low
Workaround: Persist rate limit state to database
```

---

## Security Recommendations

### For Production Deployment

1. **Add Transport Security**
   - Deploy with TLS 1.3
   - Use certificate pinning for clients

2. **Implement Persistent Storage**
   - Use encrypted database (SQLite with SEE, PostgreSQL with pgcrypto)
   - Encrypt sensitive columns

3. **Add Key Management**
   - Integrate with HSM or cloud KMS
   - Implement key rotation policies

4. **Enhance Monitoring**
   - Add intrusion detection
   - Alert on suspicious patterns

5. **Security Hardening**
   - Run with minimal privileges
   - Implement input validation
   - Add CSRF protection for web interfaces

### Security Testing Checklist

- [x] Brute force protection tested
- [x] Wrong TOTP rejection verified
- [x] Ciphertext tampering detected
- [x] Merkle proof validation tested
- [x] Signature forgery rejected
- [x] File tampering detected
- [x] Blockchain integrity verified
- [ ] Penetration testing (recommended)
- [ ] Security audit (recommended)

---

## Conclusion

CryptoVault implements defense-in-depth security with multiple layers of protection. While suitable for educational purposes and demonstrating cryptographic concepts, production deployment would require addressing the known limitations, particularly around persistent storage, transport security, and key management.

The implemented mitigations effectively protect against common attack vectors including brute force attacks, cryptographic manipulation, and data tampering. The 71% test coverage includes specific security tests for invalid inputs and attack scenarios.
