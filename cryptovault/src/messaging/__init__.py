# Secure Messaging Module
"""
Secure messaging implementations including:
- ECDH (P-256) key exchange
- HKDF key derivation
- AES-256-GCM authenticated encryption
- ECDSA digital signatures
- End-to-end encryption

Message format: [nonce | ciphertext | tag | signature]

Security features:
- Perfect forward secrecy (ephemeral ECDH)
- Authenticated encryption (AES-GCM)
- Message signing (ECDSA over ciphertext hash, not plaintext)
- Never reuse nonces
"""

from .secure_channel import (
    KeyPair,
    EncryptedMessage,
    ECDHKeyExchange,
    AESGCMCipher,
    ECDSASigner,
    SecureChannel,
    hkdf_derive_key,
    generate_nonce,
    create_secure_message,
    decrypt_secure_message,
)

__all__ = [
    'KeyPair',
    'EncryptedMessage',
    'ECDHKeyExchange',
    'AESGCMCipher',
    'ECDSASigner',
    'SecureChannel',
    'hkdf_derive_key',
    'generate_nonce',
    'create_secure_message',
    'decrypt_secure_message',
]
