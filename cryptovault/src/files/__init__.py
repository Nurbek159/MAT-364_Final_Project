# File Encryption Module
"""
File encryption implementations including:
- PBKDF2 key derivation (≥100,000 iterations)
- Random FEK (File Encryption Key)
- AES-256-GCM streaming encryption
- SHA-256 + HMAC integrity verification

Security features:
- Streaming (doesn't load large files into RAM)
- Integrity verification BEFORE decryption
- Random salt and nonce per file
- Key wrapping for FEK protection
"""

# Lazy imports to avoid RuntimeWarning when running module directly
def __getattr__(name):
    """Lazy import to avoid circular import issues when running module directly."""
    from . import file_crypto
    return getattr(file_crypto, name)

__all__ = [
    'FileEncryptor',
    'FileHeader',
    'ChunkedEncryptor',
    'ChunkedDecryptor',
    'encrypt_file',
    'decrypt_file',
    'get_file_info',
    'derive_key_pbkdf2',
    'generate_fek',
    'compute_file_hash',
    'compute_hmac',
    'verify_hmac',
    'PBKDF2_ITERATIONS',
    'DEFAULT_CHUNK_SIZE',
]
