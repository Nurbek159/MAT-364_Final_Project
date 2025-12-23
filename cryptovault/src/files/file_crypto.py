"""
File Encryption Module

Implements secure file encryption with:
- PBKDF2 key derivation (≥100,000 iterations)
- Random File Encryption Key (FEK)
- AES-256-GCM streaming encryption
- SHA-256 file hash + HMAC integrity verification

Security features:
- Streaming encryption (doesn't load entire file into RAM)
- Integrity verification BEFORE decryption
- Random salt and nonce per file
- Key wrapping for FEK protection

File Format:
    [header | encrypted_fek | chunks... | hmac]
    
Header:
    - Magic bytes (4): "CVLT"
    - Version (1): 0x01
    - Salt (32): PBKDF2 salt
    - Nonce (12): AES-GCM nonce for FEK encryption
    - FEK Tag (16): GCM tag for encrypted FEK
    - Chunk size (4): Size of each chunk
    - Original size (8): Original file size
    - File hash (32): SHA-256 of original file
"""

import os
import io
import secrets
import hashlib
import hmac
import struct
from typing import BinaryIO, Tuple, Optional, Generator
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# Constants
MAGIC_BYTES = b"CVLT"       # CryptoVault
VERSION = 0x01
SALT_SIZE = 32              # 256-bit salt
NONCE_SIZE = 12             # 96-bit nonce for GCM
TAG_SIZE = 16               # 128-bit GCM tag
KEY_SIZE = 32               # 256-bit keys
HMAC_SIZE = 32              # 256-bit HMAC
HASH_SIZE = 32              # SHA-256

# PBKDF2 configuration
PBKDF2_ITERATIONS = 100_000  # Minimum as specified
PBKDF2_ALGORITHM = hashes.SHA256()

# Chunk size for streaming (1 MB default)
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB

# Header size calculation
HEADER_SIZE = (
    4 +    # Magic
    1 +    # Version
    32 +   # Salt
    12 +   # Nonce (for FEK encryption)
    16 +   # FEK GCM tag
    32 +   # Encrypted FEK
    4 +    # Chunk size
    8 +    # Original size
    32     # File hash
)  # Total: 141 bytes


@dataclass
class FileHeader:
    """Encrypted file header."""
    magic: bytes
    version: int
    salt: bytes
    fek_nonce: bytes
    fek_tag: bytes
    encrypted_fek: bytes
    chunk_size: int
    original_size: int
    file_hash: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        return (
            self.magic +
            struct.pack('B', self.version) +
            self.salt +
            self.fek_nonce +
            self.fek_tag +
            self.encrypted_fek +
            struct.pack('>I', self.chunk_size) +
            struct.pack('>Q', self.original_size) +
            self.file_hash
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileHeader':
        """Deserialize header from bytes."""
        offset = 0
        
        magic = data[offset:offset + 4]
        offset += 4
        
        version = struct.unpack('B', data[offset:offset + 1])[0]
        offset += 1
        
        salt = data[offset:offset + 32]
        offset += 32
        
        fek_nonce = data[offset:offset + 12]
        offset += 12
        
        fek_tag = data[offset:offset + 16]
        offset += 16
        
        encrypted_fek = data[offset:offset + 32]
        offset += 32
        
        chunk_size = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        
        original_size = struct.unpack('>Q', data[offset:offset + 8])[0]
        offset += 8
        
        file_hash = data[offset:offset + 32]
        
        return cls(
            magic=magic,
            version=version,
            salt=salt,
            fek_nonce=fek_nonce,
            fek_tag=fek_tag,
            encrypted_fek=encrypted_fek,
            chunk_size=chunk_size,
            original_size=original_size,
            file_hash=file_hash
        )
    
    def validate(self) -> bool:
        """Validate header magic and version."""
        return self.magic == MAGIC_BYTES and self.version == VERSION


def derive_key_pbkdf2(password: str, salt: bytes, 
                       iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive encryption key from password using PBKDF2.
    
    Args:
        password: User password
        salt: Random salt (32 bytes)
        iterations: Number of iterations (≥100,000)
        
    Returns:
        32-byte derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=PBKDF2_ALGORITHM,
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def generate_fek() -> bytes:
    """Generate random File Encryption Key."""
    return secrets.token_bytes(KEY_SIZE)


def encrypt_fek(fek: bytes, kek: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt FEK with Key Encryption Key using AES-GCM.
    
    Args:
        fek: File Encryption Key to protect
        kek: Key Encryption Key (derived from password)
        
    Returns:
        Tuple of (nonce, encrypted_fek, tag)
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(kek)
    ciphertext_with_tag = aesgcm.encrypt(nonce, fek, None)
    
    encrypted_fek = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]
    
    return nonce, encrypted_fek, tag


def decrypt_fek(encrypted_fek: bytes, tag: bytes, nonce: bytes, 
                kek: bytes) -> bytes:
    """
    Decrypt FEK with Key Encryption Key.
    
    Args:
        encrypted_fek: Encrypted FEK
        tag: GCM authentication tag
        nonce: Nonce used for encryption
        kek: Key Encryption Key
        
    Returns:
        Decrypted FEK
    """
    aesgcm = AESGCM(kek)
    ciphertext_with_tag = encrypted_fek + tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def compute_file_hash(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """
    Compute SHA-256 hash of a file (streaming).
    
    Args:
        file_path: Path to file
        chunk_size: Read chunk size
        
    Returns:
        32-byte SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.digest()


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """Verify HMAC-SHA256 using constant-time comparison."""
    computed = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected_hmac)


class ChunkedEncryptor:
    """
    Streaming AES-GCM encryptor for large files.
    
    Each chunk is encrypted with a unique nonce derived from
    a base nonce and chunk counter.
    """
    
    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize chunked encryptor.
        
        Args:
            key: 256-bit encryption key
            chunk_size: Size of each chunk in bytes
        """
        self._aesgcm = AESGCM(key)
        self._chunk_size = chunk_size
        self._chunk_counter = 0
        self._base_nonce = secrets.token_bytes(8)  # 8-byte base nonce
    
    def _get_chunk_nonce(self) -> bytes:
        """Generate unique nonce for current chunk."""
        # Nonce = base_nonce (8 bytes) || counter (4 bytes)
        nonce = self._base_nonce + struct.pack('>I', self._chunk_counter)
        self._chunk_counter += 1
        return nonce
    
    @property
    def base_nonce(self) -> bytes:
        """Get base nonce for storage in header."""
        return self._base_nonce
    
    def encrypt_chunk(self, chunk: bytes) -> bytes:
        """
        Encrypt a single chunk.
        
        Returns:
            nonce (12 bytes) || ciphertext || tag (16 bytes)
        """
        nonce = self._get_chunk_nonce()
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, chunk, None)
        return nonce + ciphertext_with_tag
    
    def encrypt_stream(self, input_stream: BinaryIO) -> Generator[bytes, None, None]:
        """
        Encrypt a stream in chunks.
        
        Args:
            input_stream: Input file stream
            
        Yields:
            Encrypted chunks
        """
        while True:
            chunk = input_stream.read(self._chunk_size)
            if not chunk:
                break
            yield self.encrypt_chunk(chunk)


class ChunkedDecryptor:
    """
    Streaming AES-GCM decryptor for large files.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize chunked decryptor.
        
        Args:
            key: 256-bit encryption key
        """
        self._aesgcm = AESGCM(key)
    
    def decrypt_chunk(self, encrypted_chunk: bytes) -> bytes:
        """
        Decrypt a single chunk.
        
        Args:
            encrypted_chunk: nonce (12) || ciphertext || tag (16)
            
        Returns:
            Decrypted data
        """
        nonce = encrypted_chunk[:NONCE_SIZE]
        ciphertext_with_tag = encrypted_chunk[NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ciphertext_with_tag, None)


class FileEncryptor:
    """
    Complete file encryption with streaming support.
    
    Features:
    - PBKDF2 key derivation (100,000+ iterations)
    - Random FEK wrapped with password-derived key
    - AES-256-GCM streaming encryption
    - HMAC integrity verification
    
    Example:
        >>> encryptor = FileEncryptor("my_password")
        >>> encryptor.encrypt_file("document.pdf", "document.pdf.enc")
        >>> encryptor.decrypt_file("document.pdf.enc", "document_decrypted.pdf")
    """
    
    def __init__(self, password: str, iterations: int = PBKDF2_ITERATIONS):
        """
        Initialize with password.
        
        Args:
            password: Encryption password
            iterations: PBKDF2 iterations (default 100,000)
        """
        self._password = password
        self._iterations = iterations
    
    def encrypt_file(self, input_path: str, output_path: str,
                     chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict:
        """
        Encrypt a file with streaming.
        
        Args:
            input_path: Path to input file
            output_path: Path for encrypted output
            chunk_size: Chunk size for streaming
            
        Returns:
            Dict with encryption metadata
        """
        # Get file info
        file_size = os.path.getsize(input_path)
        file_hash = compute_file_hash(input_path, chunk_size)
        
        # Generate salt and derive KEK
        salt = secrets.token_bytes(SALT_SIZE)
        kek = derive_key_pbkdf2(self._password, salt, self._iterations)
        
        # Generate and encrypt FEK
        fek = generate_fek()
        fek_nonce, encrypted_fek, fek_tag = encrypt_fek(fek, kek)
        
        # Create header
        header = FileHeader(
            magic=MAGIC_BYTES,
            version=VERSION,
            salt=salt,
            fek_nonce=fek_nonce,
            fek_tag=fek_tag,
            encrypted_fek=encrypted_fek,
            chunk_size=chunk_size,
            original_size=file_size,
            file_hash=file_hash
        )
        
        # Initialize encryptor and HMAC
        encryptor = ChunkedEncryptor(fek, chunk_size)
        hmac_key = derive_key_pbkdf2(self._password, salt + b"hmac", self._iterations)
        hmac_state = hmac.new(hmac_key, digestmod=hashlib.sha256)
        
        # Write encrypted file
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write header
            header_bytes = header.to_bytes()
            fout.write(header_bytes)
            hmac_state.update(header_bytes)
            
            # Encrypt and write chunks
            for encrypted_chunk in encryptor.encrypt_stream(fin):
                fout.write(encrypted_chunk)
                hmac_state.update(encrypted_chunk)
            
            # Write HMAC
            file_hmac = hmac_state.digest()
            fout.write(file_hmac)
        
        return {
            'input_size': file_size,
            'output_size': os.path.getsize(output_path),
            'file_hash': file_hash.hex(),
            'chunk_size': chunk_size,
        }
    
    def decrypt_file(self, input_path: str, output_path: str) -> dict:
        """
        Decrypt a file with integrity verification.
        
        IMPORTANT: Verifies HMAC BEFORE decryption!
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            
        Returns:
            Dict with decryption metadata
            
        Raises:
            ValueError: If integrity check fails
        """
        encrypted_size = os.path.getsize(input_path)
        
        with open(input_path, 'rb') as f:
            # Read header
            header_bytes = f.read(HEADER_SIZE)
            header = FileHeader.from_bytes(header_bytes)
            
            if not header.validate():
                raise ValueError("Invalid file format or version")
            
            # Derive keys
            kek = derive_key_pbkdf2(self._password, header.salt, self._iterations)
            hmac_key = derive_key_pbkdf2(
                self._password, header.salt + b"hmac", self._iterations
            )
            
            # Calculate data size (excluding header and HMAC)
            data_size = encrypted_size - HEADER_SIZE - HMAC_SIZE
            
            # STEP 1: Verify HMAC BEFORE decryption
            hmac_state = hmac.new(hmac_key, digestmod=hashlib.sha256)
            hmac_state.update(header_bytes)
            
            # Read and hash encrypted data
            bytes_read = 0
            f.seek(HEADER_SIZE)
            while bytes_read < data_size:
                to_read = min(DEFAULT_CHUNK_SIZE, data_size - bytes_read)
                chunk = f.read(to_read)
                if not chunk:
                    break
                hmac_state.update(chunk)
                bytes_read += len(chunk)
            
            # Read and verify HMAC
            stored_hmac = f.read(HMAC_SIZE)
            computed_hmac = hmac_state.digest()
            
            if not hmac.compare_digest(computed_hmac, stored_hmac):
                raise ValueError("Integrity check failed - file may be corrupted or tampered")
            
            # STEP 2: Now decrypt (integrity verified)
            # Decrypt FEK
            fek = decrypt_fek(
                header.encrypted_fek,
                header.fek_tag,
                header.fek_nonce,
                kek
            )
            
            decryptor = ChunkedDecryptor(fek)
            
            # Calculate chunk overhead (nonce + tag)
            chunk_overhead = NONCE_SIZE + TAG_SIZE
            encrypted_chunk_size = header.chunk_size + chunk_overhead
            
            # Decrypt file
            f.seek(HEADER_SIZE)
            bytes_decrypted = 0
            
            with open(output_path, 'wb') as fout:
                bytes_read = 0
                while bytes_read < data_size:
                    # Determine how much to read
                    remaining = data_size - bytes_read
                    to_read = min(encrypted_chunk_size, remaining)
                    
                    encrypted_chunk = f.read(to_read)
                    if not encrypted_chunk:
                        break
                    
                    bytes_read += len(encrypted_chunk)
                    
                    # Decrypt chunk
                    decrypted = decryptor.decrypt_chunk(encrypted_chunk)
                    fout.write(decrypted)
                    bytes_decrypted += len(decrypted)
        
        # Verify decrypted file hash
        decrypted_hash = compute_file_hash(output_path)
        if decrypted_hash != header.file_hash:
            os.remove(output_path)  # Remove potentially corrupted file
            raise ValueError("Decrypted file hash mismatch")
        
        return {
            'original_size': header.original_size,
            'decrypted_size': bytes_decrypted,
            'hash_verified': True,
        }


def encrypt_file(input_path: str, output_path: str, 
                 password: str, **kwargs) -> dict:
    """Convenience function for file encryption."""
    encryptor = FileEncryptor(password, **kwargs)
    return encryptor.encrypt_file(input_path, output_path)


def decrypt_file(input_path: str, output_path: str,
                 password: str, **kwargs) -> dict:
    """Convenience function for file decryption."""
    decryptor = FileEncryptor(password, **kwargs)
    return decryptor.decrypt_file(input_path, output_path)


def get_file_info(encrypted_path: str) -> dict:
    """
    Get information about an encrypted file without decrypting.
    
    Args:
        encrypted_path: Path to encrypted file
        
    Returns:
        Dict with file metadata
    """
    with open(encrypted_path, 'rb') as f:
        header_bytes = f.read(HEADER_SIZE)
        header = FileHeader.from_bytes(header_bytes)
    
    return {
        'valid': header.validate(),
        'version': header.version,
        'original_size': header.original_size,
        'file_hash': header.file_hash.hex(),
        'chunk_size': header.chunk_size,
        'encrypted_size': os.path.getsize(encrypted_path),
    }


# Self-test when run directly
if __name__ == "__main__":
    import tempfile
    import shutil
    
    print("File Encryption Module Test")
    print("=" * 70)
    
    # Create test directory
    test_dir = tempfile.mkdtemp()
    
    try:
        # Test 1: PBKDF2 key derivation
        print("\n[Test 1] PBKDF2 key derivation (100,000 iterations)")
        salt = secrets.token_bytes(32)
        key = derive_key_pbkdf2("test_password", salt)
        print(f"  Salt: {salt.hex()[:32]}...")
        print(f"  Derived key: {key.hex()}")
        test1_pass = len(key) == 32
        print(f"  Status: {'✓ PASS' if test1_pass else '✗ FAIL'}")
        
        # Test 2: FEK encryption/decryption
        print("\n[Test 2] FEK encryption/decryption")
        fek = generate_fek()
        kek = derive_key_pbkdf2("password", salt)
        
        nonce, enc_fek, tag = encrypt_fek(fek, kek)
        dec_fek = decrypt_fek(enc_fek, tag, nonce, kek)
        
        test2_pass = dec_fek == fek
        print(f"  Original FEK: {fek.hex()[:32]}...")
        print(f"  Decrypted FEK: {dec_fek.hex()[:32]}...")
        print(f"  Match: {'✓ PASS' if test2_pass else '✗ FAIL'}")
        
        # Test 3: Create test file
        print("\n[Test 3] Create test file")
        test_file = os.path.join(test_dir, "test_file.txt")
        test_content = b"Hello, this is a test file for encryption!\n" * 1000
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        original_size = os.path.getsize(test_file)
        original_hash = compute_file_hash(test_file)
        print(f"  Created file: {original_size} bytes")
        print(f"  SHA-256: {original_hash.hex()[:32]}...")
        test3_pass = original_size > 0
        print(f"  Status: {'✓ PASS' if test3_pass else '✗ FAIL'}")
        
        # Test 4: File encryption
        print("\n[Test 4] File encryption")
        encrypted_file = os.path.join(test_dir, "test_file.enc")
        password = "SecurePassword123!"
        
        encryptor = FileEncryptor(password)
        enc_result = encryptor.encrypt_file(test_file, encrypted_file)
        
        print(f"  Input size: {enc_result['input_size']} bytes")
        print(f"  Output size: {enc_result['output_size']} bytes")
        print(f"  File hash: {enc_result['file_hash'][:32]}...")
        test4_pass = os.path.exists(encrypted_file)
        print(f"  Status: {'✓ PASS' if test4_pass else '✗ FAIL'}")
        
        # Test 5: Get file info
        print("\n[Test 5] Get encrypted file info")
        info = get_file_info(encrypted_file)
        print(f"  Valid format: {info['valid']}")
        print(f"  Original size: {info['original_size']}")
        print(f"  Encrypted size: {info['encrypted_size']}")
        test5_pass = info['valid'] and info['original_size'] == original_size
        print(f"  Status: {'✓ PASS' if test5_pass else '✗ FAIL'}")
        
        # Test 6: File decryption
        print("\n[Test 6] File decryption (with integrity check)")
        decrypted_file = os.path.join(test_dir, "test_file_dec.txt")
        
        dec_result = encryptor.decrypt_file(encrypted_file, decrypted_file)
        
        print(f"  Original size: {dec_result['original_size']}")
        print(f"  Decrypted size: {dec_result['decrypted_size']}")
        print(f"  Hash verified: {dec_result['hash_verified']}")
        
        # Verify content
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        test6_pass = decrypted_content == test_content
        print(f"  Content matches: {test6_pass}")
        print(f"  Status: {'✓ PASS' if test6_pass else '✗ FAIL'}")
        
        # Test 7: Wrong password
        print("\n[Test 7] Wrong password rejection")
        wrong_decryptor = FileEncryptor("WrongPassword")
        wrong_output = os.path.join(test_dir, "wrong.txt")
        
        try:
            wrong_decryptor.decrypt_file(encrypted_file, wrong_output)
            test7_pass = False
            print("  Error: Should have failed with wrong password")
        except Exception as e:
            test7_pass = True
            print(f"  Correctly rejected: {type(e).__name__}")
        print(f"  Status: {'✓ PASS' if test7_pass else '✗ FAIL'}")
        
        # Test 8: Tampered file detection
        print("\n[Test 8] Tampered file detection")
        tampered_file = os.path.join(test_dir, "tampered.enc")
        shutil.copy(encrypted_file, tampered_file)
        
        # Tamper with the file (modify a byte in the middle)
        with open(tampered_file, 'r+b') as f:
            f.seek(HEADER_SIZE + 100)
            f.write(b'\x00')
        
        try:
            encryptor.decrypt_file(tampered_file, os.path.join(test_dir, "tampered_dec.txt"))
            test8_pass = False
            print("  Error: Should have detected tampering")
        except ValueError as e:
            test8_pass = "Integrity" in str(e) or "corrupted" in str(e)
            print(f"  Tampering detected: {e}")
        print(f"  Status: {'✓ PASS' if test8_pass else '✗ FAIL'}")
        
        # Summary
        all_passed = all([test1_pass, test2_pass, test3_pass, test4_pass,
                          test5_pass, test6_pass, test7_pass, test8_pass])
        print("\n" + "=" * 70)
        print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
        
    finally:
        # Cleanup
        shutil.rmtree(test_dir)
