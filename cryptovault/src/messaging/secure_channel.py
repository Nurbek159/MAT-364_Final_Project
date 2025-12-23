"""
Secure Messaging Module

Implements end-to-end encrypted messaging with:
- ECDH (P-256) key exchange
- HKDF key derivation
- AES-256-GCM authenticated encryption
- ECDSA digital signatures

Message Format:
    [nonce (12 bytes) | ciphertext | tag (16 bytes) | signature (variable)]

Security features:
- Perfect forward secrecy via ephemeral ECDH
- Authenticated encryption (AES-GCM)
- Message integrity and authenticity (ECDSA)
- Never reuse nonces
- Sign hash of ciphertext, not plaintext
"""

import os
import secrets
import hashlib
import struct
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# Constants
CURVE = ec.SECP256R1()  # P-256 curve
AES_KEY_SIZE = 32       # 256 bits
NONCE_SIZE = 12         # 96 bits for GCM
TAG_SIZE = 16           # 128 bits for GCM tag
SIGNATURE_SIZE = 64     # P-256 ECDSA signature (r, s) each 32 bytes


@dataclass
class KeyPair:
    """ECDSA/ECDH key pair container."""
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    
    @classmethod
    def generate(cls) -> 'KeyPair':
        """Generate a new P-256 key pair."""
        private_key = ec.generate_private_key(CURVE, default_backend())
        public_key = private_key.public_key()
        return cls(private_key, public_key)
    
    def public_bytes(self) -> bytes:
        """Get public key as bytes (uncompressed point)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def private_bytes(self) -> bytes:
        """Get private key as bytes."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @classmethod
    def from_public_bytes(cls, data: bytes) -> 'KeyPair':
        """Create KeyPair from public key bytes (public key only)."""
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
        return cls(None, public_key)


@dataclass
class EncryptedMessage:
    """
    Container for encrypted message components.
    
    Format: [nonce | ciphertext | tag | signature]
    """
    nonce: bytes          # 12 bytes
    ciphertext: bytes     # Variable length
    tag: bytes            # 16 bytes (part of GCM output)
    signature: bytes      # Variable (typically 64-72 bytes for P-256)
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes with length prefix for ciphertext."""
        # Format: nonce (12) | ciphertext_len (4) | ciphertext | tag (16) | sig_len (2) | signature
        return (
            self.nonce +
            struct.pack('>I', len(self.ciphertext)) +
            self.ciphertext +
            self.tag +
            struct.pack('>H', len(self.signature)) +
            self.signature
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedMessage':
        """Deserialize from bytes."""
        offset = 0
        
        # Nonce (12 bytes)
        nonce = data[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE
        
        # Ciphertext length (4 bytes) and ciphertext
        ct_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        ciphertext = data[offset:offset + ct_len]
        offset += ct_len
        
        # Tag (16 bytes)
        tag = data[offset:offset + TAG_SIZE]
        offset += TAG_SIZE
        
        # Signature length (2 bytes) and signature
        sig_len = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
        signature = data[offset:offset + sig_len]
        
        return cls(nonce, ciphertext, tag, signature)
    
    def to_hex(self) -> str:
        """Serialize to hex string."""
        return self.to_bytes().hex()
    
    @classmethod
    def from_hex(cls, hex_str: str) -> 'EncryptedMessage':
        """Deserialize from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))


class ECDHKeyExchange:
    """
    Elliptic Curve Diffie-Hellman key exchange using P-256.
    
    Provides perfect forward secrecy when using ephemeral keys.
    """
    
    def __init__(self, key_pair: KeyPair = None):
        """
        Initialize ECDH with optional existing key pair.
        
        Args:
            key_pair: Existing key pair, or generate new if None
        """
        self._key_pair = key_pair or KeyPair.generate()
    
    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get public key for sharing."""
        return self._key_pair.public_key
    
    @property
    def public_bytes(self) -> bytes:
        """Get public key as bytes."""
        return self._key_pair.public_bytes()
    
    def derive_shared_secret(self, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Derive shared secret from peer's public key.
        
        Args:
            peer_public_key: The other party's public key
            
        Returns:
            Shared secret bytes (32 bytes for P-256)
        """
        shared_key = self._key_pair.private_key.exchange(
            ec.ECDH(),
            peer_public_key
        )
        return shared_key
    
    def derive_shared_secret_from_bytes(self, peer_public_bytes: bytes) -> bytes:
        """
        Derive shared secret from peer's public key bytes.
        
        Args:
            peer_public_bytes: Public key as bytes (uncompressed point)
            
        Returns:
            Shared secret bytes
        """
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, peer_public_bytes
        )
        return self.derive_shared_secret(peer_public_key)


def hkdf_derive_key(shared_secret: bytes, 
                    salt: bytes = None,
                    info: bytes = b"messaging",
                    length: int = AES_KEY_SIZE) -> bytes:
    """
    Derive encryption key from shared secret using HKDF.
    
    HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869.
    
    Args:
        shared_secret: Input key material (e.g., from ECDH)
        salt: Optional salt (random bytes)
        info: Context/application info
        length: Output key length in bytes
        
    Returns:
        Derived key bytes
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def generate_nonce() -> bytes:
    """
    Generate a random nonce for AES-GCM.
    
    CRITICAL: Never reuse a nonce with the same key!
    
    Returns:
        12 random bytes
    """
    return secrets.token_bytes(NONCE_SIZE)


class AESGCMCipher:
    """
    AES-256-GCM authenticated encryption.
    
    Provides confidentiality, integrity, and authenticity.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize with encryption key.
        
        Args:
            key: 256-bit (32-byte) key
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        self._aesgcm = AESGCM(key)
        self._used_nonces = set()  # Track used nonces to prevent reuse
    
    def encrypt(self, plaintext: bytes, 
                associated_data: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional authenticated but not encrypted data
            
        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        # Generate unique nonce
        nonce = generate_nonce()
        
        # Prevent nonce reuse (belt and suspenders)
        while nonce in self._used_nonces:
            nonce = generate_nonce()
        self._used_nonces.add(nonce)
        
        # Encrypt (GCM appends tag to ciphertext)
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]
        
        return nonce, ciphertext, tag
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes,
                associated_data: bytes = None) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.
        
        Args:
            nonce: 12-byte nonce
            ciphertext: Encrypted data
            tag: 16-byte authentication tag
            associated_data: Optional associated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            InvalidTag: If authentication fails
        """
        # Reconstruct ciphertext with tag
        ciphertext_with_tag = ciphertext + tag
        
        # Decrypt and verify
        plaintext = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        
        return plaintext


class ECDSASigner:
    """
    ECDSA digital signatures using P-256.
    
    Signs the hash of data, not the plaintext directly.
    """
    
    def __init__(self, key_pair: KeyPair):
        """
        Initialize with signing key pair.
        
        Args:
            key_pair: Key pair with private key for signing
        """
        self._key_pair = key_pair
    
    def sign(self, data: bytes) -> bytes:
        """
        Sign data using ECDSA.
        
        Signs SHA-256 hash of data (not plaintext).
        
        Args:
            data: Data to sign (will be hashed first)
            
        Returns:
            ECDSA signature bytes
        """
        if self._key_pair.private_key is None:
            raise ValueError("Private key required for signing")
        
        # Sign the SHA-256 hash of the data
        signature = self._key_pair.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    @staticmethod
    def verify(data: bytes, signature: bytes, 
               public_key: ec.EllipticCurvePublicKey) -> bool:
        """
        Verify an ECDSA signature.
        
        Args:
            data: Original data that was signed
            signature: ECDSA signature
            public_key: Signer's public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    def verify_with_key(self, data: bytes, signature: bytes) -> bool:
        """Verify signature using stored public key."""
        return self.verify(data, signature, self._key_pair.public_key)


class SecureChannel:
    """
    Complete secure messaging channel.
    
    Combines ECDH + HKDF + AES-256-GCM + ECDSA for end-to-end encryption.
    
    Example:
        # Alice's side
        alice_keys = KeyPair.generate()
        alice_channel = SecureChannel(alice_keys)
        
        # Bob's side  
        bob_keys = KeyPair.generate()
        bob_channel = SecureChannel(bob_keys)
        
        # Establish shared key
        alice_channel.establish(bob_keys.public_key)
        bob_channel.establish(alice_keys.public_key)
        
        # Alice sends to Bob
        encrypted = alice_channel.encrypt_message(b"Hello Bob!")
        
        # Bob receives
        plaintext = bob_channel.decrypt_message(encrypted, alice_keys.public_key)
    """
    
    def __init__(self, identity_keys: KeyPair):
        """
        Initialize secure channel with identity keys.
        
        Args:
            identity_keys: Long-term identity key pair for signing
        """
        self._identity_keys = identity_keys
        self._signer = ECDSASigner(identity_keys)
        self._cipher: Optional[AESGCMCipher] = None
        self._session_key: Optional[bytes] = None
        self._peer_public_key: Optional[ec.EllipticCurvePublicKey] = None
    
    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get identity public key."""
        return self._identity_keys.public_key
    
    @property
    def public_bytes(self) -> bytes:
        """Get identity public key as bytes."""
        return self._identity_keys.public_bytes()
    
    @property
    def is_established(self) -> bool:
        """Check if channel has been established."""
        return self._cipher is not None
    
    def establish(self, peer_public_key: ec.EllipticCurvePublicKey,
                  salt: bytes = None) -> bytes:
        """
        Establish secure channel with peer using ECDH.
        
        Args:
            peer_public_key: Peer's public key
            salt: Optional salt for HKDF
            
        Returns:
            Session key (for reference, typically not needed)
        """
        self._peer_public_key = peer_public_key
        
        # ECDH key exchange
        ecdh = ECDHKeyExchange(self._identity_keys)
        shared_secret = ecdh.derive_shared_secret(peer_public_key)
        
        # Derive session key using HKDF
        self._session_key = hkdf_derive_key(
            shared_secret,
            salt=salt,
            info=b"secure_messaging_v1"
        )
        
        # Initialize cipher with derived key
        self._cipher = AESGCMCipher(self._session_key)
        
        return self._session_key
    
    def establish_from_bytes(self, peer_public_bytes: bytes,
                             salt: bytes = None) -> bytes:
        """Establish channel from peer's public key bytes."""
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, peer_public_bytes
        )
        return self.establish(peer_public_key, salt)
    
    def encrypt_message(self, plaintext: bytes) -> EncryptedMessage:
        """
        Encrypt and sign a message.
        
        Message format: [nonce | ciphertext | tag | signature]
        Signature is over: nonce || ciphertext || tag (NOT plaintext)
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            EncryptedMessage container
        """
        if not self.is_established:
            raise RuntimeError("Channel not established. Call establish() first.")
        
        # Encrypt with AES-GCM
        nonce, ciphertext, tag = self._cipher.encrypt(plaintext)
        
        # Sign the encrypted data (nonce + ciphertext + tag)
        # IMPORTANT: Sign ciphertext, not plaintext!
        data_to_sign = nonce + ciphertext + tag
        signature = self._signer.sign(data_to_sign)
        
        return EncryptedMessage(nonce, ciphertext, tag, signature)
    
    def decrypt_message(self, message: EncryptedMessage,
                        sender_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Verify and decrypt a message.
        
        Args:
            message: Encrypted message
            sender_public_key: Sender's public key for signature verification
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If signature verification fails
            InvalidTag: If decryption authentication fails
        """
        if not self.is_established:
            raise RuntimeError("Channel not established. Call establish() first.")
        
        # Verify signature first
        data_to_verify = message.nonce + message.ciphertext + message.tag
        if not ECDSASigner.verify(data_to_verify, message.signature, sender_public_key):
            raise ValueError("Signature verification failed")
        
        # Decrypt
        plaintext = self._cipher.decrypt(
            message.nonce,
            message.ciphertext,
            message.tag
        )
        
        return plaintext
    
    def decrypt_message_from_bytes(self, data: bytes,
                                   sender_public_bytes: bytes) -> bytes:
        """Decrypt message from serialized bytes."""
        message = EncryptedMessage.from_bytes(data)
        sender_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, sender_public_bytes
        )
        return self.decrypt_message(message, sender_key)


def create_secure_message(plaintext: bytes,
                          sender_keys: KeyPair,
                          recipient_public_key: ec.EllipticCurvePublicKey) -> Tuple[bytes, bytes]:
    """
    One-shot function to create an encrypted, signed message.
    
    Uses ephemeral ECDH for perfect forward secrecy.
    
    Args:
        plaintext: Message to encrypt
        sender_keys: Sender's identity keys (for signing)
        recipient_public_key: Recipient's public key
        
    Returns:
        Tuple of (ephemeral_public_key, encrypted_message_bytes)
    """
    # Generate ephemeral key pair for ECDH
    ephemeral = KeyPair.generate()
    
    # ECDH key exchange
    ecdh = ECDHKeyExchange(ephemeral)
    shared_secret = ecdh.derive_shared_secret(recipient_public_key)
    
    # Derive key
    session_key = hkdf_derive_key(shared_secret)
    
    # Encrypt
    cipher = AESGCMCipher(session_key)
    nonce, ciphertext, tag = cipher.encrypt(plaintext)
    
    # Sign (ciphertext, not plaintext)
    signer = ECDSASigner(sender_keys)
    data_to_sign = nonce + ciphertext + tag
    signature = signer.sign(data_to_sign)
    
    message = EncryptedMessage(nonce, ciphertext, tag, signature)
    
    return ephemeral.public_bytes(), message.to_bytes()


def decrypt_secure_message(encrypted_data: bytes,
                           ephemeral_public_bytes: bytes,
                           recipient_keys: KeyPair,
                           sender_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    One-shot function to decrypt a secure message.
    
    Args:
        encrypted_data: Serialized encrypted message
        ephemeral_public_bytes: Sender's ephemeral public key
        recipient_keys: Recipient's key pair
        sender_public_key: Sender's identity public key
        
    Returns:
        Decrypted plaintext
    """
    # Parse message
    message = EncryptedMessage.from_bytes(encrypted_data)
    
    # Verify signature
    data_to_verify = message.nonce + message.ciphertext + message.tag
    if not ECDSASigner.verify(data_to_verify, message.signature, sender_public_key):
        raise ValueError("Signature verification failed")
    
    # ECDH to derive shared secret
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, ephemeral_public_bytes
    )
    ecdh = ECDHKeyExchange(recipient_keys)
    shared_secret = ecdh.derive_shared_secret(ephemeral_public)
    
    # Derive key
    session_key = hkdf_derive_key(shared_secret)
    
    # Decrypt
    cipher = AESGCMCipher(session_key)
    plaintext = cipher.decrypt(message.nonce, message.ciphertext, message.tag)
    
    return plaintext


# Self-test when run directly
if __name__ == "__main__":
    print("Secure Messaging Module Test")
    print("=" * 70)
    
    # Test 1: Key pair generation
    print("\n[Test 1] Key pair generation (P-256)")
    alice_keys = KeyPair.generate()
    bob_keys = KeyPair.generate()
    print(f"  Alice public key: {alice_keys.public_bytes().hex()[:64]}...")
    print(f"  Bob public key:   {bob_keys.public_bytes().hex()[:64]}...")
    test1_pass = len(alice_keys.public_bytes()) == 65  # Uncompressed point
    print(f"  Status: {'✓ PASS' if test1_pass else '✗ FAIL'}")
    
    # Test 2: ECDH key exchange
    print("\n[Test 2] ECDH key exchange")
    alice_ecdh = ECDHKeyExchange(alice_keys)
    bob_ecdh = ECDHKeyExchange(bob_keys)
    
    alice_shared = alice_ecdh.derive_shared_secret(bob_keys.public_key)
    bob_shared = bob_ecdh.derive_shared_secret(alice_keys.public_key)
    
    test2_pass = alice_shared == bob_shared
    print(f"  Alice shared secret: {alice_shared.hex()[:32]}...")
    print(f"  Bob shared secret:   {bob_shared.hex()[:32]}...")
    print(f"  Secrets match: {'✓ PASS' if test2_pass else '✗ FAIL'}")
    
    # Test 3: HKDF key derivation
    print("\n[Test 3] HKDF key derivation")
    key1 = hkdf_derive_key(alice_shared, info=b"test")
    key2 = hkdf_derive_key(alice_shared, info=b"test")
    key3 = hkdf_derive_key(alice_shared, info=b"different")
    
    test3_pass = key1 == key2 and key1 != key3
    print(f"  Same inputs produce same key: {key1 == key2}")
    print(f"  Different info produces different key: {key1 != key3}")
    print(f"  Status: {'✓ PASS' if test3_pass else '✗ FAIL'}")
    
    # Test 4: AES-GCM encryption
    print("\n[Test 4] AES-256-GCM encryption")
    cipher = AESGCMCipher(key1)
    plaintext = b"Hello, this is a secret message!"
    
    nonce, ciphertext, tag = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(nonce, ciphertext, tag)
    
    test4_pass = decrypted == plaintext
    print(f"  Plaintext:  {plaintext}")
    print(f"  Ciphertext: {ciphertext.hex()[:32]}...")
    print(f"  Decrypted:  {decrypted}")
    print(f"  Status: {'✓ PASS' if test4_pass else '✗ FAIL'}")
    
    # Test 5: ECDSA signature
    print("\n[Test 5] ECDSA signature")
    signer = ECDSASigner(alice_keys)
    message = b"Message to sign"
    signature = signer.sign(message)
    
    valid = ECDSASigner.verify(message, signature, alice_keys.public_key)
    invalid = ECDSASigner.verify(b"Tampered message", signature, alice_keys.public_key)
    
    test5_pass = valid and not invalid
    print(f"  Signature: {signature.hex()[:32]}...")
    print(f"  Valid signature verified: {valid}")
    print(f"  Tampered message rejected: {not invalid}")
    print(f"  Status: {'✓ PASS' if test5_pass else '✗ FAIL'}")
    
    # Test 6: Complete secure channel
    print("\n[Test 6] Complete secure channel")
    alice_channel = SecureChannel(alice_keys)
    bob_channel = SecureChannel(bob_keys)
    
    # Establish channels
    alice_channel.establish(bob_keys.public_key)
    bob_channel.establish(alice_keys.public_key)
    
    # Alice sends to Bob
    message = b"Hello Bob! This is a secure message from Alice."
    encrypted = alice_channel.encrypt_message(message)
    
    print(f"  Encrypted message size: {len(encrypted.to_bytes())} bytes")
    print(f"  Nonce: {encrypted.nonce.hex()}")
    
    # Bob receives and decrypts
    decrypted = bob_channel.decrypt_message(encrypted, alice_keys.public_key)
    
    test6_pass = decrypted == message
    print(f"  Original:  {message}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Status: {'✓ PASS' if test6_pass else '✗ FAIL'}")
    
    # Test 7: Message serialization
    print("\n[Test 7] Message serialization")
    serialized = encrypted.to_bytes()
    deserialized = EncryptedMessage.from_bytes(serialized)
    
    test7_pass = (
        deserialized.nonce == encrypted.nonce and
        deserialized.ciphertext == encrypted.ciphertext and
        deserialized.tag == encrypted.tag and
        deserialized.signature == encrypted.signature
    )
    print(f"  Serialized size: {len(serialized)} bytes")
    print(f"  Deserialization correct: {'✓ PASS' if test7_pass else '✗ FAIL'}")
    
    # Test 8: One-shot API
    print("\n[Test 8] One-shot secure message API")
    message = b"One-shot encrypted message with PFS"
    
    ephemeral_pub, encrypted_bytes = create_secure_message(
        message, alice_keys, bob_keys.public_key
    )
    
    decrypted = decrypt_secure_message(
        encrypted_bytes, ephemeral_pub, bob_keys, alice_keys.public_key
    )
    
    test8_pass = decrypted == message
    print(f"  Original:  {message}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Status: {'✓ PASS' if test8_pass else '✗ FAIL'}")
    
    # Summary
    all_passed = all([test1_pass, test2_pass, test3_pass, test4_pass, 
                      test5_pass, test6_pass, test7_pass, test8_pass])
    print("\n" + "=" * 70)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
