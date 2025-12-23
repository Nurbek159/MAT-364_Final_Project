"""
Unit tests for Secure Messaging module.

Tests:
- ECDH key exchange
- AES-GCM encryption
- ECDSA signatures
- Modified ciphertext detection
"""

import pytest
import os
from src.messaging.secure_channel import (
    KeyPair, ECDHKeyExchange, AESGCMCipher, ECDSASigner,
    SecureChannel, hkdf_derive_key
)


class TestECDHKeyExchange:
    """Tests for ECDH key exchange."""
    
    def test_generate_keypair(self):
        """Key pair generation should work."""
        kp = KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None
    
    def test_shared_secret_agreement(self):
        """Both parties should derive same shared secret."""
        alice = ECDHKeyExchange()
        bob = ECDHKeyExchange()
        
        alice_secret = alice.derive_shared_secret_from_bytes(bob.public_bytes)
        bob_secret = bob.derive_shared_secret_from_bytes(alice.public_bytes)
        
        assert alice_secret == bob_secret
    
    def test_different_keypairs_different_secrets(self):
        """Different key pairs should produce different secrets."""
        alice = ECDHKeyExchange()
        bob1 = ECDHKeyExchange()
        bob2 = ECDHKeyExchange()
        
        secret1 = alice.derive_shared_secret_from_bytes(bob1.public_bytes)
        secret2 = alice.derive_shared_secret_from_bytes(bob2.public_bytes)
        
        assert secret1 != secret2


class TestHKDF:
    """Tests for HKDF key derivation."""
    
    def test_derive_key(self):
        """HKDF should derive key of correct length."""
        secret = os.urandom(32)
        key = hkdf_derive_key(secret, length=32)
        assert len(key) == 32
    
    def test_different_info_different_keys(self):
        """Different info should produce different keys."""
        secret = os.urandom(32)
        key1 = hkdf_derive_key(secret, info=b"purpose1")
        key2 = hkdf_derive_key(secret, info=b"purpose2")
        assert key1 != key2
    
    def test_deterministic(self):
        """HKDF should be deterministic with same inputs."""
        secret = b"fixed_secret_for_test"
        salt = b"fixed_salt"
        key1 = hkdf_derive_key(secret, salt=salt, info=b"test")
        key2 = hkdf_derive_key(secret, salt=salt, info=b"test")
        assert key1 == key2


class TestAESGCM:
    """Tests for AES-GCM encryption."""
    
    def test_encrypt_decrypt(self):
        """Encryption/decryption roundtrip should work."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        plaintext = b"Hello, secure world!"
        nonce, ciphertext, tag = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(nonce, ciphertext, tag)
        
        assert decrypted == plaintext
    
    def test_different_nonces(self):
        """Each encryption should use different nonce."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        nonce1, _, _ = cipher.encrypt(b"message")
        nonce2, _, _ = cipher.encrypt(b"message")
        
        assert nonce1 != nonce2
    
    def test_aad_verified(self):
        """Associated data should be verified."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        plaintext = b"message"
        aad = b"authenticated but not encrypted"
        nonce, ciphertext, tag = cipher.encrypt(plaintext, aad)
        
        # Should decrypt with correct AAD
        decrypted = cipher.decrypt(nonce, ciphertext, tag, aad)
        assert decrypted == plaintext
    
    def test_wrong_aad_rejected(self):
        """Wrong associated data should fail decryption."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        nonce, ciphertext, tag = cipher.encrypt(b"message", b"correct_aad")
        
        with pytest.raises(Exception):
            cipher.decrypt(nonce, ciphertext, tag, b"wrong_aad")
    
    def test_modified_ciphertext_rejected(self):
        """Modified ciphertext should fail decryption."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        nonce, ciphertext, tag = cipher.encrypt(b"secret message")
        
        # Modify ciphertext
        modified = bytearray(ciphertext)
        modified[0] ^= 0xFF
        modified = bytes(modified)
        
        with pytest.raises(Exception):
            cipher.decrypt(nonce, modified, tag)
    
    def test_truncated_ciphertext_rejected(self):
        """Truncated ciphertext should fail decryption."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        nonce, ciphertext, tag = cipher.encrypt(b"secret message")
        
        with pytest.raises(Exception):
            cipher.decrypt(nonce, ciphertext[:-5], tag)
    
    def test_wrong_nonce_rejected(self):
        """Wrong nonce should fail decryption."""
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        
        nonce, ciphertext, tag = cipher.encrypt(b"message")
        wrong_nonce = os.urandom(12)
        
        with pytest.raises(Exception):
            cipher.decrypt(wrong_nonce, ciphertext, tag)
    
    def test_wrong_key_rejected(self):
        """Wrong key should fail decryption."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        cipher1 = AESGCMCipher(key1)
        cipher2 = AESGCMCipher(key2)
        
        nonce, ciphertext, tag = cipher1.encrypt(b"message")
        
        with pytest.raises(Exception):
            cipher2.decrypt(nonce, ciphertext, tag)


class TestECDSA:
    """Tests for ECDSA signatures."""
    
    def test_sign_verify(self):
        """Signature should verify correctly."""
        key_pair = KeyPair.generate()
        signer = ECDSASigner(key_pair)
        message = b"Message to sign"
        signature = signer.sign(message)
        
        assert signer.verify_with_key(message, signature)
    
    def test_wrong_message_rejected(self):
        """Signature should not verify with wrong message."""
        key_pair = KeyPair.generate()
        signer = ECDSASigner(key_pair)
        signature = signer.sign(b"original message")
        
        assert not signer.verify_with_key(b"different message", signature)
    
    def test_tampered_signature_rejected(self):
        """Tampered signature should not verify."""
        key_pair = KeyPair.generate()
        signer = ECDSASigner(key_pair)
        message = b"test message"
        signature = signer.sign(message)
        
        # Tamper with signature
        tampered = bytearray(signature)
        tampered[10] ^= 0xFF
        tampered = bytes(tampered)
        
        assert not signer.verify_with_key(message, tampered)
    
    def test_wrong_public_key_rejected(self):
        """Signature should not verify with wrong public key."""
        key_pair1 = KeyPair.generate()
        key_pair2 = KeyPair.generate()
        signer1 = ECDSASigner(key_pair1)
        
        message = b"test"
        signature = signer1.sign(message)
        
        # Verify with wrong public key
        assert not ECDSASigner.verify(message, signature, key_pair2.public_key)


class TestSecureChannel:
    """Tests for complete secure channel."""
    
    def test_establish_channel(self):
        """Secure channel establishment should work."""
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        # Exchange public keys
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        assert alice._session_key is not None
        assert bob._session_key is not None
    
    def test_send_receive(self):
        """Message send/receive should work."""
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        message = b"Hello Bob!"
        encrypted = alice.encrypt_message(message)
        decrypted = bob.decrypt_message(encrypted, alice.public_key)
        
        assert decrypted == message
    
    def test_bidirectional(self):
        """Both parties should be able to send."""
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        # Alice to Bob
        msg1 = b"Hello Bob!"
        encrypted1 = alice.encrypt_message(msg1)
        assert bob.decrypt_message(encrypted1, alice.public_key) == msg1
        
        # Bob to Alice
        msg2 = b"Hello Alice!"
        encrypted2 = bob.encrypt_message(msg2)
        assert alice.decrypt_message(encrypted2, bob.public_key) == msg2
    
    def test_tampered_message_rejected(self):
        """Tampered message should be rejected."""
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        encrypted = alice.encrypt_message(b"secret")
        
        # Tamper with encrypted message
        tampered_ct = bytearray(encrypted.ciphertext)
        tampered_ct[0] ^= 0xFF
        from src.messaging.secure_channel import EncryptedMessage
        tampered_msg = EncryptedMessage(
            encrypted.nonce,
            bytes(tampered_ct),
            encrypted.tag,
            encrypted.signature
        )
        
        with pytest.raises(Exception):
            bob.decrypt_message(tampered_msg, alice.public_key)
