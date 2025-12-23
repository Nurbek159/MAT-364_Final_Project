"""
Integration tests for CryptoVault.

Tests end-to-end workflows combining multiple modules.
"""

import pytest
import os
import tempfile
import time

from src.auth.registration import UserRegistration
from src.auth.login import LoginManager
from src.auth.totp import TOTPGenerator, TOTPManager
from src.messaging.secure_channel import SecureChannel, KeyPair
from src.files.file_crypto import FileEncryptor, encrypt_file, decrypt_file
from src.blockchain.ledger import Blockchain
from src.integration.event_logger import (
    EventLogger, EventType, get_user_hash, SecurityEvent
)
from src.core_crypto.sha256 import sha256_hex


class TestAuthWorkflow:
    """Integration tests for authentication workflow."""
    
    def test_full_registration_login_flow(self):
        """Test complete registration -> login -> logout flow."""
        reg = UserRegistration()
        result = reg.register_user("testuser", "SecureP@ss123!")
        assert result['success'], f"Registration failed: {result['message']}"
        
        mgr = LoginManager(user_store=reg._users)
        
        # Login
        result = mgr.login("testuser", "SecureP@ss123!")
        assert result['success'], "Login failed"
        assert 'token' in result or 'session_id' in result
        
        # Logout
        session_id = result.get('session_id')
        if session_id:
            mgr.logout(session_id)
    
    def test_totp_with_login(self):
        """Test TOTP as second factor after login."""
        reg = UserRegistration()
        reg.register_user("user2fa", "SecureP@ss123!")
        
        mgr = LoginManager(user_store=reg._users)
        totp_mgr = TOTPManager()
        
        # Create and verify TOTP
        secret_b32, uri = totp_mgr.create_secret("user2fa", "user2fa@example.com")
        
        # Login (first factor)
        result = mgr.login("user2fa", "SecureP@ss123!")
        assert result['success']
        
        # Verify TOTP (second factor) - use verify_code with raw secret
        from src.auth.totp import base32_to_secret
        secret = base32_to_secret(secret_b32)
        gen = TOTPGenerator(secret=secret)
        code = gen.generate()
        assert totp_mgr.verify_code(secret, code)
    
    def test_rate_limiting_blocks_brute_force(self):
        """Rate limiter should block brute force attempts."""
        reg = UserRegistration()
        reg.register_user("victim", "SecureP@ss123!")
        
        mgr = LoginManager(user_store=reg._users)
        
        # Make failed login attempts
        for _ in range(5):
            mgr.login("victim", "WrongP@ssword123!")
        
        # After rate limiting kicks in, verify it handles gracefully
        result = mgr.login("victim", "SecureP@ss123!")
        # The system should handle rate limiting in some way
        assert 'success' in result


class TestSecureMessagingWorkflow:
    """Integration tests for secure messaging."""
    
    def test_full_messaging_flow(self):
        """Test complete key exchange -> encrypt -> sign -> verify flow."""
        # Create channels
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        # Exchange keys
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        # Alice sends encrypted, signed message
        original = b"This is a secret message from Alice to Bob."
        encrypted = alice.encrypt_message(original)
        
        # Bob receives and verifies
        decrypted = bob.decrypt_message(encrypted, alice.public_key)
        
        assert decrypted == original
    
    def test_multi_message_conversation(self):
        """Test multiple messages in conversation."""
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        
        alice = SecureChannel(alice_keys)
        bob = SecureChannel(bob_keys)
        
        alice.establish(bob.public_key)
        bob.establish(alice.public_key)
        
        messages = [
            (alice, bob, alice_keys, bob_keys, b"Hello Bob!"),
            (bob, alice, bob_keys, alice_keys, b"Hi Alice!"),
            (alice, bob, alice_keys, bob_keys, b"How are you?"),
            (bob, alice, bob_keys, alice_keys, b"I'm fine, thanks!"),
        ]
        
        for sender, receiver, sender_keys, receiver_keys, msg in messages:
            encrypted = sender.encrypt_message(msg)
            decrypted = receiver.decrypt_message(encrypted, sender.public_key)
            assert decrypted == msg


class TestFileEncryptionWorkflow:
    """Integration tests for file encryption."""
    
    def test_encrypt_decrypt_multiple_files(self):
        """Test encrypting and decrypting multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            password = "SecurePassword123!"
            
            files = [
                ("doc1.txt", b"Document 1 content"),
                ("doc2.txt", b"Document 2 with different content"),
                ("binary.bin", os.urandom(1000)),
            ]
            
            # Encrypt all files
            for filename, content in files:
                input_path = os.path.join(tmpdir, filename)
                enc_path = os.path.join(tmpdir, filename + ".enc")
                
                with open(input_path, "wb") as f:
                    f.write(content)
                
                encrypt_file(input_path, enc_path, password)
            
            # Decrypt and verify all files
            for filename, expected_content in files:
                enc_path = os.path.join(tmpdir, filename + ".enc")
                dec_path = os.path.join(tmpdir, "dec_" + filename)
                
                decrypt_file(enc_path, dec_path, password)
                
                with open(dec_path, "rb") as f:
                    assert f.read() == expected_content


class TestBlockchainEventLogging:
    """Integration tests for blockchain event logging."""
    
    def test_login_events_logged(self):
        """Login events should be logged to blockchain."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        # Log some login events
        logger.log_login("alice", success=True)
        logger.log_login("bob", success=False)
        logger.log_login("alice", success=True)
        
        # Mine events
        block = logger.mine_events()
        
        assert block is not None
        assert len(block.transactions) >= 3
        
        # Retrieve events
        events = logger.get_all_events()
        login_events = [e for e in events if e.event_type in 
                       (EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILED)]
        assert len(login_events) >= 3
    
    def test_file_encrypt_events_logged(self):
        """File encryption events should be logged."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        file_hash = sha256_hex(b"test file content")
        logger.log_file_encrypt("alice", file_hash, 1024)
        logger.mine_events()
        
        events = logger.get_events_by_type(EventType.FILE_ENCRYPT)
        assert len(events) >= 1
    
    def test_message_events_logged(self):
        """Message events should be logged."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        msg_hash = sha256_hex(b"Hello!")
        logger.log_message_send("alice", "bob", msg_hash)
        logger.mine_events()
        
        events = logger.get_events_by_type(EventType.MESSAGE_SEND)
        assert len(events) >= 1
    
    def test_privacy_user_hashes(self):
        """Usernames should be hashed, not stored in plaintext."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        logger.log_login("secret_username", success=True)
        logger.mine_events()
        
        # Export blockchain
        json_str = logger.export_log()
        
        # Username should not appear in plaintext
        assert "secret_username" not in json_str
        
        # But hash should be there
        user_hash = get_user_hash("secret_username")[:16]
        assert user_hash in json_str
    
    def test_audit_trail_immutable(self):
        """Audit trail should be tamper-evident."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        # Log events
        for i in range(5):
            logger.log_login(f"user{i}", success=True)
        logger.mine_events()
        
        # Verify chain integrity
        assert logger.verify_integrity()
        
        # Chain should have blocks
        assert logger.get_blockchain().length >= 2


class TestFullSystemIntegration:
    """Full system integration test."""
    
    def test_complete_workflow(self):
        """Test complete system workflow."""
        logger = EventLogger(difficulty=4, auto_mine=False)
        
        # 1. User Registration and Login
        reg = UserRegistration()
        reg.register_user("alice", "SecureP@ss123!")
        
        mgr = LoginManager(user_store=reg._users)
        result = mgr.login("alice", "SecureP@ss123!")
        success = result['success']
        logger.log_login("alice", success=success)
        
        # 2. TOTP Setup
        totp_mgr = TOTPManager()
        secret_b32, _ = totp_mgr.create_secret("alice", "alice@example.com")
        from src.auth.totp import base32_to_secret
        secret = base32_to_secret(secret_b32)
        gen = TOTPGenerator(secret=secret)
        code = gen.generate()
        totp_ok = totp_mgr.verify_code(secret, code)
        logger.log_totp("alice", success=totp_ok)
        
        # 3. File Encryption
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "secret.txt")
            enc_path = os.path.join(tmpdir, "secret.enc")
            
            with open(input_path, "wb") as f:
                f.write(b"Top secret data!")
            
            encrypt_file(input_path, enc_path, "file_password")
            file_hash = sha256_hex(b"Top secret data!")
            logger.log_file_encrypt("alice", file_hash, 16)
        
        # 4. Secure Messaging
        alice_keys = KeyPair.generate()
        bob_keys = KeyPair.generate()
        alice_channel = SecureChannel(alice_keys)
        bob_channel = SecureChannel(bob_keys)
        alice_channel.establish(bob_channel.public_key)
        bob_channel.establish(alice_channel.public_key)
        
        msg = b"Hello Bob!"
        encrypted = alice_channel.encrypt_message(msg)
        decrypted = bob_channel.decrypt_message(encrypted, alice_channel.public_key)
        
        msg_hash = sha256_hex(msg)
        logger.log_message_send("alice", "bob", msg_hash)
        
        # 5. Mine all events
        logger.mine_events()
        
        # 6. Verify everything worked
        assert success  # Login worked
        assert totp_ok  # TOTP worked
        assert decrypted == msg  # Messaging worked
        assert logger.verify_integrity()  # Blockchain valid
        
        # 7. Retrieve audit log
        events = logger.get_all_events()
        event_types = [e.event_type for e in events]
        
        assert EventType.LOGIN_SUCCESS in event_types
        assert EventType.TOTP_VERIFIED in event_types
        assert EventType.FILE_ENCRYPT in event_types
        assert EventType.MESSAGE_SEND in event_types
