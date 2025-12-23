"""
Unit tests for File Encryption module.

Tests:
- PBKDF2 key derivation
- File encryption/decryption
- Modified ciphertext detection
- Wrong password rejection
"""

import pytest
import os
import tempfile
from src.files.file_crypto import (
    FileEncryptor, FileHeader, ChunkedEncryptor, ChunkedDecryptor,
    encrypt_file, decrypt_file, get_file_info,
    derive_key_pbkdf2, generate_fek, compute_file_hash, compute_hmac, verify_hmac,
    PBKDF2_ITERATIONS
)


class TestPBKDF2:
    """Tests for PBKDF2 key derivation."""
    
    def test_derive_key(self):
        """PBKDF2 should derive a key."""
        password = "test_password"
        salt = os.urandom(16)
        key = derive_key_pbkdf2(password, salt)
        assert len(key) == 32
    
    def test_deterministic_with_same_salt(self):
        """Same password and salt should produce same key."""
        password = "test_password"
        salt = b"fixed_salt_1234"
        key1 = derive_key_pbkdf2(password, salt)
        key2 = derive_key_pbkdf2(password, salt)
        assert key1 == key2
    
    def test_different_salt_different_key(self):
        """Different salt should produce different key."""
        password = "test_password"
        key1 = derive_key_pbkdf2(password, b"salt1" + b"\x00" * 11)
        key2 = derive_key_pbkdf2(password, b"salt2" + b"\x00" * 11)
        assert key1 != key2
    
    def test_different_password_different_key(self):
        """Different password should produce different key."""
        salt = b"fixed_salt_1234"
        key1 = derive_key_pbkdf2("password1", salt)
        key2 = derive_key_pbkdf2("password2", salt)
        assert key1 != key2
    
    def test_iterations_count(self):
        """PBKDF2 should use at least 100,000 iterations."""
        assert PBKDF2_ITERATIONS >= 100000


class TestFEK:
    """Tests for File Encryption Key."""
    
    def test_generate_fek(self):
        """FEK generation should produce 32 bytes."""
        fek = generate_fek()
        assert len(fek) == 32
    
    def test_fek_random(self):
        """Each FEK should be unique."""
        fek1 = generate_fek()
        fek2 = generate_fek()
        assert fek1 != fek2


class TestHMAC:
    """Tests for HMAC."""
    
    def test_compute_hmac(self):
        """HMAC computation should work."""
        key = os.urandom(32)
        data = b"test data"
        mac = compute_hmac(key, data)
        assert len(mac) == 32
    
    def test_verify_hmac(self):
        """Valid HMAC should verify."""
        key = os.urandom(32)
        data = b"test data"
        mac = compute_hmac(key, data)
        assert verify_hmac(key, data, mac)
    
    def test_wrong_data_hmac_fails(self):
        """Wrong data should fail HMAC verification."""
        key = os.urandom(32)
        mac = compute_hmac(key, b"correct data")
        assert not verify_hmac(key, b"wrong data", mac)
    
    def test_wrong_key_hmac_fails(self):
        """Wrong key should fail HMAC verification."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"test data"
        mac = compute_hmac(key1, data)
        assert not verify_hmac(key2, data, mac)


class TestFileEncryptor:
    """Tests for FileEncryptor class."""
    
    def test_encrypt_decrypt_file(self):
        """File encryption/decryption roundtrip."""
        encryptor = FileEncryptor("test_password")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "output.enc")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            
            test_data = b"Hello, File Encryption!" * 100
            with open(input_path, "wb") as f:
                f.write(test_data)
            
            # Encrypt
            encryptor.encrypt_file(input_path, output_path)
            
            # Decrypt
            encryptor.decrypt_file(output_path, decrypted_path)
            
            # Verify
            with open(decrypted_path, "rb") as f:
                decrypted_data = f.read()
            
            assert decrypted_data == test_data
    
    def test_wrong_password_rejected(self):
        """Wrong password should fail decryption."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "output.enc")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            
            with open(input_path, "wb") as f:
                f.write(b"secret data")
            
            # Encrypt with one password
            encryptor1 = FileEncryptor("correct_password")
            encryptor1.encrypt_file(input_path, output_path)
            
            # Try to decrypt with wrong password
            encryptor2 = FileEncryptor("wrong_password")
            with pytest.raises(ValueError):
                encryptor2.decrypt_file(output_path, decrypted_path)
    
    def test_tampered_file_detected(self):
        """Tampered encrypted file should be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "output.enc")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            
            with open(input_path, "wb") as f:
                f.write(b"secret data" * 100)
            
            encryptor = FileEncryptor("password")
            encryptor.encrypt_file(input_path, output_path)
            
            # Tamper with encrypted file
            with open(output_path, "r+b") as f:
                f.seek(100)  # Seek into the file
                original = f.read(1)
                f.seek(100)
                f.write(bytes([original[0] ^ 0xFF]))
            
            # Should detect tampering
            with pytest.raises(ValueError) as exc_info:
                encryptor.decrypt_file(output_path, decrypted_path)
            
            assert "integrity" in str(exc_info.value).lower() or "tamper" in str(exc_info.value).lower()
    
    def test_large_file_streaming(self):
        """Large files should be encrypted in streaming mode."""
        encryptor = FileEncryptor("password")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "large.bin")
            output_path = os.path.join(tmpdir, "large.enc")
            decrypted_path = os.path.join(tmpdir, "large_dec.bin")
            
            # Create 1MB file
            test_data = os.urandom(1024 * 1024)
            with open(input_path, "wb") as f:
                f.write(test_data)
            
            encryptor.encrypt_file(input_path, output_path)
            encryptor.decrypt_file(output_path, decrypted_path)
            
            with open(decrypted_path, "rb") as f:
                decrypted_data = f.read()
            
            assert decrypted_data == test_data


class TestFileInfo:
    """Tests for get_file_info."""
    
    def test_get_info(self):
        """Should retrieve encrypted file info."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "output.enc")
            
            test_data = b"test content"
            with open(input_path, "wb") as f:
                f.write(test_data)
            
            encryptor = FileEncryptor("password")
            encryptor.encrypt_file(input_path, output_path)
            
            info = get_file_info(output_path)
            
            assert info['valid'] == True
            assert info['original_size'] == len(test_data)


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""
    
    def test_encrypt_decrypt_functions(self):
        """encrypt_file and decrypt_file functions should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "output.enc")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            
            test_data = b"Convenience function test"
            with open(input_path, "wb") as f:
                f.write(test_data)
            
            encrypt_file(input_path, output_path, "password")
            decrypt_file(output_path, decrypted_path, "password")
            
            with open(decrypted_path, "rb") as f:
                assert f.read() == test_data
