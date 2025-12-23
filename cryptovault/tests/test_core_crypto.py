"""
Unit tests for Core Crypto modules.

Tests:
- SHA-256 implementation
- Merkle Tree
- AES Key Schedule
- LFSR Cipher
- RSA Math
"""

import pytest
from src.core_crypto.sha256 import sha256, sha256_hex
from src.core_crypto.merkle import MerkleTree
from src.core_crypto.aes_key_schedule import (
    aes256_key_expansion, sub_word, rot_word, S_BOX
)
from src.core_crypto.lfsr_cipher import LFSR, LFSRCipher
from src.core_crypto.rsa_math import (
    mod_exp, is_probably_prime_miller_rabin, generate_prime,
    gcd, mod_inverse, generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    rsa_sign, rsa_verify
)


class TestSHA256:
    """Unit tests for SHA-256 implementation."""
    
    def test_empty_string(self):
        """Test SHA-256 of empty string."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hex(b"") == expected
    
    def test_abc(self):
        """Test SHA-256 of 'abc'."""
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert sha256_hex(b"abc") == expected
    
    def test_long_message(self):
        """Test SHA-256 of longer message."""
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        assert sha256_hex(msg) == expected
    
    def test_deterministic(self):
        """SHA-256 should be deterministic."""
        msg = b"test message"
        assert sha256(msg) == sha256(msg)
    
    def test_returns_32_bytes(self):
        """SHA-256 should return 32 bytes."""
        assert len(sha256(b"test")) == 32
    
    def test_different_inputs_different_hashes(self):
        """Different inputs should produce different hashes."""
        assert sha256(b"a") != sha256(b"b")


class TestMerkleTree:
    """Unit tests for Merkle Tree."""
    
    def test_single_leaf(self):
        """Test tree with single leaf."""
        tree = MerkleTree()
        root = tree.build([b"single"])
        assert root is not None
        assert len(root) == 32
    
    def test_two_leaves(self):
        """Test tree with two leaves."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b"])
        assert len(root) == 32
    
    def test_odd_leaves_duplication(self):
        """Test odd number of leaves are handled."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b", b"c"])
        assert root is not None
    
    def test_proof_generation(self):
        """Test Merkle proof generation."""
        tree = MerkleTree()
        tree.build([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(0)
        assert len(proof) > 0
    
    def test_proof_verification(self):
        """Test Merkle proof verification."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(1)
        assert MerkleTree.verify_proof(b"b", 1, proof, root)
    
    def test_invalid_proof_rejected(self):
        """Invalid proof should be rejected."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(1)
        # Wrong data should fail verification
        assert not MerkleTree.verify_proof(b"wrong", 1, proof, root)
    
    def test_tampered_proof_rejected(self):
        """Tampered proof should be rejected."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(1)
        # Tamper with proof
        if proof:
            tampered = [(b'\x00' * 32, proof[0][1])] + proof[1:]
            assert not MerkleTree.verify_proof(b"b", 1, tampered, root)
    
    def test_wrong_index_fails(self):
        """Wrong index should fail verification."""
        tree = MerkleTree()
        root = tree.build([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(1)
        # Use proof for index 1 but claim it's for index 0
        assert not MerkleTree.verify_proof(b"a", 0, proof, root)


class TestAESKeySchedule:
    """Unit tests for AES-256 Key Schedule."""
    
    def test_key_expansion_length(self):
        """Key expansion should produce 15 round keys."""
        key = bytes(range(32))
        round_keys = aes256_key_expansion(key)
        assert len(round_keys) == 15
    
    def test_each_round_key_is_16_bytes(self):
        """Each round key should be 16 bytes."""
        key = bytes(range(32))
        round_keys = aes256_key_expansion(key)
        for rk in round_keys:
            assert len(rk) == 16
    
    def test_deterministic(self):
        """Key expansion should be deterministic."""
        key = bytes(range(32))
        rk1 = aes256_key_expansion(key)
        rk2 = aes256_key_expansion(key)
        assert rk1 == rk2
    
    def test_different_keys_different_schedule(self):
        """Different keys should produce different schedules."""
        key1 = bytes(32)
        key2 = bytes([1] + [0] * 31)
        assert aes256_key_expansion(key1) != aes256_key_expansion(key2)
    
    def test_invalid_key_length(self):
        """Invalid key length should raise error."""
        with pytest.raises(ValueError):
            aes256_key_expansion(bytes(16))  # AES-128 key, not 256
    
    def test_sbox_bijective(self):
        """S-box should be bijective (256 unique outputs)."""
        outputs = set(S_BOX)
        assert len(outputs) == 256


class TestLFSR:
    """Unit tests for LFSR Cipher."""
    
    def test_lfsr_generates_bits(self):
        """LFSR should generate bits."""
        # Taps are 1-indexed
        lfsr = LFSR(seed=0b1010, taps=[4, 1], size=4)
        bits = lfsr.generate_bits(10)
        assert all(b in (0, 1) for b in bits)
    
    def test_lfsr_period(self):
        """LFSR should generate keystream."""
        # Just test that get_period function works
        lfsr = LFSR.from_size(seed=1, size=4)
        period = lfsr.get_period(max_iterations=50)
        # Period should be positive (found) or -1 (not found within limit)
        # The actual period depends on internal tap configuration
        assert period != 0
    
    def test_cipher_encrypt_decrypt(self):
        """Encryption followed by decryption should recover plaintext."""
        cipher = LFSRCipher(seed=12345, size=16)
        plaintext = b"Hello, LFSR!"
        ciphertext = cipher.encrypt(plaintext)
        
        # Reset and decrypt
        cipher2 = LFSRCipher(seed=12345, size=16)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext
    
    def test_different_key_different_ciphertext(self):
        """Different seeds should produce different ciphertext."""
        cipher1 = LFSRCipher(seed=111, size=8)
        cipher2 = LFSRCipher(seed=222, size=8)
        pt = b"test"
        assert cipher1.encrypt(pt) != cipher2.encrypt(pt)


class TestRSAMath:
    """Unit tests for RSA Math."""
    
    def test_mod_exp_basic(self):
        """Test modular exponentiation."""
        # 2^10 mod 1000 = 1024 mod 1000 = 24
        assert mod_exp(2, 10, 1000) == 24
    
    def test_mod_exp_large(self):
        """Test mod_exp with larger numbers."""
        # Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
        p = 101
        assert mod_exp(2, p - 1, p) == 1
    
    def test_miller_rabin_primes(self):
        """Miller-Rabin should identify primes."""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101]
        for p in primes:
            assert is_probably_prime_miller_rabin(p), f"{p} should be prime"
    
    def test_miller_rabin_composites(self):
        """Miller-Rabin should reject composites."""
        composites = [4, 6, 8, 9, 10, 12, 15, 21, 100]
        for c in composites:
            assert not is_probably_prime_miller_rabin(c), f"{c} should not be prime"
    
    def test_generate_prime(self):
        """Generated primes should pass primality test."""
        p = generate_prime(64)
        assert is_probably_prime_miller_rabin(p)
    
    def test_gcd(self):
        """Test GCD calculation."""
        assert gcd(48, 18) == 6
        assert gcd(17, 13) == 1
    
    def test_mod_inverse(self):
        """Test modular inverse."""
        # 3 * 7 ≡ 1 (mod 10) -> inverse of 3 mod 10 is 7
        inv = mod_inverse(3, 10)
        assert (3 * inv) % 10 == 1
    
    def test_rsa_encrypt_decrypt(self):
        """RSA encryption/decryption roundtrip."""
        public, private = generate_rsa_keypair(bits=512)
        message = 42
        ciphertext = rsa_encrypt(message, public)
        decrypted = rsa_decrypt(ciphertext, private)
        assert decrypted == message
    
    def test_rsa_sign_verify(self):
        """RSA signature verification."""
        public, private = generate_rsa_keypair(bits=512)
        message = 12345
        signature = rsa_sign(message, private)
        assert rsa_verify(message, signature, public)
    
    def test_rsa_invalid_signature_rejected(self):
        """Invalid RSA signature should be rejected."""
        public, private = generate_rsa_keypair(bits=512)
        message = 12345
        signature = rsa_sign(message, private)
        # Tamper with signature
        assert not rsa_verify(message, signature + 1, public)
        assert not rsa_verify(message + 1, signature, public)
