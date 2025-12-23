"""
Unit tests for Authentication module.

Tests:
- Password hashing (Argon2id)
- Login with rate limiting
- TOTP (including invalid codes)
"""

import pytest
import time
import hmac
import hashlib
import struct
from unittest.mock import patch

from src.auth.registration import (
    PasswordHasher_, UserRegistration, validate_password_strength
)
from src.auth.login import (
    RateLimiter, SessionManager, LoginManager, secure_compare
)
from src.auth.totp import (
    hotp, totp, TOTPGenerator, TOTPManager,
    generate_secret, TOTP_DIGITS, TOTP_TIME_STEP
)


class TestPasswordHashing:
    """Unit tests for password hashing."""
    
    def test_hash_password(self):
        """Password hashing should work."""
        hasher = PasswordHasher_()
        hash_result = hasher.hash_password("SecureP@ss123!")
        assert hash_result is not None
        assert len(hash_result) > 0
    
    def test_verify_correct_password(self):
        """Correct password should verify."""
        hasher = PasswordHasher_()
        password = "MySecurePassword123!"
        hash_result = hasher.hash_password(password)
        assert hasher.verify_password(password, hash_result)
    
    def test_verify_wrong_password(self):
        """Wrong password should fail verification."""
        hasher = PasswordHasher_()
        hash_result = hasher.hash_password("SecureP@ss123!Correct")
        assert not hasher.verify_password("SecureP@ss123!Wrong", hash_result)
    
    def test_different_passwords_different_hashes(self):
        """Different passwords should have different hashes."""
        hasher = PasswordHasher_()
        hash1 = hasher.hash_password("SecureP@ss123!One")
        hash2 = hasher.hash_password("SecureP@ss123!Two")
        assert hash1 != hash2
    
    def test_same_password_different_hashes(self):
        """Same password should have different hashes (random salt)."""
        hasher = PasswordHasher_()
        hash1 = hasher.hash_password("SecureP@ss123!Same")
        hash2 = hasher.hash_password("SecureP@ss123!Same")
        assert hash1 != hash2  # Different salts


class TestPasswordStrength:
    """Tests for password strength validation."""
    
    def test_strong_password(self):
        """Strong password should pass."""
        result = validate_password_strength("MyStr0ng!Pass@123")
        assert result['valid']
    
    def test_short_password_rejected(self):
        """Short password should be rejected."""
        result = validate_password_strength("Ab1!")
        assert not result['valid']
    
    def test_no_uppercase_rejected(self):
        """Password without uppercase should be rejected."""
        result = validate_password_strength("nouppercase123!")
        assert not result['valid']
    
    def test_no_digit_rejected(self):
        """Password without digit should be rejected."""
        result = validate_password_strength("nodigitshere!")
        assert not result['valid']


class TestUserRegistration:
    """Tests for user registration."""
    
    def test_register_user(self):
        """User registration should work."""
        reg = UserRegistration()
        result = reg.register_user("testuser", "SecureP@ss123!")
        assert result['success']
    
    def test_duplicate_user_rejected(self):
        """Duplicate username should be rejected."""
        reg = UserRegistration()
        reg.register_user("duplicate", "SecureP@ss123!")
        result = reg.register_user("duplicate", "AnotherP@ss123!")
        assert not result['success']
        assert "exists" in result['message'].lower()
    
    def test_weak_password_rejected(self):
        """Weak password should be rejected."""
        reg = UserRegistration()
        result = reg.register_user("newuser", "weak")
        assert not result['success']


class TestRateLimiter:
    """Tests for rate limiting."""
    
    def test_allows_initial_attempts(self):
        """Rate limiter should allow initial attempts."""
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        is_locked, _ = limiter.is_locked_out("user1")
        assert not is_locked
    
    def test_blocks_after_max_attempts(self):
        """Rate limiter should block after max attempts."""
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        limiter.record_attempt("user1", success=False)
        limiter.record_attempt("user1", success=False)
        is_locked, _ = limiter.is_locked_out("user1")
        assert is_locked
    
    def test_different_users_independent(self):
        """Different users should have independent limits."""
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        limiter.record_attempt("user1", success=False)
        is_locked, _ = limiter.is_locked_out("user2")
        assert not is_locked


class TestSessionManager:
    """Tests for session management."""
    
    def test_create_session(self):
        """Session creation should work."""
        mgr = SessionManager()
        token, session = mgr.create_session("uid123", "user1")
        assert token is not None
        assert len(token) > 0
    
    def test_validate_session(self):
        """Valid session should be validated."""
        mgr = SessionManager()
        token, session = mgr.create_session("uid123", "user1")
        verified = mgr.verify_token(session.session_id, token)
        assert verified is not None
    
    def test_invalid_token_rejected(self):
        """Invalid token should be rejected."""
        mgr = SessionManager()
        token, session = mgr.create_session("uid123", "user1")
        verified = mgr.verify_token(session.session_id, "wrong_token")
        assert verified is None
    
    def test_invalidate_session(self):
        """Invalidated session should be rejected."""
        mgr = SessionManager()
        token, session = mgr.create_session("uid123", "user1")
        mgr.invalidate_session(session.session_id)
        verified = mgr.verify_token(session.session_id, token)
        assert verified is None


class TestSecureCompare:
    """Tests for secure comparison."""
    
    def test_equal_strings(self):
        """Equal strings should match."""
        assert secure_compare("abc", "abc")
    
    def test_different_strings(self):
        """Different strings should not match."""
        assert not secure_compare("abc", "abd")
    
    def test_different_lengths(self):
        """Different length strings should not match."""
        assert not secure_compare("abc", "abcd")


class TestLoginManager:
    """Tests for login manager."""
    
    def test_login_success(self):
        """Valid credentials should login successfully."""
        reg = UserRegistration()
        reg.register_user("testuser", "SecureP@ss123!")
        
        mgr = LoginManager(user_store=reg._users)
        result = mgr.login("testuser", "SecureP@ss123!")
        assert result['success']
    
    def test_login_wrong_password(self):
        """Wrong password should fail login."""
        reg = UserRegistration()
        reg.register_user("testuser", "SecureP@ss123!")
        
        mgr = LoginManager(user_store=reg._users)
        result = mgr.login("testuser", "WrongP@ssword123!")
        assert not result['success']
    
    def test_login_unknown_user(self):
        """Unknown user should fail login."""
        mgr = LoginManager()
        result = mgr.login("unknown", "AnyPassword123!")
        assert not result['success']


class TestTOTP:
    """Tests for TOTP implementation."""
    
    def test_hotp_generates_code(self):
        """HOTP should generate valid code."""
        secret = b"12345678901234567890"
        code = hotp(secret, 0)
        assert len(code) == TOTP_DIGITS
        assert code.isdigit()
    
    def test_hotp_deterministic(self):
        """HOTP should be deterministic."""
        secret = b"testsecret123456"
        assert hotp(secret, 1) == hotp(secret, 1)
    
    def test_hotp_different_counters(self):
        """Different counters should produce different codes."""
        secret = b"testsecret123456"
        assert hotp(secret, 0) != hotp(secret, 1)
    
    def test_totp_generates_code(self):
        """TOTP should generate valid code."""
        secret = b"12345678901234567890"
        code = totp(secret)
        assert len(code) == TOTP_DIGITS
        assert code.isdigit()
    
    def test_totp_generator_verify(self):
        """TOTP generator should verify correct code."""
        gen = TOTPGenerator()
        code = gen.generate()
        assert gen.verify(code)
    
    def test_totp_wrong_code_rejected(self):
        """Wrong TOTP code should be rejected."""
        gen = TOTPGenerator()
        # Generate a definitely wrong code
        wrong_code = "000000"
        real_code = gen.generate()
        if wrong_code == real_code:
            wrong_code = "111111"
        assert not gen.verify(wrong_code)
    
    def test_totp_invalid_format_rejected(self):
        """Invalid TOTP format should be rejected."""
        gen = TOTPGenerator()
        assert not gen.verify("12345")  # too short
        assert not gen.verify("1234567")  # too long
        assert not gen.verify("abcdef")  # not digits
    
    def test_totp_expired_code_rejected(self):
        """Expired TOTP code should be rejected."""
        gen = TOTPGenerator()
        
        # Generate code at current time
        current_time = time.time()
        code = gen.generate(timestamp=current_time)
        
        # try to verify at a much later time
        later_time = current_time + (TOTP_TIME_STEP * 60)
        assert not gen.verify(code, timestamp=later_time)
    
    def test_totp_manager_setup(self):
        """TOTP manager setup should work."""
        mgr = TOTPManager()
        secret_b32, uri = mgr.create_secret("user1", "testuser@example.com")
        assert secret_b32 is not None
        assert "otpauth://" in uri
    
    def test_totp_manager_verify(self):
        """TOTP manager should verify codes."""
        mgr = TOTPManager()
        
        #create a secret and verify directly
        secret = generate_secret()
        gen = TOTPGenerator(secret=secret)
        code = gen.generate()
        
        assert mgr.verify_code(secret, code)
    
    def test_totp_manager_wrong_user(self):
        """Wrong TOTP code should fail verification."""
        mgr = TOTPManager()
        fake_secret = generate_secret()
        #a random code should fail
        assert not mgr.verify_code(fake_secret, "123456")
