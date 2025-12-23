# Authentication Module
"""
Authentication implementations including:
- Password hashing (Argon2id) - registration.py
- TOTP/HOTP (2FA, RFC 6238) - totp.py
- HMAC-SHA256 session tokens - login.py
- Rate limiting - login.py

Security features:
- Argon2id for password hashing (PHC winner)
- Constant-time comparison for hash verification
- Cryptographically secure random tokens
- Rate limiting against brute-force attacks
"""

from .registration import (
    PasswordHasher_,
    UserRegistration,
    hash_password,
    verify_password,
    validate_password_strength,
    generate_secure_salt,
)

from .login import (
    LoginManager,
    SessionManager,
    RateLimiter,
    Session,
    secure_compare,
    generate_session_token,
    create_hmac_token,
    verify_hmac_token,
)

from .totp import (
    TOTPGenerator,
    TOTPManager,
    totp,
    verify_totp,
    hotp,
    generate_secret,
    secret_to_base32,
    base32_to_secret,
)

__all__ = [
    # Registration
    'PasswordHasher_',
    'UserRegistration',
    'hash_password',
    'verify_password',
    'validate_password_strength',
    'generate_secure_salt',
    # Login
    'LoginManager',
    'SessionManager',
    'RateLimiter',
    'Session',
    'secure_compare',
    'generate_session_token',
    'create_hmac_token',
    'verify_hmac_token',
    # TOTP
    'TOTPGenerator',
    'TOTPManager',
    'totp',
    'verify_totp',
    'hotp',
    'generate_secret',
    'secret_to_base32',
    'base32_to_secret',
]
