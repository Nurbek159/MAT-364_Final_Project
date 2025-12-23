"""
User Registration Module

Implements secure password hashing using Argon2id algorithm.

Features:
- Argon2id password hashing (winner of Password Hashing Competition)
- Cryptographically secure random salt generation
- Password strength validation
- Secure storage format

Security considerations:
- Never store plaintext passwords
- Use constant-time comparison for hash verification
- Salt is automatically handled by argon2-cffi
"""

import secrets
import re
from typing import Tuple, Optional, Dict
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import hmac


# Argon2id configuration
# These parameters balance security and performance
# - time_cost: number of iterations
# - memory_cost: memory usage in KiB
# - parallelism: number of parallel threads
# - hash_len: length of the hash output
# - salt_len: length of the random salt
ARGON2_CONFIG = {
    'time_cost': 3,          # Number of iterations
    'memory_cost': 65536,    # 64 MiB memory
    'parallelism': 4,        # 4 parallel threads
    'hash_len': 32,          # 256-bit hash
    'salt_len': 16,          # 128-bit salt
    'type': Type.ID          # Argon2id (hybrid)
}


# Password strength requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
PASSWORD_REQUIREMENTS = {
    'min_length': PASSWORD_MIN_LENGTH,
    'max_length': PASSWORD_MAX_LENGTH,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_special': True,
}


class PasswordHasher_:
    """
    Secure password hasher using Argon2id.
    
    Argon2id is the recommended variant for password hashing as it
    provides resistance against both side-channel and GPU attacks.
    
    Example:
        >>> hasher = PasswordHasher_()
        >>> hash = hasher.hash_password("SecurePass123!")
        >>> hasher.verify_password("SecurePass123!", hash)
        True
    """
    
    def __init__(self, **kwargs):
        """
        Initialize the password hasher with Argon2id.
        
        Args:
            **kwargs: Override default Argon2 parameters
        """
        config = ARGON2_CONFIG.copy()
        config.update(kwargs)
        
        self._hasher = PasswordHasher(
            time_cost=config['time_cost'],
            memory_cost=config['memory_cost'],
            parallelism=config['parallelism'],
            hash_len=config['hash_len'],
            salt_len=config['salt_len'],
            type=config['type']
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.
        
        The resulting hash contains the algorithm parameters and salt,
        allowing for future parameter upgrades.
        
        Args:
            password: Plaintext password to hash
            
        Returns:
            Argon2id hash string (includes salt and parameters)
            
        Raises:
            ValueError: If password doesn't meet requirements
        """
        # Validate password strength
        validation = validate_password_strength(password)
        if not validation['valid']:
            raise ValueError(f"Password too weak: {', '.join(validation['errors'])}")
        
        # Hash with Argon2id (salt is automatically generated)
        return self._hasher.hash(password)
    
    def verify_password(self, password: str, hash_str: str) -> bool:
        """
        Verify a password against an Argon2id hash.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            password: Plaintext password to verify
            hash_str: Argon2id hash string to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            self._hasher.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False
        except InvalidHashError:
            return False
    
    def needs_rehash(self, hash_str: str) -> bool:
        """
        Check if a hash needs to be rehashed with updated parameters.
        
        Useful for upgrading security parameters over time.
        
        Args:
            hash_str: Existing hash to check
            
        Returns:
            True if hash should be regenerated with new parameters
        """
        return self._hasher.check_needs_rehash(hash_str)


def generate_secure_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Args:
        length: Salt length in bytes (default 16 = 128 bits)
        
    Returns:
        Random bytes suitable for use as salt
    """
    return secrets.token_bytes(length)


def validate_password_strength(password: str) -> Dict:
    """
    Validate password against strength requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Dict with 'valid' bool and 'errors' list
    """
    errors = []
    
    # Length checks
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"Must be at most {PASSWORD_MAX_LENGTH} characters")
    
    # Character class checks
    if PASSWORD_REQUIREMENTS['require_uppercase'] and not re.search(r'[A-Z]', password):
        errors.append("Must contain at least one uppercase letter")
    
    if PASSWORD_REQUIREMENTS['require_lowercase'] and not re.search(r'[a-z]', password):
        errors.append("Must contain at least one lowercase letter")
    
    if PASSWORD_REQUIREMENTS['require_digit'] and not re.search(r'\d', password):
        errors.append("Must contain at least one digit")
    
    if PASSWORD_REQUIREMENTS['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Must contain at least one special character")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'score': calculate_password_score(password)
    }


def calculate_password_score(password: str) -> int:
    """
    Calculate a password strength score (0-100).
    
    Args:
        password: Password to score
        
    Returns:
        Score from 0 (weak) to 100 (strong)
    """
    score = 0
    
    # Length scoring (up to 30 points)
    score += min(len(password) * 2, 30)
    
    # Character variety (up to 40 points)
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[A-Z]', password):
        score += 10
    if re.search(r'\d', password):
        score += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 10
    
    # Bonus for length (up to 20 points)
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    # Penalty for common patterns
    if re.search(r'(.)\1{2,}', password):  # Repeated characters
        score -= 10
    if re.search(r'(012|123|234|345|456|567|678|789)', password):  # Sequential numbers
        score -= 10
    if re.search(r'(abc|bcd|cde|def|efg)', password.lower()):  # Sequential letters
        score -= 10
    
    return max(0, min(100, score))


class UserRegistration:
    """
    User registration handler with secure password storage.
    
    Example:
        >>> reg = UserRegistration()
        >>> result = reg.register_user("alice", "SecurePass123!", "alice@example.com")
        >>> result['success']
        True
    """
    
    def __init__(self, user_store: Optional[Dict] = None):
        """
        Initialize registration handler.
        
        Args:
            user_store: Optional dict to use as user database
        """
        self._hasher = PasswordHasher_()
        self._users = user_store if user_store is not None else {}
    
    def register_user(self, username: str, password: str, 
                      email: Optional[str] = None) -> Dict:
        """
        Register a new user with secure password hashing.
        
        Args:
            username: Unique username
            password: Plaintext password (will be hashed)
            email: Optional email address
            
        Returns:
            Dict with 'success', 'message', and optionally 'user_id'
        """
        # Validate username
        if not username or len(username) < 3:
            return {'success': False, 'message': 'Username must be at least 3 characters'}
        
        if username in self._users:
            return {'success': False, 'message': 'Username already exists'}
        
        # Validate and hash password
        try:
            password_hash = self._hasher.hash_password(password)
        except ValueError as e:
            return {'success': False, 'message': str(e)}
        
        # Generate unique user ID
        user_id = secrets.token_hex(16)
        
        # Store user (never store plaintext password!)
        self._users[username] = {
            'user_id': user_id,
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'created_at': None,  # Would use datetime in production
            'totp_secret': None,
            'totp_enabled': False,
        }
        
        return {
            'success': True,
            'message': 'User registered successfully',
            'user_id': user_id
        }
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user data (excluding password hash for safety)."""
        user = self._users.get(username)
        if user:
            # Return copy without sensitive data
            return {
                'user_id': user['user_id'],
                'username': user['username'],
                'email': user['email'],
                'totp_enabled': user['totp_enabled'],
            }
        return None
    
    def get_password_hash(self, username: str) -> Optional[str]:
        """Get password hash for verification (internal use only)."""
        user = self._users.get(username)
        return user['password_hash'] if user else None
    
    def update_password(self, username: str, old_password: str, 
                        new_password: str) -> Dict:
        """
        Update user's password after verifying old password.
        
        Args:
            username: Username
            old_password: Current password for verification
            new_password: New password to set
            
        Returns:
            Dict with 'success' and 'message'
        """
        user = self._users.get(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        # Verify old password
        if not self._hasher.verify_password(old_password, user['password_hash']):
            return {'success': False, 'message': 'Current password is incorrect'}
        
        # Hash and store new password
        try:
            user['password_hash'] = self._hasher.hash_password(new_password)
        except ValueError as e:
            return {'success': False, 'message': str(e)}
        
        return {'success': True, 'message': 'Password updated successfully'}
    
    @property
    def users(self) -> Dict:
        """Access to user store (for testing)."""
        return self._users


# Module-level hasher instance
_default_hasher = PasswordHasher_()


def hash_password(password: str) -> str:
    """Convenience function to hash a password."""
    return _default_hasher.hash_password(password)


def verify_password(password: str, hash_str: str) -> bool:
    """Convenience function to verify a password."""
    return _default_hasher.verify_password(password, hash_str)


# Self-test when run directly
if __name__ == "__main__":
    print("User Registration Module Test")
    print("=" * 60)
    
    # Test 1: Password validation
    print("\n[Test 1] Password strength validation")
    test_passwords = [
        ("weak", False),
        ("Weakpass", False),
        ("Weakpass1", False),
        ("StrongPass1!", True),
        ("MyS3cur3P@ssw0rd!", True),
    ]
    test1_pass = True
    for pwd, expected_valid in test_passwords:
        result = validate_password_strength(pwd)
        passed = result['valid'] == expected_valid
        test1_pass = test1_pass and passed
        status = "✓" if passed else "✗"
        print(f"  {status} '{pwd}': valid={result['valid']}, score={result['score']}")
    
    # Test 2: Password hashing
    print("\n[Test 2] Argon2id password hashing")
    hasher = PasswordHasher_()
    password = "TestPassword123!"
    hash1 = hasher.hash_password(password)
    hash2 = hasher.hash_password(password)
    
    print(f"  Password: {password}")
    print(f"  Hash 1:   {hash1[:50]}...")
    print(f"  Hash 2:   {hash2[:50]}...")
    print(f"  Hashes are different (unique salts): {hash1 != hash2}")
    
    # Test 3: Password verification
    print("\n[Test 3] Password verification")
    correct = hasher.verify_password(password, hash1)
    incorrect = hasher.verify_password("WrongPassword!", hash1)
    test3_pass = correct and not incorrect
    print(f"  Correct password verified: {correct}")
    print(f"  Wrong password rejected:   {not incorrect}")
    print(f"  Status: {'✓ PASS' if test3_pass else '✗ FAIL'}")
    
    # Test 4: User registration
    print("\n[Test 4] User registration")
    reg = UserRegistration()
    result = reg.register_user("alice", "AliceSecure123!", "alice@example.com")
    test4_pass = result['success']
    print(f"  Registration result: {result}")
    print(f"  Status: {'✓ PASS' if test4_pass else '✗ FAIL'}")
    
    # Test 5: Duplicate registration
    print("\n[Test 5] Duplicate username rejection")
    result2 = reg.register_user("alice", "AnotherPass123!", "alice2@example.com")
    test5_pass = not result2['success']
    print(f"  Duplicate result: {result2}")
    print(f"  Status: {'✓ PASS' if test5_pass else '✗ FAIL'}")
    
    # Test 6: Password update
    print("\n[Test 6] Password update")
    update_result = reg.update_password("alice", "AliceSecure123!", "NewSecure456!")
    test6_pass = update_result['success']
    print(f"  Update result: {update_result}")
    print(f"  Status: {'✓ PASS' if test6_pass else '✗ FAIL'}")
    
    # Summary
    all_passed = test1_pass and test3_pass and test4_pass and test5_pass and test6_pass
    print("\n" + "=" * 60)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
