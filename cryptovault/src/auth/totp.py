"""
TOTP (Time-based One-Time Password) Implementation

Implements RFC 6238 TOTP for two-factor authentication.

Features:
- TOTP code generation and verification
- Configurable time step and digits
- Secret key generation
- QR code generation for authenticator apps
- Time drift tolerance

Used with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any RFC 6238 compliant authenticator
"""

import hmac
import hashlib
import secrets
import base64
import struct
import time
from typing import Optional, Tuple, List
from urllib.parse import quote

# Try to import qrcode for QR generation
try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# Try to import pyotp for reference implementation
try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False


# TOTP configuration (RFC 6238 defaults)
TOTP_DIGITS = 6           # Number of digits in OTP
TOTP_TIME_STEP = 30       # Time step in seconds
TOTP_SECRET_BYTES = 20    # Secret key length (160 bits for SHA-1)
TOTP_ALGORITHM = 'SHA1'   # Hash algorithm
TOTP_DRIFT_TOLERANCE = 1  # Accept codes from +/- this many time steps


def generate_secret(length: int = TOTP_SECRET_BYTES) -> bytes:
    """
    Generate a cryptographically secure random secret.
    
    Args:
        length: Secret length in bytes (default 20 for SHA-1)
        
    Returns:
        Random bytes for use as TOTP secret
    """
    return secrets.token_bytes(length)


def secret_to_base32(secret: bytes) -> str:
    """
    Encode secret as base32 string (for authenticator apps).
    
    Args:
        secret: Raw secret bytes
        
    Returns:
        Base32-encoded string (no padding)
    """
    return base64.b32encode(secret).decode('ascii').rstrip('=')


def base32_to_secret(encoded: str) -> bytes:
    """
    Decode base32 secret string to bytes.
    
    Args:
        encoded: Base32-encoded string
        
    Returns:
        Raw secret bytes
    """
    # Add padding if needed
    padding = 8 - (len(encoded) % 8)
    if padding != 8:
        encoded += '=' * padding
    return base64.b32decode(encoded.upper())


def get_time_counter(timestamp: float = None, time_step: int = TOTP_TIME_STEP) -> int:
    """
    Get the time counter value for TOTP.
    
    Args:
        timestamp: Unix timestamp (uses current time if None)
        time_step: Time step in seconds
        
    Returns:
        Time counter (T = floor(time / time_step))
    """
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp) // time_step


def hotp(secret: bytes, counter: int, digits: int = TOTP_DIGITS,
         algorithm: str = TOTP_ALGORITHM) -> str:
    """
    Generate HOTP (HMAC-based OTP) value.
    
    Implements RFC 4226.
    
    Args:
        secret: Shared secret key
        counter: Counter value (8-byte integer)
        digits: Number of digits in OTP (default 6)
        algorithm: Hash algorithm (SHA1, SHA256, SHA512)
        
    Returns:
        OTP string with specified number of digits
    """
    # Pack counter as 8-byte big-endian integer
    counter_bytes = struct.pack('>Q', counter)
    
    # Select hash algorithm
    hash_algo = {
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256,
        'SHA512': hashlib.sha512,
    }.get(algorithm.upper(), hashlib.sha1)
    
    # Compute HMAC
    hmac_hash = hmac.new(secret, counter_bytes, hash_algo).digest()
    
    # Dynamic truncation (RFC 4226)
    # Get offset from last 4 bits of hash
    offset = hmac_hash[-1] & 0x0F
    
    # Extract 4 bytes starting at offset
    truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
    
    # Clear the most significant bit (ensure positive number)
    truncated &= 0x7FFFFFFF
    
    # Get the specified number of digits
    otp = truncated % (10 ** digits)
    
    # Pad with leading zeros if needed
    return str(otp).zfill(digits)


def totp(secret: bytes, timestamp: float = None, 
         digits: int = TOTP_DIGITS,
         time_step: int = TOTP_TIME_STEP,
         algorithm: str = TOTP_ALGORITHM) -> str:
    """
    Generate TOTP (Time-based OTP) value.
    
    Implements RFC 6238.
    
    Args:
        secret: Shared secret key
        timestamp: Unix timestamp (uses current time if None)
        digits: Number of digits in OTP
        time_step: Time step in seconds
        algorithm: Hash algorithm
        
    Returns:
        TOTP string with specified number of digits
    """
    counter = get_time_counter(timestamp, time_step)
    return hotp(secret, counter, digits, algorithm)


def verify_totp(secret: bytes, code: str,
                timestamp: float = None,
                digits: int = TOTP_DIGITS,
                time_step: int = TOTP_TIME_STEP,
                algorithm: str = TOTP_ALGORITHM,
                drift_tolerance: int = TOTP_DRIFT_TOLERANCE) -> bool:
    """
    Verify a TOTP code with drift tolerance.
    
    Checks the code against current time step and +/- drift_tolerance
    time steps to account for clock drift.
    
    Args:
        secret: Shared secret key
        code: OTP code to verify
        timestamp: Unix timestamp (uses current time if None)
        digits: Expected number of digits
        time_step: Time step in seconds
        algorithm: Hash algorithm
        drift_tolerance: Number of time steps to check in each direction
        
    Returns:
        True if code is valid, False otherwise
    """
    if timestamp is None:
        timestamp = time.time()
    
    # Clean up code (remove spaces, ensure string)
    code = str(code).replace(' ', '').strip()
    
    # Verify length
    if len(code) != digits:
        return False
    
    current_counter = get_time_counter(timestamp, time_step)
    
    # Check current time step and +/- drift tolerance
    for offset in range(-drift_tolerance, drift_tolerance + 1):
        counter = current_counter + offset
        expected = hotp(secret, counter, digits, algorithm)
        
        # Use constant-time comparison
        if hmac.compare_digest(code, expected):
            return True
    
    return False


def get_remaining_seconds(time_step: int = TOTP_TIME_STEP) -> int:
    """
    Get seconds remaining until next TOTP code.
    
    Args:
        time_step: Time step in seconds
        
    Returns:
        Seconds until next code
    """
    return time_step - (int(time.time()) % time_step)


class TOTPGenerator:
    """
    TOTP generator and verifier for a specific secret.
    
    Example:
        >>> totp_gen = TOTPGenerator()
        >>> code = totp_gen.generate()
        >>> totp_gen.verify(code)
        True
    """
    
    def __init__(self, secret: bytes = None,
                 digits: int = TOTP_DIGITS,
                 time_step: int = TOTP_TIME_STEP,
                 algorithm: str = TOTP_ALGORITHM,
                 issuer: str = "CryptoVault",
                 account_name: str = "user"):
        """
        Initialize TOTP generator.
        
        Args:
            secret: Shared secret (generated if None)
            digits: Number of digits in OTP
            time_step: Time step in seconds
            algorithm: Hash algorithm
            issuer: Service name for authenticator apps
            account_name: Account identifier
        """
        self._secret = secret or generate_secret()
        self._digits = digits
        self._time_step = time_step
        self._algorithm = algorithm
        self._issuer = issuer
        self._account_name = account_name
        self._drift_tolerance = TOTP_DRIFT_TOLERANCE
    
    @property
    def secret(self) -> bytes:
        """Raw secret bytes."""
        return self._secret
    
    @property
    def secret_base32(self) -> str:
        """Base32-encoded secret for authenticator apps."""
        return secret_to_base32(self._secret)
    
    @property
    def time_step(self) -> int:
        """Time step in seconds."""
        return self._time_step
    
    @property
    def digits(self) -> int:
        """Number of digits in OTP."""
        return self._digits
    
    def generate(self, timestamp: float = None) -> str:
        """
        Generate TOTP code for current or specified time.
        
        Args:
            timestamp: Unix timestamp (uses current time if None)
            
        Returns:
            TOTP code string
        """
        return totp(
            self._secret,
            timestamp,
            self._digits,
            self._time_step,
            self._algorithm
        )
    
    def verify(self, code: str, timestamp: float = None) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            code: OTP code to verify
            timestamp: Unix timestamp (uses current time if None)
            
        Returns:
            True if code is valid
        """
        return verify_totp(
            self._secret,
            code,
            timestamp,
            self._digits,
            self._time_step,
            self._algorithm,
            self._drift_tolerance
        )
    
    def get_provisioning_uri(self) -> str:
        """
        Generate otpauth:// URI for QR code.
        
        This URI can be encoded as a QR code and scanned by
        authenticator apps like Google Authenticator.
        
        Returns:
            otpauth:// URI string
        """
        label = f"{self._issuer}:{self._account_name}"
        params = {
            'secret': self.secret_base32,
            'issuer': self._issuer,
            'algorithm': self._algorithm,
            'digits': str(self._digits),
            'period': str(self._time_step),
        }
        
        param_str = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"otpauth://totp/{quote(label)}?{param_str}"
    
    def generate_qr_code(self, filename: str = None) -> Optional[str]:
        """
        Generate QR code for authenticator app setup.
        
        Args:
            filename: Optional filename to save QR code image
            
        Returns:
            ASCII QR code string if no filename, else None
        """
        if not HAS_QRCODE:
            raise ImportError("qrcode library required for QR generation")
        
        uri = self.get_provisioning_uri()
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        if filename:
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(filename)
            return None
        else:
            # Return ASCII representation
            from io import StringIO
            f = StringIO()
            qr.print_ascii(out=f)
            return f.getvalue()
    
    def remaining_seconds(self) -> int:
        """Get seconds until next code."""
        return get_remaining_seconds(self._time_step)
    
    def __repr__(self) -> str:
        return f"TOTPGenerator(issuer='{self._issuer}', account='{self._account_name}')"


class TOTPManager:
    """
    Manage TOTP secrets for multiple users.
    
    Handles 2FA enrollment and verification.
    """
    
    def __init__(self, issuer: str = "CryptoVault"):
        """
        Initialize TOTP manager.
        
        Args:
            issuer: Service name shown in authenticator apps
        """
        self._issuer = issuer
        self._pending_secrets: dict = {}  # Secrets pending confirmation
    
    def create_secret(self, user_id: str, 
                      account_name: str) -> Tuple[str, str]:
        """
        Create a new TOTP secret for enrollment.
        
        The secret should be stored only after user confirms
        they can generate valid codes.
        
        Args:
            user_id: User identifier
            account_name: Account name (usually email)
            
        Returns:
            Tuple of (base32_secret, provisioning_uri)
        """
        secret = generate_secret()
        generator = TOTPGenerator(
            secret=secret,
            issuer=self._issuer,
            account_name=account_name
        )
        
        # Store pending (not confirmed yet)
        self._pending_secrets[user_id] = secret
        
        return generator.secret_base32, generator.get_provisioning_uri()
    
    def confirm_enrollment(self, user_id: str, code: str) -> Tuple[bool, Optional[bytes]]:
        """
        Confirm TOTP enrollment by verifying a code.
        
        Args:
            user_id: User identifier
            code: TOTP code from authenticator app
            
        Returns:
            Tuple of (success, secret_bytes if success else None)
        """
        secret = self._pending_secrets.get(user_id)
        if not secret:
            return False, None
        
        if verify_totp(secret, code):
            # Remove from pending
            del self._pending_secrets[user_id]
            return True, secret
        
        return False, None
    
    def verify_code(self, secret: bytes, code: str) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            secret: User's TOTP secret
            code: Code to verify
            
        Returns:
            True if valid
        """
        return verify_totp(secret, code)
    
    def cancel_enrollment(self, user_id: str) -> bool:
        """Cancel pending enrollment."""
        if user_id in self._pending_secrets:
            del self._pending_secrets[user_id]
            return True
        return False


# Self-test when run directly
if __name__ == "__main__":
    print("TOTP (RFC 6238) Implementation Test")
    print("=" * 60)
    
    # Test 1: HOTP generation (RFC 4226 test vectors)
    print("\n[Test 1] HOTP test vectors (RFC 4226)")
    # Test secret: "12345678901234567890" (20 bytes)
    test_secret = b"12345678901234567890"
    
    # RFC 4226 Appendix D test values
    expected_hotp = [
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489"
    ]
    
    test1_pass = True
    for counter, expected in enumerate(expected_hotp):
        result = hotp(test_secret, counter)
        passed = result == expected
        test1_pass = test1_pass and passed
        if not passed:
            print(f"  Counter {counter}: {result} (expected {expected}) ✗")
    
    print(f"  All 10 HOTP test vectors: {'✓ PASS' if test1_pass else '✗ FAIL'}")
    
    # Test 2: TOTP generation
    print("\n[Test 2] TOTP generation")
    generator = TOTPGenerator(
        secret=test_secret,
        issuer="TestApp",
        account_name="test@example.com"
    )
    
    current_code = generator.generate()
    print(f"  Current TOTP: {current_code}")
    print(f"  Valid for: {generator.remaining_seconds()} more seconds")
    print(f"  Secret (base32): {generator.secret_base32}")
    
    # Test 3: TOTP verification
    print("\n[Test 3] TOTP verification")
    verified = generator.verify(current_code)
    test3a_pass = verified
    print(f"  Current code verified: {'✓' if verified else '✗'}")
    
    # Wrong code should fail
    wrong_verified = generator.verify("000000")
    test3b_pass = not wrong_verified
    print(f"  Wrong code rejected: {'✓' if not wrong_verified else '✗'}")
    
    test3_pass = test3a_pass and test3b_pass
    print(f"  Status: {'✓ PASS' if test3_pass else '✗ FAIL'}")
    
    # Test 4: Time drift tolerance
    print("\n[Test 4] Time drift tolerance")
    now = time.time()
    
    # Generate code for previous time step
    prev_step = now - TOTP_TIME_STEP
    prev_code = generator.generate(prev_step)
    
    # Should still verify due to drift tolerance
    drift_verified = generator.verify(prev_code)
    test4_pass = drift_verified
    print(f"  Previous time step code accepted: {'✓' if drift_verified else '✗'}")
    print(f"  Status: {'✓ PASS' if test4_pass else '✗ FAIL'}")
    
    # Test 5: Provisioning URI
    print("\n[Test 5] Provisioning URI")
    uri = generator.get_provisioning_uri()
    test5_pass = uri.startswith("otpauth://totp/")
    print(f"  URI: {uri[:60]}...")
    print(f"  Valid format: {'✓ PASS' if test5_pass else '✗ FAIL'}")
    
    # Test 6: Compare with pyotp if available
    if HAS_PYOTP:
        print("\n[Test 6] Comparison with pyotp library")
        pyotp_gen = pyotp.TOTP(generator.secret_base32)
        pyotp_code = pyotp_gen.now()
        our_code = generator.generate()
        
        test6_pass = pyotp_code == our_code
        print(f"  Our implementation: {our_code}")
        print(f"  pyotp library:      {pyotp_code}")
        print(f"  Match: {'✓ PASS' if test6_pass else '✗ FAIL'}")
    else:
        test6_pass = True
        print("\n[Test 6] Skipped (pyotp not installed)")
    
    # Test 7: TOTP Manager enrollment flow
    print("\n[Test 7] TOTP enrollment flow")
    manager = TOTPManager(issuer="CryptoVault")
    
    secret_b32, prov_uri = manager.create_secret("user123", "alice@example.com")
    print(f"  Created secret: {secret_b32[:16]}...")
    
    # Generate a valid code and confirm
    temp_gen = TOTPGenerator(secret=base32_to_secret(secret_b32))
    valid_code = temp_gen.generate()
    
    success, confirmed_secret = manager.confirm_enrollment("user123", valid_code)
    test7_pass = success and confirmed_secret is not None
    print(f"  Enrollment confirmed: {'✓ PASS' if test7_pass else '✗ FAIL'}")
    
    # Summary
    all_passed = test1_pass and test3_pass and test4_pass and test5_pass and test6_pass and test7_pass
    print("\n" + "=" * 60)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
