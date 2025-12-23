"""
User Login Module

Implements secure authentication with:
- HMAC-SHA256 session tokens
- Rate limiting to prevent brute-force attacks
- Constant-time comparison for security
- Session management

Security considerations:
- Use constant-time comparison (hmac.compare_digest) for hash comparison
- Rate limiting prevents brute-force attacks
- Session tokens are cryptographically random
- Never log sensitive data (passwords, tokens)
"""

import secrets
import hmac
import hashlib
import time
from typing import Dict, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field


# Session configuration
SESSION_TOKEN_BYTES = 32  # 256-bit tokens
SESSION_EXPIRY_SECONDS = 3600  # 1 hour default
SESSION_SECRET_KEY = secrets.token_bytes(32)  # Server-side secret for HMAC

# Rate limiting configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes
ATTEMPT_WINDOW_SECONDS = 300    # 5 minute window for counting attempts


@dataclass
class LoginAttempt:
    """Track login attempts for rate limiting."""
    attempts: int = 0
    first_attempt_time: float = 0.0
    lockout_until: float = 0.0


@dataclass
class Session:
    """Represents an authenticated session."""
    session_id: str
    user_id: str
    username: str
    created_at: float
    expires_at: float
    token_hash: str  # HMAC of the token for verification
    is_valid: bool = True
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return time.time() > self.expires_at


class RateLimiter:
    """
    Rate limiter to prevent brute-force login attacks.
    
    Tracks failed login attempts per username/IP and enforces
    lockout periods after too many failures.
    """
    
    def __init__(self, max_attempts: int = MAX_LOGIN_ATTEMPTS,
                 lockout_duration: int = LOCKOUT_DURATION_SECONDS,
                 window_seconds: int = ATTEMPT_WINDOW_SECONDS):
        """
        Initialize rate limiter.
        
        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_duration: Lockout duration in seconds
            window_seconds: Time window for counting attempts
        """
        self._attempts: Dict[str, LoginAttempt] = defaultdict(LoginAttempt)
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration
        self._window_seconds = window_seconds
    
    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if an identifier (username/IP) is locked out.
        
        Args:
            identifier: Username or IP to check
            
        Returns:
            Tuple of (is_locked, seconds_remaining)
        """
        attempt = self._attempts.get(identifier)
        if not attempt:
            return False, 0
        
        now = time.time()
        
        if attempt.lockout_until > now:
            remaining = int(attempt.lockout_until - now)
            return True, remaining
        
        # Reset if window has passed
        if now - attempt.first_attempt_time > self._window_seconds:
            self._attempts[identifier] = LoginAttempt()
            return False, 0
        
        return False, 0
    
    def record_attempt(self, identifier: str, success: bool) -> None:
        """
        Record a login attempt.
        
        Args:
            identifier: Username or IP
            success: Whether the login was successful
        """
        now = time.time()
        
        if success:
            # Reset on successful login
            self._attempts[identifier] = LoginAttempt()
            return
        
        attempt = self._attempts[identifier]
        
        # Reset if window has passed
        if now - attempt.first_attempt_time > self._window_seconds:
            attempt = LoginAttempt()
            self._attempts[identifier] = attempt
        
        if attempt.attempts == 0:
            attempt.first_attempt_time = now
        
        attempt.attempts += 1
        
        # Lock out if too many attempts
        if attempt.attempts >= self._max_attempts:
            attempt.lockout_until = now + self._lockout_duration
    
    def get_remaining_attempts(self, identifier: str) -> int:
        """Get number of remaining login attempts."""
        attempt = self._attempts.get(identifier)
        if not attempt:
            return self._max_attempts
        
        now = time.time()
        if now - attempt.first_attempt_time > self._window_seconds:
            return self._max_attempts
        
        return max(0, self._max_attempts - attempt.attempts)
    
    def reset(self, identifier: str) -> None:
        """Reset attempts for an identifier."""
        self._attempts[identifier] = LoginAttempt()


class SessionManager:
    """
    Manages authenticated sessions with HMAC-SHA256 tokens.
    
    Security features:
    - Cryptographically random session tokens
    - HMAC-SHA256 for token verification
    - Automatic session expiration
    - Constant-time token comparison
    """
    
    def __init__(self, secret_key: bytes = None,
                 expiry_seconds: int = SESSION_EXPIRY_SECONDS):
        """
        Initialize session manager.
        
        Args:
            secret_key: Server-side secret for HMAC (generated if not provided)
            expiry_seconds: Session lifetime in seconds
        """
        self._secret_key = secret_key or secrets.token_bytes(32)
        self._expiry_seconds = expiry_seconds
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, str] = {}  # user_id -> session_id
    
    def _generate_token(self) -> Tuple[str, str]:
        """
        Generate a secure session token and its HMAC.
        
        Returns:
            Tuple of (token, token_hash)
        """
        # Generate random token
        token = secrets.token_hex(SESSION_TOKEN_BYTES)
        
        # Create HMAC for verification
        token_hash = hmac.new(
            self._secret_key,
            token.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return token, token_hash
    
    def create_session(self, user_id: str, username: str) -> Tuple[str, Session]:
        """
        Create a new authenticated session.
        
        Args:
            user_id: User's unique identifier
            username: User's username
            
        Returns:
            Tuple of (session_token, Session object)
        """
        # Invalidate existing session for this user
        if user_id in self._user_sessions:
            old_session_id = self._user_sessions[user_id]
            if old_session_id in self._sessions:
                self._sessions[old_session_id].is_valid = False
                del self._sessions[old_session_id]
        
        # Generate new token
        token, token_hash = self._generate_token()
        session_id = secrets.token_hex(16)
        
        now = time.time()
        session = Session(
            session_id=session_id,
            user_id=user_id,
            username=username,
            created_at=now,
            expires_at=now + self._expiry_seconds,
            token_hash=token_hash,
            is_valid=True
        )
        
        self._sessions[session_id] = session
        self._user_sessions[user_id] = session_id
        
        return token, session
    
    def verify_token(self, session_id: str, token: str) -> Optional[Session]:
        """
        Verify a session token using constant-time comparison.
        
        Args:
            session_id: Session identifier
            token: Session token to verify
            
        Returns:
            Session if valid, None otherwise
        """
        session = self._sessions.get(session_id)
        if not session:
            return None
        
        if not session.is_valid or session.is_expired():
            return None
        
        # Compute HMAC of provided token
        provided_hash = hmac.new(
            self._secret_key,
            token.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # CONSTANT-TIME comparison (prevents timing attacks)
        if hmac.compare_digest(provided_hash, session.token_hash):
            return session
        
        return None
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate (logout) a session.
        
        Args:
            session_id: Session to invalidate
            
        Returns:
            True if session was invalidated, False if not found
        """
        session = self._sessions.get(session_id)
        if session:
            session.is_valid = False
            if session.user_id in self._user_sessions:
                del self._user_sessions[session.user_id]
            del self._sessions[session_id]
            return True
        return False
    
    def cleanup_expired(self) -> int:
        """
        Remove expired sessions.
        
        Returns:
            Number of sessions removed
        """
        expired = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]
        
        for sid in expired:
            session = self._sessions[sid]
            if session.user_id in self._user_sessions:
                del self._user_sessions[session.user_id]
            del self._sessions[sid]
        
        return len(expired)
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID (without token verification)."""
        return self._sessions.get(session_id)


class LoginManager:
    """
    Complete login management with rate limiting and session handling.
    
    Example:
        >>> login_mgr = LoginManager(user_store)
        >>> result = login_mgr.login("alice", "password123")
        >>> if result['success']:
        ...     token = result['token']
        ...     session = result['session']
    """
    
    def __init__(self, user_store: Dict = None, 
                 password_verifier=None,
                 totp_verifier=None):
        """
        Initialize login manager.
        
        Args:
            user_store: Dict of username -> user data
            password_verifier: Function to verify password (password, hash) -> bool
            totp_verifier: Optional function for 2FA (secret, code) -> bool
        """
        self._users = user_store or {}
        self._password_verifier = password_verifier
        self._totp_verifier = totp_verifier
        self._rate_limiter = RateLimiter()
        self._session_manager = SessionManager()
    
    def login(self, username: str, password: str, 
              totp_code: Optional[str] = None,
              client_ip: Optional[str] = None) -> Dict:
        """
        Authenticate a user and create a session.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            totp_code: Optional TOTP code for 2FA
            client_ip: Optional client IP for rate limiting
            
        Returns:
            Dict with 'success', 'message', and optionally 'token', 'session'
        """
        # Rate limiting check
        identifier = client_ip or username
        is_locked, remaining = self._rate_limiter.is_locked_out(identifier)
        
        if is_locked:
            return {
                'success': False,
                'message': f'Account locked. Try again in {remaining} seconds.',
                'locked': True,
                'lockout_remaining': remaining
            }
        
        # Get user
        user = self._users.get(username)
        if not user:
            # Record failed attempt (but don't reveal user doesn't exist)
            self._rate_limiter.record_attempt(identifier, False)
            return {
                'success': False,
                'message': 'Invalid username or password',
                'attempts_remaining': self._rate_limiter.get_remaining_attempts(identifier)
            }
        
        # Verify password
        password_hash = user.get('password_hash', '')
        
        if self._password_verifier:
            password_valid = self._password_verifier(password, password_hash)
        else:
            # Default: use argon2 verification
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            hasher = PasswordHasher()
            try:
                hasher.verify(password_hash, password)
                password_valid = True
            except VerifyMismatchError:
                password_valid = False
        
        if not password_valid:
            self._rate_limiter.record_attempt(identifier, False)
            return {
                'success': False,
                'message': 'Invalid username or password',
                'attempts_remaining': self._rate_limiter.get_remaining_attempts(identifier)
            }
        
        # Check 2FA if enabled
        if user.get('totp_enabled') and user.get('totp_secret'):
            if not totp_code:
                return {
                    'success': False,
                    'message': 'TOTP code required',
                    'requires_totp': True
                }
            
            if self._totp_verifier:
                totp_valid = self._totp_verifier(user['totp_secret'], totp_code)
            else:
                totp_valid = False  # No verifier configured
            
            if not totp_valid:
                self._rate_limiter.record_attempt(identifier, False)
                return {
                    'success': False,
                    'message': 'Invalid TOTP code',
                    'attempts_remaining': self._rate_limiter.get_remaining_attempts(identifier)
                }
        
        # Successful login
        self._rate_limiter.record_attempt(identifier, True)
        
        # Create session
        token, session = self._session_manager.create_session(
            user['user_id'],
            username
        )
        
        return {
            'success': True,
            'message': 'Login successful',
            'token': token,
            'session_id': session.session_id,
            'user_id': user['user_id'],
            'expires_at': session.expires_at
        }
    
    def logout(self, session_id: str) -> Dict:
        """
        Log out by invalidating a session.
        
        Args:
            session_id: Session to invalidate
            
        Returns:
            Dict with 'success' and 'message'
        """
        if self._session_manager.invalidate_session(session_id):
            return {'success': True, 'message': 'Logged out successfully'}
        return {'success': False, 'message': 'Session not found'}
    
    def verify_session(self, session_id: str, token: str) -> Optional[Session]:
        """
        Verify a session token.
        
        Args:
            session_id: Session identifier
            token: Session token
            
        Returns:
            Session if valid, None otherwise
        """
        return self._session_manager.verify_token(session_id, token)
    
    @property
    def rate_limiter(self) -> RateLimiter:
        """Access rate limiter."""
        return self._rate_limiter
    
    @property
    def session_manager(self) -> SessionManager:
        """Access session manager."""
        return self._session_manager


def secure_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison.
    
    Prevents timing attacks by ensuring comparison takes
    the same amount of time regardless of where strings differ.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a.encode(), b.encode())


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_hex(SESSION_TOKEN_BYTES)


def create_hmac_token(data: str, secret_key: bytes) -> str:
    """
    Create an HMAC-SHA256 token.
    
    Args:
        data: Data to authenticate
        secret_key: Secret key for HMAC
        
    Returns:
        Hex-encoded HMAC
    """
    return hmac.new(secret_key, data.encode(), hashlib.sha256).hexdigest()


def verify_hmac_token(data: str, token: str, secret_key: bytes) -> bool:
    """
    Verify an HMAC-SHA256 token using constant-time comparison.
    
    Args:
        data: Original data
        token: HMAC token to verify
        secret_key: Secret key for HMAC
        
    Returns:
        True if token is valid, False otherwise
    """
    expected = hmac.new(secret_key, data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)


# Self-test when run directly
if __name__ == "__main__":
    print("Login Module Test")
    print("=" * 60)
    
    # Setup test user store
    from argon2 import PasswordHasher
    hasher = PasswordHasher()
    
    test_users = {
        'testuser': {
            'user_id': 'user123',
            'username': 'testuser',
            'password_hash': hasher.hash('TestPass123!'),
            'totp_enabled': False,
            'totp_secret': None,
        }
    }
    
    # Test 1: Rate limiter
    print("\n[Test 1] Rate limiter")
    limiter = RateLimiter(max_attempts=3, lockout_duration=10)
    
    for i in range(4):
        limiter.record_attempt('testip', False)
        locked, remaining = limiter.is_locked_out('testip')
        print(f"  Attempt {i+1}: locked={locked}, remaining={limiter.get_remaining_attempts('testip')}")
    
    test1_pass = limiter.is_locked_out('testip')[0]
    print(f"  Lockout triggered: {'✓ PASS' if test1_pass else '✗ FAIL'}")
    
    # Test 2: Session management
    print("\n[Test 2] Session management")
    session_mgr = SessionManager(expiry_seconds=3600)
    token, session = session_mgr.create_session('user123', 'testuser')
    
    print(f"  Session ID: {session.session_id}")
    print(f"  Token (first 32 chars): {token[:32]}...")
    
    # Verify valid token
    verified = session_mgr.verify_token(session.session_id, token)
    test2a_pass = verified is not None
    print(f"  Valid token verified: {'✓' if test2a_pass else '✗'}")
    
    # Verify invalid token
    verified_bad = session_mgr.verify_token(session.session_id, 'wrong_token')
    test2b_pass = verified_bad is None
    print(f"  Invalid token rejected: {'✓' if test2b_pass else '✗'}")
    
    test2_pass = test2a_pass and test2b_pass
    print(f"  Status: {'✓ PASS' if test2_pass else '✗ FAIL'}")
    
    # Test 3: Login flow
    print("\n[Test 3] Complete login flow")
    login_mgr = LoginManager(user_store=test_users)
    
    # Successful login
    result = login_mgr.login('testuser', 'TestPass123!')
    test3a_pass = result['success']
    print(f"  Valid credentials: success={result['success']}")
    
    # Failed login
    result_bad = login_mgr.login('testuser', 'WrongPassword')
    test3b_pass = not result_bad['success']
    print(f"  Invalid credentials: success={result_bad['success']}")
    
    test3_pass = test3a_pass and test3b_pass
    print(f"  Status: {'✓ PASS' if test3_pass else '✗ FAIL'}")
    
    # Test 4: HMAC token verification
    print("\n[Test 4] HMAC-SHA256 token verification")
    secret = secrets.token_bytes(32)
    data = "session_data_123"
    token = create_hmac_token(data, secret)
    
    valid = verify_hmac_token(data, token, secret)
    invalid = verify_hmac_token("tampered_data", token, secret)
    
    test4_pass = valid and not invalid
    print(f"  Valid data verified: {valid}")
    print(f"  Tampered data rejected: {not invalid}")
    print(f"  Status: {'✓ PASS' if test4_pass else '✗ FAIL'}")
    
    # Test 5: Constant-time comparison
    print("\n[Test 5] Constant-time comparison")
    test5_pass = secure_compare("hello", "hello") and not secure_compare("hello", "world")
    print(f"  Equal strings: {secure_compare('hello', 'hello')}")
    print(f"  Different strings: {secure_compare('hello', 'world')}")
    print(f"  Status: {'✓ PASS' if test5_pass else '✗ FAIL'}")
    
    # Summary
    all_passed = test1_pass and test2_pass and test3_pass and test4_pass and test5_pass
    print("\n" + "=" * 60)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
