"""
Event Logger Module

Integrates all cryptovault modules with blockchain-based event logging.
Every security event is recorded to the blockchain for audit trail.

Features:
- Login events
- File encryption events  
- Message send events
- Privacy-preserving user hashes (SHA-256)
- Tamper-evident audit log via blockchain

Author: CryptoVault Project
"""

import time
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Callable

# Use our custom SHA-256 for privacy hashing
from ..core_crypto.sha256 import sha256, sha256_hex
from ..blockchain.ledger import Blockchain, Block, create_blockchain


# ============================================================================
# Constants
# ============================================================================

DEFAULT_DIFFICULTY = 4  # Lower difficulty for faster logging
EVENT_VERSION = "1.0"


# ============================================================================
# Privacy Functions
# ============================================================================

def get_user_hash(username: str) -> str:
    """
    Compute privacy-preserving hash of username.
    
    Uses SHA-256 to ensure usernames are never stored in plaintext
    on the blockchain, while still allowing correlation of events
    for the same user.
    
    Args:
        username: The plaintext username
        
    Returns:
        Hex-encoded SHA-256 hash of the username
    """
    user_hash = sha256(username.encode())
    return user_hash.hex()


def get_user_hash_short(username: str) -> str:
    """
    Get shortened user hash for display purposes.
    
    Args:
        username: The plaintext username
        
    Returns:
        First 16 characters of the hex hash
    """
    return get_user_hash(username)[:16]


# ============================================================================
# Event Types
# ============================================================================

class EventType(Enum):
    """Types of security events that can be logged."""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    TOTP_VERIFIED = "totp_verified"
    TOTP_FAILED = "totp_failed"
    
    # File encryption events
    FILE_ENCRYPT = "file_encrypt"
    FILE_DECRYPT = "file_decrypt"
    FILE_INTEGRITY_CHECK = "file_integrity_check"
    FILE_INTEGRITY_FAILED = "file_integrity_failed"
    
    # Messaging events
    MESSAGE_SEND = "message_send"
    MESSAGE_RECEIVE = "message_receive"
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE_VERIFIED = "signature_verified"
    SIGNATURE_FAILED = "signature_failed"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"


# ============================================================================
# Event Structure
# ============================================================================

@dataclass
class SecurityEvent:
    """
    Represents a security event to be logged.
    
    All user-identifying information is hashed for privacy.
    """
    event_type: EventType
    user_hash: str  # SHA-256 hash of username
    timestamp: int  # Unix timestamp
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_transaction(self) -> str:
        """Convert event to blockchain transaction string."""
        return json.dumps({
            'version': EVENT_VERSION,
            'type': self.event_type.value,
            'user': self.user_hash[:16],  # Short hash for readability
            'time': self.timestamp,
            'iso_time': datetime.fromtimestamp(self.timestamp).isoformat(),
            'details': self.details,
        }, separators=(',', ':'))  # Compact JSON
    
    @classmethod
    def from_transaction(cls, tx_str: str) -> 'SecurityEvent':
        """Parse event from blockchain transaction."""
        data = json.loads(tx_str)
        return cls(
            event_type=EventType(data['type']),
            user_hash=data['user'],
            timestamp=data['time'],
            details=data.get('details', {}),
        )
    
    def __str__(self) -> str:
        dt = datetime.fromtimestamp(self.timestamp)
        return (
            f"[{dt.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{self.event_type.value} | "
            f"user:{self.user_hash[:8]}..."
        )


# ============================================================================
# Event Logger
# ============================================================================

class EventLogger:
    """
    Blockchain-based event logger for security audit trail.
    
    All events are recorded to an immutable blockchain, providing
    a tamper-evident log of all security-relevant actions.
    """
    
    def __init__(
        self,
        difficulty: int = DEFAULT_DIFFICULTY,
        blockchain: Optional[Blockchain] = None,
        auto_mine: bool = True,
        batch_size: int = 10
    ):
        """
        Initialize the event logger.
        
        Args:
            difficulty: Proof of Work difficulty for blockchain
            blockchain: Optional existing blockchain to use
            auto_mine: If True, mine blocks automatically
            batch_size: Number of events before auto-mining
        """
        self._blockchain = blockchain or create_blockchain(difficulty)
        self._auto_mine = auto_mine
        self._batch_size = batch_size
        self._event_count = 0
        self._callbacks: List[Callable[[SecurityEvent], None]] = []
        
        # Log system start
        self._log_system_event(EventType.SYSTEM_START)
    
    def _log_system_event(self, event_type: EventType) -> None:
        """Log a system event (no user)."""
        event = SecurityEvent(
            event_type=event_type,
            user_hash="system",
            timestamp=int(time.time()),
            details={'node': 'cryptovault'}
        )
        self._add_event(event)
    
    def _add_event(self, event: SecurityEvent) -> None:
        """Add event to pending transactions."""
        self._blockchain.add_transaction(event.to_transaction())
        self._event_count += 1
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't let callbacks break logging
        
        # Auto-mine if batch size reached
        if self._auto_mine and self._event_count >= self._batch_size:
            self.mine_events()
    
    def add_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Add a callback to be notified of new events."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    # ========================================================================
    # Login Events
    # ========================================================================
    
    def log_login(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> SecurityEvent:
        """
        Log a login attempt.
        
        Args:
            username: The username (will be hashed)
            success: Whether login was successful
            ip_address: Optional IP address (will be hashed)
            user_agent: Optional user agent string
            
        Returns:
            The logged event
        """
        user_hash = get_user_hash(username)
        
        details = {}
        if ip_address:
            # Hash IP for privacy
            details['ip_hash'] = sha256_hex(ip_address.encode())[:16]
        if user_agent:
            # Just store browser family, not full UA
            details['ua'] = user_agent[:50] if user_agent else None
        
        event = SecurityEvent(
            event_type=EventType.LOGIN_SUCCESS if success else EventType.LOGIN_FAILED,
            user_hash=user_hash,
            timestamp=int(time.time()),
            details=details
        )
        
        self._add_event(event)
        return event
    
    def log_logout(self, username: str) -> SecurityEvent:
        """Log a logout event."""
        event = SecurityEvent(
            event_type=EventType.LOGOUT,
            user_hash=get_user_hash(username),
            timestamp=int(time.time()),
        )
        self._add_event(event)
        return event
    
    def log_totp(self, username: str, success: bool) -> SecurityEvent:
        """Log TOTP verification attempt."""
        event = SecurityEvent(
            event_type=EventType.TOTP_VERIFIED if success else EventType.TOTP_FAILED,
            user_hash=get_user_hash(username),
            timestamp=int(time.time()),
        )
        self._add_event(event)
        return event
    
    # ========================================================================
    # File Encryption Events
    # ========================================================================
    
    def log_file_encrypt(
        self,
        username: str,
        file_hash: str,
        file_size: int,
        algorithm: str = "AES-256-GCM"
    ) -> SecurityEvent:
        """
        Log a file encryption event.
        
        Args:
            username: The username (will be hashed)
            file_hash: Hash of the file (for identification without revealing content)
            file_size: Size of the file in bytes
            algorithm: Encryption algorithm used
            
        Returns:
            The logged event
        """
        event = SecurityEvent(
            event_type=EventType.FILE_ENCRYPT,
            user_hash=get_user_hash(username),
            timestamp=int(time.time()),
            details={
                'file_id': file_hash[:16],  # Short hash for identification
                'size': file_size,
                'algo': algorithm,
            }
        )
        self._add_event(event)
        return event
    
    def log_file_decrypt(
        self,
        username: str,
        file_hash: str,
        success: bool = True
    ) -> SecurityEvent:
        """Log a file decryption event."""
        event = SecurityEvent(
            event_type=EventType.FILE_DECRYPT if success else EventType.FILE_INTEGRITY_FAILED,
            user_hash=get_user_hash(username),
            timestamp=int(time.time()),
            details={
                'file_id': file_hash[:16],
                'success': success,
            }
        )
        self._add_event(event)
        return event
    
    # ========================================================================
    # Messaging Events
    # ========================================================================
    
    def log_message_send(
        self,
        sender: str,
        recipient: str,
        message_hash: str,
        encrypted: bool = True,
        signed: bool = True
    ) -> SecurityEvent:
        """
        Log a message send event.
        
        Args:
            sender: Sender username (will be hashed)
            recipient: Recipient username (will be hashed)
            message_hash: Hash of message content
            encrypted: Whether message was encrypted
            signed: Whether message was signed
            
        Returns:
            The logged event
        """
        event = SecurityEvent(
            event_type=EventType.MESSAGE_SEND,
            user_hash=get_user_hash(sender),
            timestamp=int(time.time()),
            details={
                'to': get_user_hash_short(recipient),
                'msg_id': message_hash[:16],
                'encrypted': encrypted,
                'signed': signed,
            }
        )
        self._add_event(event)
        return event
    
    def log_message_receive(
        self,
        recipient: str,
        sender: str,
        message_hash: str,
        verified: bool = True
    ) -> SecurityEvent:
        """Log a message receive event."""
        event = SecurityEvent(
            event_type=EventType.MESSAGE_RECEIVE,
            user_hash=get_user_hash(recipient),
            timestamp=int(time.time()),
            details={
                'from': get_user_hash_short(sender),
                'msg_id': message_hash[:16],
                'verified': verified,
            }
        )
        self._add_event(event)
        return event
    
    def log_key_exchange(
        self,
        user1: str,
        user2: str,
        algorithm: str = "ECDH-P256"
    ) -> SecurityEvent:
        """Log a key exchange event."""
        event = SecurityEvent(
            event_type=EventType.KEY_EXCHANGE,
            user_hash=get_user_hash(user1),
            timestamp=int(time.time()),
            details={
                'peer': get_user_hash_short(user2),
                'algo': algorithm,
            }
        )
        self._add_event(event)
        return event
    
    # ========================================================================
    # Mining and Retrieval
    # ========================================================================
    
    def mine_events(self) -> Optional[Block]:
        """
        Mine pending events into a new block.
        
        Returns:
            The new block, or None if no pending events
        """
        if not self._blockchain.pending_transactions:
            return None
        
        block = self._blockchain.mine_block()
        self._event_count = 0
        return block
    
    def flush(self) -> Optional[Block]:
        """Alias for mine_events - ensure all events are committed."""
        return self.mine_events()
    
    def get_blockchain(self) -> Blockchain:
        """Get the underlying blockchain."""
        return self._blockchain
    
    def get_all_events(self) -> List[SecurityEvent]:
        """
        Retrieve all logged events from the blockchain.
        
        Returns:
            List of all security events
        """
        events = []
        for block in self._blockchain.chain:
            for tx in block.transactions:
                try:
                    # Skip genesis/non-event transactions
                    if tx.startswith('{"version"'):
                        events.append(SecurityEvent.from_transaction(tx))
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass  # Skip non-event transactions
        return events
    
    def get_user_events(self, username: str) -> List[SecurityEvent]:
        """
        Get all events for a specific user.
        
        Args:
            username: The username to search for
            
        Returns:
            List of events for that user
        """
        user_hash_short = get_user_hash_short(username)
        return [
            e for e in self.get_all_events()
            if e.user_hash.startswith(user_hash_short[:8])
        ]
    
    def get_events_by_type(self, event_type: EventType) -> List[SecurityEvent]:
        """Get all events of a specific type."""
        return [
            e for e in self.get_all_events()
            if e.event_type == event_type
        ]
    
    def get_recent_events(self, count: int = 10) -> List[SecurityEvent]:
        """Get the most recent events."""
        events = self.get_all_events()
        return events[-count:] if len(events) > count else events
    
    def print_audit_log(self, last_n: Optional[int] = None) -> None:
        """Print the audit log in a readable format."""
        events = self.get_all_events()
        if last_n:
            events = events[-last_n:]
        
        print("\n" + "=" * 70)
        print("SECURITY AUDIT LOG")
        print("=" * 70)
        
        for event in events:
            print(event)
            if event.details:
                for k, v in event.details.items():
                    print(f"    {k}: {v}")
        
        print("=" * 70)
        print(f"Total events: {len(self.get_all_events())}")
        print(f"Blockchain length: {self._blockchain.length}")
        print("=" * 70)
    
    def verify_integrity(self) -> bool:
        """Verify the integrity of the audit log."""
        try:
            return self._blockchain.validate_chain()
        except Exception:
            return False
    
    def export_log(self) -> str:
        """Export the entire audit log as JSON."""
        return self._blockchain.to_json()
    
    @classmethod
    def import_log(cls, json_str: str) -> 'EventLogger':
        """Import an audit log from JSON."""
        blockchain = Blockchain.from_json(json_str)
        logger = cls(blockchain=blockchain, auto_mine=True)
        return logger


# ============================================================================
# Convenience Functions
# ============================================================================

def create_event_logger(difficulty: int = DEFAULT_DIFFICULTY) -> EventLogger:
    """Create a new event logger."""
    return EventLogger(difficulty=difficulty)


# ============================================================================
# Self-Test
# ============================================================================

def _run_tests():
    """Run comprehensive tests for the event logger module."""
    print("Event Logger Integration Test")
    print("=" * 70)
    
    tests_passed = 0
    tests_total = 0
    
    def test(name: str, condition: bool, details: str = ""):
        nonlocal tests_passed, tests_total
        tests_total += 1
        status = "✓ PASS" if condition else "✗ FAIL"
        print(f"\n[Test {tests_total}] {name}")
        if details:
            print(f"  {details}")
        print(f"  Status: {status}")
        if condition:
            tests_passed += 1
        return condition
    
    # Test 1: Privacy - User hash generation
    username = "alice@example.com"
    user_hash = get_user_hash(username)
    hash_correct = (
        len(user_hash) == 64 and  # 32 bytes = 64 hex chars
        user_hash == get_user_hash(username)  # Deterministic
    )
    test(
        "Privacy: SHA-256 user hash",
        hash_correct,
        f"Username: '{username}' → Hash: {user_hash[:32]}..."
    )
    
    # Test 2: Create event logger
    logger = EventLogger(difficulty=4, auto_mine=False)
    logger_created = logger is not None and logger._blockchain.length == 1
    test(
        "Create event logger with blockchain",
        logger_created,
        f"Blockchain initialized with genesis block"
    )
    
    # Test 3: Log login event
    login_event = logger.log_login(
        username="alice",
        success=True,
        ip_address="192.168.1.100"
    )
    login_logged = (
        login_event.event_type == EventType.LOGIN_SUCCESS and
        login_event.user_hash == get_user_hash("alice")
    )
    test(
        "Log LOGIN event",
        login_logged,
        f"Event: {login_event}"
    )
    
    # Test 4: Log file encrypt event
    file_hash = sha256_hex(b"test file content")
    encrypt_event = logger.log_file_encrypt(
        username="alice",
        file_hash=file_hash,
        file_size=1024
    )
    encrypt_logged = encrypt_event.event_type == EventType.FILE_ENCRYPT
    test(
        "Log FILE_ENCRYPT event",
        encrypt_logged,
        f"Event: {encrypt_event}"
    )
    
    # Test 5: Log message send event
    msg_hash = sha256_hex(b"Hello Bob!")
    msg_event = logger.log_message_send(
        sender="alice",
        recipient="bob",
        message_hash=msg_hash
    )
    msg_logged = (
        msg_event.event_type == EventType.MESSAGE_SEND and
        'to' in msg_event.details
    )
    test(
        "Log MESSAGE_SEND event",
        msg_logged,
        f"Event: {msg_event}"
    )
    
    # Test 6: Mine events to blockchain
    block = logger.mine_events()
    mined = (
        block is not None and
        block.index == 1 and
        len(block.transactions) >= 3  # login, encrypt, message
    )
    test(
        "Mine events to blockchain",
        mined,
        f"Block #{block.index if block else 'N/A'} with {len(block.transactions) if block else 0} transactions"
    )
    
    # Test 7: Events are in blockchain
    chain = logger.get_blockchain()
    tx_count = sum(len(b.transactions) for b in chain.chain)
    events_stored = tx_count >= 4  # genesis + 3 events + system_start
    test(
        "Events stored in blockchain",
        events_stored,
        f"Total transactions across all blocks: {tx_count}"
    )
    
    # Test 8: Retrieve all events
    all_events = logger.get_all_events()
    events_retrieved = len(all_events) >= 3  # At least our 3 test events
    test(
        "Retrieve all events from blockchain",
        events_retrieved,
        f"Retrieved {len(all_events)} events"
    )
    
    # Test 9: Filter by user
    alice_events = logger.get_user_events("alice")
    user_filter = len(alice_events) >= 3  # login, encrypt, message
    test(
        "Filter events by user",
        user_filter,
        f"Events for 'alice': {len(alice_events)}"
    )
    
    # Test 10: Filter by type
    login_events = logger.get_events_by_type(EventType.LOGIN_SUCCESS)
    type_filter = len(login_events) >= 1
    test(
        "Filter events by type",
        type_filter,
        f"LOGIN_SUCCESS events: {len(login_events)}"
    )
    
    # Test 11: Blockchain integrity
    integrity = logger.verify_integrity()
    test(
        "Blockchain integrity verification",
        integrity,
        f"Chain valid: {integrity}"
    )
    
    # Test 12: Privacy - usernames not in plaintext
    log_json = logger.export_log()
    privacy_ok = (
        "alice" not in log_json and
        "bob" not in log_json and
        get_user_hash("alice")[:16] in log_json  # But hash is there
    )
    test(
        "Privacy: No plaintext usernames in log",
        privacy_ok,
        f"Usernames hashed, only short hashes stored"
    )
    
    # Test 13: Export/Import
    exported = logger.export_log()
    imported = EventLogger.import_log(exported)
    import_ok = (
        imported._blockchain.length == logger._blockchain.length and
        len(imported.get_all_events()) == len(all_events)
    )
    test(
        "Export/Import audit log",
        import_ok,
        f"Imported blockchain length: {imported._blockchain.length}"
    )
    
    # Test 14: Auto-mine feature
    auto_logger = EventLogger(difficulty=4, auto_mine=True, batch_size=3)
    for i in range(5):
        auto_logger.log_login(f"user{i}", success=True)
    auto_logger.flush()  # Ensure all mined
    auto_mined = auto_logger._blockchain.length > 1
    test(
        "Auto-mine after batch size",
        auto_mined,
        f"Blocks after 5 logins: {auto_logger._blockchain.length}"
    )
    
    # Print audit log sample
    print("\n" + "=" * 70)
    print("Sample Audit Log:")
    logger.print_audit_log()
    
    # Print summary
    print("\n" + "=" * 70)
    print(f"Overall: {tests_passed}/{tests_total} tests passed!")
    
    return tests_passed == tests_total


if __name__ == "__main__":
    success = _run_tests()
    exit(0 if success else 1)
