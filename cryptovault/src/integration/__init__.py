# Integration Module
"""
Integration and logging system that records events to the blockchain.

All events are logged with privacy-preserving user hashes.
"""

# Lazy imports to avoid RuntimeWarning when running module directly
def __getattr__(name):
    """Lazy import to avoid circular import issues."""
    from . import event_logger
    return getattr(event_logger, name)

__all__ = [
    'EventType',
    'SecurityEvent',
    'EventLogger',
    'get_user_hash',
    'create_event_logger',
]
