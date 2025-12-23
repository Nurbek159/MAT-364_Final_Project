# Blockchain Module
"""
Blockchain Ledger implementation including:
- Merkle root for transaction integrity
- SHA-256 chaining (using custom implementation)
- Proof of Work consensus
- Adjustable difficulty target

Security features:
- Immutable blocks (frozen dataclass)
- Full chain validation
- No skipping validation
"""

# Lazy imports to avoid RuntimeWarning when running module directly
def __getattr__(name):
    """Lazy import to avoid circular import issues."""
    from . import ledger
    return getattr(ledger, name)

__all__ = [
    'Block',
    'Blockchain',
    'ProofOfWork',
    'ValidationError',
    'create_blockchain',
    'mine_transactions',
    'compute_block_hash',
    'GENESIS_PREV_HASH',
    'DEFAULT_DIFFICULTY',
    'MAX_NONCE',
]
"""
Blockchain implementations including:
- Block structure
- Chain validation
- Proof of work
"""
