"""
Blockchain Ledger Module

Implements a simple blockchain with:
- Merkle root for transaction integrity
- SHA-256 chaining (using our custom implementation)
- Proof of Work consensus
- Adjustable difficulty target

Security features:
- Immutable blocks (frozen dataclass)
- Full chain validation
- Merkle proofs for transaction verification

Author: CryptoVault Project
"""

import time
import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
from enum import Enum

# Use our custom implementations
from ..core_crypto.sha256 import sha256, sha256_hex
from ..core_crypto.merkle import MerkleTree


# ============================================================================
# Constants
# ============================================================================

GENESIS_PREV_HASH = b'\x00' * 32  # 32 zero bytes for genesis block
DEFAULT_DIFFICULTY = 4  # Number of leading zero bits required
MAX_NONCE = 2 ** 32  # Maximum nonce value before giving up


# ============================================================================
# Block Structure (Immutable)
# ============================================================================

@dataclass(frozen=True)
class Block:
    """
    Immutable block structure for the blockchain.
    
    frozen=True ensures blocks cannot be modified after creation,
    which is essential for blockchain integrity.
    """
    index: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    nonce: int
    hash: bytes
    transactions: Tuple[str, ...]  # Immutable tuple of transactions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary for serialization."""
        return {
            'index': self.index,
            'prev_hash': self.prev_hash.hex(),
            'merkle_root': self.merkle_root.hex(),
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'hash': self.hash.hex(),
            'transactions': list(self.transactions),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create block from dictionary."""
        return cls(
            index=data['index'],
            prev_hash=bytes.fromhex(data['prev_hash']),
            merkle_root=bytes.fromhex(data['merkle_root']),
            timestamp=data['timestamp'],
            nonce=data['nonce'],
            hash=bytes.fromhex(data['hash']),
            transactions=tuple(data['transactions']),
        )
    
    def __str__(self) -> str:
        return (
            f"Block #{self.index}\n"
            f"  Hash: {self.hash.hex()[:16]}...\n"
            f"  Prev: {self.prev_hash.hex()[:16]}...\n"
            f"  Merkle: {self.merkle_root.hex()[:16]}...\n"
            f"  Nonce: {self.nonce}\n"
            f"  Transactions: {len(self.transactions)}"
        )


# ============================================================================
# Proof of Work
# ============================================================================

class ProofOfWork:
    """
    Proof of Work implementation with adjustable difficulty.
    
    Difficulty is measured in leading zero BITS required in the hash.
    Higher difficulty = more computational work required.
    """
    
    def __init__(self, difficulty: int = DEFAULT_DIFFICULTY):
        """
        Initialize PoW with given difficulty.
        
        Args:
            difficulty: Number of leading zero bits required (1-256)
        """
        if not 1 <= difficulty <= 256:
            raise ValueError("Difficulty must be between 1 and 256")
        self.difficulty = difficulty
        self._target = self._calculate_target(difficulty)
    
    @staticmethod
    def _calculate_target(difficulty: int) -> int:
        """
        Calculate the target value for given difficulty.
        
        A valid hash must be less than this target.
        """
        # Target = 2^(256 - difficulty)
        # More difficulty = smaller target = harder to find valid hash
        return 2 ** (256 - difficulty)
    
    @property
    def target(self) -> int:
        """Get current target as integer."""
        return self._target
    
    @property
    def target_hex(self) -> str:
        """Get current target as hex string (64 chars, padded)."""
        return format(self._target, '064x')
    
    def hash_meets_target(self, hash_bytes: bytes) -> bool:
        """Check if a hash meets the difficulty target."""
        hash_int = int.from_bytes(hash_bytes, 'big')
        return hash_int < self._target
    
    def count_leading_zeros(self, hash_bytes: bytes) -> int:
        """Count leading zero bits in a hash."""
        hash_int = int.from_bytes(hash_bytes, 'big')
        if hash_int == 0:
            return 256
        # Count leading zeros
        return 256 - hash_int.bit_length()
    
    def mine(
        self,
        index: int,
        prev_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        max_nonce: int = MAX_NONCE
    ) -> Tuple[int, bytes]:
        """
        Mine for a valid nonce (Proof of Work).
        
        Args:
            index: Block index
            prev_hash: Previous block hash
            merkle_root: Merkle root of transactions
            timestamp: Block timestamp
            max_nonce: Maximum attempts before giving up
            
        Returns:
            Tuple of (nonce, hash) if successful
            
        Raises:
            RuntimeError: If no valid nonce found within limit
        """
        for nonce in range(max_nonce):
            # Compute block hash with this nonce
            block_hash = self._compute_block_hash(
                index, prev_hash, merkle_root, timestamp, nonce
            )
            
            if self.hash_meets_target(block_hash):
                return nonce, block_hash
        
        raise RuntimeError(
            f"Failed to find valid nonce after {max_nonce} attempts"
        )
    
    @staticmethod
    def _compute_block_hash(
        index: int,
        prev_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        nonce: int
    ) -> bytes:
        """Compute hash for block header."""
        # Serialize block header
        header = (
            index.to_bytes(8, 'big') +
            prev_hash +
            merkle_root +
            timestamp.to_bytes(8, 'big') +
            nonce.to_bytes(8, 'big')
        )
        # Double SHA-256 (like Bitcoin)
        return sha256(sha256(header))


def compute_block_hash(
    index: int,
    prev_hash: bytes,
    merkle_root: bytes,
    timestamp: int,
    nonce: int
) -> bytes:
    """Compute hash for a block (public function)."""
    return ProofOfWork._compute_block_hash(
        index, prev_hash, merkle_root, timestamp, nonce
    )


# ============================================================================
# Blockchain
# ============================================================================

class ValidationError(Exception):
    """Raised when blockchain validation fails."""
    pass


class Blockchain:
    """
    A simple blockchain implementation.
    
    Features:
    - Merkle root for transaction integrity
    - SHA-256 chaining with double hashing
    - Proof of Work consensus
    - Full chain validation
    - Immutable blocks
    """
    
    def __init__(self, difficulty: int = DEFAULT_DIFFICULTY):
        """
        Initialize a new blockchain.
        
        Args:
            difficulty: PoW difficulty (leading zero bits required)
        """
        self._chain: List[Block] = []
        self._pow = ProofOfWork(difficulty)
        self._pending_transactions: List[str] = []
        
        # Create genesis block
        self._create_genesis_block()
    
    def _create_genesis_block(self) -> None:
        """Create the genesis (first) block."""
        genesis_tx = ["Genesis Block - CryptoVault Blockchain"]
        
        # Compute merkle root
        merkle_tree = MerkleTree()
        merkle_root = merkle_tree.build([tx.encode() for tx in genesis_tx])
        
        timestamp = 0  # Genesis uses timestamp 0
        
        # Mine genesis block
        nonce, block_hash = self._pow.mine(
            index=0,
            prev_hash=GENESIS_PREV_HASH,
            merkle_root=merkle_root,
            timestamp=timestamp
        )
        
        # Create immutable genesis block
        genesis = Block(
            index=0,
            prev_hash=GENESIS_PREV_HASH,
            merkle_root=merkle_root,
            timestamp=timestamp,
            nonce=nonce,
            hash=block_hash,
            transactions=tuple(genesis_tx)
        )
        
        self._chain.append(genesis)
    
    @property
    def chain(self) -> List[Block]:
        """Get the blockchain (read-only view)."""
        return list(self._chain)  # Return copy to prevent mutation
    
    @property
    def length(self) -> int:
        """Get blockchain length."""
        return len(self._chain)
    
    @property
    def last_block(self) -> Block:
        """Get the last block in the chain."""
        return self._chain[-1]
    
    @property
    def difficulty(self) -> int:
        """Get current difficulty."""
        return self._pow.difficulty
    
    @property
    def pending_transactions(self) -> List[str]:
        """Get pending transactions."""
        return list(self._pending_transactions)
    
    def add_transaction(self, transaction: str) -> int:
        """
        Add a transaction to the pending pool.
        
        Args:
            transaction: Transaction data (string)
            
        Returns:
            Number of pending transactions
        """
        if not transaction:
            raise ValueError("Transaction cannot be empty")
        self._pending_transactions.append(transaction)
        return len(self._pending_transactions)
    
    def mine_block(self) -> Block:
        """
        Mine a new block with pending transactions.
        
        Returns:
            The newly mined block
            
        Raises:
            ValueError: If no pending transactions
        """
        if not self._pending_transactions:
            raise ValueError("No pending transactions to mine")
        
        # Get transactions for this block
        transactions = self._pending_transactions.copy()
        self._pending_transactions.clear()
        
        # Compute merkle root
        merkle_tree = MerkleTree()
        merkle_root = merkle_tree.build([tx.encode() for tx in transactions])
        
        # Get previous block info
        prev_block = self.last_block
        index = prev_block.index + 1
        prev_hash = prev_block.hash
        timestamp = int(time.time())
        
        # Mine (find valid nonce)
        nonce, block_hash = self._pow.mine(
            index=index,
            prev_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=timestamp
        )
        
        # Create immutable block
        new_block = Block(
            index=index,
            prev_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            nonce=nonce,
            hash=block_hash,
            transactions=tuple(transactions)
        )
        
        # Validate before adding
        self._validate_block(new_block, prev_block)
        
        self._chain.append(new_block)
        return new_block
    
    def _validate_block(self, block: Block, prev_block: Block) -> None:
        """
        Validate a block against the previous block.
        
        Raises:
            ValidationError: If block is invalid
        """
        # Check index
        if block.index != prev_block.index + 1:
            raise ValidationError(
                f"Invalid index: expected {prev_block.index + 1}, got {block.index}"
            )
        
        # Check previous hash
        if block.prev_hash != prev_block.hash:
            raise ValidationError("Previous hash mismatch")
        
        # Verify merkle root
        merkle_tree = MerkleTree()
        computed_merkle = merkle_tree.build([tx.encode() for tx in block.transactions])
        if computed_merkle != block.merkle_root:
            raise ValidationError("Merkle root mismatch")
        
        # Verify block hash
        computed_hash = compute_block_hash(
            block.index,
            block.prev_hash,
            block.merkle_root,
            block.timestamp,
            block.nonce
        )
        if computed_hash != block.hash:
            raise ValidationError("Block hash mismatch")
        
        # Verify PoW
        if not self._pow.hash_meets_target(block.hash):
            raise ValidationError("Block does not meet difficulty target")
    
    def validate_chain(self) -> bool:
        """
        Validate the entire blockchain.
        
        Returns:
            True if chain is valid
            
        Raises:
            ValidationError: If chain is invalid
        """
        if not self._chain:
            raise ValidationError("Chain is empty")
        
        # Validate genesis block
        genesis = self._chain[0]
        if genesis.prev_hash != GENESIS_PREV_HASH:
            raise ValidationError("Invalid genesis block")
        
        # Validate each block
        for i in range(1, len(self._chain)):
            self._validate_block(self._chain[i], self._chain[i-1])
        
        return True
    
    def get_transaction_proof(
        self,
        block_index: int,
        transaction: str
    ) -> Optional[Tuple[int, List[Tuple[bytes, str]]]]:
        """
        Get Merkle proof for a transaction in a block.
        
        Args:
            block_index: Index of the block
            transaction: The transaction to prove
            
        Returns:
            Tuple of (tx_index, proof) or None if not found
        """
        if block_index < 0 or block_index >= len(self._chain):
            return None
        
        block = self._chain[block_index]
        
        if transaction not in block.transactions:
            return None
        
        tx_index = block.transactions.index(transaction)
        merkle_tree = MerkleTree()
        merkle_tree.build([tx.encode() for tx in block.transactions])
        
        return (tx_index, merkle_tree.get_proof(tx_index))
    
    def verify_transaction(
        self,
        block_index: int,
        transaction: str,
        tx_index: int,
        proof: List[Tuple[bytes, str]]
    ) -> bool:
        """
        Verify a transaction exists in a block using Merkle proof.
        
        Args:
            block_index: Index of the block
            transaction: The transaction to verify
            tx_index: Index of the transaction in the block
            proof: Merkle proof from get_transaction_proof
            
        Returns:
            True if transaction is verified
        """
        if block_index < 0 or block_index >= len(self._chain):
            return False
        
        block = self._chain[block_index]
        
        return MerkleTree.verify_proof(
            transaction.encode(), tx_index, proof, block.merkle_root
        )
    
    def to_json(self) -> str:
        """Serialize blockchain to JSON."""
        return json.dumps({
            'difficulty': self._pow.difficulty,
            'chain': [block.to_dict() for block in self._chain],
        }, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Blockchain':
        """Deserialize blockchain from JSON."""
        data = json.loads(json_str)
        
        # Create blockchain with same difficulty
        blockchain = cls.__new__(cls)
        blockchain._pow = ProofOfWork(data['difficulty'])
        blockchain._pending_transactions = []
        blockchain._chain = [
            Block.from_dict(block_data)
            for block_data in data['chain']
        ]
        
        # Validate loaded chain
        blockchain.validate_chain()
        
        return blockchain
    
    def print_chain(self) -> None:
        """Print the blockchain."""
        print(f"\nBlockchain (difficulty={self.difficulty}, length={self.length})")
        print("=" * 60)
        for block in self._chain:
            print(block)
            print("-" * 40)


# ============================================================================
# Convenience Functions
# ============================================================================

def create_blockchain(difficulty: int = DEFAULT_DIFFICULTY) -> Blockchain:
    """Create a new blockchain with given difficulty."""
    return Blockchain(difficulty)


def mine_transactions(
    blockchain: Blockchain,
    transactions: List[str]
) -> Block:
    """Add transactions and mine a block."""
    for tx in transactions:
        blockchain.add_transaction(tx)
    return blockchain.mine_block()


# ============================================================================
# Self-Test
# ============================================================================

def _run_tests():
    """Run comprehensive tests for the blockchain module."""
    import os
    
    print("Blockchain Ledger Module Test")
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
    
    # Test 1: Proof of Work target calculation
    pow_test = ProofOfWork(difficulty=16)
    target_correct = pow_test.target == 2 ** (256 - 16)
    test(
        "Proof of Work target calculation",
        target_correct,
        f"Difficulty: 16, Target bits: {256 - 16}"
    )
    
    # Test 2: Genesis block creation
    blockchain = Blockchain(difficulty=8)  # Low difficulty for testing
    genesis = blockchain.chain[0]
    genesis_valid = (
        genesis.index == 0 and
        genesis.prev_hash == GENESIS_PREV_HASH and
        len(genesis.transactions) > 0
    )
    test(
        "Genesis block creation",
        genesis_valid,
        f"Index: {genesis.index}, Has transactions: {len(genesis.transactions) > 0}"
    )
    
    # Test 3: Block immutability
    try:
        genesis.index = 999  # Should fail - frozen dataclass
        immutable = False
    except Exception:
        immutable = True
    test(
        "Block immutability (frozen dataclass)",
        immutable,
        "Attempting to modify block.index raises exception"
    )
    
    # Test 4: Mining with Proof of Work
    blockchain.add_transaction("Alice -> Bob: 10 coins")
    blockchain.add_transaction("Bob -> Charlie: 5 coins")
    block1 = blockchain.mine_block()
    
    pow_valid = blockchain._pow.hash_meets_target(block1.hash)
    leading_zeros = blockchain._pow.count_leading_zeros(block1.hash)
    test(
        "Mining with Proof of Work",
        pow_valid and block1.index == 1,
        f"Block #{block1.index}, Leading zero bits: {leading_zeros}, Nonce: {block1.nonce}"
    )
    
    # Test 5: SHA-256 chaining
    chain_valid = block1.prev_hash == genesis.hash
    test(
        "SHA-256 chaining (prev_hash linkage)",
        chain_valid,
        f"Block 1 prev_hash matches Genesis hash: {chain_valid}"
    )
    
    # Test 6: Merkle root verification
    merkle_tree = MerkleTree()
    computed_root = merkle_tree.build([tx.encode() for tx in block1.transactions])
    merkle_valid = computed_root == block1.merkle_root
    test(
        "Merkle root in block",
        merkle_valid,
        f"Merkle root: {block1.merkle_root.hex()[:32]}..."
    )
    
    # Test 7: Difficulty target enforcement
    hash_int = int.from_bytes(block1.hash, 'big')
    meets_target = hash_int < blockchain._pow.target
    test(
        "Difficulty target enforcement",
        meets_target,
        f"Hash < Target: {meets_target}"
    )
    
    # Test 8: Full chain validation
    # Add more blocks
    for i in range(3):
        blockchain.add_transaction(f"Transaction {i}")
        blockchain.mine_block()
    
    try:
        valid = blockchain.validate_chain()
    except ValidationError:
        valid = False
    test(
        "Full chain validation",
        valid,
        f"Chain length: {blockchain.length}, All blocks valid: {valid}"
    )
    
    # Test 9: Merkle proof for transaction
    tx = "Alice -> Bob: 10 coins"
    proof_result = blockchain.get_transaction_proof(1, tx)
    proof_exists = proof_result is not None
    test(
        "Merkle proof generation",
        proof_exists,
        f"Proof length: {len(proof_result[1]) if proof_result else 0}"
    )
    
    # Test 10: Merkle proof verification
    if proof_result:
        tx_index, proof = proof_result
        verified = blockchain.verify_transaction(1, tx, tx_index, proof)
    else:
        verified = False
    test(
        "Merkle proof verification",
        verified,
        f"Transaction verified in block: {verified}"
    )
    
    # Test 11: Tampered transaction detection
    fake_tx = "Alice -> Bob: 1000000 coins"
    if proof_result:
        tx_index, proof = proof_result
        fake_verified = blockchain.verify_transaction(1, fake_tx, tx_index, proof)
    else:
        fake_verified = True  # Force fail
    test(
        "Tampered transaction detection",
        not fake_verified,
        f"Fake transaction rejected: {not fake_verified}"
    )
    
    # Test 12: Serialization/Deserialization
    json_str = blockchain.to_json()
    loaded = Blockchain.from_json(json_str)
    serialize_valid = (
        loaded.length == blockchain.length and
        loaded.last_block.hash == blockchain.last_block.hash
    )
    test(
        "JSON serialization/deserialization",
        serialize_valid,
        f"Loaded chain length: {loaded.length}, Hash match: {serialize_valid}"
    )
    
    # Test 13: Validation rejects invalid blocks
    try:
        # Try to create a block with wrong prev_hash
        fake_block = Block(
            index=blockchain.length,
            prev_hash=b'\xff' * 32,  # Wrong hash
            merkle_root=b'\x00' * 32,
            timestamp=int(time.time()),
            nonce=0,
            hash=b'\x00' * 32,
            transactions=("Fake transaction",)
        )
        blockchain._validate_block(fake_block, blockchain.last_block)
        validation_works = False
    except ValidationError:
        validation_works = True
    test(
        "Validation rejects invalid blocks",
        validation_works,
        "Invalid block correctly rejected"
    )
    
    # Print summary
    print("\n" + "=" * 70)
    print(f"Overall: {tests_passed}/{tests_total} tests passed!")
    
    # Print sample blockchain
    print("\n" + "=" * 70)
    print("Sample Blockchain:")
    blockchain.print_chain()
    
    return tests_passed == tests_total


if __name__ == "__main__":
    success = _run_tests()
    exit(0 if success else 1)
