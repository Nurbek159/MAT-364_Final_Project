"""
Unit tests for Blockchain Ledger module.

Tests:
- Block creation
- Proof of Work
- Chain validation
- Invalid block rejection
- Merkle proofs
"""

import pytest
import time
from src.blockchain.ledger import (
    Block, Blockchain, ProofOfWork, ValidationError,
    create_blockchain, mine_transactions, compute_block_hash,
    GENESIS_PREV_HASH, DEFAULT_DIFFICULTY
)
from src.core_crypto.merkle import MerkleTree


class TestProofOfWork:
    """Tests for Proof of Work."""
    
    def test_target_calculation(self):
        """Target should be 2^(256-difficulty)."""
        pow = ProofOfWork(difficulty=16)
        expected = 2 ** (256 - 16)
        assert pow.target == expected
    
    def test_hash_meets_target(self):
        """Hash below target should be valid."""
        pow = ProofOfWork(difficulty=8)
        # A hash with leading zeros meets target
        valid_hash = b'\x00' + b'\xff' * 31
        assert pow.hash_meets_target(valid_hash)
    
    def test_hash_above_target(self):
        """Hash above target should be invalid."""
        pow = ProofOfWork(difficulty=8)
        # A hash with no leading zeros
        invalid_hash = b'\xff' * 32
        assert not pow.hash_meets_target(invalid_hash)
    
    def test_mining_finds_valid_nonce(self):
        """Mining should find a valid nonce."""
        pow = ProofOfWork(difficulty=4)  # Low difficulty for fast test
        
        nonce, hash_result = pow.mine(
            index=1,
            prev_hash=b'\x00' * 32,
            merkle_root=b'\x00' * 32,
            timestamp=int(time.time())
        )
        
        assert pow.hash_meets_target(hash_result)
    
    def test_invalid_difficulty_rejected(self):
        """Invalid difficulty should raise error."""
        with pytest.raises(ValueError):
            ProofOfWork(difficulty=0)
        with pytest.raises(ValueError):
            ProofOfWork(difficulty=257)


class TestBlock:
    """Tests for Block structure."""
    
    def test_block_immutable(self):
        """Block should be immutable (frozen)."""
        block = Block(
            index=0,
            prev_hash=b'\x00' * 32,
            merkle_root=b'\x00' * 32,
            timestamp=0,
            nonce=0,
            hash=b'\x00' * 32,
            transactions=("tx1",)
        )
        
        with pytest.raises(Exception):  # FrozenInstanceError
            block.index = 1
    
    def test_block_to_dict(self):
        """Block serialization should work."""
        block = Block(
            index=1,
            prev_hash=b'\xab' * 32,
            merkle_root=b'\xcd' * 32,
            timestamp=1234567890,
            nonce=42,
            hash=b'\xef' * 32,
            transactions=("tx1", "tx2")
        )
        
        d = block.to_dict()
        assert d['index'] == 1
        assert d['nonce'] == 42
        assert len(d['transactions']) == 2
    
    def test_block_from_dict(self):
        """Block deserialization should work."""
        data = {
            'index': 1,
            'prev_hash': 'ab' * 32,
            'merkle_root': 'cd' * 32,
            'timestamp': 1234567890,
            'nonce': 42,
            'hash': 'ef' * 32,
            'transactions': ['tx1', 'tx2']
        }
        
        block = Block.from_dict(data)
        assert block.index == 1
        assert block.nonce == 42


class TestBlockchain:
    """Tests for Blockchain."""
    
    def test_genesis_block_created(self):
        """Blockchain should start with genesis block."""
        bc = Blockchain(difficulty=4)
        assert bc.length == 1
        assert bc.chain[0].index == 0
        assert bc.chain[0].prev_hash == GENESIS_PREV_HASH
    
    def test_add_transaction(self):
        """Adding transactions should work."""
        bc = Blockchain(difficulty=4)
        count = bc.add_transaction("test transaction")
        assert count >= 1
        assert "test transaction" in bc.pending_transactions
    
    def test_mine_block(self):
        """Mining a block should work."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.add_transaction("tx2")
        
        block = bc.mine_block()
        
        assert block.index == 1
        assert "tx1" in block.transactions
        assert "tx2" in block.transactions
        assert len(bc.pending_transactions) == 0
    
    def test_chain_grows(self):
        """Chain should grow with mined blocks."""
        bc = Blockchain(difficulty=4)
        initial_length = bc.length
        
        bc.add_transaction("tx")
        bc.mine_block()
        
        assert bc.length == initial_length + 1
    
    def test_blocks_linked(self):
        """Blocks should be linked via prev_hash."""
        bc = Blockchain(difficulty=4)
        
        bc.add_transaction("tx1")
        block1 = bc.mine_block()
        
        bc.add_transaction("tx2")
        block2 = bc.mine_block()
        
        assert block2.prev_hash == block1.hash
    
    def test_validate_chain(self):
        """Valid chain should pass validation."""
        bc = Blockchain(difficulty=4)
        
        for i in range(3):
            bc.add_transaction(f"tx{i}")
            bc.mine_block()
        
        assert bc.validate_chain() == True
    
    def test_empty_transaction_rejected(self):
        """Empty transaction should be rejected."""
        bc = Blockchain(difficulty=4)
        with pytest.raises(ValueError):
            bc.add_transaction("")
    
    def test_no_pending_transactions_error(self):
        """Mining with no pending transactions should error."""
        bc = Blockchain(difficulty=4)
        with pytest.raises(ValueError):
            bc.mine_block()
    
    def test_serialization(self):
        """Blockchain serialization should work."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.mine_block()
        
        json_str = bc.to_json()
        loaded = Blockchain.from_json(json_str)
        
        assert loaded.length == bc.length
        assert loaded.last_block.hash == bc.last_block.hash


class TestBlockchainValidation:
    """Tests for blockchain validation - invalid inputs."""
    
    def test_invalid_index_rejected(self):
        """Block with wrong index should be rejected."""
        bc = Blockchain(difficulty=4)
        
        # Create a block with wrong index
        fake_block = Block(
            index=999,  # Wrong index
            prev_hash=bc.last_block.hash,
            merkle_root=b'\x00' * 32,
            timestamp=int(time.time()),
            nonce=0,
            hash=b'\x00' * 32,
            transactions=("fake",)
        )
        
        with pytest.raises(ValidationError):
            bc._validate_block(fake_block, bc.last_block)
    
    def test_invalid_prev_hash_rejected(self):
        """Block with wrong prev_hash should be rejected."""
        bc = Blockchain(difficulty=4)
        
        fake_block = Block(
            index=1,
            prev_hash=b'\xff' * 32,  # Wrong prev_hash
            merkle_root=b'\x00' * 32,
            timestamp=int(time.time()),
            nonce=0,
            hash=b'\x00' * 32,
            transactions=("fake",)
        )
        
        with pytest.raises(ValidationError):
            bc._validate_block(fake_block, bc.last_block)
    
    def test_invalid_merkle_root_rejected(self):
        """Block with wrong merkle root should be rejected."""
        bc = Blockchain(difficulty=4)
        
        # Build a valid-looking block but with wrong merkle root
        fake_block = Block(
            index=1,
            prev_hash=bc.last_block.hash,
            merkle_root=b'\xff' * 32,  # Wrong merkle root
            timestamp=int(time.time()),
            nonce=0,
            hash=b'\x00' * 32,
            transactions=("tx1",)
        )
        
        with pytest.raises(ValidationError):
            bc._validate_block(fake_block, bc.last_block)
    
    def test_invalid_block_hash_rejected(self):
        """Block with wrong hash should be rejected."""
        bc = Blockchain(difficulty=4)
        
        # Compute correct merkle root
        tree = MerkleTree()
        merkle_root = tree.build([b"tx1"])
        
        fake_block = Block(
            index=1,
            prev_hash=bc.last_block.hash,
            merkle_root=merkle_root,
            timestamp=int(time.time()),
            nonce=0,
            hash=b'\xff' * 32,  # Wrong hash
            transactions=("tx1",)
        )
        
        with pytest.raises(ValidationError):
            bc._validate_block(fake_block, bc.last_block)


class TestMerkleProofs:
    """Tests for Merkle proofs in blockchain."""
    
    def test_get_transaction_proof(self):
        """Getting transaction proof should work."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.add_transaction("tx2")
        bc.mine_block()
        
        result = bc.get_transaction_proof(1, "tx1")
        assert result is not None
        tx_index, proof = result
        assert len(proof) >= 0
    
    def test_verify_transaction(self):
        """Transaction verification should work."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.add_transaction("tx2")
        bc.mine_block()
        
        result = bc.get_transaction_proof(1, "tx1")
        tx_index, proof = result
        
        assert bc.verify_transaction(1, "tx1", tx_index, proof)
    
    def test_invalid_transaction_proof_rejected(self):
        """Invalid transaction should fail verification."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.mine_block()
        
        result = bc.get_transaction_proof(1, "tx1")
        tx_index, proof = result
        
        # Try to verify different transaction with same proof
        assert not bc.verify_transaction(1, "FAKE_TX", tx_index, proof)
    
    def test_nonexistent_transaction(self):
        """Nonexistent transaction should return None."""
        bc = Blockchain(difficulty=4)
        bc.add_transaction("tx1")
        bc.mine_block()
        
        result = bc.get_transaction_proof(1, "nonexistent")
        assert result is None
    
    def test_invalid_block_index(self):
        """Invalid block index should return None/False."""
        bc = Blockchain(difficulty=4)
        
        result = bc.get_transaction_proof(999, "tx")
        assert result is None
        
        assert not bc.verify_transaction(999, "tx", 0, [])
