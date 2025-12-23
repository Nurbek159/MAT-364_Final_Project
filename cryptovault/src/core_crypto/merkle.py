"""
Merkle Tree Implementation

A Merkle tree (hash tree) is a tree data structure where:
- Leaf nodes contain hashes of data blocks
- Non-leaf nodes contain hashes of their children
- The root hash represents the entire dataset

Features:
- Odd leaf duplication (last leaf duplicated when odd count)
- Root hash generation
- Proof generation (authentication path)
- Proof verification

Used in: Blockchain, Audit logs, File integrity verification
"""

from typing import List, Tuple, Optional
from .sha256 import sha256


class MerkleTree:
    """
    Merkle Tree implementation using SHA-256 hashing.
    
    Example:
        >>> tree = MerkleTree()
        >>> leaves = [b"tx1", b"tx2", b"tx3", b"tx4"]
        >>> root = tree.build(leaves)
        >>> proof = tree.get_proof(1)  # Proof for tx2
        >>> MerkleTree.verify_proof(b"tx2", 1, proof, root)
        True
    """
    
    def __init__(self):
        """Initialize an empty Merkle tree."""
        self._leaves: List[bytes] = []
        self._leaf_hashes: List[bytes] = []
        self._layers: List[List[bytes]] = []
        self._root: Optional[bytes] = None
    
    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """
        Hash a leaf node.
        Uses a 0x00 prefix to distinguish from internal nodes.
        
        Args:
            data: Raw leaf data
            
        Returns:
            SHA-256 hash of prefixed data
        """
        return sha256(b'\x00' + data)
    
    @staticmethod
    def hash_internal(left: bytes, right: bytes) -> bytes:
        """
        Hash two child nodes to create parent.
        Uses a 0x01 prefix to distinguish from leaf nodes.
        
        Args:
            left: Left child hash
            right: Right child hash
            
        Returns:
            SHA-256 hash of concatenated children
        """
        return sha256(b'\x01' + left + right)
    
    def build(self, leaves: List[bytes]) -> bytes:
        """
        Build the Merkle tree from a list of leaf data.
        
        Handles odd number of leaves by duplicating the last leaf.
        
        Args:
            leaves: List of raw data bytes for each leaf
            
        Returns:
            Root hash of the tree (32 bytes)
            
        Raises:
            ValueError: If leaves list is empty
        """
        if not leaves:
            raise ValueError("Cannot build Merkle tree with no leaves")
        
        # Store original leaves
        self._leaves = list(leaves)
        
        # Hash all leaves
        self._leaf_hashes = [self.hash_leaf(leaf) for leaf in leaves]
        
        # Build tree layers from bottom up
        self._layers = [self._leaf_hashes.copy()]
        current_layer = self._leaf_hashes.copy()
        
        while len(current_layer) > 1:
            next_layer = []
            
            # Handle odd number of nodes by duplicating the last one
            if len(current_layer) % 2 == 1:
                current_layer.append(current_layer[-1])
            
            # Pair up nodes and hash them
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1]
                parent = self.hash_internal(left, right)
                next_layer.append(parent)
            
            self._layers.append(next_layer)
            current_layer = next_layer
        
        self._root = current_layer[0]
        return self._root
    
    @property
    def root(self) -> Optional[bytes]:
        """Get the root hash of the tree."""
        return self._root
    
    @property
    def root_hex(self) -> Optional[str]:
        """Get the root hash as a hexadecimal string."""
        return self._root.hex() if self._root else None
    
    @property
    def leaf_count(self) -> int:
        """Get the number of leaves in the tree."""
        return len(self._leaves)
    
    @property
    def height(self) -> int:
        """Get the height of the tree (number of layers)."""
        return len(self._layers)
    
    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """
        Generate a Merkle proof (authentication path) for a leaf.
        
        The proof consists of sibling hashes needed to reconstruct
        the path from the leaf to the root.
        
        Args:
            index: Index of the leaf (0-based)
            
        Returns:
            List of (hash, position) tuples where position is 'left' or 'right'
            indicating which side the sibling is on
            
        Raises:
            ValueError: If tree not built or index out of range
        """
        if not self._layers:
            raise ValueError("Tree has not been built yet")
        
        if index < 0 or index >= len(self._leaves):
            raise ValueError(f"Index {index} out of range [0, {len(self._leaves) - 1}]")
        
        proof = []
        current_index = index
        
        # Traverse from leaf layer to root (excluding root layer)
        for layer in self._layers[:-1]:
            # Handle odd layer by considering duplication
            layer_with_dup = layer.copy()
            if len(layer_with_dup) % 2 == 1:
                layer_with_dup.append(layer_with_dup[-1])
            
            # Determine sibling
            if current_index % 2 == 0:
                # Current is left child, sibling is on right
                sibling_index = current_index + 1
                sibling_position = 'right'
            else:
                # Current is right child, sibling is on left
                sibling_index = current_index - 1
                sibling_position = 'left'
            
            sibling_hash = layer_with_dup[sibling_index]
            proof.append((sibling_hash, sibling_position))
            
            # Move to parent index
            current_index = current_index // 2
        
        return proof
    
    def get_proof_hashes(self, index: int) -> List[bytes]:
        """
        Get only the hashes from the proof (without positions).
        
        Args:
            index: Index of the leaf
            
        Returns:
            List of sibling hashes in order from leaf to root
        """
        return [h for h, _ in self.get_proof(index)]
    
    @staticmethod
    def verify_proof(leaf_data: bytes, index: int, 
                     proof: List[Tuple[bytes, str]], root: bytes) -> bool:
        """
        Verify a Merkle proof for a leaf.
        
        Args:
            leaf_data: Original leaf data (not hashed)
            index: Index of the leaf in the tree
            proof: List of (hash, position) tuples
            root: Expected root hash
            
        Returns:
            True if proof is valid, False otherwise
        """
        # Start with leaf hash
        current_hash = MerkleTree.hash_leaf(leaf_data)
        
        # Apply each proof element
        for sibling_hash, position in proof:
            if position == 'left':
                # Sibling is on left
                current_hash = MerkleTree.hash_internal(sibling_hash, current_hash)
            else:
                # Sibling is on right
                current_hash = MerkleTree.hash_internal(current_hash, sibling_hash)
        
        return current_hash == root
    
    @staticmethod
    def verify_proof_simple(leaf_hash: bytes, index: int,
                            proof_hashes: List[bytes], root: bytes) -> bool:
        """
        Verify a Merkle proof using index to determine positions.
        
        Args:
            leaf_hash: Hash of the leaf (already hashed)
            index: Index of the leaf in the tree
            proof_hashes: List of sibling hashes
            root: Expected root hash
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = leaf_hash
        current_index = index
        
        for sibling_hash in proof_hashes:
            if current_index % 2 == 0:
                # Current is left child
                current_hash = MerkleTree.hash_internal(current_hash, sibling_hash)
            else:
                # Current is right child
                current_hash = MerkleTree.hash_internal(sibling_hash, current_hash)
            current_index = current_index // 2
        
        return current_hash == root
    
    def get_leaf_hash(self, index: int) -> bytes:
        """Get the hash of a leaf at the given index."""
        if index < 0 or index >= len(self._leaf_hashes):
            raise ValueError(f"Index {index} out of range")
        return self._leaf_hashes[index]
    
    def __repr__(self) -> str:
        """String representation of the tree."""
        if not self._root:
            return "MerkleTree(empty)"
        return f"MerkleTree(leaves={self.leaf_count}, height={self.height}, root={self.root_hex[:16]}...)"


def build_merkle_root(data_list: List[bytes]) -> bytes:
    """
    Convenience function to build a Merkle tree and return only the root.
    
    Args:
        data_list: List of data items
        
    Returns:
        Root hash of the Merkle tree
    """
    tree = MerkleTree()
    return tree.build(data_list)


# Self-test when run directly
if __name__ == "__main__":
    print("Merkle Tree Implementation Test")
    print("=" * 60)
    
    # Test 1: Build tree with even number of leaves
    print("\n[Test 1] Even number of leaves (4)")
    leaves = [b"tx1", b"tx2", b"tx3", b"tx4"]
    tree = MerkleTree()
    root = tree.build(leaves)
    print(f"Leaves: {[l.decode() for l in leaves]}")
    print(f"Root: {root.hex()[:32]}...")
    print(f"Height: {tree.height}")
    
    # Test 2: Build tree with odd number of leaves
    print("\n[Test 2] Odd number of leaves (5)")
    leaves_odd = [b"a", b"b", b"c", b"d", b"e"]
    tree_odd = MerkleTree()
    root_odd = tree_odd.build(leaves_odd)
    print(f"Leaves: {[l.decode() for l in leaves_odd]}")
    print(f"Root: {root_odd.hex()[:32]}...")
    print(f"Height: {tree_odd.height}")
    
    # Test 3: Generate and verify proofs
    print("\n[Test 3] Proof generation and verification")
    all_proofs_valid = True
    for i in range(len(leaves)):
        proof = tree.get_proof(i)
        is_valid = MerkleTree.verify_proof(leaves[i], i, proof, root)
        all_proofs_valid = all_proofs_valid and is_valid
        print(f"  Leaf {i} ({leaves[i].decode()}): Proof size={len(proof)}, Valid={is_valid}")
    
    # Test 4: Proof for modified data should fail
    print("\n[Test 4] Tampered data detection")
    proof = tree.get_proof(0)
    tampered_valid = MerkleTree.verify_proof(b"tampered", 0, proof, root)
    print(f"  Original leaf verified: {MerkleTree.verify_proof(leaves[0], 0, proof, root)}")
    print(f"  Tampered leaf verified: {tampered_valid}")
    
    # Test 5: Single leaf tree
    print("\n[Test 5] Single leaf tree")
    single_tree = MerkleTree()
    single_root = single_tree.build([b"only_one"])
    single_proof = single_tree.get_proof(0)
    single_valid = MerkleTree.verify_proof(b"only_one", 0, single_proof, single_root)
    print(f"  Root: {single_root.hex()[:32]}...")
    print(f"  Proof size: {len(single_proof)}")
    print(f"  Valid: {single_valid}")
    
    # Summary
    print("\n" + "=" * 60)
    tests_passed = all_proofs_valid and not tampered_valid and single_valid
    print(f"Overall: {'All tests passed!' if tests_passed else 'Some tests failed!'}")
