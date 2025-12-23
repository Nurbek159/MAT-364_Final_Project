"""
LFSR (Linear Feedback Shift Register) Stream Cipher

A stream cipher implementation using LFSR for keystream generation.
This is for EDUCATIONAL/DEMONSTRATION purposes only - not cryptographically secure!

Components:
- LFSR: Configurable linear feedback shift register
- Keystream generation from LFSR output
- XOR-based encryption/decryption

Security Note:
    LFSRs alone are NOT secure for cryptographic use. They are linear and
    can be broken with known-plaintext attacks using the Berlekamp-Massey
    algorithm. This implementation is for learning purposes only.
"""

from typing import List, Tuple, Optional, Generator


class LFSR:
    """
    Linear Feedback Shift Register implementation.
    
    An LFSR generates a pseudo-random bit sequence based on:
    - Initial state (seed)
    - Tap positions (feedback polynomial)
    
    The feedback bit is computed as XOR of bits at tap positions.
    
    Example:
        >>> lfsr = LFSR(seed=0b1011, taps=[4, 3], size=4)
        >>> [lfsr.next_bit() for _ in range(10)]
        [1, 1, 0, 1, 0, 1, 1, 1, 1, 0]
    
    Common maximal-length tap configurations:
        - 4-bit:  [4, 3]
        - 8-bit:  [8, 6, 5, 4]
        - 16-bit: [16, 15, 13, 4]
        - 32-bit: [32, 22, 2, 1]
    """
    
    # Common maximal-length polynomial taps (produces period 2^n - 1)
    MAXIMAL_TAPS = {
        4: [4, 3],
        5: [5, 3],
        6: [6, 5],
        7: [7, 6],
        8: [8, 6, 5, 4],
        16: [16, 15, 13, 4],
        24: [24, 23, 22, 17],
        32: [32, 22, 2, 1],
    }
    
    def __init__(self, seed: int, taps: List[int], size: int):
        """
        Initialize the LFSR.
        
        Args:
            seed: Initial state of the register (must be non-zero)
            taps: List of tap positions (1-indexed from right/LSB)
                  These determine the feedback polynomial
            size: Number of bits in the register
            
        Raises:
            ValueError: If seed is zero or taps are invalid
        """
        if seed == 0:
            raise ValueError("Seed must be non-zero (all-zero state is invalid)")
        
        if not taps:
            raise ValueError("At least one tap position required")
        
        if any(t < 1 or t > size for t in taps):
            raise ValueError(f"Tap positions must be between 1 and {size}")
        
        self._size = size
        self._mask = (1 << size) - 1  # Bit mask for register size
        self._state = seed & self._mask
        self._taps = sorted(taps, reverse=True)  # Highest tap first
        self._initial_seed = seed & self._mask
        self._initial_taps = list(taps)
    
    @property
    def state(self) -> int:
        """Current state of the register."""
        return self._state
    
    @property
    def size(self) -> int:
        """Size of the register in bits."""
        return self._size
    
    @property
    def taps(self) -> List[int]:
        """Tap positions (feedback polynomial)."""
        return self._taps.copy()
    
    def next_bit(self) -> int:
        """
        Generate the next bit of the keystream.
        
        The output bit is the LSB of the current state.
        The feedback bit is computed as XOR of all tap positions.
        The register shifts right, with feedback entering at MSB.
        
        Returns:
            Next bit of the sequence (0 or 1)
        """
        # Output bit is the LSB
        output_bit = self._state & 1
        
        # Compute feedback as XOR of tap positions
        feedback = 0
        for tap in self._taps:
            # Tap positions are 1-indexed from right
            bit = (self._state >> (tap - 1)) & 1
            feedback ^= bit
        
        # Shift right and insert feedback at MSB
        self._state = (self._state >> 1) | (feedback << (self._size - 1))
        
        return output_bit
    
    def next_byte(self) -> int:
        """
        Generate the next byte (8 bits) of the keystream.
        
        Returns:
            Integer 0-255 representing the next byte
        """
        byte_val = 0
        for i in range(8):
            byte_val |= (self.next_bit() << i)
        return byte_val
    
    def generate_bits(self, count: int) -> List[int]:
        """
        Generate multiple bits from the LFSR.
        
        Args:
            count: Number of bits to generate
            
        Returns:
            List of bits (0s and 1s)
        """
        return [self.next_bit() for _ in range(count)]
    
    def generate_bytes(self, count: int) -> bytes:
        """
        Generate multiple bytes from the LFSR.
        
        Args:
            count: Number of bytes to generate
            
        Returns:
            Bytes object containing the keystream
        """
        return bytes(self.next_byte() for _ in range(count))
    
    def keystream(self, length: int) -> Generator[int, None, None]:
        """
        Generator yielding keystream bytes.
        
        Args:
            length: Number of bytes to yield
            
        Yields:
            Keystream bytes one at a time
        """
        for _ in range(length):
            yield self.next_byte()
    
    def reset(self, new_seed: Optional[int] = None):
        """
        Reset the LFSR to initial or new state.
        
        Args:
            new_seed: Optional new seed (uses original if None)
        """
        if new_seed is not None:
            if new_seed == 0:
                raise ValueError("Seed must be non-zero")
            self._state = new_seed & self._mask
            self._initial_seed = self._state
        else:
            self._state = self._initial_seed
    
    def get_period(self, max_iterations: int = None) -> int:
        """
        Determine the period of the LFSR sequence.
        
        For a maximal-length LFSR, period = 2^n - 1.
        
        Args:
            max_iterations: Maximum iterations to check
            
        Returns:
            Period length, or -1 if not found within limit
        """
        if max_iterations is None:
            max_iterations = (1 << self._size)  # 2^size
        
        initial_state = self._state
        
        for i in range(1, max_iterations + 1):
            self.next_bit()
            if self._state == initial_state:
                return i
        
        return -1
    
    @classmethod
    def from_size(cls, seed: int, size: int) -> 'LFSR':
        """
        Create an LFSR with maximal-length taps for the given size.
        
        Args:
            seed: Initial state
            size: Register size in bits
            
        Returns:
            LFSR with appropriate tap configuration
        """
        if size not in cls.MAXIMAL_TAPS:
            raise ValueError(f"No predefined taps for size {size}. "
                           f"Available: {list(cls.MAXIMAL_TAPS.keys())}")
        return cls(seed, cls.MAXIMAL_TAPS[size], size)
    
    def __repr__(self) -> str:
        return f"LFSR(state=0b{self._state:0{self._size}b}, taps={self._taps}, size={self._size})"


class LFSRCipher:
    """
    Stream cipher using LFSR for keystream generation.
    
    WARNING: This is for educational purposes only!
    LFSR-based ciphers are NOT cryptographically secure.
    
    Example:
        >>> cipher = LFSRCipher(seed=0xDEADBEEF, size=32)
        >>> ciphertext = cipher.encrypt(b"Hello, World!")
        >>> cipher.reset()
        >>> plaintext = cipher.decrypt(ciphertext)
        >>> plaintext == b"Hello, World!"
        True
    """
    
    def __init__(self, seed: int, taps: List[int] = None, size: int = 32):
        """
        Initialize the LFSR cipher.
        
        Args:
            seed: Initial state for LFSR (the "key")
            taps: Tap positions (uses maximal-length if None)
            size: LFSR size in bits
        """
        if taps is None:
            if size not in LFSR.MAXIMAL_TAPS:
                raise ValueError(f"No default taps for size {size}")
            taps = LFSR.MAXIMAL_TAPS[size]
        
        self._lfsr = LFSR(seed, taps, size)
        self._seed = seed
        self._taps = taps
        self._size = size
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using XOR with LFSR keystream.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        keystream = self._lfsr.generate_bytes(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using XOR with LFSR keystream.
        
        Since XOR is symmetric, decryption is identical to encryption.
        The LFSR must be in the same state as when encryption started.
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            Decrypted plaintext
        """
        # XOR decryption is the same as encryption
        return self.encrypt(ciphertext)
    
    def reset(self, new_seed: Optional[int] = None):
        """
        Reset the cipher to initial state.
        
        Args:
            new_seed: Optional new seed/key
        """
        self._lfsr.reset(new_seed)
    
    def encrypt_stream(self, data: bytes) -> Generator[int, None, None]:
        """
        Generator for streaming encryption.
        
        Args:
            data: Data to encrypt
            
        Yields:
            Encrypted bytes one at a time
        """
        for byte in data:
            yield byte ^ self._lfsr.next_byte()
    
    @property
    def lfsr(self) -> LFSR:
        """Access to underlying LFSR."""
        return self._lfsr


def xor_encrypt(data: bytes, keystream: bytes) -> bytes:
    """
    Simple XOR encryption/decryption.
    
    Args:
        data: Data to encrypt/decrypt
        keystream: Keystream bytes (must be at least as long as data)
        
    Returns:
        XOR result
    """
    if len(keystream) < len(data):
        raise ValueError("Keystream must be at least as long as data")
    return bytes(d ^ k for d, k in zip(data, keystream))


def generate_keystream(seed: int, length: int, size: int = 32) -> bytes:
    """
    Generate a keystream using LFSR.
    
    Args:
        seed: LFSR seed (key)
        length: Number of bytes to generate
        size: LFSR size in bits
        
    Returns:
        Keystream bytes
    """
    lfsr = LFSR.from_size(seed, size)
    return lfsr.generate_bytes(length)


# Self-test when run directly
if __name__ == "__main__":
    print("LFSR Stream Cipher Test")
    print("=" * 60)
    
    # Test 1: Basic LFSR operation
    print("\n[Test 1] Basic LFSR operation (4-bit)")
    lfsr = LFSR(seed=0b1011, taps=[4, 3], size=4)
    print(f"  Initial: {lfsr}")
    bits = [lfsr.next_bit() for _ in range(15)]
    print(f"  First 15 bits: {''.join(map(str, bits))}")
    
    # Test 2: Period verification (maximal length = 2^4 - 1 = 15)
    print("\n[Test 2] Period verification")
    lfsr.reset()
    period = lfsr.get_period()
    expected_period = (1 << 4) - 1  # 15 for maximal-length 4-bit LFSR
    print(f"  Period: {period} (expected: {expected_period})")
    print(f"  Maximal length: {'Yes' if period == expected_period else 'No'}")
    
    # Test 3: 32-bit LFSR for encryption
    print("\n[Test 3] 32-bit LFSR encryption/decryption")
    cipher = LFSRCipher(seed=0xDEADBEEF, size=32)
    plaintext = b"Hello, World! This is a secret message."
    
    ciphertext = cipher.encrypt(plaintext)
    print(f"  Plaintext:  {plaintext}")
    print(f"  Ciphertext: {ciphertext.hex()[:60]}...")
    
    cipher.reset()
    decrypted = cipher.decrypt(ciphertext)
    print(f"  Decrypted:  {decrypted}")
    test3_pass = decrypted == plaintext
    print(f"  Match: {test3_pass}")
    
    # Test 4: Keystream generation
    print("\n[Test 4] Keystream generation")
    ks1 = generate_keystream(seed=12345, length=16, size=32)
    ks2 = generate_keystream(seed=12345, length=16, size=32)
    print(f"  Keystream 1: {ks1.hex()}")
    print(f"  Keystream 2: {ks2.hex()}")
    test4_pass = ks1 == ks2
    print(f"  Deterministic: {test4_pass}")
    
    # Test 5: Different seeds produce different keystreams
    print("\n[Test 5] Different seeds = different keystreams")
    ks_a = generate_keystream(seed=0xAAAA, length=8, size=16)
    ks_b = generate_keystream(seed=0xBBBB, length=8, size=16)
    print(f"  Seed 0xAAAA: {ks_a.hex()}")
    print(f"  Seed 0xBBBB: {ks_b.hex()}")
    test5_pass = ks_a != ks_b
    print(f"  Different: {test5_pass}")
    
    # Test 6: XOR properties
    print("\n[Test 6] XOR cipher properties")
    data = b"Test data"
    keystream = generate_keystream(seed=999, length=len(data), size=32)
    encrypted = xor_encrypt(data, keystream)
    decrypted = xor_encrypt(encrypted, keystream)
    test6_pass = decrypted == data
    print(f"  Original:  {data}")
    print(f"  Encrypted: {encrypted.hex()}")
    print(f"  Decrypted: {decrypted}")
    print(f"  XOR symmetric: {test6_pass}")
    
    # Summary
    all_passed = test3_pass and test4_pass and test5_pass and test6_pass
    print("\n" + "=" * 60)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
    print("\n⚠️  WARNING: LFSR ciphers are NOT secure for real cryptographic use!")
