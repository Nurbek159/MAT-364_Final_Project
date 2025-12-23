"""
SHA-256 Hash Implementation (From Scratch)

Implements the SHA-256 cryptographic hash function as defined in FIPS 180-4.
This implementation avoids using hashlib and builds the algorithm from scratch.

Components:
- Padding: Pads message to multiple of 512 bits
- Message Schedule: Expands 16 words to 64 words
- Compression: 64 rounds of compression function
- Output: 256-bit (32-byte) digest
"""

from typing import List


# Initial hash values: first 32 bits of fractional parts of square roots of first 8 primes
H_INITIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Round constants: first 32 bits of fractional parts of cube roots of first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Mask for 32-bit arithmetic
MASK_32 = 0xFFFFFFFF


def _right_rotate(value: int, amount: int) -> int:
    """Right rotate a 32-bit integer by the specified amount."""
    return ((value >> amount) | (value << (32 - amount))) & MASK_32


def _ch(x: int, y: int, z: int) -> int:
    """Choice function: if x then y else z (bitwise)."""
    return (x & y) ^ (~x & z) & MASK_32


def _maj(x: int, y: int, z: int) -> int:
    """Majority function: majority vote of bits."""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x: int) -> int:
    """Lowercase sigma 0: used in message schedule."""
    return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ (x >> 3)


def _sigma1(x: int) -> int:
    """Lowercase sigma 1: used in message schedule."""
    return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ (x >> 10)


def _big_sigma0(x: int) -> int:
    """Uppercase Sigma 0: used in compression."""
    return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _big_sigma1(x: int) -> int:
    """Uppercase Sigma 1: used in compression."""
    return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _pad_message(data: bytes) -> bytes:
    """
    Pad the message according to SHA-256 specification.
    
    Padding rules:
    1. Append bit '1' to message (0x80 byte)
    2. Append zeros until message length ≡ 448 (mod 512)
    3. Append original message length as 64-bit big-endian integer
    
    Args:
        data: The original message bytes
        
    Returns:
        Padded message as bytes (length is multiple of 64 bytes / 512 bits)
    """
    original_length = len(data)
    original_bit_length = original_length * 8
    
    # Append the bit '1' (0x80 = 10000000 in binary)
    data += b'\x80'
    
    # Append zeros until length ≡ 448 mod 512 (56 mod 64 in bytes)
    # We need: (current_length + padding_zeros) % 64 == 56
    padding_length = (56 - (len(data) % 64)) % 64
    data += b'\x00' * padding_length
    
    # Append the original length as 64-bit big-endian integer
    data += original_bit_length.to_bytes(8, byteorder='big')
    
    return data


def _bytes_to_words(chunk: bytes) -> List[int]:
    """Convert a 64-byte chunk into 16 32-bit words (big-endian)."""
    words = []
    for i in range(0, 64, 4):
        word = int.from_bytes(chunk[i:i+4], byteorder='big')
        words.append(word)
    return words


def _create_message_schedule(words: List[int]) -> List[int]:
    """
    Expand 16 words into 64 words for the message schedule.
    
    For i from 16 to 63:
        W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    """
    w = words.copy()
    for i in range(16, 64):
        s0 = _sigma0(w[i - 15])
        s1 = _sigma1(w[i - 2])
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK_32)
    return w


def _compress(state: List[int], w: List[int]) -> List[int]:
    """
    Perform 64 rounds of compression on the state.
    
    Args:
        state: Current hash state (8 32-bit words)
        w: Message schedule (64 32-bit words)
        
    Returns:
        Updated hash state
    """
    # Initialize working variables
    a, b, c, d, e, f, g, h = state
    
    # 64 rounds
    for i in range(64):
        # Calculate temporary values
        t1 = (h + _big_sigma1(e) + _ch(e, f, g) + K[i] + w[i]) & MASK_32
        t2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK_32
        
        # Update working variables
        h = g
        g = f
        f = e
        e = (d + t1) & MASK_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_32
    
    # Add compressed chunk to current hash value
    new_state = [
        (state[0] + a) & MASK_32,
        (state[1] + b) & MASK_32,
        (state[2] + c) & MASK_32,
        (state[3] + d) & MASK_32,
        (state[4] + e) & MASK_32,
        (state[5] + f) & MASK_32,
        (state[6] + g) & MASK_32,
        (state[7] + h) & MASK_32,
    ]
    
    return new_state


def sha256(data: bytes) -> bytes:
    """
    Compute the SHA-256 hash of the input data.
    
    Args:
        data: Input bytes to hash
        
    Returns:
        256-bit (32-byte) digest as bytes
        
    Example:
        >>> sha256(b"hello").hex()
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    # Pad the message
    padded = _pad_message(data)
    
    # Initialize hash state
    state = H_INITIAL.copy()
    
    # Process each 512-bit (64-byte) chunk
    for i in range(0, len(padded), 64):
        chunk = padded[i:i + 64]
        
        # Convert chunk to 16 32-bit words
        words = _bytes_to_words(chunk)
        
        # Create message schedule (expand to 64 words)
        w = _create_message_schedule(words)
        
        # Compress
        state = _compress(state, w)
    
    # Produce final hash value (big-endian)
    digest = b''.join(word.to_bytes(4, byteorder='big') for word in state)
    
    return digest


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hexadecimal string.
    
    Args:
        data: Input bytes to hash
        
    Returns:
        64-character hexadecimal string
    """
    return sha256(data).hex()


def sha256_string(text: str, encoding: str = 'utf-8') -> bytes:
    """
    Compute SHA-256 hash of a string.
    
    Args:
        text: Input string to hash
        encoding: String encoding (default: utf-8)
        
    Returns:
        256-bit (32-byte) digest as bytes
    """
    return sha256(text.encode(encoding))


# Self-test when run directly
if __name__ == "__main__":
    # Test vectors from NIST
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        (b"The quick brown fox jumps over the lazy dog", 
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ]
    
    print("SHA-256 Implementation Test")
    print("=" * 60)
    
    all_passed = True
    for data, expected in test_cases:
        result = sha256_hex(data)
        passed = result == expected
        all_passed = all_passed and passed
        
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"\nInput: {data[:50]}{'...' if len(data) > 50 else ''}")
        print(f"Expected: {expected}")
        print(f"Got:      {result}")
        print(f"Status:   {status}")
    
    print("\n" + "=" * 60)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
