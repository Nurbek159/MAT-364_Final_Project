"""
RSA Mathematical Operations Implementation

Implements the core mathematical operations for RSA cryptography:
- Modular exponentiation (square-and-multiply algorithm)
- Miller-Rabin primality testing
- Prime number generation
- RSA key pair generation
- Extended Euclidean Algorithm for modular inverse

Note: This implementation avoids using Python's built-in pow(a, b, mod).
      All modular exponentiation uses the square-and-multiply algorithm.
"""

import secrets
from typing import Tuple, Optional


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """
    Modular exponentiation using square-and-multiply algorithm.
    
    Computes (base^exponent) mod modulus efficiently without using
    Python's built-in pow(a, b, mod).
    
    Algorithm (right-to-left binary method):
    1. Start with result = 1
    2. For each bit of exponent (from LSB to MSB):
       - If bit is 1, multiply result by base (mod modulus)
       - Square the base (mod modulus)
    
    Time complexity: O(log exponent) multiplications
    
    Args:
        base: The base number
        exponent: The exponent (must be non-negative)
        modulus: The modulus (must be positive)
        
    Returns:
        (base^exponent) mod modulus
        
    Raises:
        ValueError: If exponent < 0 or modulus <= 0
    """
    if exponent < 0:
        raise ValueError("Exponent must be non-negative")
    if modulus <= 0:
        raise ValueError("Modulus must be positive")
    if modulus == 1:
        return 0
    
    # Handle special cases
    if exponent == 0:
        return 1
    if base == 0:
        return 0
    
    # Reduce base first
    base = base % modulus
    result = 1
    
    # Square-and-multiply (right-to-left binary method)
    while exponent > 0:
        # If current bit is 1, multiply result by base
        if exponent & 1:  # exponent is odd (LSB is 1)
            result = (result * base) % modulus
        
        # Square the base for next bit
        base = (base * base) % modulus
        
        # Shift to next bit
        exponent >>= 1
    
    return result


def gcd(a: int, b: int) -> int:
    """
    Compute the greatest common divisor using Euclidean algorithm.
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        GCD of a and b
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Finds integers x, y such that: a*x + b*y = gcd(a, b)
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        Tuple (gcd, x, y) where a*x + b*y = gcd
    """
    if b == 0:
        return a, 1, 0
    
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    
    return g, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse using Extended Euclidean Algorithm.
    
    Finds x such that (a * x) mod m = 1
    
    Args:
        a: The number to find inverse of
        m: The modulus
        
    Returns:
        Modular inverse of a mod m
        
    Raises:
        ValueError: If inverse doesn't exist (gcd(a, m) != 1)
    """
    g, x, _ = extended_gcd(a % m, m)
    
    if g != 1:
        raise ValueError(f"Modular inverse doesn't exist (gcd({a}, {m}) = {g})")
    
    return x % m


def is_probably_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    
    A probabilistic test that determines if n is probably prime.
    Probability of false positive: at most (1/4)^k
    
    Algorithm:
    1. Write n-1 as 2^r * d (factor out powers of 2)
    2. For k random witnesses a:
       - Compute x = a^d mod n
       - If x = 1 or x = n-1, continue
       - Square x up to r-1 times, looking for n-1
       - If never found, n is composite
    
    Args:
        n: Number to test for primality
        k: Number of rounds (witnesses to test)
        
    Returns:
        True if n is probably prime, False if definitely composite
    """
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Small prime check for efficiency
    small_primes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        # Random witness in range [2, n-2]
        a = secrets.randbelow(n - 3) + 2
        
        # Compute x = a^d mod n using our square-and-multiply
        x = mod_exp(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        # Square up to r-1 times
        composite = True
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False
    
    return True


def generate_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random prime number of specified bit length.
    
    Uses Miller-Rabin primality testing with k rounds.
    
    Args:
        bits: Desired bit length of the prime
        k: Number of Miller-Rabin rounds
        
    Returns:
        A prime number of the specified bit length
        
    Raises:
        ValueError: If bits < 2
    """
    if bits < 2:
        raise ValueError("Bit length must be at least 2")
    
    while True:
        # Generate random odd number with correct bit length
        # Set MSB to ensure correct bit length
        # Set LSB to ensure odd number
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # Set MSB
        candidate |= 1  # Set LSB (make odd)
        
        if is_probably_prime_miller_rabin(candidate, k):
            return candidate


def generate_rsa_keypair(bits: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate an RSA key pair.
    
    Generates two random primes p and q, computes n = p*q,
    and finds appropriate public and private exponents.
    
    Args:
        bits: Desired bit length of modulus n (default 2048)
        
    Returns:
        Tuple of ((e, n), (d, n)) where:
        - (e, n) is the public key
        - (d, n) is the private key
    """
    # Generate two distinct primes of half the bit length
    prime_bits = bits // 2
    
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(prime_bits)
    
    # Compute modulus
    n = p * q
    
    # Compute Euler's totient: φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Choose public exponent e
    # Common choice is 65537 (2^16 + 1) - it's prime and efficient
    e = 65537
    
    # Ensure gcd(e, φ(n)) = 1
    while gcd(e, phi_n) != 1:
        e += 2  # Try next odd number
    
    # Compute private exponent d = e^(-1) mod φ(n)
    d = mod_inverse(e, phi_n)
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key


def rsa_encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    RSA encryption of a message.
    
    Computes ciphertext = message^e mod n
    
    Args:
        message: Integer message (must be < n)
        public_key: Tuple (e, n)
        
    Returns:
        Encrypted ciphertext as integer
    """
    e, n = public_key
    if message >= n:
        raise ValueError("Message must be less than modulus n")
    return mod_exp(message, e, n)


def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    RSA decryption of a ciphertext.
    
    Computes message = ciphertext^d mod n
    
    Args:
        ciphertext: Encrypted integer
        private_key: Tuple (d, n)
        
    Returns:
        Decrypted message as integer
    """
    d, n = private_key
    return mod_exp(ciphertext, d, n)


def rsa_sign(message: int, private_key: Tuple[int, int]) -> int:
    """
    RSA digital signature.
    
    Computes signature = message^d mod n
    
    Args:
        message: Message hash as integer (must be < n)
        private_key: Tuple (d, n)
        
    Returns:
        Digital signature as integer
    """
    d, n = private_key
    if message >= n:
        raise ValueError("Message must be less than modulus n")
    return mod_exp(message, d, n)


def rsa_verify(message: int, signature: int, public_key: Tuple[int, int]) -> bool:
    """
    Verify an RSA digital signature.
    
    Checks if signature^e mod n == message
    
    Args:
        message: Original message hash as integer
        signature: Digital signature
        public_key: Tuple (e, n)
        
    Returns:
        True if signature is valid, False otherwise
    """
    e, n = public_key
    decrypted = mod_exp(signature, e, n)
    return decrypted == message


def bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    """Convert integer to bytes (big-endian)."""
    if length is None:
        length = (n.bit_length() + 7) // 8
        length = max(1, length)  # At least 1 byte
    return n.to_bytes(length, byteorder='big')


class RSAKeyPair:
    """
    RSA key pair container with convenient methods.
    
    Example:
        >>> keypair = RSAKeyPair.generate(bits=1024)
        >>> message = 12345
        >>> ciphertext = keypair.encrypt(message)
        >>> decrypted = keypair.decrypt(ciphertext)
        >>> decrypted == message
        True
    """
    
    def __init__(self, public_key: Tuple[int, int], private_key: Tuple[int, int]):
        """
        Initialize with existing keys.
        
        Args:
            public_key: Tuple (e, n)
            private_key: Tuple (d, n)
        """
        self._public_key = public_key
        self._private_key = private_key
        self._e, self._n = public_key
        self._d, _ = private_key
    
    @classmethod
    def generate(cls, bits: int = 2048) -> 'RSAKeyPair':
        """
        Generate a new RSA key pair.
        
        Args:
            bits: Bit length of modulus n
            
        Returns:
            New RSAKeyPair instance
        """
        public_key, private_key = generate_rsa_keypair(bits)
        return cls(public_key, private_key)
    
    @property
    def public_key(self) -> Tuple[int, int]:
        """Public key (e, n)."""
        return self._public_key
    
    @property
    def private_key(self) -> Tuple[int, int]:
        """Private key (d, n)."""
        return self._private_key
    
    @property
    def modulus(self) -> int:
        """Modulus n."""
        return self._n
    
    @property
    def public_exponent(self) -> int:
        """Public exponent e."""
        return self._e
    
    @property
    def private_exponent(self) -> int:
        """Private exponent d."""
        return self._d
    
    @property
    def key_size(self) -> int:
        """Key size in bits."""
        return self._n.bit_length()
    
    def encrypt(self, message: int) -> int:
        """Encrypt a message using public key."""
        return rsa_encrypt(message, self._public_key)
    
    def decrypt(self, ciphertext: int) -> int:
        """Decrypt a ciphertext using private key."""
        return rsa_decrypt(ciphertext, self._private_key)
    
    def sign(self, message: int) -> int:
        """Sign a message using private key."""
        return rsa_sign(message, self._private_key)
    
    def verify(self, message: int, signature: int) -> bool:
        """Verify a signature using public key."""
        return rsa_verify(message, signature, self._public_key)
    
    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt bytes (must be shorter than key size)."""
        msg_int = bytes_to_int(data)
        if msg_int >= self._n:
            raise ValueError("Data too long for key size")
        cipher_int = self.encrypt(msg_int)
        return int_to_bytes(cipher_int, (self._n.bit_length() + 7) // 8)
    
    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt bytes."""
        cipher_int = bytes_to_int(data)
        msg_int = self.decrypt(cipher_int)
        return int_to_bytes(msg_int)
    
    def __repr__(self) -> str:
        return f"RSAKeyPair(bits={self.key_size}, e={self._e})"


# Self-test when run directly
if __name__ == "__main__":
    print("RSA Math Implementation Test")
    print("=" * 70)
    
    # Test 1: Modular exponentiation (square-and-multiply)
    print("\n[Test 1] Modular exponentiation (square-and-multiply)")
    test_cases = [
        (2, 10, 1000, 24),       # 2^10 mod 1000 = 1024 mod 1000 = 24
        (3, 7, 13, 3),           # 3^7 mod 13 = 2187 mod 13 = 3
        (5, 117, 19, 1),         # Fermat's little theorem: 5^18 ≡ 1 (mod 19)
        (7, 0, 13, 1),           # Any number^0 = 1
        (0, 5, 13, 0),           # 0^n = 0
    ]
    test1_pass = True
    for base, exp, mod, expected in test_cases:
        result = mod_exp(base, exp, mod)
        passed = result == expected
        test1_pass = test1_pass and passed
        print(f"  {base}^{exp} mod {mod} = {result} (expected {expected}) {'✓' if passed else '✗'}")
    
    # Test 2: Miller-Rabin primality test
    print("\n[Test 2] Miller-Rabin primality test")
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101, 1009, 104729]
    composites = [4, 6, 8, 9, 10, 15, 21, 100, 1000, 104730]
    
    test2_pass = True
    for p in primes:
        result = is_probably_prime_miller_rabin(p)
        if not result:
            print(f"  FAIL: {p} should be prime")
            test2_pass = False
    for c in composites:
        result = is_probably_prime_miller_rabin(c)
        if result:
            print(f"  FAIL: {c} should be composite")
            test2_pass = False
    print(f"  Tested {len(primes)} primes and {len(composites)} composites: {'✓ PASS' if test2_pass else '✗ FAIL'}")
    
    # Test 3: Prime generation
    print("\n[Test 3] Prime generation")
    prime_16 = generate_prime(16)
    prime_32 = generate_prime(32)
    test3_pass = (is_probably_prime_miller_rabin(prime_16) and 
                  is_probably_prime_miller_rabin(prime_32) and
                  prime_16.bit_length() == 16 and
                  prime_32.bit_length() == 32)
    print(f"  16-bit prime: {prime_16} (bits: {prime_16.bit_length()})")
    print(f"  32-bit prime: {prime_32} (bits: {prime_32.bit_length()})")
    print(f"  Valid primes with correct bit lengths: {'✓ PASS' if test3_pass else '✗ FAIL'}")
    
    # Test 4: RSA key generation and encryption (small key for speed)
    print("\n[Test 4] RSA key generation and encryption (512-bit for test)")
    keypair = RSAKeyPair.generate(bits=512)
    print(f"  Generated: {keypair}")
    print(f"  Modulus n: {keypair.modulus.bit_length()} bits")
    
    original_message = 12345678901234567890
    ciphertext = keypair.encrypt(original_message)
    decrypted = keypair.decrypt(ciphertext)
    test4_pass = decrypted == original_message
    print(f"  Original:  {original_message}")
    print(f"  Encrypted: {ciphertext}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Correct decryption: {'✓ PASS' if test4_pass else '✗ FAIL'}")
    
    # Test 5: RSA digital signature
    print("\n[Test 5] RSA digital signature")
    message_hash = 9876543210
    signature = keypair.sign(message_hash)
    valid = keypair.verify(message_hash, signature)
    invalid = keypair.verify(message_hash + 1, signature)  # Tampered message
    test5_pass = valid and not invalid
    print(f"  Message hash: {message_hash}")
    print(f"  Signature:    {signature}")
    print(f"  Valid signature: {valid}")
    print(f"  Tampered message rejected: {not invalid}")
    print(f"  Signature verification: {'✓ PASS' if test5_pass else '✗ FAIL'}")
    
    # Test 6: Modular inverse
    print("\n[Test 6] Modular inverse")
    a, m = 17, 43
    inv = mod_inverse(a, m)
    check = (a * inv) % m
    test6_pass = check == 1
    print(f"  {a}^(-1) mod {m} = {inv}")
    print(f"  Verification: {a} * {inv} mod {m} = {check}")
    print(f"  Correct inverse: {'✓ PASS' if test6_pass else '✗ FAIL'}")
    
    # Summary
    all_passed = test1_pass and test2_pass and test3_pass and test4_pass and test5_pass and test6_pass
    print("\n" + "=" * 70)
    print(f"Overall: {'All tests passed!' if all_passed else 'Some tests failed!'}")
