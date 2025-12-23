# CryptoVault

A comprehensive cryptography project demonstrating various cryptographic concepts and implementations.

## Project Structure

```
cryptovault/
├── src/
│   ├── core_crypto/      # Core cryptographic implementations
│   │   ├── sha256.py     # SHA-256 hash implementation
│   │   ├── merkle.py     # Merkle tree implementation
│   │   ├── aes_key_schedule.py  # AES key schedule
│   │   ├── lfsr_cipher.py       # LFSR stream cipher
│   │   └── rsa_math.py   # RSA mathematical operations
│   ├── auth/             # Authentication modules
│   ├── messaging/        # Secure messaging
│   ├── files/            # File encryption
│   ├── blockchain/       # Blockchain implementation
│   └── main.py           # Main entry point
├── tests/                # Unit tests
├── README.md
└── requirements.txt
```

## Setup

1. Create virtual environment:
   ```bash
   python -m venv venv
   ```

2. Activate virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python src/main.py
```

## Testing

```bash
pytest tests/
```

## Coverage

```bash
coverage run -m pytest tests/
coverage report
```
