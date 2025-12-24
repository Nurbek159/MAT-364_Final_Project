#!/usr/bin/env python
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        CRYPTOVAULT LIVE DEMO                                  ║
║                   MAT-364 Final Project Demonstration                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

This script provides an interactive live demonstration of CryptoVault's
cryptographic features including:
- User Registration with password hashing
- TOTP Two-Factor Authentication setup
- Login with MFA
- Blockchain-based audit logging
- Secure encrypted messaging between users
"""

import time
import sys

# Import all required modules
from src.auth.registration import UserRegistration, PasswordHasher_, validate_password_strength
from src.auth.login import LoginManager, RateLimiter
from src.auth.totp import TOTPGenerator, TOTPManager
from src.messaging.secure_channel import SecureChannel, KeyPair
from src.integration.event_logger import EventLogger, EventType
from src.core_crypto.sha256 import sha256_hex


def print_header(title):
    """Print a formatted section header"""
    print("\n" + "═" * 70)
    print(f"  {title}")
    print("═" * 70)


def print_step(step_num, description):
    """Print a numbered step"""
    print(f"\n  [{step_num}] {description}")


def pause(message="Press ENTER to continue..."):
    """Pause for presenter to explain"""
    print(f"\n  [PAUSE] {message}")
    input()


def typing_effect(text, delay=0.02):
    """Print text with typing effect"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()


def main():
    
    print("\n" * 2)
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "        CRYPTOVAULT - SECURE CRYPTOGRAPHIC PLATFORM".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("║" + "              MAT-364 Final Project Live Demo".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    
    print("\n  This demonstration showcases:")
    print("  • User registration with Argon2id password hashing")
    print("  • TOTP two-factor authentication (Google Authenticator compatible)")
    print("  • Secure login with multi-factor authentication")
    print("  • Blockchain-based immutable audit logging")
    print("  • End-to-end encrypted secure messaging")
    
    pause("Press ENTER to begin the demonstration...")

    print_header("PART 1: USER REGISTRATION")
    
    # Initialize systems
    registration = UserRegistration()
    event_logger = EventLogger(difficulty=4, auto_mine=False)
    
    print_step("1.1", "Password Strength Validation")
    
    # Weak password example
    weak_password = "password123"
    print(f"\n  Testing weak password: '{weak_password}'")
    result = validate_password_strength(weak_password)
    print(f"  [X] Valid: {result['valid']}")
    print(f"  Score: {result['score']}/100")
    if result['errors']:
        print(f"  [!] Errors: {result['errors']}")
    
    pause()
    
    # Strong password example
    strong_password = "SecureP@ss123!"
    print(f"\n  Testing strong password: '{strong_password}'")
    result = validate_password_strength(strong_password)
    print(f"  [OK] Valid: {result['valid']}")
    print(f"  Score: {result['score']}/100")
    
    pause()
    
    print_step("1.2", "Registering User 'Alice'")
    
    alice_password = "AliceSecure@2024!"
    reg_result = registration.register_user(
        username="alice",
        password=alice_password,
        email="alice@example.com"
    )
    
    print(f"\n  Username: alice")
    print(f"  Email: alice@example.com")
    print(f"  Password: {'*' * len(alice_password)}")
    print(f"\n  [OK] Registration Success: {reg_result['success']}")
    if reg_result.get('user_id'):
        print(f"  User ID: {reg_result['user_id'][:16]}...")
    
    pause()
    
    # Demonstrate password hashing
    print_step("1.3", "Password Hashing with Argon2id")
    
    hasher = PasswordHasher_()
    demo_hash = hasher.hash_password(alice_password)
    print(f"  Original Password: {alice_password}")
    print(f"\n  Argon2id Hash:")
    print(f"  {demo_hash[:60]}...")
    print(f"\n  The hash is:")
    print("  - One-way (cannot be reversed)")
    print("  - Salted (unique per password)")
    print("  - Memory-hard (resistant to GPU attacks)")
    
    pause()

    print_header("PART 2: TOTP TWO-FACTOR AUTHENTICATION SETUP")
    
    print_step("2.1", "Generating TOTP Secret for Alice")
    
    alice_totp = TOTPGenerator(
        issuer="CryptoVault",
        account_name="alice@example.com"
    )
    
    print(f"\n  TOTP Configuration:")
    print(f"  - Issuer: CryptoVault")
    print(f"  - Account: alice@example.com")
    print(f"  - Algorithm: SHA-1 (HMAC)")
    print(f"  - Digits: 6")
    print(f"  - Period: 30 seconds")
    
    pause()
    
    print_step("2.2", "Secret Key (for Authenticator App)")
    print(f"\n  Base32 Secret: {alice_totp.secret_base32}")
    
    print(f"\n  Provisioning URI (for QR code):")
    uri = alice_totp.get_provisioning_uri()
    print(f"  {uri[:60]}...")
    
    pause()
    
    print_step("2.3", "Generating Current TOTP Code")
    current_code = alice_totp.generate()
    print(f"\n  Current TOTP Code: {current_code}")
    print(f"  (Valid for ~30 seconds, changes automatically)")
    
    # Verify the code
    is_valid = alice_totp.verify(current_code)
    print(f"\n  [OK] Code Verification: {is_valid}")
    
    pause()

    print_header("PART 3: LOGIN WITH MULTI-FACTOR AUTHENTICATION")
    
    # Create login manager
    login_mgr = LoginManager(user_store=registration._users)
    
    print_step("3.1", "Alice Attempts Login with Password")
    
    login_result = login_mgr.login("alice", alice_password)
    print(f"\n  Username: alice")
    print(f"  Password: {'*' * len(alice_password)}")
    print(f"\n  [OK] Password Verification: {login_result['success']}")
    
    if login_result['success']:
        print(f"  Session ID: {login_result['session_id'][:20]}...")
        print(f"  Auth Token: {login_result['token'][:30]}...")
    
    pause()
    
    print_step("3.2", "TOTP Verification (Second Factor)")
    
    totp_code = alice_totp.generate()
    print(f"\n  Alice enters TOTP code: {totp_code}")
    totp_valid = alice_totp.verify(totp_code)
    print(f"  [OK] TOTP Verification: {totp_valid}")
    
    if totp_valid:
        print("\n  MULTI-FACTOR AUTHENTICATION SUCCESSFUL!")
        print("  Alice is now securely logged in.")
    
    pause()
    
    print_step("3.3", "Logging Event to Blockchain")
    
    event_logger.log_login("alice", success=True, ip_address="192.168.1.100")
    event_logger.log_totp("alice", success=True)
    event_logger.mine_events()
    
    print("\n  Events logged:")
    print("  - LOGIN_SUCCESS: alice from 192.168.1.100")
    print("  - TOTP_SUCCESS: alice verified 2FA")
    print("\n  Events mined into blockchain block")
    print(f"  Blockchain length: {event_logger.get_blockchain().length} blocks")
    print(f"  [OK] Audit trail integrity: {event_logger.verify_integrity()}")
    
    pause()
    
    # Demonstrate failed login attempt
    print_step("3.4", "Demonstrating Failed Login Attempt")
    
    failed_result = login_mgr.login("alice", "WrongPassword123!")
    print(f"\n  Username: alice")
    print(f"  Password: WrongPassword123!")
    print(f"\n  [X] Login Success: {failed_result['success']}")
    print(f"  Message: {failed_result['message']}")
    
    # Log failed attempt
    event_logger.log_login("alice", success=False, ip_address="10.0.0.99")
    event_logger.mine_events()
    print("\n  [!] Failed login attempt logged to blockchain")
    
    pause()

    print_header("PART 4: SECURE END-TO-END ENCRYPTED MESSAGING")
    
    print_step("4.1", "Registering Second User 'Bob'")
    
    bob_password = "BobSecure@2024!"
    reg_result = registration.register_user(
        username="bob",
        password=bob_password,
        email="bob@example.com"
    )
    print(f"\n  [OK] Bob registered successfully: {reg_result['success']}")
    
    pause()
    
    print_step("4.2", "Creating Secure Communication Channels")
    
    # Create key pairs for Alice and Bob
    alice_keys = KeyPair.generate()
    bob_keys = KeyPair.generate()
    
    print(f"\n  Alice's Public Key: {alice_keys.public_bytes().hex()[:40]}...")
    print(f"  Bob's Public Key: {bob_keys.public_bytes().hex()[:40]}...")
    
    # Create secure channels
    alice_channel = SecureChannel(alice_keys)
    bob_channel = SecureChannel(bob_keys)
    
    pause()
    
    print_step("4.3", "Establishing Shared Secret (ECDH Key Exchange)")
    
    alice_channel.establish(bob_channel.public_key)
    bob_channel.establish(alice_channel.public_key)
    
    print("\n  Key Exchange Complete!")
    print("  - Alice and Bob now share a secret session key")
    print("  - The key was NEVER transmitted over the network")
    print("  - An eavesdropper cannot derive the shared secret")
    
    pause()
    
    print_step("4.4", "Alice Sends Encrypted Message to Bob")
    
    secret_message = b"Hey Bob! This is a TOP SECRET message. Meet me at noon."
    print(f"\n  Original Message: {secret_message.decode()}")
    
    # Encrypt message
    encrypted_msg = alice_channel.encrypt_message(secret_message)
    encrypted_bytes = encrypted_msg.to_bytes()
    print(f"\n  Encrypted (AES-GCM):")
    print(f"  {encrypted_bytes.hex()[:60]}...")
    print(f"  (Total encrypted size: {len(encrypted_bytes)} bytes)")
    
    # Log the message send event
    msg_hash = sha256_hex(secret_message)
    event_logger.log_message_send("alice", "bob", message_hash=msg_hash[:16])
    
    pause()
    
    print_step("4.5", "Bob Decrypts Alice's Message")
    
    # Bob decrypts
    decrypted_msg = bob_channel.decrypt_message(encrypted_msg, alice_channel.public_key)
    print(f"\n  Bob receives encrypted data...")
    print(f"  Decrypted Message: {decrypted_msg.decode()}")
    print(f"\n  [OK] Message integrity verified (AEAD authentication)")
    
    pause()
    
    print_step("4.6", "Bob Replies to Alice")
    
    reply_message = b"Got it Alice! I'll be there. Stay safe!"
    print(f"\n  Bob's Reply: {reply_message.decode()}")
    
    encrypted_reply = bob_channel.encrypt_message(reply_message)
    print(f"  Encrypted Reply: {encrypted_reply.to_bytes().hex()[:40]}...")
    
    decrypted_reply = alice_channel.decrypt_message(encrypted_reply, bob_channel.public_key)
    print(f"  Alice Receives: {decrypted_reply.decode()}")
    
    event_logger.log_message_send("bob", "alice", message_hash=sha256_hex(reply_message)[:16])
    event_logger.mine_events()
    
    pause()

    print_header("PART 5: BLOCKCHAIN AUDIT TRAIL SUMMARY")
    
    print_step("5.1", "Complete Audit Log")
    
    events = event_logger.get_all_events()
    print(f"\n  Total Events Recorded: {len(events)}")
    print("\n  Event History:")
    
    for i, event in enumerate(events, 1):
        event_icon = {
            'LOGIN_SUCCESS': '[OK]',
            'LOGIN_FAILED': '[X]',
            'TOTP_SUCCESS': '[2FA]',
            'MESSAGE_SENT': '[MSG]',
        }.get(event.event_type.name, '[EVT]')
        
        print(f"  {i}. {event_icon} [{event.event_type.name}]")
        print(f"      User Hash: {event.user_hash[:16]}...")
        print(f"      Timestamp: {event.timestamp}")
    
    pause()
    
    print_step("5.2", "Blockchain Integrity Verification")
    
    chain = event_logger.get_blockchain()
    print(f"\n  Blockchain Statistics:")
    print(f"  - Total Blocks: {chain.length}")
    print(f"  - Mining Difficulty: 4 (4 leading zero bits)")
    
    # Show a block
    if chain.length > 1:
        blocks = chain.chain  # Get list of blocks
        block = blocks[1]  # Second block (after genesis)
        print(f"\n  Sample Block #{block.index}:")
        print(f"  - Transactions: {len(block.transactions)}")
        print(f"  - Merkle Root: {block.merkle_root.hex()[:32]}...")
        print(f"  - Previous Hash: {block.prev_hash.hex()[:32]}...")
        print(f"  - Block Hash: {block.hash.hex()[:32]}...")
        print(f"  - Nonce: {block.nonce}")
    
    is_valid = chain.validate_chain()
    print(f"\n  Chain Integrity Check: {'[OK] VALID' if is_valid else '[X] TAMPERED'}")
    
    if is_valid:
        print("\n  The audit trail is cryptographically secured and tamper-proof!")

    print("\n\n" + "═" * 70)
    print("  DEMONSTRATION COMPLETE!")
    print("═" * 70)
    

if __name__ == "__main__":
    main()
