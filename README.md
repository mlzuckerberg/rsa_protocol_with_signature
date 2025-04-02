# RSA Encryption and Digital Signature Demo

This Python program demonstrates RSA encryption and digital signatures using a simplified two-letter block system.

## Overview

The program implements:
- Basic RSA encryption/decryption
- Digital signatures
- Combined encryption with signatures
- Two-user message exchange simulation

## How It Works

### Message Encoding
- Messages are split into 2-letter blocks (e.g., "MICHELLE" → ["MI", "CH", "EL", "LE"])
- Each block is converted to a number (e.g., "MI" → 1309)
- Only uppercase letters A-Z are supported

### RSA Requirements
- Product of primes (n = p*q) must be > 2626 to handle any 2-letter block
- 'AA' → 0101 (smallest block)
- 'ZZ' → 2626 (largest block)

### Example Key Values
Good values:
- p = 61, q = 53 → n = 3233 (good: 3233 > 2626)
- e = 17 (common choice)

Bad values:
- p = 23, q = 53 → n = 1219 (bad: 1219 < 2626)
- Would fail for messages like 'OV' (1522)

## Usage

1. Run the program:
   - bash
   - python rsa_signature.py
   
2. Choose an operation (1-9):
   - Simple RSA Encryption
   - Simple RSA Decryption
   - Simple Digital Signature
   - Simple Digital Signature Verification
   - Two-User RSA Encryption
   - Two-User RSA Decryption
   - Two-User RSA Encryption with Signature
   - Two-User RSA Decryption with Signature Verification
   - Exit

3. Follow the prompts to:
   - Generate keys (enter prime numbers)
   - Input messages
   - Encrypt/decrypt/sign/verify

## Requirements

- Python 3.6+
- No external dependencies

## License

MIT License
