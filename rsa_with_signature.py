"""
RSA Encryption and Digital Signature Protocol

Each user (A and B) has their own key pairs:
User A:
    Public key: (eA, nA) - Known to everyone
    Private key: (dA, nA) - Known only to A
    where nA = pA * qA and φ(nA) = (pA-1)(qA-1)

User B:
    Public key: (eB, nB) - Known to everyone
    Private key: (dB, nB) - Known only to B
    where nB = pB * qB and φ(nB) = (pB-1)(qB-1)

Protocol Operations:
1. Simple RSA Encryption (A → B): 
    c = (m^eB) mod nB
2. Simple RSA Decryption (B): 
    m = (c^dB) mod nB
3. Digital Signature (A): 
    s = (m^dA) mod nA
4. Signature Verification (using A's signature):
    m = (s^eA) mod nA
5. Secure Message (A → B):
    c = (m^eB) mod nB
6. Secure Message Decryption (B):
    m = (c^dB) mod nB
7. Signed Secure Message (A → B):
    s = (m^dA) mod nA (sign)
    c = (s^eB) mod nB (encrypt)
8. Signed Message Decryption and Verification (B):
    s = (c^dB) mod nB (decrypt)
    m = (s^eA) mod nA (verify)

"""
from math import gcd

def is_prime(n):
    """
    Check if a number is prime.
    """
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) where gcd is the greatest common divisor of a and b
    and x, y are coefficients where ax + by = gcd
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """
    Calculate the modular multiplicative inverse of a modulo m.
    Returns x where (a * x) % m = 1
    """
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} (mod {m})")
    return x % m

def get_prime_input(prompt):
    """
    Prompt the user for a prime number and validate it.
    
    Args:
        prompt (str): Message to display to user
    
    Returns:
        int: A validated prime number
        
    Note: Warns if number is too small for real RSA (< 127)
    """
    while True:
        try:
            value = int(input(prompt))
            if value < 127:  # Minimum reasonable size for demonstration
                print("Warning: Small prime numbers are not secure for real RSA.")
            if is_prime(value):
                return value
            else:
                print("The number is not prime. Please enter a prime number.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

def get_coprime_input(prompt, phi):
    """
    Prompt the user for a number e that is coprime with phi.
    
    Args:
        prompt (str): Message to display to user
        phi (int): The totient value φ(n) = (p-1)(q-1)
    
    Returns:
        int: A number coprime with phi (gcd(e,phi) = 1)
    """
    while True:
        try:
            value = int(input(prompt))
            if gcd(value, phi) == 1:
                return value
            else:
                print(f"The number is not coprime with {phi}. Please enter a different number.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

def generate_keypair(prompt_prefix=""):
    """
    Generate RSA key pair by prompting for p, q, and e values.
    
    RSA Key Generation Requirements:
    1. Choose primes p, q where n = p*q must be larger than any possible message block
    2. For 2-letter blocks:
       - 'AA' → 0101 (smallest)
       - 'ZZ' → 2626 (largest)
       - Therefore n must be > 2626
    3. If n is too small:
       - Message m ≥ n will wrap around due to modulo
       - Multiple messages would encrypt to same value
       - Decryption becomes ambiguous
    
    Example of good values:
    - p = 61, q = 53 → n = 3233 (good: 3233 > 2626)
    - e = 17 (common choice, must be coprime with (p-1)(q-1))
    
    Example of bad values:
    - p = 23, q = 53 → n = 1219 (bad: 1219 < 2626)
    - This would fail for messages like 'OV' (1522) or 'ZZ' (2626)
    """
    print(f"\nGenerating {prompt_prefix}keys...")
    print("Note: For secure RSA, primes should be at least 512 bits each.")
    print("Important: Use different primes for each user!")
    while True:
        p = get_prime_input(f"Enter a prime number for {prompt_prefix}p: ")
        q = get_prime_input(f"Enter a prime number for {prompt_prefix}q: ")
        n = p * q
        if n < 2627:  # Check if n is large enough for any 2-letter block
            print(f"n = {n} is too small! Need n > 2626 to handle all possible 2-letter blocks.")
            print("Please use larger prime numbers.")
            continue
        phi = (p - 1) * (q - 1)
        
        print(f"\nChoose e (must be coprime with {phi})")
        print("Common choice is 17 or 65537. Must be coprime with phi.")
        e = get_coprime_input(f"Enter a number for {prompt_prefix}e: ", phi)
            
        d = mod_inverse(e, phi)
        return ((e, n), (d, n))

def text_to_number(text):
    """Convert text to a single number."""
    return int(''.join(f"{ord(char) - ord('A') + 1:02}" for char in text.upper()))

def number_to_text(number):
    """Convert a number back to text, ensuring valid mapping."""
    num_str = f"{number:0{len(str(number))}d}"
    result = []
    for i in range(0, len(num_str), 2):
        num = int(num_str[i:i+2])
        if 1 <= num <= 26:
            result.append(chr(num + ord('A') - 1))
    return ''.join(result)

def partition_number(number, block_size):
    """Partition a number into blocks of a given size."""
    num_str = f"{number:0{len(str(number))}d}"
    return [int(num_str[i:i + block_size]) for i in range(0, len(num_str), block_size)]

def partition_message(message, block_size=2):
    """
    Split message into 2-letter blocks for RSA processing.
    
    Example: 
        'MICHELLE' becomes ['MI', 'CH', 'EL', 'LE']
    
    Args:
        message (str): Uppercase letters only
        block_size (int): Size of each block (default 2)
    
    Returns:
        list: List of 2-letter blocks
    """
    message = message.upper()
    if not all(char.isalpha() for char in message):
        raise ValueError("Message must contain only letters A-Z")
    
    blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
    print(f"Partitioning '{message}' into blocks: {blocks}")  # Debug print
    return blocks

def text_block_to_number(text_block):
    """
    Convert a 2-letter block to its numerical representation.
    
    The number must be smaller than n in RSA key pair.
    Example: 
        'MI' → '13-09' → 1309
        'ZZ' → '26-26' → 2626 (largest possible value)
    
    This is why we need n > 2626 in our RSA key generation.
    """
    return int(''.join(f"{(ord(char) - ord('A') + 1):02}" for char in text_block))

def number_to_text_block(number):
    """
    Convert a number back to a 2-letter block.
    
    Example:
        1309 → '13-09' → 'MI'
        2626 → '26-26' → 'ZZ'
    
    The input number must come from RSA decryption
    and must represent a valid 2-letter block (00-26 for each position).
    """
    num_str = f"{number:04d}"  # Pad to 4 digits for 2-letter blocks
    result = []
    for i in range(0, len(num_str), 2):
        num = int(num_str[i:i+2])
        if 1 <= num <= 26:
            result.append(chr(num + ord('A') - 1))
        else:
            raise ValueError(f"Invalid number {num} in conversion (must be 1-26)")
    return ''.join(result)

def simple_rsa_encrypt(recipient_public_key, message):
    """
    Encrypt a message block by block using recipient's public key.
    
    Process:
        1. Split message into 2-letter blocks
        2. Convert each block to number (e.g., 'MI' → 1309)
        3. Encrypt each number: c = m^e mod n
    
    Args:
        recipient_public_key (tuple): (e,n) of recipient
        message (str): Message to encrypt
    
    Returns:
        list: Encrypted blocks (ciphertext numbers)
    """
    e, n = recipient_public_key
    print("\nENCRYPTION STEPS:")
    print(f"Using public key: e = {e}, n = {n}")
    print(f"Original message: {message}")
    
    blocks = partition_message(message)
    print(f"Message blocks: {blocks}")
    
    encrypted_blocks = []
    for i, block in enumerate(blocks):
        print(f"\nProcessing block {i+1}: '{block}'")
        m = text_block_to_number(block)
        if m >= n:
            raise ValueError(f"Block number {m} is too large for modulus {n}. Please use larger prime numbers.")
        print(f"Block to number: '{block}' → {m}")
        c = pow(m, e, n)
        print(f"Encryption: {m}^{e} mod {n} = {c}")
        encrypted_blocks.append(c)
    
    print(f"\nFinal encrypted blocks: {encrypted_blocks}")
    return encrypted_blocks

def simple_rsa_decrypt(own_private_key, ciphertext_blocks):
    """
    Decrypt ciphertext blocks using your private key.
    
    Process:
        1. Decrypt each block: m = c^d mod n
        2. Convert each number back to letters
        3. Join blocks to form message
    
    Args:
        own_private_key (tuple): (d,n) of recipient
        ciphertext_blocks (list): List of encrypted numbers
    
    Returns:
        str: Decrypted message
    """
    d, n = own_private_key
    decrypted_message = []
    
    for block in ciphertext_blocks:
        # Decrypt the block
        m = pow(block, d, n)
        # Convert number back to text
        text_block = number_to_text_block(m)
        decrypted_message.append(text_block)
    
    return ''.join(decrypted_message)

def simple_sign(own_private_key, message):
    """
    Sign a message block by block using your private key.
    
    Process:
        1. Split message into 2-letter blocks
        2. Convert each block to number
        3. Sign each number: s = m^d mod n
    
    Args:
        own_private_key (tuple): (d,n) of signer
        message (str): Message to sign
    
    Returns:
        list: Signature blocks
    """
    d, n = own_private_key
    print("\nSIGNING STEPS:")
    print(f"Using private key: d = {d}, n = {n}")
    print(f"Message to sign: {message}")
    
    blocks = partition_message(message)
    print(f"Message blocks: {blocks}")
    
    signature_blocks = []
    for i, block in enumerate(blocks):
        print(f"\nProcessing block {i+1}: '{block}'")
        m = text_block_to_number(block)
        print(f"Block to number: '{block}' → {m}")
        s = pow(m, d, n)
        print(f"Signing: {m}^{d} mod {n} = {s}")
        signature_blocks.append(s)
    
    print(f"\nFinal signature blocks: {signature_blocks}")
    return signature_blocks

def simple_verify(signer_public_key, signature_blocks):
    """
    Verify signature blocks using signer's public key.
    
    Process:
        1. Verify each block: m = s^e mod n
        2. Convert recovered numbers to text
        3. Join blocks to form original message
    
    Args:
        signer_public_key (tuple): (e,n) of signer
        signature_blocks (list): List of signature numbers
    
    Returns:
        str: Verified message
    
    Raises:
        ValueError: If verification fails (invalid numbers)
    """
    e, n = signer_public_key
    print("\nVERIFICATION STEPS:")
    print(f"Using public key: e = {e}, n = {n}")
    print(f"Received signature blocks: {signature_blocks}")
    
    verified_message = []
    for i, block in enumerate(signature_blocks):
        print(f"\nProcessing block {i+1}: {block}")
        m = pow(block, e, n)
        print(f"Verification: {block}^{e} mod {n} = {m}")
        # Convert back to original message format (1309 → 'MI')
        m_str = f"{m:04d}"  # Pad to 4 digits for 2-letter blocks
        # Take pairs of digits and convert to letters (13-09 → 'MI')
        text_block = ''
        for j in range(0, len(m_str), 2):
            num = int(m_str[j:j+2])
            if 1 <= num <= 26:
                text_block += chr(num + ord('A') - 1)
            else:
                print(f"Warning: Got invalid number {num} during verification.")
                print(f"Original number: {m}")
                print(f"Formatted string: {m_str}")
                print(f"Current pair: {m_str[j:j+2]}")
                raise ValueError(f"Invalid number {num} in conversion (must be 1-26)")
        print(f"Number to text: {m} → '{text_block}'")
        verified_message.append(text_block)
    
    final_message = ''.join(verified_message)
    print(f"\nFinal verified message: '{final_message}'")
    return final_message

def main():
    while True:
        # Reset keys at the start of each operation
        public_key_A = private_key_A = None
        public_key_B = private_key_B = None

        print("\nChoose an operation:")
        print("1. Simple RSA Encryption")
        print("2. Simple RSA Decryption")
        print("3. Simple Digital Signature")
        print("4. Simple Digital Signature Verification")
        print("5. Two-User RSA Encryption without Digital Signature")
        print("6. Two-User RSA Decryption without Digital Signature Verification")
        print("7. Two-User RSA Encryption with Digital Signature")
        print("8. Two-User RSA Decryption with Digital Signature Verification")
        print("9. Exit")

        choice = input("Enter your choice (1-9): ")

        if choice == '1':
            if not public_key_A:
                print("Generating keys for A...")
                public_key_A, private_key_A = generate_keypair("A")
            message = input("Enter the message to encrypt: ")
            ciphertext_blocks = simple_rsa_encrypt(public_key_A, message)
            print("Ciphertext Blocks:", ' '.join(f"{block:04}" for block in ciphertext_blocks))

        elif choice == '2':
            if not private_key_A:
                print("Generating keys for A...")
                public_key_A, private_key_A = generate_keypair("A")
            ciphertext = input("Enter the ciphertext blocks to decrypt (space-separated numbers): ")
            ciphertext_blocks = list(map(int, ciphertext.split()))
            plaintext = simple_rsa_decrypt(private_key_A, ciphertext_blocks)
            print("Decrypted Message:", plaintext)

        elif choice == '3':
            if not private_key_A:
                print("Generating keys for A...")
                public_key_A, private_key_A = generate_keypair("A")
            message = input("Enter the message to sign: ")
            signature_blocks = simple_sign(private_key_A, message)
            print("Signature Blocks:", ' '.join(f"{block:04}" for block in signature_blocks))

        elif choice == '4':
            if not public_key_A:
                print("Generating keys for A...")
                public_key_A, private_key_A = generate_keypair("A")
            signature = input("Enter the signature blocks to verify (space-separated numbers): ")
            signature_blocks = list(map(int, signature.split()))
            verified_message = simple_verify(public_key_A, signature_blocks)
            print("Verified Message:", verified_message)

        elif choice == '5':
            if not public_key_B:
                print("Generating keys for B...")
                public_key_B, private_key_B = generate_keypair("B")
            message = input("Enter the message to encrypt: ")
            ciphertext_blocks = simple_rsa_encrypt(public_key_B, message)
            print("Ciphertext Blocks:", ' '.join(f"{block:04}" for block in ciphertext_blocks))

        elif choice == '6':
            if not private_key_B:
                print("Generating keys for B...")
                public_key_B, private_key_B = generate_keypair("B")
            ciphertext = input("Enter the ciphertext blocks to decrypt (space-separated numbers): ")
            ciphertext_blocks = list(map(int, ciphertext.split()))
            plaintext = simple_rsa_decrypt(private_key_B, ciphertext_blocks)
            print("Decrypted Message:", plaintext)

        elif choice == '7':
            if not private_key_A:
                print("Generating keys for A...")
                public_key_A, private_key_A = generate_keypair("A")
            if not public_key_B:
                print("Generating keys for B...")
                public_key_B, private_key_B = generate_keypair("B")
            message = input("Enter the message to encrypt and sign: ")
            
            print("\nSIGNING PROCESS (Using A's private key):")
            signature_blocks = simple_sign(private_key_A, message)
            
            print("\nENCRYPTION PROCESS (Using B's public key):")
            encrypted_blocks = []
            for block in signature_blocks:
                c = pow(block, public_key_B[0], public_key_B[1])
                encrypted_blocks.append(c)
            
            print("Final ciphertext blocks:", ' '.join(f"{block:04}" for block in encrypted_blocks))

        elif choice == '8':
            if not (private_key_B and public_key_A):  # Check both keys at once
                if not private_key_B:
                    print("Generating keys for B...")
                    public_key_B, private_key_B = generate_keypair("B's ")
                if not public_key_A:
                    print("Generating keys for A...")
                    public_key_A, private_key_A = generate_keypair("A's ")
            
            ciphertext = input("Enter the ciphertext blocks to decrypt and verify (space-separated numbers): ")
            ciphertext_blocks = list(map(int, ciphertext.split()))
            
            print("\nDECRYPTION PROCESS (Using B's private key):")
            signature_blocks = []
            for i, block in enumerate(ciphertext_blocks):
                print(f"\nDecrypting block {i+1}: {block}")
                s = pow(block, private_key_B[0], private_key_B[1])
                print(f"Decryption: {block}^d mod n = {s}")
                signature_blocks.append(s)
            
            print("\nVERIFICATION PROCESS (Using A's public key):")
            try:
                verified_message = simple_verify(public_key_A, signature_blocks)
                print("Verified Message:", verified_message)
            except ValueError as e:
                print(f"Verification failed: {e}")
                print("This might happen if:")
                print("1. The keys used for verification don't match the ones used for signing")
                print("2. The message was corrupted")
                print("Please try again with matching keys")

        elif choice == '9':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

        # Ask if the user wants to perform more computations
        continue_choice = input("Would you like to make more computations? (y/n): ").strip().lower()
        if continue_choice != 'y':
            print("Exiting...")
            break

if __name__ == "__main__":
    main()

