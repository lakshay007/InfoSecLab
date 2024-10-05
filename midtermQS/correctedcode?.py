import random
import hashlib
from sympy import isprime

def generate_large_prime(bits=128):
    """Generate a large prime number."""
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def encrypt_message(message, n, e):
    """Encrypt the message using Rabin encryption."""
    encrypted_message = []
    for char in message:
        m = ord(char)  # Convert character to its ASCII value
        c = pow(m, e, n)  # Encryption: c = m^e % n
        encrypted_message.append(c)
    return encrypted_message

def sha512_hash(data):
    """Return SHA-512 hash of the given data."""
    return hashlib.sha512(data).hexdigest()

def mod_inverse(a, m):
    """Calculate modular inverse of a under modulo m using Extended Euclidean Algorithm."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    """Calculate the greatest common divisor (GCD) of a and b."""
    while b:
        a, b = b, a % b
    return a

def rabin():
    """Perform Rabin encryption and decryption."""
    p = generate_large_prime(128)
    q = generate_large_prime(128)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Ensure e is coprime with phi_n and less than phi_n
    e = 2
    while e >= phi_n or gcd(e, phi_n) != 1:
        e += 1

    # Compute the modular inverse for the private key
    d = mod_inverse(e, phi_n)

    message = input("Enter the message to encrypt: ")
    encrypted_message = encrypt_message(message, n, e)

    print("Original Message:", message)
    print("Encrypted Message:", encrypted_message)

    # Decryption process (for demonstration, we can decrypt each encrypted character)
    decrypted_message = decrypt_message(encrypted_message, n, d)
    print("Decrypted Message:", decrypted_message)

def decrypt_message(encrypted_message, n, d):
    """Decrypt the message using Rabin decryption."""
    decrypted_message = []
    for c in encrypted_message:
        m = pow(c, d, n)  # Decryption: m = c^d % n
        decrypted_message.append(chr(m))  # Convert ASCII value back to character
    return ''.join(decrypted_message)

def elgamal():
    """Perform ElGamal encryption and decryption."""
    p = generate_large_prime(128)  # Generate a large prime
    g = random.randint(2, p - 1)    # Choose a random generator
    x = random.randint(2, p - 2)    # Private key
    h = pow(g, x, p)                 # Public key component

    message = input("Enter the message to encrypt: ")
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')

    # Encryption
    k = random.randint(1, p - 2)  # Random integer
    c1 = pow(g, k, p)             # c1 = g^k mod p
    s = pow(h, k, p)              # s = h^k mod p
    c2 = (message_int * s) % p    # c2 = m * s mod p

    # Decryption
    s_inv = mod_inverse(s, p)      # Compute modular inverse of s
    message_int_decrypted = (c2 * s_inv) % p  # m = c2 * s_inv mod p

    # Convert integer back to bytes
    message_decrypted = message_int_decrypted.to_bytes((message_int_decrypted.bit_length() + 7) // 8, 'big').decode('utf-8')

    # Output results
    print("Original Message:", message)
    print("Encrypted Message:")
    print("c1:", c1)
    print("c2:", c2)
    print("Decrypted Message:", message_decrypted)

# Main menu for encryption and hashing
while True:
    print("\n1. For Rabin Encryption\n2. For ElGamal Encryption\n3. For SHA-512 Hashing\n4. For Exit")
    try:
        ch = int(input("Enter the choice: "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        continue

    if ch == 1:
        rabin()
    elif ch == 2:
        elgamal()
    elif ch == 3:
        message = input("Enter the message to hash: ")
        print("SHA-512 Hash:", sha512_hash(message.encode()))
    elif ch == 4:
        break
    else:
        print("Wrong Choice")
