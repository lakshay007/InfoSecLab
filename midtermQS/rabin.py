import random
from sympy import isprime


def generate_large_prime(bits=256):
    """Generate a large prime number."""
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p


def generate_keys():
    """Generate Rabin cryptosystem keys (public and private)."""
    p = generate_large_prime(128)  # Use smaller bits for faster computation in examples
    q = generate_large_prime(128)

    n = p * q
    return (n, p, q)


def encrypt(message, n):
    """Encrypt a message using the Rabin cryptosystem."""
    message_int = int.from_bytes(message.encode(), 'big')
    ciphertext = pow(message_int, 2, n)  # c = m^2 mod n
    return ciphertext


def decrypt(ciphertext, p, q):
    """Decrypt a ciphertext using the Rabin cryptosystem."""
    n = p * q

    # Compute the square roots modulo p and q
    sqrt_p = pow(ciphertext, (p + 1) // 4, p)  # m = c^((p + 1) // 4) mod p
    sqrt_q = pow(ciphertext, (q + 1) // 4, q)  # m = c^((q + 1) // 4) mod q

    # Using the Chinese Remainder Theorem (CRT) to find the original message
    m1 = sqrt_p
    m2 = (sqrt_q + n) % n
    m3 = (n - sqrt_p) % n
    m4 = (n - sqrt_q) % n

    return [m1, m2, m3, m4]


def valid_utf8_bytes(message_int):
    """Check if the integer can be converted to a valid UTF-8 string."""
    try:
        return message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big').decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        return None


def main():
    # Generate keys
    n, p, q = generate_keys()
    print("Public Key (n):", n)
    print("Private Key (p, q):", (p, q))

    # Take user input for the message
    message = input("Enter the message to encrypt: ")
    print("Original Message:", message)

    # Encrypt the message
    ciphertext = encrypt(message, n)
    print("Ciphertext:", ciphertext)

    # Decrypt the message
    decrypted_messages = decrypt(ciphertext, p, q)
    print("Decrypted Messages:")
    for m in decrypted_messages:
        decoded_message = valid_utf8_bytes(m)
        if decoded_message:
            print(decoded_message)
        else:
            print("Could not decode:", m)


if __name__ == "__main__":
    main()
