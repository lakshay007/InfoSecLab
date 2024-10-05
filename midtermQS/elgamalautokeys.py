import random
from hashlib import sha256
from sympy import isprime, randprime


# Extended Euclidean Algorithm to find the GCD and coefficients
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# Function to compute modular inverse using Extended Euclidean Algorithm
def modinv(a, p):
    g, x, y = egcd(a, p)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % p


# Function to generate ElGamal signature
def elgamal_sign(p, g, x, message):
    # Generate a random k such that gcd(k, p-1) = 1
    while True:
        k = random.randint(1, p - 2)
        if egcd(k, p - 1)[0] == 1:
            break

    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    m_hash = int(sha256(message.encode()).hexdigest(), 16)

    s = (k_inv * (m_hash - x * r)) % (p - 1)

    return (r, s)


# Function to verify ElGamal signature
def elgamal_verify(p, g, y, message, signature):
    r, s = signature
    if r <= 0 or r >= p:
        return False

    m_hash = int(sha256(message.encode()).hexdigest(), 16)

    v1 = pow(g, m_hash, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p

    return v1 == v2


# Function to auto-generate keys
def generate_keys(keysize=512):
    # Generate a random large prime p
    p = randprime(2 ** (keysize - 1), 2 ** keysize)  # p is a prime number

    # Select a random generator g
    g = random.randint(2, p - 2)

    # Private key x
    x = random.randint(1, p - 2)

    # Public key y = g^x mod p
    y = pow(g, x, p)

    return p, g, x, y


# Main Function
def main():
    print("ElGamal Digital Signature with Auto-Generated Keys")

    # Auto-generate keys
    p, g, x, y = generate_keys()

    print("Generated Prime (p):", p)
    print("Generated Generator (g):", g)
    print("Private Key (x):", x)
    print("Public Key (y):", y)

    # Message to sign
    message = input("Enter the message to sign: ")

    # Generate signature
    signature = elgamal_sign(p, g, x, message)

    print("\nSignature (r, s): ", signature)

    # Verify the signature
    verification_result = elgamal_verify(p, g, y, message, signature)

    if verification_result:
        print("The signature is valid!")
    else:
        print("The signature is NOT valid!")


# Run the main function
if __name__ == "__main__":
    main()
