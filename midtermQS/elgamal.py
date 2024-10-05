import random
from hashlib import sha256


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


# Main Function for User Input
def main():
    print("ElGamal Digital Signature")

    # Inputs from the user
    p = int(input("Enter prime number p: "))
    g = int(input("Enter generator g: "))
    x = int(input("Enter private key x: "))

    # Public key
    y = pow(g, x, p)

    print("\nPublic Key y: ", y)

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
