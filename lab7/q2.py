import random
from sympy import isprime, mod_inverse

class RSA:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keypair()

    def generate_prime(self):
        while True:
            p = random.getrandbits(self.key_size // 2)
            if isprime(p):
                return p

    def generate_keypair(self):
        p = self.generate_prime()
        q = self.generate_prime()
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = random.randrange(1, phi_n)
        g = gcd(e, phi_n)
        while g != 1:
            e = random.randrange(1, phi_n)
            g = gcd(e, phi_n)
        d = mod_inverse(e, phi_n)
        public_key = (n, e)
        private_key = (n, d)
        return public_key, private_key

    def encrypt(self, plaintext):
        n, e = self.public_key
        return pow(plaintext, e, n)

    def decrypt(self, ciphertext):
        n, d = self.private_key
        return pow(ciphertext, d, n)

    def multiply_encrypted(self, c1, c2):
        n, _ = self.public_key
        return (c1 * c2) % n

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Example Usage with User Input
def main():
    rsa = RSA(key_size=512)

    try:
        plaintext1 = int(input("Enter the first integer to encrypt: "))
        plaintext2 = int(input("Enter the second integer to encrypt: "))
    except ValueError:
        print("Please enter valid integers.")
        return


    ciphertext1 = rsa.encrypt(plaintext1)
    ciphertext2 = rsa.encrypt(plaintext2)

    print(f"Ciphertext 1: {ciphertext1}")
    print(f"Ciphertext 2: {ciphertext2}")


    encrypted_product = rsa.multiply_encrypted(ciphertext1, ciphertext2)
    print(f"Encrypted Product: {encrypted_product}")

    decrypted_product = rsa.decrypt(encrypted_product)
    print(f"Decrypted Product: {decrypted_product}")


    print(f"Original Product: {plaintext1 * plaintext2}")

if __name__ == "__main__":
    main()
