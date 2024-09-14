import random
import sympy
from sympy import mod_inverse

# Paillier Cryptosystem
class Paillier:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keypair()

    def generate_keypair(self):
        p = self._generate_prime()
        q = self._generate_prime()
        n = p * q
        g = n + 1
        lambda_n = (p - 1) * (q - 1)
        mu = mod_inverse(lambda_n, n)
        public_key = (n, g)
        private_key = (lambda_n, mu)
        return public_key, private_key

    def _generate_prime(self):
        return sympy.nextprime(random.getrandbits(self.key_size // 2))

    def encrypt(self, plaintext):
        n, g = self.public_key
        r = random.randint(1, n - 1)
        ciphertext = (pow(g, plaintext, n**2) * pow(r, n, n**2)) % (n**2)
        return ciphertext

    def decrypt(self, ciphertext):
        n, g = self.public_key
        lambda_n, mu = self.private_key
        x = pow(ciphertext, lambda_n, n**2) - 1
        l = x // n
        plaintext = (l * mu) % n
        return plaintext

    def add_encrypted(self, ciphertext1, ciphertext2):
        return (ciphertext1 * ciphertext2) % (self.public_key[0] ** 2)

# Example Usage with User Input
def main():
    # Initialize Paillier Cryptosystem
    paillier = Paillier()

    # Take user input for two integers
    try:
        plaintext1 = int(input("Enter the first integer to encrypt: "))
        plaintext2 = int(input("Enter the second integer to encrypt: "))
    except ValueError:
        print("Please enter valid integers.")
        return

    # Encrypt the integers
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    print(f"Ciphertext 1: {ciphertext1}")
    print(f"Ciphertext 2: {ciphertext2}")

    # Perform homomorphic addition on encrypted integers
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    print(f"Encrypted Sum: {encrypted_sum}")

    # Decrypt the result
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print(f"Decrypted Sum: {decrypted_sum}")

    # Verify that it matches the sum of the original integers
    print(f"Original Sum: {plaintext1 + plaintext2}")

if __name__ == "__main__":
    main()
