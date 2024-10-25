import random
from sympy import mod_inverse, nextprime, isprime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict
import sys


# -------------------- Paillier Cryptosystem -------------------- #

class Paillier:
    def __init__(self, bit_length=512):
        # Generate two distinct large prime numbers p and q
        self.p = nextprime(random.getrandbits(bit_length))
        self.q = nextprime(random.getrandbits(bit_length))
        while self.q == self.p:
            self.q = nextprime(random.getrandbits(bit_length))

        # Compute n as the product of p and q
        self.n = self.p * self.q

        # Compute n squared
        self.n_squared = self.n * self.n

        # g is set to n + 1
        self.g = self.n + 1

        # Calculate lambda(n), the least common multiple of (p-1) and (q-1)
        self.lambda_n = (self.p - 1) * (self.q - 1) // gcd(self.p - 1, self.q - 1)

        # Calculate mu, the modular inverse of lambda(n) modulo n
        self.mu = mod_inverse(self.lambda_n, self.n)

    def encrypt(self, plaintext):
        # Generate a random integer r in the range [1, n-1]
        r = random.randint(1, self.n - 1)

        # Compute c1 as g^plaintext mod n_squared
        c1 = pow(self.g, plaintext, self.n_squared)

        # Compute c2 as r^n mod n_squared
        c2 = pow(r, self.n, self.n_squared)

        # Return the ciphertext as the product of c1 and c2 mod n_squared
        return (c1 * c2) % self.n_squared

    def decrypt(self, ciphertext):
        # Compute u as (ciphertext^lambda(n) - 1) / n
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n

        # Recover the plaintext by multiplying u with mu mod n
        plaintext = (u * self.mu) % self.n
        return plaintext

    def add_encrypted(self, c1, c2):
        # Perform homomorphic addition on two ciphertexts
        return (c1 * c2) % self.n_squared


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# -------------------- RSA Cryptosystem -------------------- #

class RSA:
    def __init__(self, bit_length=16):
        # Generate two distinct prime numbers p and q
        self.p = self.generate_prime(bit_length)
        self.q = self.generate_prime(bit_length)
        while self.q == self.p:
            self.q = self.generate_prime(bit_length)

        # Compute n as the product of p and q
        self.n = self.p * self.q

        # Calculate φ(n) = (p - 1)(q - 1)
        self.phi_n = (self.p - 1) * (self.q - 1)

        # Set e to a commonly used value, 65537
        self.e = 65537

        # Calculate d, the modular inverse of e mod φ(n)
        self.d = mod_inverse(self.e, self.phi_n)

    def generate_prime(self, bit_length):
        # Continuously generate random numbers until a prime is found
        while True:
            num = random.getrandbits(bit_length)  # Generate a random number of the specified bit length
            if isprime(num):  # Check if the number is prime
                return num  # Return the prime number

    def encrypt(self, plaintext):
        # Encrypt the plaintext using the public key (n, e)
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        # Decrypt the ciphertext using the private key (n, d)
        return pow(ciphertext, self.d, self.n)

    def multiply_encrypted(self, c1, c2):
        # Perform multiplication on two ciphertexts (homomorphic property)
        return (c1 * c2) % self.n


# -------------------- AES-based Encrypted Document Search -------------------- #

# 1a. Generate text corpus
documents = [
    "The wind howled through the empty streets on a cold evening.",
    "An orange cat sat silently under the oak tree, watching the world.",
    "Quantum computing may revolutionize cryptographic systems.",
    "Bright colors danced across the sky during the sunset.",
    "The spaceship drifted silently through the vast emptiness of space.",
    "Baking a cake requires precision and patience for the best results.",
    "The ancient ruins held secrets that no one had yet uncovered.",
    "Robots are becoming an essential part of modern manufacturing.",
    "A mysterious note was left on the doorstep in the dead of night.",
    "The evolution of technology is accelerating faster than ever before."
]


# Encryption & Decryption functions using AES
def get_aes_key():
    """Generate a random AES key."""
    return hashlib.sha256(b"supersecretkey").digest()


def encrypt_aes(text, key):
    """Encrypt text using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_aes(ciphertext, key):
    """Decrypt ciphertext using AES."""
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted.decode("utf-8")


# 1c. Create inverted index using word hashes
def build_inverted_index(docs):
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            # Remove punctuation from word
            word_clean = ''.join(char for char in word if char.isalnum())
            word_hash = hashlib.sha256(word_clean.lower().encode("utf-8")).hexdigest()
            index[word_hash].append(doc_id)
    return index


# Encrypt document IDs
def encrypt_inverted_index(index, key):
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt_aes(",".join(map(str, doc_ids)), key)
    return encrypted_index


# Decrypt inverted index results
def decrypt_inverted_index_results(encrypted_doc_ids, key):
    decrypted_doc_ids = decrypt_aes(encrypted_doc_ids, key)
    return list(map(int, decrypted_doc_ids.split(",")))


# 1d. Implement search function
def search_documents(query, encrypted_index, key, documents):
    # Hash the query instead of encrypting
    query_clean = ''.join(char for char in query if char.isalnum())
    query_hash = hashlib.sha256(query_clean.lower().encode("utf-8")).hexdigest()
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        doc_ids = decrypt_inverted_index_results(encrypted_doc_ids, key)
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        return []


# -------------------- Menu-Driven Interface -------------------- #

def paillier_menu():
    print("\n--- Paillier Cryptosystem ---")
    bit_length = input("Enter bit length for key generation (default 512): ")
    bit_length = int(bit_length) if bit_length.isdigit() else 512
    print("Generating Paillier keys...")
    paillier = Paillier(bit_length)
    print("Keys generated successfully.")

    while True:
        print("\nPaillier Menu:")
        print("1. Encrypt a number")
        print("2. Decrypt a ciphertext")
        print("3. Homomorphic Addition of Two Ciphertexts")
        print("4. View Keys")
        print("5. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                ciphertext = paillier.encrypt(plaintext)
                print("Ciphertext:", ciphertext)
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext = int(input("Enter ciphertext to decrypt: "))
                plaintext = paillier.decrypt(ciphertext)
                print("Decrypted Plaintext:", plaintext)
            except ValueError:
                print("Invalid input. Please enter a valid ciphertext.")

        elif choice == '3':
            try:
                c1 = int(input("Enter first ciphertext: "))
                c2 = int(input("Enter second ciphertext: "))
                encrypted_sum = paillier.add_encrypted(c1, c2)
                print("Encrypted Sum:", encrypted_sum)
                decrypted_sum = paillier.decrypt(encrypted_sum)
                print("Decrypted Sum:", decrypted_sum)
            except ValueError:
                print("Invalid input. Please enter valid ciphertexts.")

        elif choice == '4':
            print("\n--- Paillier Keys ---")
            print(f"p: {paillier.p}")
            print(f"q: {paillier.q}")
            print(f"n: {paillier.n}")
            print(f"n_squared: {paillier.n_squared}")
            print(f"g: {paillier.g}")
            print(f"lambda(n): {paillier.lambda_n}")
            print(f"mu: {paillier.mu}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Please select a valid option.")


def rsa_menu():
    print("\n--- RSA Cryptosystem ---")
    bit_length = input("Enter bit length for key generation (default 16): ")
    bit_length = int(bit_length) if bit_length.isdigit() else 16
    print("Generating RSA keys...")
    rsa = RSA(bit_length)
    print("Keys generated successfully.")

    while True:
        print("\nRSA Menu:")
        print("1. Encrypt a number")
        print("2. Decrypt a ciphertext")
        print("3. Homomorphic Multiplication of Two Ciphertexts")
        print("4. View Keys")
        print("5. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                ciphertext = rsa.encrypt(plaintext)
                print("Ciphertext:", ciphertext)
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext = int(input("Enter ciphertext to decrypt: "))
                plaintext = rsa.decrypt(ciphertext)
                print("Decrypted Plaintext:", plaintext)
            except ValueError:
                print("Invalid input. Please enter a valid ciphertext.")

        elif choice == '3':
            try:
                c1 = int(input("Enter first ciphertext: "))
                c2 = int(input("Enter second ciphertext: "))
                encrypted_product = rsa.multiply_encrypted(c1, c2)
                print("Decrypted Product:", encrypted_product)
                decrypted_product = rsa.decrypt(encrypted_product)
                print("Encrypted Product:", decrypted_product)
            except ValueError:
                print("Invalid input. Please enter valid ciphertexts.")

        elif choice == '4':
            print("\n--- RSA Keys ---")
            print(f"p: {rsa.p}")
            print(f"q: {rsa.q}")
            print(f"n: {rsa.n}")
            print(f"phi(n): {rsa.phi_n}")
            print(f"e: {rsa.e}")
            print(f"d: {rsa.d}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Please select a valid option.")


def aes_search_menu():
    print("\n--- Encrypted Document Search ---")
    aes_key = get_aes_key()

    print("Building inverted index...")
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, aes_key)
    print("Inverted index built and encrypted successfully.")

    while True:
        print("\nAES Search Menu:")
        print("1. Search for a word")
        print("2. View Encrypted Inverted Index (Limited Display)")
        print("3. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            query = input("Enter search query: ")
            results = search_documents(query, encrypted_index, aes_key, documents)
            if results:
                print("\nDocuments matching query:")
                for result in results:
                    print("-", result)
            else:
                print("No matching documents found.")

        elif choice == '2':
            print("\n--- Encrypted Inverted Index (First 5 Entries) ---")
            count = 0
            for word_hash, encrypted_doc_ids in encrypted_index.items():
                print(f"{word_hash}: {encrypted_doc_ids.hex()}")
                count += 1
                if count >= 5:
                    break
            if len(encrypted_index) > 5:
                print("...")  # Indicate more entries exist

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select a valid option.")


def main_menu():
    while True:
        print("\n=== Cryptographic Systems Menu ===")
        print("1. Paillier Cryptosystem")
        print("2. RSA Cryptosystem")
        print("3. Encrypted Document Search (AES)")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            paillier_menu()
        elif choice == '2':
            rsa_menu()
        elif choice == '3':
            aes_search_menu()
        elif choice == '4':
            print("Exiting the application. Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main_menu()
