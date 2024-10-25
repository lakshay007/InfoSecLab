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
        self.p = nextprime(random.getrandbits(bit_length))
        self.q = nextprime(random.getrandbits(bit_length))
        while self.q == self.p:
            self.q = nextprime(random.getrandbits(bit_length))
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (self.p - 1) * (self.q - 1) // gcd(self.p - 1, self.q - 1)
        self.mu = mod_inverse(self.lambda_n, self.n)
        self.ciphertexts = {}  # Store ciphertexts with IDs

    def encrypt(self, plaintext):
        r = random.randint(1, self.n - 1)
        c1 = pow(self.g, plaintext, self.n_squared)
        c2 = pow(r, self.n, self.n_squared)
        ciphertext = (c1 * c2) % self.n_squared
        return ciphertext

    def decrypt(self, ciphertext):
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n
        plaintext = (u * self.mu) % self.n
        return plaintext

    def add_encrypted(self, c1, c2):
        return (c1 * c2) % self.n_squared

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# -------------------- RSA Cryptosystem -------------------- #

class RSA:
    def __init__(self, bit_length=16):
        self.p = self.generate_prime(bit_length)
        self.q = self.generate_prime(bit_length)
        while self.q == self.p:
            self.q = self.generate_prime(bit_length)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = mod_inverse(self.e, self.phi_n)
        self.ciphertexts = {}  # Store ciphertexts with IDs

    def generate_prime(self, bit_length):
        while True:
            num = random.getrandbits(bit_length)
            if isprime(num):
                return num

    def encrypt(self, plaintext):
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        return pow(ciphertext, self.d, self.n)

    def multiply_encrypted(self, c1, c2):
        return (c1 * c2) % self.n


# -------------------- AES-based Encrypted Document Search -------------------- #

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


def get_aes_key():
    return hashlib.sha256(b"supersecretkey").digest()


def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_aes(ciphertext, key):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted.decode("utf-8")


def build_inverted_index(docs):
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            word_clean = ''.join(char for char in word if char.isalnum())
            word_hash = hashlib.sha256(word_clean.lower().encode("utf-8")).hexdigest()
            index[word_hash].append(doc_id)
    return index


def encrypt_inverted_index(index, key):
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt_aes(",".join(map(str, doc_ids)), key)
    return encrypted_index


def decrypt_inverted_index_results(encrypted_doc_ids, key):
    decrypted_doc_ids = decrypt_aes(encrypted_doc_ids, key)
    return list(map(int, decrypted_doc_ids.split(",")))


def search_documents(query, encrypted_index, key, documents):
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
        print("2. Decrypt a ciphertext by ID")
        print("3. Homomorphic Addition of Two Ciphertexts")
        print("4. View Keys")
        print("5. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                ciphertext = paillier.encrypt(plaintext)
                ciphertext_id = len(paillier.ciphertexts) + 1  # Generate a new ID
                paillier.ciphertexts[ciphertext_id] = ciphertext
                print(f"Ciphertext ID: {ciphertext_id}, Ciphertext: {ciphertext}")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext_id = int(input("Enter ciphertext ID to decrypt: "))
                if ciphertext_id in paillier.ciphertexts:
                    ciphertext = paillier.ciphertexts[ciphertext_id]
                    plaintext = paillier.decrypt(ciphertext)
                    print(f"Decrypted Plaintext from ID {ciphertext_id}: {plaintext}")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter a valid ID.")

        elif choice == '3':
            try:
                id1 = int(input("Enter first ciphertext ID: "))
                id2 = int(input("Enter second ciphertext ID: "))
                if id1 in paillier.ciphertexts and id2 in paillier.ciphertexts:
                    c1 = paillier.ciphertexts[id1]
                    c2 = paillier.ciphertexts[id2]
                    encrypted_sum = paillier.add_encrypted(c1, c2)
                    print("Encrypted Sum:", encrypted_sum)
                    decrypted_sum = paillier.decrypt(encrypted_sum)
                    print("Decrypted Sum:", decrypted_sum)
                else:
                    print("Invalid IDs. Ensure both exist.")
            except ValueError:
                print("Invalid input. Please enter valid IDs.")

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
        print("2. Decrypt a ciphertext by ID")
        print("3. Multiply Two Ciphertexts")
        print("4. View Keys")
        print("5. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                ciphertext = rsa.encrypt(plaintext)
                ciphertext_id = len(rsa.ciphertexts) + 1  # Generate a new ID
                rsa.ciphertexts[ciphertext_id] = ciphertext
                print(f"Ciphertext ID: {ciphertext_id}, Ciphertext: {ciphertext}")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext_id = int(input("Enter ciphertext ID to decrypt: "))
                if ciphertext_id in rsa.ciphertexts:
                    ciphertext = rsa.ciphertexts[ciphertext_id]
                    plaintext = rsa.decrypt(ciphertext)
                    print(f"Decrypted Plaintext from ID {ciphertext_id}: {plaintext}")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter a valid ID.")

        elif choice == '3':
            try:
                id1 = int(input("Enter first ciphertext ID: "))
                id2 = int(input("Enter second ciphertext ID: "))
                if id1 in rsa.ciphertexts and id2 in rsa.ciphertexts:
                    c1 = rsa.ciphertexts[id1]
                    c2 = rsa.ciphertexts[id2]
                    encrypted_product = rsa.multiply_encrypted(c1, c2)
                    print("Encrypted Product:", encrypted_product)
                    decrypted_product = rsa.decrypt(encrypted_product)
                    print("Decrypted Product:", decrypted_product)
                else:
                    print("Invalid IDs. Ensure both exist.")
            except ValueError:
                print("Invalid input. Please enter valid IDs.")

        elif choice == '4':
            print("\n--- RSA Keys ---")
            print(f"p: {rsa.p}")
            print(f"q: {rsa.q}")
            print(f"n: {rsa.n}")
            print(f"e: {rsa.e}")
            print(f"d: {rsa.d}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Please select a valid option.")


def main_menu():
    while True:
        print("\n--- Main Menu ---")
        print("1. Paillier Cryptosystem")
        print("2. RSA Cryptosystem")
        print("3. AES Encrypted Document Search")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            paillier_menu()
        elif choice == '2':
            rsa_menu()
        elif choice == '3':
            key = get_aes_key()
            index = build_inverted_index(documents)
            encrypted_index = encrypt_inverted_index(index, key)
            while True:
                query = input("\nEnter your search query (or type 'exit' to go back): ")
                if query.lower() == 'exit':
                    break
                results = search_documents(query, encrypted_index, key, documents)
                if results:
                    print("Documents found:")
                    for result in results:
                        print("-", result)
                else:
                    print("No documents found.")
        elif choice == '4':
            sys.exit()
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main_menu()
