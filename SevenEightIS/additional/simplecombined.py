import random
import hashlib
from sympy import mod_inverse, nextprime, isprime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict


# Paillier Cryptosystem
class Paillier:
    def __init__(self, bit_length=512):
        self.p = nextprime(random.getrandbits(bit_length))
        self.q = nextprime(random.getrandbits(bit_length))
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (self.p - 1) * (self.q - 1)
        self.mu = mod_inverse(self.lambda_n, self.n)

    def encrypt(self, plaintext):
        r = random.randint(1, self.n - 1)
        c1 = pow(self.g, plaintext, self.n_squared)
        c2 = pow(r, self.n, self.n_squared)
        return (c1 * c2) % self.n_squared

    def decrypt(self, ciphertext):
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n
        return (u * self.mu) % self.n

    def add_encrypted(self, c1, c2):
        return (c1 * c2) % self.n_squared


# RSA Cryptosystem
class RSA:
    def __init__(self, bit_length=16):
        self.p = self.generate_prime(bit_length)
        self.q = self.generate_prime(bit_length)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = mod_inverse(self.e, self.phi_n)

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


# AES Encryption/Decryption
def get_aes_key():
    return hashlib.sha256(b"supersecretkey").digest()


def encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt(ciphertext, key):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted.decode("utf-8")


def build_inverted_index(docs):
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            word_hash = hashlib.sha256(word.lower().encode("utf-8")).hexdigest()
            index[word_hash].append(doc_id)
    return index


def encrypt_inverted_index(index, key):
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt(",".join(map(str, doc_ids)), key)
    return encrypted_index


def decrypt_inverted_index_results(encrypted_doc_ids, key):
    decrypted_doc_ids = decrypt(encrypted_doc_ids, key)
    return list(map(int, decrypted_doc_ids.split(",")))


def search(query, encrypted_index, key, documents):
    query_hash = hashlib.sha256(query.lower().encode("utf-8")).hexdigest()
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        doc_ids = decrypt_inverted_index_results(encrypted_doc_ids, key)
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        return []


# Menu-Driven Approach
def main_menu():
    print("Select an option:")
    print("1. Paillier Cryptosystem")
    print("2. RSA Cryptosystem")
    print("3. AES Encryption/Decryption")
    print("4. Exit")


if __name__ == "__main__":
    while True:
        main_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            paillier = Paillier()
            plaintext1 = int(input("Enter first integer to encrypt: "))
            plaintext2 = int(input("Enter second integer to encrypt: "))
            ciphertext1 = paillier.encrypt(plaintext1)
            ciphertext2 = paillier.encrypt(plaintext2)
            print("Ciphertext 1:", ciphertext1)
            print("Ciphertext 2:", ciphertext2)
            encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
            decrypted_sum = paillier.decrypt(encrypted_sum)
            print("Decrypted Sum:", decrypted_sum)
            print("Original Sum:", plaintext1 + plaintext2)

        elif choice == "2":
            rsa = RSA()
            plaintext1 = int(input("Enter first integer to encrypt: "))
            plaintext2 = int(input("Enter second integer to encrypt: "))
            ciphertext1 = rsa.encrypt(plaintext1)
            ciphertext2 = rsa.encrypt(plaintext2)
            print("Ciphertext 1:", ciphertext1)
            print("Ciphertext 2:", ciphertext2)
            encrypted_product = rsa.multiply_encrypted(ciphertext1, ciphertext2)
            decrypted_product = rsa.decrypt(encrypted_product)
            print("Decrypted Product:", decrypted_product)
            print("Original Product:", plaintext1 * plaintext2)

        elif choice == "3":
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
                "Digital art is changing the way we perceive creativity."
            ]
            index = build_inverted_index(documents)
            aes_key = get_aes_key()
            encrypted_index = encrypt_inverted_index(index, aes_key)
            query = input("Enter a search query: ")
            results = search(query, encrypted_index, aes_key, documents)
            print("Search Results:", results)

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")
