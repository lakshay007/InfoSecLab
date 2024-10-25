import random
import hashlib
import time
import sys
from sympy import mod_inverse, nextprime, isprime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict
from phe import paillier  # For Paillier encryption using the 'phe' library
from Crypto.Util import number  # For ElGamal's prime generation


# -------------------- Utility Functions -------------------- #

def gcd(a, b):
    """Compute the Greatest Common Divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def word_to_hash(word):
    """Convert a word to a hash representation using SHA-256."""
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


# -------------------- Paillier Cryptosystem -------------------- #

class PaillierCustom:
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
        """Encrypt an integer plaintext."""
        r = random.randint(1, self.n - 1)
        while gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        c1 = pow(self.g, plaintext, self.n_squared)
        c2 = pow(r, self.n, self.n_squared)
        ciphertext = (c1 * c2) % self.n_squared
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext to retrieve the plaintext."""
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n
        plaintext = (u * self.mu) % self.n
        return plaintext

    def add_encrypted(self, c1, c2):
        """Homomorphically add two ciphertexts."""
        return (c1 * c2) % self.n_squared

    def scalar_multiply(self, c, scalar):
        """Homomorphically multiply a ciphertext by a scalar."""
        return pow(c, scalar, self.n_squared)


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
        """Generate a random prime number of specified bit length."""
        while True:
            num = random.getrandbits(bit_length)
            if isprime(num):
                return num

    def encrypt(self, plaintext):
        """Encrypt an integer plaintext."""
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext to retrieve the plaintext."""
        return pow(ciphertext, self.d, self.n)

    def multiply_encrypted(self, c1, c2):
        """Homomorphically multiply two ciphertexts."""
        return (c1 * c2) % self.n


# -------------------- ElGamal Cryptosystem -------------------- #

class ElGamalCustom:
    def __init__(self, bit_length=2048):
        self.p = number.getPrime(bit_length)
        self.g = random.randint(2, self.p - 2)
        # Ensure that g is a generator
        while pow(self.g, self.p - 1, self.p) != 1:
            self.g = random.randint(2, self.p - 2)
        self.x = random.randint(1, self.p - 2)
        self.y = pow(self.g, self.x, self.p)
        self.ciphertexts = {}  # Store ciphertexts with IDs

    def encrypt(self, message):
        """Encrypt an integer message."""
        k = random.randint(1, self.p - 2)
        while gcd(k, self.p - 1) != 1:
            k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (message * pow(self.y, k, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext to retrieve the plaintext."""
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        plaintext = (c2 * s_inv) % self.p
        return plaintext

    def multiply_encrypted(self, c1, c2):
        """Homomorphically multiply two ciphertexts."""
        c1_new = (c1[0] * c2[0]) % self.p
        c2_new = (c1[1] * c2[1]) % self.p
        return (c1_new, c2_new)

    def scalar_multiply(self, ciphertext, scalar):
        """Homomorphically multiply a ciphertext by a scalar."""
        c1, c2 = ciphertext
        c1_new = pow(c1, scalar, self.p)
        c2_new = pow(c2, scalar, self.p)
        return (c1_new, c2_new)


# -------------------- AES-based Encrypted Document Search -------------------- #

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
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted.decode("utf-8")


def build_inverted_index(docs):
    """Create an inverted index mapping word hashes to document IDs."""
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            word_clean = ''.join(char for char in word if char.isalnum())
            word_hash = word_to_hash(word_clean.lower())
            index[word_hash].append(doc_id)
    return index


def encrypt_inverted_index(index, pub_key):
    """Encrypt the document IDs in the inverted index using Paillier."""
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = [pub_key.encrypt(doc_id) for doc_id in doc_ids]
    return encrypted_index


def decrypt_inverted_index_results(encrypted_doc_ids, priv_key):
    """Decrypt the encrypted document IDs."""
    return [priv_key.decrypt(enc_id) for enc_id in encrypted_doc_ids]


def search_documents(query, encrypted_index, priv_key, documents):
    """Search for a query in the encrypted inverted index."""
    query_hash = word_to_hash(query.lower())
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        doc_ids = decrypt_inverted_index_results(encrypted_doc_ids, priv_key)
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        return []


# -------------------- Batch Operations -------------------- #

def batch_operations_paillier(paillier, numbers, scalar):
    """Perform batch encryption, homomorphic addition, scalar multiplication, and decryption for Paillier."""
    print("\n[Paillier] Batch Operations:")

    # Timing encryption
    start_time = time.time()
    encrypted_numbers = [paillier.encrypt(num) for num in numbers]
    encryption_time = time.time() - start_time
    print(f"Encryption Time for {len(numbers)} numbers: {encryption_time:.6f} seconds")

    # Timing homomorphic addition
    start_time = time.time()
    encrypted_sum = encrypted_numbers[0]
    for enc_num in encrypted_numbers[1:]:
        encrypted_sum = paillier.add_encrypted(encrypted_sum, enc_num)
    addition_time = time.time() - start_time
    print(f"Homomorphic Addition Time: {addition_time:.6f} seconds")

    # Decrypt the sum
    start_time = time.time()
    decrypted_sum = paillier.decrypt(encrypted_sum)
    decryption_time = time.time() - start_time
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    # Timing scalar multiplication
    start_time = time.time()
    encrypted_scalar = paillier.scalar_multiply(encrypted_sum, scalar)
    scalar_multiplication_time = time.time() - start_time
    print(f"Scalar Multiplication Time: {scalar_multiplication_time:.6f} seconds")

    # Decrypt the scalar multiplication result
    start_time = time.time()
    decrypted_scalar = paillier.decrypt(encrypted_scalar)
    scalar_decryption_time = time.time() - start_time
    print(f"Scalar Decryption Time: {scalar_decryption_time:.6f} seconds")

    # Verify results
    expected_sum = sum(numbers)
    expected_scalar = expected_sum * scalar
    print(f"Decrypted Sum: {decrypted_sum} (Expected: {expected_sum})")
    print(f"Decrypted Scalar Multiplication: {decrypted_scalar} (Expected: {expected_scalar})")


def batch_operations_rsa(rsa, numbers, scalar):
    """Perform batch encryption, homomorphic multiplication, scalar multiplication, and decryption for RSA."""
    print("\n[RSA] Batch Operations:")

    # Timing encryption
    start_time = time.time()
    encrypted_numbers = [rsa.encrypt(num) for num in numbers]
    encryption_time = time.time() - start_time
    print(f"Encryption Time for {len(numbers)} numbers: {encryption_time:.6f} seconds")

    # Timing homomorphic multiplication
    start_time = time.time()
    encrypted_product = encrypted_numbers[0]
    for enc_num in encrypted_numbers[1:]:
        encrypted_product = rsa.multiply_encrypted(encrypted_product, enc_num)
    multiplication_time = time.time() - start_time
    print(f"Homomorphic Multiplication Time: {multiplication_time:.6f} seconds")

    # Decrypt the product
    start_time = time.time()
    decrypted_product = rsa.decrypt(encrypted_product)
    decryption_time = time.time() - start_time
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    # Timing scalar multiplication (encrypt, multiply, decrypt)
    start_time = time.time()
    encrypted_scalar = rsa.multiply_encrypted(encrypted_product, scalar)
    scalar_multiplication_time = time.time() - start_time
    print(f"Scalar Multiplication Time: {scalar_multiplication_time:.6f} seconds")

    # Decrypt the scalar multiplication result
    start_time = time.time()
    decrypted_scalar = rsa.decrypt(encrypted_scalar)
    scalar_decryption_time = time.time() - start_time
    print(f"Scalar Decryption Time: {scalar_decryption_time:.6f} seconds")

    # Verify results
    expected_product = 1
    for num in numbers:
        expected_product *= num
    expected_scalar = expected_product * scalar
    print(f"Decrypted Product: {decrypted_product} (Expected: {expected_product})")
    print(f"Decrypted Scalar Multiplication: {decrypted_scalar} (Expected: {expected_scalar})")


def batch_operations_elgamal(elgamal, numbers, scalar):
    """Perform batch encryption, homomorphic multiplication, scalar multiplication, and decryption for ElGamal."""
    print("\n[ElGamal] Batch Operations:")

    # Timing encryption
    start_time = time.time()
    encrypted_numbers = [elgamal.encrypt(num) for num in numbers]
    encryption_time = time.time() - start_time
    print(f"Encryption Time for {len(numbers)} numbers: {encryption_time:.6f} seconds")

    # Timing homomorphic multiplication
    start_time = time.time()
    encrypted_product = encrypted_numbers[0]
    for enc_num in encrypted_numbers[1:]:
        encrypted_product = elgamal.multiply_encrypted(encrypted_product, enc_num)
    multiplication_time = time.time() - start_time
    print(f"Homomorphic Multiplication Time: {multiplication_time:.6f} seconds")

    # Decrypt the product
    start_time = time.time()
    decrypted_product = elgamal.decrypt(encrypted_product)
    decryption_time = time.time() - start_time
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    # Timing scalar multiplication
    start_time = time.time()
    encrypted_scalar = elgamal.scalar_multiply(encrypted_product, scalar)
    scalar_multiplication_time = time.time() - start_time
    print(f"Scalar Multiplication Time: {scalar_multiplication_time:.6f} seconds")

    # Decrypt the scalar multiplication result
    start_time = time.time()
    decrypted_scalar = elgamal.decrypt(encrypted_scalar)
    scalar_decryption_time = time.time() - start_time
    print(f"Scalar Decryption Time: {scalar_decryption_time:.6f} seconds")

    # Verify results
    expected_product = 1
    for num in numbers:
        expected_product *= num
    expected_scalar = expected_product * scalar
    print(f"Decrypted Product: {decrypted_product} (Expected: {expected_product})")
    print(f"Decrypted Scalar Multiplication: {decrypted_scalar} (Expected: {expected_scalar})")


# -------------------- AES-based Encrypted Document Search -------------------- #

def aes_search_menu(public_key_phe, private_key_phe):
    print("\n--- AES Encrypted Document Search ---")
    aes_key = get_aes_key()

    # Sample documents
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

    # Build inverted index and encrypt document IDs using Paillier
    print("Building inverted index...")
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, public_key_phe)
    print("Inverted index built and encrypted successfully.")

    while True:
        print("\nAES Search Menu:")
        print("1. Search for a word")
        print("2. View Encrypted Inverted Index (First 5 Entries)")
        print("3. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            query = input("Enter search query: ")
            start_time = time.time()
            results = search_documents(query, encrypted_index, private_key_phe, documents)
            end_time = time.time()
            print(f"Search Time: {end_time - start_time:.6f} seconds")
            if results:
                print("Documents matching query:")
                for result in results:
                    print("-", result)
            else:
                print("No matching documents found.")

        elif choice == '2':
            print("\n--- Encrypted Inverted Index (First 5 Entries) ---")
            count = 0
            for word_hash, encrypted_doc_ids in encrypted_index.items():
                # Display the encrypted document IDs in hexadecimal format
                encrypted_doc_ids_hex = [enc_id.ciphertext() for enc_id in encrypted_doc_ids]
                print(f"{word_hash}: {encrypted_doc_ids_hex}")
                count += 1
                if count >= 5:
                    break
            if len(encrypted_index) > 5:
                print("...")  # Indicate more entries exist

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- Paillier Menu -------------------- #

def paillier_menu(paillier):
    while True:
        print("\n--- Paillier Cryptosystem Menu ---")
        print("1. Encrypt a number")
        print("2. Decrypt a ciphertext by ID")
        print("3. Homomorphic Addition of Two Ciphertexts")
        print("4. Homomorphic Scalar Multiplication")
        print("5. View Keys")
        print("6. Perform Batch Operations")
        print("7. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                start_time = time.time()
                ciphertext = paillier.encrypt(plaintext)
                end_time = time.time()
                ciphertext_id = len(paillier.ciphertexts) + 1
                paillier.ciphertexts[ciphertext_id] = ciphertext
                print(f"Ciphertext ID: {ciphertext_id}, Ciphertext: {ciphertext}")
                print(f"Encryption Time: {end_time - start_time:.6f} seconds")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext_id = int(input("Enter ciphertext ID to decrypt: "))
                if ciphertext_id in paillier.ciphertexts:
                    ciphertext = paillier.ciphertexts[ciphertext_id]
                    start_time = time.time()
                    plaintext = paillier.decrypt(ciphertext)
                    end_time = time.time()
                    print(f"Decrypted Plaintext from ID {ciphertext_id}: {plaintext}")
                    print(f"Decryption Time: {end_time - start_time:.6f} seconds")
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
                    start_time = time.time()
                    encrypted_sum = paillier.add_encrypted(c1, c2)
                    end_time = time.time()
                    print("Encrypted Sum:", encrypted_sum)
                    decrypted_sum = paillier.decrypt(encrypted_sum)
                    print("Decrypted Sum:", decrypted_sum)
                    print(f"Addition Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid IDs. Ensure both exist.")
            except ValueError:
                print("Invalid input. Please enter valid IDs.")

        elif choice == '4':
            try:
                id1 = int(input("Enter ciphertext ID to multiply: "))
                scalar = int(input("Enter scalar value: "))
                if id1 in paillier.ciphertexts:
                    c = paillier.ciphertexts[id1]
                    start_time = time.time()
                    encrypted_result = paillier.scalar_multiply(c, scalar)
                    end_time = time.time()
                    decrypted_result = paillier.decrypt(encrypted_result)
                    print("Encrypted Scalar Multiplication Result:", encrypted_result)
                    print("Decrypted Scalar Multiplication Result:", decrypted_result)
                    print(f"Scalar Multiplication Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter valid ID and scalar.")

        elif choice == '5':
            print("\n--- Paillier Keys ---")
            print(f"p: {paillier.p}")
            print(f"q: {paillier.q}")
            print(f"n: {paillier.n}")
            print(f"n_squared: {paillier.n_squared}")
            print(f"g: {paillier.g}")
            print(f"lambda(n): {paillier.lambda_n}")
            print(f"mu: {paillier.mu}")

        elif choice == '6':
            # Perform batch operations for both small and large numbers
            print("\n--- Batch Operations ---")
            small_numbers = [10]
            large_numbers = [10000]
            scalar = 3
            print("\nPaillier - Small Numbers:")
            batch_operations_paillier(paillier, small_numbers, scalar)
            print("\nPaillier - Large Numbers:")
            batch_operations_paillier(paillier, large_numbers, scalar)

        elif choice == '7':
            break
        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- RSA Menu -------------------- #

def rsa_menu(rsa):
    while True:
        print("\n--- RSA Cryptosystem Menu ---")
        print("1. Encrypt a number")
        print("2. Decrypt a ciphertext by ID")
        print("3. Homomorphic Multiplication of Two Ciphertexts")
        print("4. Homomorphic Scalar Multiplication")
        print("5. View Keys")
        print("6. Perform Batch Operations")
        print("7. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                start_time = time.time()
                ciphertext = rsa.encrypt(plaintext)
                end_time = time.time()
                ciphertext_id = len(rsa.ciphertexts) + 1
                rsa.ciphertexts[ciphertext_id] = ciphertext
                print(f"Ciphertext ID: {ciphertext_id}, Ciphertext: {ciphertext}")
                print(f"Encryption Time: {end_time - start_time:.6f} seconds")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext_id = int(input("Enter ciphertext ID to decrypt: "))
                if ciphertext_id in rsa.ciphertexts:
                    ciphertext = rsa.ciphertexts[ciphertext_id]
                    start_time = time.time()
                    plaintext = rsa.decrypt(ciphertext)
                    end_time = time.time()
                    print(f"Decrypted Plaintext from ID {ciphertext_id}: {plaintext}")
                    print(f"Decryption Time: {end_time - start_time:.6f} seconds")
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
                    start_time = time.time()
                    encrypted_product = rsa.multiply_encrypted(c1, c2)
                    end_time = time.time()
                    print("Encrypted Product:", encrypted_product)
                    decrypted_product = rsa.decrypt(encrypted_product)
                    print("Decrypted Product:", decrypted_product)
                    print(f"Multiplication Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid IDs. Ensure both exist.")
            except ValueError:
                print("Invalid input. Please enter valid IDs.")

        elif choice == '4':
            try:
                id1 = int(input("Enter ciphertext ID to multiply: "))
                scalar = int(input("Enter scalar value: "))
                if id1 in rsa.ciphertexts:
                    c = rsa.ciphertexts[id1]
                    start_time = time.time()
                    encrypted_scalar = rsa.multiply_encrypted(c, scalar)
                    end_time = time.time()
                    decrypted_scalar = rsa.decrypt(encrypted_scalar)
                    print("Encrypted Scalar Multiplication Result:", encrypted_scalar)
                    print("Decrypted Scalar Multiplication Result:", decrypted_scalar)
                    print(f"Scalar Multiplication Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter valid ID and scalar.")

        elif choice == '5':
            print("\n--- RSA Keys ---")
            print(f"p: {rsa.p}")
            print(f"q: {rsa.q}")
            print(f"n: {rsa.n}")
            print(f"phi(n): {rsa.phi_n}")
            print(f"e: {rsa.e}")
            print(f"d: {rsa.d}")

        elif choice == '6':
            # Perform batch operations for both small and large numbers
            print("\n--- Batch Operations ---")
            small_numbers = [7]
            large_numbers = [10000]
            scalar = 3
            print("\nRSA - Small Numbers:")
            batch_operations_rsa(rsa, small_numbers, scalar)
            print("\nRSA - Large Numbers:")
            batch_operations_rsa(rsa, large_numbers, scalar)

        elif choice == '7':
            break
        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- ElGamal Menu -------------------- #

def elgamal_menu(elgamal):
    while True:
        print("\n--- ElGamal Cryptosystem Menu ---")
        print("1. Encrypt a number")
        print("2. Decrypt a ciphertext by ID")
        print("3. Homomorphic Multiplication of Two Ciphertexts")
        print("4. Homomorphic Scalar Multiplication")
        print("5. View Keys")
        print("6. Perform Batch Operations")
        print("7. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            try:
                plaintext = int(input("Enter integer to encrypt: "))
                start_time = time.time()
                ciphertext = elgamal.encrypt(plaintext)
                end_time = time.time()
                ciphertext_id = len(elgamal.ciphertexts) + 1
                elgamal.ciphertexts[ciphertext_id] = ciphertext
                print(f"Ciphertext ID: {ciphertext_id}, Ciphertext: {ciphertext}")
                print(f"Encryption Time: {end_time - start_time:.6f} seconds")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        elif choice == '2':
            try:
                ciphertext_id = int(input("Enter ciphertext ID to decrypt: "))
                if ciphertext_id in elgamal.ciphertexts:
                    ciphertext = elgamal.ciphertexts[ciphertext_id]
                    start_time = time.time()
                    plaintext = elgamal.decrypt(ciphertext)
                    end_time = time.time()
                    print(f"Decrypted Plaintext from ID {ciphertext_id}: {plaintext}")
                    print(f"Decryption Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter a valid ID.")

        elif choice == '3':
            try:
                id1 = int(input("Enter first ciphertext ID: "))
                id2 = int(input("Enter second ciphertext ID: "))
                if id1 in elgamal.ciphertexts and id2 in elgamal.ciphertexts:
                    c1 = elgamal.ciphertexts[id1]
                    c2 = elgamal.ciphertexts[id2]
                    start_time = time.time()
                    encrypted_product = elgamal.multiply_encrypted(c1, c2)
                    end_time = time.time()
                    print("Encrypted Product:", encrypted_product)
                    decrypted_product = elgamal.decrypt(encrypted_product)
                    print("Decrypted Product:", decrypted_product)
                    print(f"Multiplication Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid IDs. Ensure both exist.")
            except ValueError:
                print("Invalid input. Please enter valid IDs.")

        elif choice == '4':
            try:
                id1 = int(input("Enter ciphertext ID to multiply: "))
                scalar = int(input("Enter scalar value: "))
                if id1 in elgamal.ciphertexts:
                    c = elgamal.ciphertexts[id1]
                    start_time = time.time()
                    encrypted_scalar = elgamal.scalar_multiply(c, scalar)
                    end_time = time.time()
                    decrypted_scalar = elgamal.decrypt(encrypted_scalar)
                    print("Encrypted Scalar Multiplication Result:", encrypted_scalar)
                    print("Decrypted Scalar Multiplication Result:", decrypted_scalar)
                    print(f"Scalar Multiplication Time: {end_time - start_time:.6f} seconds")
                else:
                    print("Invalid ID. No such ciphertext found.")
            except ValueError:
                print("Invalid input. Please enter valid ID and scalar.")

        elif choice == '5':
            print("\n--- ElGamal Keys ---")
            print(f"p: {elgamal.p}")
            print(f"g: {elgamal.g}")
            print(f"x (Private Key): {elgamal.x}")
            print(f"y (Public Key): {elgamal.y}")

        elif choice == '6':
            # Perform batch operations for both small and large numbers
            print("\n--- Batch Operations ---")
            small_numbers = [5]
            large_numbers = [10000]
            scalar = 3
            print("\nElGamal - Small Numbers:")
            batch_operations_elgamal(elgamal, small_numbers, scalar)
            print("\nElGamal - Large Numbers:")
            batch_operations_elgamal(elgamal, large_numbers, scalar)

        elif choice == '7':
            break
        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- AES-based Encrypted Document Search -------------------- #

def aes_search_menu(public_key_phe, private_key_phe):
    print("\n--- AES Encrypted Document Search ---")
    aes_key = get_aes_key()

    # Sample documents
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

    # Build inverted index and encrypt document IDs using Paillier
    print("Building inverted index...")
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, public_key_phe)
    print("Inverted index built and encrypted successfully.")

    while True:
        print("\nAES Search Menu:")
        print("1. Search for a word")
        print("2. View Encrypted Inverted Index (First 5 Entries)")
        print("3. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == '1':
            query = input("Enter search query: ")
            start_time = time.time()
            results = search_documents(query, encrypted_index, private_key_phe, documents)
            end_time = time.time()
            print(f"Search Time: {end_time - start_time:.6f} seconds")
            if results:
                print("Documents matching query:")
                for result in results:
                    print("-", result)
            else:
                print("No matching documents found.")

        elif choice == '2':
            print("\n--- Encrypted Inverted Index (First 5 Entries) ---")
            count = 0
            for word_hash, encrypted_doc_ids in encrypted_index.items():
                # Display the encrypted document IDs
                encrypted_doc_ids_hex = [enc_id.ciphertext() for enc_id in encrypted_doc_ids]
                print(f"{word_hash}: {encrypted_doc_ids_hex}")
                count += 1
                if count >= 5:
                    break
            if len(encrypted_index) > 5:
                print("...")  # Indicate more entries exist

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- Main Menu -------------------- #

def main_menu():
    # Initialize Paillier using 'phe' library for encrypted document search
    public_key_phe, private_key_phe = paillier.generate_paillier_keypair()

    # Initialize custom cryptosystems
    paillier_custom = PaillierCustom()
    rsa = RSA()
    elgamal = ElGamalCustom()

    while True:
        print("\n=== Cryptographic Systems Menu ===")
        print("1. Paillier Cryptosystem")
        print("2. RSA Cryptosystem")
        print("3. ElGamal Cryptosystem")
        print("4. AES Encrypted Document Search")
        print("5. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            paillier_menu(paillier_custom)

        elif choice == '2':
            rsa_menu(rsa)

        elif choice == '3':
            elgamal_menu(elgamal)

        elif choice == '4':
            aes_search_menu(public_key_phe, private_key_phe)

        elif choice == '5':
            print("Exiting the application. Goodbye!")
            sys.exit()

        else:
            print("Invalid choice. Please select a valid option.")


# -------------------- Main Execution -------------------- #

if __name__ == "__main__":
    main_menu()
