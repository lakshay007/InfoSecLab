import random
from sympy import mod_inverse, nextprime, isprime
import time
from collections import defaultdict


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

    def scalar_multiply(self, ciphertext, scalar):
        # Homomorphic scalar multiplication (not truly secure, just for the purpose of this demonstration)
        # Note: This isn't secure because it assumes the plaintext is revealed.
        return self.encrypt(self.decrypt(ciphertext) * scalar)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# -------------------- Inverted Index Functions -------------------- #

def create_inverted_index(numbers):
    index = defaultdict(list)
    for doc_id, number in enumerate(numbers):
        index[number].append(doc_id)
    return index


def encrypt_index(index, paillier):
    encrypted_index = {}
    for number, doc_ids in index.items():
        encrypted_number = paillier.encrypt(number)
        encrypted_index[encrypted_number] = doc_ids
    return encrypted_index


def search_index(encrypted_index, query, paillier):
    encrypted_query = paillier.encrypt(query)
    if encrypted_query in encrypted_index:
        return encrypted_index[encrypted_query]
    return []


# -------------------- Batch Operations -------------------- #

def batch_operations(paillier, numbers, scalar):
    print("\nBatch Operations for numbers:", numbers)

    # Timing encryption
    start_time = time.time()
    encrypted_numbers = [paillier.encrypt(num) for num in numbers]
    encryption_time = time.time() - start_time
    print(f"Time taken for Encryption: {encryption_time:.6f} seconds")

    # Timing homomorphic addition
    start_time = time.time()
    encrypted_sum = encrypted_numbers[0]
    for num in encrypted_numbers[1:]:
        encrypted_sum = paillier.add_encrypted(encrypted_sum, num)
    addition_time = time.time() - start_time
    print(f"Time taken for Homomorphic Addition: {addition_time:.6f} seconds")

    # Timing decryption
    start_time = time.time()
    decrypted_sum = paillier.decrypt(encrypted_sum)
    decryption_time = time.time() - start_time
    print(f"Time taken for Decryption: {decryption_time:.6f} seconds")

    return decrypted_sum


# -------------------- Main Code -------------------- #

if __name__ == "__main__":
    # Initialize the Paillier encryption system
    paillier = Paillier()

    # Encrypt two integers
    num1 = 15
    num2 = 25
    encrypted_num1 = paillier.encrypt(num1)
    encrypted_num2 = paillier.encrypt(num2)

    print(f"Encrypted 15: {encrypted_num1}")
    print(f"Encrypted 25: {encrypted_num2}")

    # Perform addition
    encrypted_sum = paillier.add_encrypted(encrypted_num1, encrypted_num2)
    print(f"Encrypted Sum (15 + 25): {encrypted_sum}")

    # Decrypt the result
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print(f"Decrypted Sum: {decrypted_sum} (Expected: {num1 + num2})")

    # Extend the scheme for multiple numbers
    numbers = [20, 25, 30, 25]
    print("\nEncrypting multiple numbers:")
    encrypted_numbers = [paillier.encrypt(num) for num in numbers]
    for num in numbers:
        print(f"Encrypted {num}: {paillier.encrypt(num)}")

    # Scalar multiplication
    scalar = 3
    encrypted_num_to_multiply = encrypted_numbers[0]  # Encrypted 20
    encrypted_result = paillier.scalar_multiply(encrypted_num_to_multiply, scalar)
    print(f"Encrypted Result of {numbers[0]} * {scalar}: {encrypted_result}")

    # Decrypt the result of multiplication
    decrypted_result = paillier.decrypt(encrypted_result)
    print(f"Decrypted Result: {decrypted_result} (Expected: {numbers[0] * scalar})")

    # Create an inverted index and encrypt it
    inverted_index = create_inverted_index(numbers)
    encrypted_index = encrypt_index(inverted_index, paillier)

    # Search query
    query = 25
    document_ids = search_index(encrypted_index, query, paillier)

    print(f"\nSearch Query: {query}")
    if document_ids:
        print(f"Document IDs for {query}: {document_ids}")
    else:
        print(f"No Document IDs found for {query}")

    # Perform batch operations and compare time
    small_numbers = [10]  # Small batch
    large_numbers = [10000]  # Large batch

    print("\nBatch Operations for small numbers:")
    small_sum = batch_operations(paillier, small_numbers, scalar)

    print("\nBatch Operations for large numbers:")
    large_sum = batch_operations(paillier, large_numbers, scalar)
