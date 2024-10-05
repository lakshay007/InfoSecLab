import random
import sympy
from collections import defaultdict


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
        mu = sympy.mod_inverse(lambda_n, n)
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

# Convert string to integer
def string_to_int(s):
    return int.from_bytes(s.encode(), 'big')

# Convert integer to string
def int_to_string(i):
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big').decode()

# Step 2a: Create Dataset
documents = [
    "Secure search engine implementation using Paillier encryption.",
    "Building an inverted index for document retrieval.",
    "Encrypting and decrypting data with Paillier cryptosystem.",
    "Implementing secure search on encrypted indexes.",
    "Handling text documents with multiple words.",
    "Search functionality on encrypted data.",
    "Paillier encryption for secure document search.",
    "Creating a secure encrypted index.",
    "Decrypting results to retrieve original documents.",
    "Text corpus generation and indexing for PKSE."
]

doc_id_map = {i: doc for i, doc in enumerate(documents)}

# Step 2c: Create an Encrypted Index
def build_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in docs.items():
        words = set(text.lower().split())
        for word in words:
            index[word].add(doc_id)
    return index

def encrypt_index(index, paillier):
    encrypted_index = {}
    for word, doc_ids in index.items():
        encrypted_word = paillier.encrypt(string_to_int(word))
        encrypted_doc_ids = {paillier.encrypt(doc_id) for doc_id in doc_ids}
        encrypted_index[encrypted_word] = encrypted_doc_ids
    return encrypted_index

# Create Paillier instance and build encrypted index
paillier = Paillier(key_size=512)
index = build_inverted_index(doc_id_map)
encrypted_index = encrypt_index(index, paillier)


def search(query, encrypted_index, paillier):
    encrypted_query = paillier.encrypt(string_to_int(query))
    matching_doc_ids = set()
    for encrypted_word, encrypted_doc_ids in encrypted_index.items():
        if encrypted_query == encrypted_word:
            for encrypted_doc_id in encrypted_doc_ids:
                matching_doc_ids.add(paillier.decrypt(encrypted_doc_id))
    return matching_doc_ids

# Sample search query
query = "secure"
matching_ids = search(query, encrypted_index, paillier)


matching_docs = [doc_id_map[int(doc_id)] for doc_id in matching_ids]
print("Matching Documents:")
for doc in matching_docs:
    print(doc)
