import random
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Step 1a: Create Dataset
documents = [
    "Secure search engine implementation with AES encryption.",
    "Building an inverted index for document retrieval.",
    "Encrypting and decrypting data using AES.",
    "Implementing secure search on encrypted indexes.",
    "Handling text documents with multiple words.",
    "Search functionality on encrypted data.",
    "AES encryption for secure document search.",
    "Creating a secure inverted index.",
    "Decrypting results to retrieve original documents.",
    "Text corpus generation and indexing for SSE."
]

doc_id_map = {i: doc for i, doc in enumerate(documents)}

# Step 1b: Implement Encryption and Decryption Functions
def get_cipher(key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=backend)
    return cipher

def encrypt(data, key):
    cipher = get_cipher(key)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

def decrypt(encrypted_data, key):
    cipher = get_cipher(key)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# Step 1c: Create an Inverted Index
def build_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in docs.items():
        words = set(text.lower().split())
        for word in words:
            index[word].add(doc_id)
    return index

def encrypt_index(index, key):
    encrypted_index = {}
    for word, doc_ids in index.items():
        encrypted_word = encrypt(word, key)
        encrypted_doc_ids = {encrypt(str(doc_id), key) for doc_id in doc_ids}
        encrypted_index[encrypted_word] = encrypted_doc_ids
    return encrypted_index

# Step 1d: Implement the Search Function
def search(query, encrypted_index, key):
    encrypted_query = encrypt(query, key)
    matching_doc_ids = set()
    for encrypted_word, encrypted_doc_ids in encrypted_index.items():
        if encrypted_query == encrypted_word:
            for encrypted_doc_id in encrypted_doc_ids:
                matching_doc_ids.add(decrypt(encrypted_doc_id, key))
    return matching_doc_ids

# Sample AES key (must be 16, 24, or 32 bytes long)
key = os.urandom(16)

# Build and encrypt the index
index = build_inverted_index(doc_id_map)
encrypted_index = encrypt_index(index, key)

# Sample search query
query = "secure"
matching_ids = search(query, encrypted_index, key)

# Decrypt and display matching documents
matching_docs = [doc_id_map[int(doc_id)] for doc_id in matching_ids]
print("Matching Documents:")
for doc in matching_docs:
    print(doc)
