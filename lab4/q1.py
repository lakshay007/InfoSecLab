from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import os
import base64


# Key Management
class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def store_key_pair(self, identifier, private_key, public_key):
        self.keys[identifier] = {
            'private': private_key,
            'public': public_key
        }

    def get_private_key(self, identifier):
        return self.keys[identifier]['private']

    def get_public_key(self, identifier):
        return self.keys[identifier]['public']


# Secure Communication
class SecureCommunication:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt_message(self, message, public_key):
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_message).decode()

    def decrypt_message(self, encrypted_message, private_key):
        encrypted_message = base64.b64decode(encrypted_message)
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()


# Diffie-Hellman Key Exchange
class DiffieHellman:
    def __init__(self):
        self.parameters = dh.generate_parameters(
            generator=2,
            key_size=2048,
            backend=default_backend()
        )

    def generate_private_key(self):
        return self.parameters.generate_private_key()

    def generate_shared_key(self, private_key, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        return shared_key


# Example Usage
def main():
    # Initialize Key Manager and Secure Communication
    key_manager = KeyManager()
    secure_comm = SecureCommunication(key_manager)

    # Generate RSA key pairs for two systems
    private_key_A, public_key_A = key_manager.generate_key_pair()
    private_key_B, public_key_B = key_manager.generate_key_pair()

    # Store the key pairs
    key_manager.store_key_pair('SystemA', private_key_A, public_key_A)
    key_manager.store_key_pair('SystemB', private_key_B, public_key_B)

    # Example message
    message = "Confidential Report"

    # Encrypt message with SystemB's public key and decrypt it with SystemB's private key
    encrypted_message = secure_comm.encrypt_message(message, public_key_B)
    decrypted_message = secure_comm.decrypt_message(encrypted_message, private_key_B)

    print(f"Original Message: {message}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    main()
