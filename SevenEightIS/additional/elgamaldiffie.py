import hashlib
import random
from sympy import isprime
from math import gcd
from Crypto.Util.number import getPrime, inverse
import sys

# ---- ElGamal Cryptosystem ----
def elgamal_keygen(bits=512):
    """
    Generates ElGamal key pair.

    Args:
        bits (int): Bit length of the prime p.

    Returns:
        public_key (dict): Contains 'p', 'g', and 'y'.
        private_key (int): Private key x.
    """
    while True:
        p = getPrime(bits)
        if is_prime(p):
            break
    g = 2  # Typically, a small generator is chosen; 2 is common.
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key component
    return {'p': p, 'g': g, 'y': y}, x

def elgamal_encrypt(plaintext, public_key):
    """
    Encrypts plaintext using ElGamal encryption.

    Args:
        plaintext (str): The message to encrypt.
        public_key (dict): The ElGamal public key.

    Returns:
        tuple: Ciphertext as (c1, c2).
    """
    p = public_key['p']
    g = public_key['g']
    y = public_key['y']
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    if m >= p:
        raise ValueError("Message too long for the key size.")
    k = random.randint(1, p - 2)  # Ephemeral key
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, public_key):
    """
    Decrypts ciphertext using ElGamal decryption.

    Args:
        ciphertext (tuple): The ciphertext as (c1, c2).
        private_key (int): The ElGamal private key x.
        public_key (dict): The ElGamal public key.

    Returns:
        str or None: Decrypted plaintext or None if decryption fails.
    """
    p = public_key['p']
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    byte_length = (m.bit_length() + 7) // 8
    try:
        plaintext = m.to_bytes(byte_length, byteorder='big').decode('utf-8')
    except:
        plaintext = None
    return plaintext

def is_prime(n):
    """
    Checks if a number is prime using sympy's isprime.

    Args:
        n (int): The number to check.

    Returns:
        bool: True if prime, False otherwise.
    """
    return isprime(n)

# ---- ElGamal Signature Scheme ----
def elgamal_sign(message, private_key, public_key):
    """
    Signs a message using the ElGamal signature scheme.

    Args:
        message (str): The message to sign.
        private_key (int): The signer's private key x.
        public_key (dict): The signer's public key.

    Returns:
        tuple: Signature as (r, s).
    """
    p = public_key['p']
    g = public_key['g']
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = (k_inv * (h - private_key * r)) % (p - 1)
    return (r, s)

def elgamal_verify(message, signature, public_key):
    """
    Verifies an ElGamal signature.

    Args:
        message (str): The original message.
        signature (tuple): The signature as (r, s).
        public_key (dict): The signer's public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    p = public_key['p']
    g = public_key['g']
    y = public_key['y']
    r, s = signature
    if not (0 < r < p):
        return False
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    lhs = (pow(y, r, p) * pow(r, s, p)) % p
    rhs = pow(g, h, p)
    return lhs == rhs

# ---- Hospital System Setup ----
class HospitalSystem:
    def __init__(self):
        self.records = {}      # Encrypted records
        self.hashes = {}       # Record hashes
        self.signatures = {}   # Record signatures

        # ElGamal key generation for encryption/decryption by Doctor
        print("Generating ElGamal keys for encryption/decryption (Doctor)...")
        self.elgamal_public_enc, self.elgamal_private_enc = elgamal_keygen()

        # ElGamal key generation for signing by Nurse/Admin
        print("Generating ElGamal keys for signing (Nurse/Admin)...")
        self.elgamal_public_sig, self.elgamal_private_sig = elgamal_keygen()

    # Doctor: Add/Update Records (ElGamal Encrypted & ElGamal Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using ElGamal
        try:
            encrypted_record = elgamal_encrypt(record_data, self.elgamal_public_enc)
        except ValueError as ve:
            print(f"Encryption Error: {ve}")
            return

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with ElGamal Signature
        signature = elgamal_sign(record_data, self.elgamal_private_sig, self.elgamal_public_sig)

        # Store encrypted record, hash, and signature
        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        print(f"Record Hash: {record_hash}")
        print(f"Signature: {signature}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\nDoctor viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private_enc, self.elgamal_public_enc)
            if decrypted_record:
                print(f"Decrypted Record for {patient_id}: {decrypted_record}")
            else:
                print("Decryption failed or invalid data.")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private_enc, self.elgamal_public_enc)
            if decrypted_record:
                computed_hash = hashlib.sha256(decrypted_record.encode()).hexdigest()
                stored_hash = self.hashes.get(patient_id)
                if computed_hash == stored_hash:
                    print(f"Record hash for {patient_id} is valid.")
                else:
                    print(f"Record hash for {patient_id} is invalid.")
            else:
                print("Decryption failed or invalid data.")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\nAdmin verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private_enc, self.elgamal_public_enc)
            if decrypted_record:
                if elgamal_verify(decrypted_record, signature, self.elgamal_public_sig):
                    print(f"Signature for {patient_id} is valid.")
                else:
                    print(f"Signature for {patient_id} is invalid.")
            else:
                print("Decryption failed or invalid data.")
        else:
            print("No record or signature found.")

# ---- Menu for the Hospital System ----
def menu():
    hospital = HospitalSystem()
    print("\n=== Hospital Key Management System ===")
    print("1. ADD RECORD")
    print("2. VIEW RECORD")
    print("3. VERIFY HASH")
    print("4. VERIFY SIGNATURE")
    print("5. EXIT")
    while True:
        choice = input("\nChoose an option (1-5): ")
        if choice == '1':
            patient_id = input("Enter patient ID: ")
            message = input("Enter record data: ")
            hospital.doctor_add_record(patient_id, message)
        elif choice == '2':
            patient_id = input("Enter patient ID: ")
            hospital.doctor_view_record(patient_id)
        elif choice == '3':
            patient_id = input("Enter patient ID: ")
            hospital.nurse_verify_hash(patient_id)
        elif choice == '4':
            patient_id = input("Enter patient ID: ")
            hospital.admin_verify_signature(patient_id)
        elif choice == '5':
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
