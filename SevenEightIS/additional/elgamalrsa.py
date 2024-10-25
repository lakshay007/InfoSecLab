import hashlib
import random
from sympy import isprime
from math import gcd
from Crypto.Util.number import getPrime, inverse
import sys

# ---- ElGamal Cryptosystem ----
def elgamal_keygen(bits=512):
    # Generate a large prime p
    p = getPrime(bits)
    # Choose generator g
    g = 2
    # Private key x
    x = random.randint(1, p - 2)
    # Public key y = g^x mod p
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'y': y}, x

def elgamal_encrypt(plaintext, public_key):
    p = public_key['p']
    g = public_key['g']
    y = public_key['y']
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    if m >= p:
        raise ValueError("Message too long for the key size.")
    # Choose random k
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, public_key):
    p = public_key['p']
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    # Convert integer back to bytes
    byte_length = (m.bit_length() + 7) // 8
    try:
        plaintext = m.to_bytes(byte_length, byteorder='big').decode('utf-8')
    except:
        plaintext = None
    return plaintext

# ---- RSA Digital Signature ----
def rsa_keygen(bits=2048):
    e = 65537
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p != q:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) == 1:
        d = inverse(e, phi)
        return {'n': n, 'e': e}, d

def rsa_sign(message, private_key, public_key):
    n = public_key['n']
    d = private_key
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    signature = pow(h, d, n)
    return signature

def rsa_verify(message, signature, public_key):
    n = public_key['n']
    e = public_key['e']
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    h_from_sig = pow(signature, e, n)
    return h == h_from_sig

# ---- Hospital System Setup ----
class HospitalSystem:
    def __init__(self):
        self.records = {}      # Encrypted records
        self.hashes = {}       # Record hashes
        self.signatures = {}   # Record signatures

        # ElGamal key generation for encryption/decryption by Doctor
        self.elgamal_public, self.elgamal_private = elgamal_keygen()

        # RSA key generation for signing by Nurse/Admin
        self.rsa_public, self.rsa_private = rsa_keygen()

    # Doctor: Add/Update Records (ElGamal Encrypted & RSA Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using ElGamal
        encrypted_record = elgamal_encrypt(record_data, self.elgamal_public)

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with RSA
        signature = rsa_sign(record_data, self.rsa_private, self.rsa_public)

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
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private, self.elgamal_public)
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
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private, self.elgamal_public)
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
            decrypted_record = elgamal_decrypt(encrypted_record, self.elgamal_private, self.elgamal_public)
            if decrypted_record:
                if rsa_verify(decrypted_record, signature, self.rsa_public):
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
    print("Key Management System")
    print("1. ADD RECORD")
    print("2. VIEW")
    print("3. Verify Hash")
    print("4. Verify Signature Record")
    print("5. Exit")
    while True:
        choice = input("\nChoose an option: ")
        if choice == '1':
            patient_id = input("Enter patient ID: ")
            message = input("Enter record data: ")
            try:
                hospital.doctor_add_record(patient_id, message)
            except ValueError as ve:
                print(f"Error: {ve}")
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
