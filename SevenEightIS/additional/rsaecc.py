import hashlib
import sys
from sympy import isprime
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random as crypto_random

# ---- Utility Functions ----
def gcd(a, b):
    """Computes the Greatest Common Divisor using Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Computes the modular inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    return x % m

def prime_factors(n):
    """Returns the set of prime factors of n."""
    i = 2
    factors = set()
    while i * i <= n:
        while n % i == 0:
            factors.add(i)
            n //= i
        i += 1
    if n > 1:
        factors.add(n)
    return factors

def is_primitive_root(g, p):
    """Checks if g is a primitive root modulo p."""
    if gcd(g, p) != 1:
        return False
    phi = p - 1
    factors = prime_factors(phi)
    for factor in factors:
        if pow(g, phi // factor, p) == 1:
            return False
    return True

# ---- RSA Cryptosystem for Encryption ----
def rsa_keygen(key_size=2048):
    """Generates RSA public and private keys."""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    """Encrypts plaintext using RSA encryption."""
    rsa_public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypts ciphertext using RSA decryption."""
    rsa_private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_message = cipher.decrypt(ciphertext).decode('utf-8')
    return decrypted_message

# ---- ECC for Signing ----
def ecc_keygen():
    """Generates ECC private and public keys."""
    key = ECC.generate(curve='P-256')  # Using a standard curve
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

def ecc_sign(message, private_key_pem):
    """Signs a message using ECC."""
    private_key = ECC.import_key(private_key_pem)
    signer = DSS.new(private_key, 'fips-186-3')
    hash_obj = SHA256.new(message.encode('utf-8'))
    signature = signer.sign(hash_obj)
    return signature

def ecc_verify(message, signature, public_key_pem):
    """Verifies an ECC signature."""
    public_key = ECC.import_key(public_key_pem)
    verifier = DSS.new(public_key, 'fips-186-3')
    hash_obj = SHA256.new(message.encode('utf-8'))
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

# ---- Hospital System Setup ----
class HospitalSystem:
    def __init__(self):
        self.records = {}      # Encrypted records
        self.hashes = {}       # Record hashes
        self.signatures = {}   # Record signatures

        # RSA key generation for Doctor (Encryption/Decryption)
        print("Generating RSA keys for Doctor...")
        self.rsa_private_key, self.rsa_public_key = rsa_keygen()

        # ECC key generation for Nurse (Signing) and Admin (Verification)
        print("Generating ECC keys for Nurse...")
        self.ecc_private_key, self.ecc_public_key = ecc_keygen()

    # Doctor: Add/Update Records (RSA Encrypted & ECC Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\n[Doctor] Adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using RSA
        try:
            encrypted_record = rsa_encrypt(record_data, self.rsa_public_key)
        except Exception as e:
            print(f"Encryption Error: {e}")
            return

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with ECC
        try:
            signature = ecc_sign(record_data, self.ecc_private_key)
        except Exception as e:
            print(f"Signing Error: {e}")
            return

        # Store encrypted record, hash, and signature
        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for '{patient_id}': {encrypted_record.hex()}")
        print(f"Record Hash: {record_hash}")
        print(f"Signature: {signature.hex()}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\n[Doctor] Viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private_key)
                print(f"Decrypted Record for '{patient_id}': {decrypted_record}")
            except Exception as e:
                print(f"Decryption Error: {e}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\n[Nurse] Verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private_key)
                computed_hash = hashlib.sha256(decrypted_record.encode()).hexdigest()
                stored_hash = self.hashes.get(patient_id)
                if computed_hash == stored_hash:
                    print(f"Record hash for '{patient_id}' is valid.")
                else:
                    print(f"Record hash for '{patient_id}' is INVALID.")
            except Exception as e:
                print(f"Decryption Error: {e}")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\n[Admin] Verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private_key)
                is_valid = ecc_verify(decrypted_record, signature, self.ecc_public_key)
                if is_valid:
                    print(f"Signature for '{patient_id}' is VALID.")
                else:
                    print(f"Signature for '{patient_id}' is INVALID.")
            except Exception as e:
                print(f"Decryption or Verification Error: {e}")
        else:
            print("No record or signature found.")

# ---- Menu for the Hospital System ----
def menu():
    hospital = HospitalSystem()
    print("\n=== Hospital Key Management System ===")
    print("1. Add/Update Record (Doctor)")
    print("2. View Record (Doctor)")
    print("3. Verify Record Hash (Nurse)")
    print("4. Verify Record Signature (Admin)")
    print("5. Exit")

    while True:
        choice = input("\nChoose an option (1-5): ").strip()
        if choice == '1':
            patient_id = input("Enter patient ID: ").strip()
            message = input("Enter record data: ").strip()
            hospital.doctor_add_record(patient_id, message)
        elif choice == '2':
            patient_id = input("Enter patient ID: ").strip()
            hospital.doctor_view_record(patient_id)
        elif choice == '3':
            patient_id = input("Enter patient ID: ").strip()
            hospital.nurse_verify_hash(patient_id)
        elif choice == '4':
            patient_id = input("Enter patient ID: ").strip()
            hospital.admin_verify_signature(patient_id)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nExiting the system. Goodbye!")
        sys.exit(0)
