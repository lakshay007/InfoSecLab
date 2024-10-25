import hashlib
import random
from sympy import isprime


# ---- RSA Cryptosystem ----
def rsa_keygen(bit_length=1024):
    """Generates RSA public and private keys."""

    def generate_prime(bits):
        while True:
            prime_candidate = random.getrandbits(bits)
            # Ensure it's odd and has the correct bit length
            prime_candidate |= (1 << bits - 1) | 1
            if isprime(prime_candidate):
                return prime_candidate

    # Generate two distinct primes p and q
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    while q == p:
        q = generate_prime(bit_length // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent e
    e = 65537  # Commonly used prime
    if gcd(e, phi) != 1:
        # If e and phi are not coprime, find another e
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    # Compute private exponent d
    d = pow(e, -1, phi)

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


def rsa_encrypt(plaintext, public_key):
    """Encrypts plaintext using RSA encryption."""
    n, e = public_key
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    if m >= n:
        raise ValueError("Message too long for the key size.")
    c = pow(m, e, n)
    return c


def rsa_decrypt(ciphertext, private_key):
    """Decrypts ciphertext using RSA decryption."""
    n, d = private_key
    m = pow(ciphertext, d, n)
    try:
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
        return plaintext
    except:
        raise ValueError("Failed to decrypt the message.")


# ---- ElGamal Signature Scheme ----
def elgamal_keygen(bit_length=512):
    """Generates ElGamal public and private keys."""

    def generate_prime(bits):
        while True:
            prime_candidate = random.getrandbits(bits)
            prime_candidate |= (1 << bits - 1) | 1
            if isprime(prime_candidate):
                return prime_candidate

    # Generate a prime p
    p = generate_prime(bit_length)

    # Choose a generator g for the multiplicative group of integers modulo p
    # For simplicity, choose g = 2
    g = 2
    while pow(g, (p - 1) // 2, p) == 1:
        g += 1

    # Choose a private key x
    private_key = random.randint(2, p - 2)

    # Compute the public key y = g^x mod p
    public_key = pow(g, private_key, p)

    return (p, g, public_key), private_key


def elgamal_sign(message, public_key, private_key):
    """Signs a message using the ElGamal signature scheme."""
    p, g, y = public_key
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - private_key * r)) % (p - 1)

    return (r, s)


def elgamal_verify(message, signature, public_key):
    """Verifies an ElGamal signature."""
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p):
        return False
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2


def gcd(a, b):
    """Computes the Greatest Common Divisor using Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


# ---- Hospital System Setup ----
class HospitalSystem:
    def __init__(self):
        self.records = {}  # Encrypted records
        self.hashes = {}  # Record hashes
        self.signatures = {}  # Record signatures

        # RSA key generation for encryption/decryption (Doctor)
        print("Generating RSA keys for Doctor...")
        self.rsa_public, self.rsa_private = rsa_keygen()

        # ElGamal key generation for signing (Doctor)
        print("Generating ElGamal keys for Doctor...")
        self.elgamal_public, self.elgamal_private = elgamal_keygen()

    # Doctor: Add/Update Records (RSA Encrypted & ElGamal Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\n[Doctor] Adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using RSA
        try:
            encrypted_record = rsa_encrypt(record_data, self.rsa_public)
        except ValueError as ve:
            print(f"Encryption Error: {ve}")
            return

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with ElGamal
        signature = elgamal_sign(record_data, self.elgamal_public, self.elgamal_private)

        # Store encrypted record, hash, and signature
        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for '{patient_id}': {encrypted_record}")
        print(f"Record Hash: {record_hash}")
        print(f"Signature: {signature}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\n[Doctor] Viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private)
                print(f"Decrypted Record for '{patient_id}': {decrypted_record}")
            except ValueError as ve:
                print(f"Decryption Error: {ve}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\n[Nurse] Verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private)
                computed_hash = hashlib.sha256(decrypted_record.encode()).hexdigest()
                stored_hash = self.hashes.get(patient_id)
                if computed_hash == stored_hash:
                    print(f"Record hash for '{patient_id}' is valid.")
                else:
                    print(f"Record hash for '{patient_id}' is INVALID.")
            except ValueError as ve:
                print(f"Decryption Error: {ve}")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\n[Admin] Verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            try:
                decrypted_record = rsa_decrypt(encrypted_record, self.rsa_private)
                is_valid = elgamal_verify(decrypted_record, signature, self.elgamal_public)
                if is_valid:
                    print(f"Signature for '{patient_id}' is VALID.")
                else:
                    print(f"Signature for '{patient_id}' is INVALID.")
            except ValueError as ve:
                print(f"Decryption Error: {ve}")
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
            print("Exiting the system. Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option (1-5).")


if __name__ == "__main__":
    menu()
