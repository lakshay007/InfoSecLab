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

# ---- Rabin Cryptosystem for Encryption ----
def rabin_keygen(bit_length=512):
    """Generates Rabin public and private keys."""
    p = q = 0
    while True:
        p = crypto_random.getrandbits(bit_length)
        p |= (1 << (bit_length - 1)) | 1  # Ensure p is odd and has bit_length
        if isprime(p) and p % 4 == 3:
            break
    while True:
        q = crypto_random.getrandbits(bit_length)
        q |= (1 << (bit_length - 1)) | 1  # Ensure q is odd and has bit_length
        if isprime(q) and q % 4 == 3 and q != p:
            break
    n = p * q
    return p, q, n

def rabin_encrypt(plaintext, n):
    """Encrypts plaintext using Rabin cryptosystem."""
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    if m >= n:
        raise ValueError("Message too long for the key size.")
    c = pow(m, 2, n)
    return c

def rabin_decrypt(c, p, q):
    """Decrypts ciphertext using Rabin cryptosystem."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    gcd_val, yp, yq = extended_gcd(p, q)

    # Compute the four possible roots
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = (yp * p * mq - yq * q * mp) % n
    r3 = n - r1
    r4 = n - r2

    possible_roots = [r1, r2, r3, r4]

    for r in possible_roots:
        try:
            plaintext = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
            return plaintext
        except:
            continue

    return None

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

        # Rabin key generation for Doctor (Encryption/Decryption)
        print("Generating Rabin keys for Doctor...")
        self.rabin_p, self.rabin_q, self.rabin_n = rabin_keygen()

        # ECC key generation for Nurse (Signing)
        print("Generating ECC keys for Nurse...")
        self.ecc_private_key, self.ecc_public_key = ecc_keygen()

    # Doctor: Add/Update Records (Rabin Encrypted & ECC Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\n[Doctor] Adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using Rabin
        try:
            encrypted_record = rabin_encrypt(record_data, self.rabin_n)
        except ValueError as ve:
            print(f"Encryption Error: {ve}")
            return

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with ECC (using Nurse's private key)
        try:
            signature = ecc_sign(record_data, self.ecc_private_key)
        except Exception as e:
            print(f"Signing Error: {e}")
            return

        # Store encrypted record, hash, and signature
        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for '{patient_id}': {encrypted_record}")
        print(f"Record Hash: {record_hash}")
        print(f"Signature: {signature.hex()}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\n[Doctor] Viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rabin_decrypt(encrypted_record, self.rabin_p, self.rabin_q)
            if decrypted_record:
                print(f"Decrypted Record for '{patient_id}': {decrypted_record}")
            else:
                print("Failed to decrypt the record. Possible data corruption.")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\n[Nurse] Verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rabin_decrypt(encrypted_record, self.rabin_p, self.rabin_q)
            if decrypted_record:
                computed_hash = hashlib.sha256(decrypted_record.encode()).hexdigest()
                stored_hash = self.hashes.get(patient_id)
                if computed_hash == stored_hash:
                    print(f"Record hash for '{patient_id}' is VALID.")
                else:
                    print(f"Record hash for '{patient_id}' is INVALID.")
            else:
                print("Failed to decrypt the record. Possible data corruption.")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\n[Admin] Verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            decrypted_record = rabin_decrypt(encrypted_record, self.rabin_p, self.rabin_q)
            if decrypted_record:
                is_valid = ecc_verify(decrypted_record, signature, self.ecc_public_key)
                if is_valid:
                    print(f"Signature for '{patient_id}' is VALID.")
                else:
                    print(f"Signature for '{patient_id}' is INVALID.")
            else:
                print("Failed to decrypt the record. Possible data corruption.")
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
