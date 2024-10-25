import hashlib
import random
from sympy import isprime
from Crypto.Random import random as crypto_random


# ---- Rabin Cryptosystem for Doctor ----
def rabin_keygen():
    p = q = 0
    while not (isprime(p) and p % 4 == 3):
        p = crypto_random.getrandbits(512)
    while not (isprime(q) and q % 4 == 3):
        q = crypto_random.getrandbits(512)
    n = p * q
    return p, q, n


def rabin_encrypt(plaintext, n):
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    c = pow(m, 2, n)
    return c


def rabin_decrypt(c, p, q):
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    gcd, yp, yq = extended_gcd(p, q)

    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = (yp * p * mq - yq * q * mp) % n
    r3 = n - r1
    r4 = n - r2

    for r in [r1, r2, r3, r4]:
        try:
            return r.to_bytes((r.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
        except:
            pass

    return None


def extended_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


# ---- Diffie-Hellman for Nurse/Doctor Signature ----
def dh_keygen():
    p = 23  # Small prime (example purposes), can be larger in practice
    g = 5  # Primitive root modulo p
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return p, g, public_key, private_key


def dh_sign(message, p, g, private_key):
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - private_key * r)) % (p - 1)
    return r, s


def dh_verify(message, r, s, p, g, public_key):
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    v1 = (pow(public_key, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# ---- Hospital System Setup ----
# ---- Hospital System Setup ----
class HospitalSystem:
    def __init__(self):  # Corrected the method name
        self.records = {}  # Encrypted records
        self.hashes = {}  # Record hashes
        self.signatures = {}  # Record signatures
        self.doctor_p, self.doctor_q, self.doctor_n = rabin_keygen()
        self.nurse_p, self.nurse_g, self.nurse_public, self.nurse_private = dh_keygen()
        self.admin_p, self.admin_g, self.admin_public, self.admin_private = dh_keygen()

    # Doctor: Add/Update Records (Rabin Encrypted & DH Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using Rabin
        encrypted_record = rabin_encrypt(record_data, self.doctor_n)

        # Hash for integrity check
        record_hash = hashlib.sha256(record_data_bytes).hexdigest()

        # Sign the record with Diffie-Hellman
        signature = dh_sign(record_data, self.nurse_p, self.nurse_g, self.nurse_private)

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
            decrypted_record = rabin_decrypt(encrypted_record, self.doctor_p, self.doctor_q)
            print(f"Decrypted Record for {patient_id}: {decrypted_record}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rabin_decrypt(encrypted_record, self.doctor_p, self.doctor_q)
            computed_hash = hashlib.sha256(decrypted_record.encode()).hexdigest()
            stored_hash = self.hashes.get(patient_id)
            if computed_hash == stored_hash:
                print(f"Record hash for {patient_id} is valid.")
            else:
                print(f"Record hash for {patient_id} is invalid.")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\nAdmin verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            decrypted_record = rabin_decrypt(encrypted_record, self.doctor_p, self.doctor_q)
            if dh_verify(decrypted_record, *signature, self.nurse_p, self.nurse_g, self.nurse_public):
                print(f"Signature for {patient_id} is valid.")
            else:
                print(f"Signature for {patient_id} is invalid.")
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
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    menu()