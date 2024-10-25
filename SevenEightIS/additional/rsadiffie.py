import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import isprime


# ---- RSA Cryptosystem for Doctor ----
def rsa_keygen():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(plaintext, public_key):
    rsa_public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    rsa_private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_message = cipher.decrypt(ciphertext).decode('utf-8')
    return decrypted_message


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
class HospitalSystem:
    def __init__(self):
        self.records = {}  # Encrypted records
        self.hashes = {}  # Record hashes
        self.signatures = {}  # Record signatures

        # RSA key generation for doctor
        self.doctor_private_key, self.doctor_public_key = rsa_keygen()

        # DH key generation for nurse and admin
        self.nurse_p, self.nurse_g, self.nurse_public, self.nurse_private = dh_keygen()
        self.admin_p, self.admin_g, self.admin_public, self.admin_private = dh_keygen()

    # Doctor: Add/Update Records (RSA Encrypted & DH Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using RSA
        encrypted_record = rsa_encrypt(record_data, self.doctor_public_key)

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
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private_key)
            print(f"Decrypted Record for {patient_id}: {decrypted_record}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private_key)
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
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private_key)
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
