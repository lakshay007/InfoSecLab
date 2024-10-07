import random
from sympy import randprime
from hashlib import sha512
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# --- Rabin Encryption Functions ---
def rabin_keygen(bit_size=512):
    p = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    q = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    n = p * q
    return (p, q, n)


def rabin_encrypt(n, message):
    m = int.from_bytes(message.encode(), 'big')
    return (m * m) % n


def rabin_decrypt(p, q, n, ciphertext):
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    yp = q * modinv(q, p)
    yq = p * modinv(p, q)

    r1 = (mp * yp + mq * yq) % n
    r2 = (mp * yp - mq * yq) % n
    r3 = (-mp * yp + mq * yq) % n
    r4 = (-mp * yp - mq * yq) % n

    possible_roots = [r1, r2, r3, r4]

    for root in possible_roots:
        try:
            decrypted_message = root.to_bytes((root.bit_length() + 7) // 8, 'big').decode()
            return decrypted_message
        except:
            continue

    return "Decryption failed: Unable to convert decrypted data to a valid string."


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    return x % m


def create_digest(message):
    return sha512(message.encode()).hexdigest()


# --- RSA Functions ---
def rsa_keygen():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature


def rsa_verify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False


# --- File Handling ---
def write_log(data):
    with open('log.json', 'w') as f:
        json.dump(data, f, indent=4)


def read_log():
    try:
        with open('log.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.nurse_rabin_keys = rabin_keygen()
        self.doctor_rabin_keys = rabin_keygen()

        # RSA key pairs for Nurse and Doctor
        self.nurse_rsa_private_key, self.nurse_rsa_public_key = rsa_keygen()
        self.doctor_rsa_private_key, self.doctor_rsa_public_key = rsa_keygen()

        self.encrypted_data = None
        self.signature = None
        self.prescription = None

    def nurse(self):
        print("\nNurse's Role:")

        # Collect four pieces of patient information
        name = input("Enter patient's name: ")
        age = input("Enter patient's age: ")
        problem = input("Enter patient's problem: ")
        dob = input("Enter patient's date of birth (DOB): ")

        # Combine all patient details into a single string
        patient_details = f"Name: {name}, Age: {age}, Problem: {problem}, DOB: {dob}"

        # Encrypt with Rabin
        _, _, n = self.doctor_rabin_keys
        self.encrypted_data = rabin_encrypt(n, patient_details)
        print(f"Encrypted Data: {self.encrypted_data}")

        # Sign with RSA
        self.signature = rsa_sign(self.nurse_rsa_private_key, str(self.encrypted_data))
        print(f"Digital Signature (RSA): {self.signature.hex()}")

        # Save unencrypted patient details, encrypted data, and signature to log
        log_data = read_log()
        log_data['nurse'] = {
            'patient_details': patient_details,  # Unencrypted data
            'encrypted_data': self.encrypted_data,
            'signature': self.signature.hex()  # Store signature as hex
        }
        write_log(log_data)

    def doctor(self):
        print("\nDoctor's Role:")

        # Retrieve data from log
        log_data = read_log()
        if 'nurse' not in log_data:
            print("No patient data found in the log.")
            return

        self.encrypted_data = log_data['nurse']['encrypted_data']
        self.signature = bytes.fromhex(log_data['nurse']['signature'])

        # Verify RSA Signature
        valid = rsa_verify(self.nurse_rsa_public_key, str(self.encrypted_data), self.signature)
        if not valid:
            print("Signature verification failed.")
            return

        print("Signature verified successfully.")

        # Decrypt with Rabin
        p, q, n = self.doctor_rabin_keys
        decrypted_data = rabin_decrypt(p, q, n, self.encrypted_data)
        print(f"Decrypted Data (Patient Details): {decrypted_data}")

        # Write prescription
        self.prescription = input("Write a prescription: ")

        # Save prescription to log
        log_data['doctor'] = {'prescription': self.prescription}
        write_log(log_data)

    def technician(self):
        print("\nTechnician's Role:")

        # Retrieve prescription from log
        log_data = read_log()
        if 'doctor' not in log_data or 'prescription' not in log_data['doctor']:
            print("No prescription found in the log.")
            return

        self.prescription = log_data['doctor']['prescription']

        # Create Message Digest using SHA-512
        digest = create_digest(self.prescription)
        print(f"Message Digest (SHA-512): {digest}")

        # Save digest to log
        log_data['technician'] = {'digest': digest}
        write_log(log_data)

    def run(self):
        while True:
            print("\nMenu:")
            print("1. Nurse")
            print("2. Doctor")
            print("3. Technician")
            print("4. Exit")

            choice = input("Choose an option: ")

            if choice == '1':
                self.nurse()
            elif choice == '2':
                self.doctor()
            elif choice == '3':
                self.technician()
            elif choice == '4':
                break
            else:
                print("Invalid option, try again.")


# Instantiate the system and run
system = SecureSystem()
system.run()
