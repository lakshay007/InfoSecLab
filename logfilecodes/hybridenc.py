import random
from sympy import isprime, randprime
from hashlib import sha512, sha256
import json
from cryptography.fernet import Fernet
# AES encryption using Fernet
def aes_encrypt(data):
    key = Fernet.generate_key()  # Generate a new AES key
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())  # Encrypt the data (patient details)
    return key, encrypted_data

# AES decryption using Fernet
def aes_decrypt(key, encrypted_data):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data).decode()  # Decrypt and return as string
    return decrypted_data

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


def elgamal_keygen(bit_size=512):
    p = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, x, y)


def elgamal_sign(p, g, x, message):
    h = int(sha256(message.encode()).hexdigest(), 16)
    while True:
        k = random.randint(1, p - 2)
        if egcd(k, p - 1)[0] == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s


def elgamal_verify(p, g, y, message, r, s):
    h = int(sha256(message.encode()).hexdigest(), 16)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


def create_digest(message):
    return sha512(message.encode()).hexdigest()


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
        self.nurse_elgamal_keys = elgamal_keygen()
        self.doctor_rabin_keys = rabin_keygen()
        self.doctor_elgamal_keys = elgamal_keygen()
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

        # Step 1: Encrypt patient details using AES
        aes_key, self.encrypted_data = aes_encrypt(patient_details)
        print(f"Encrypted Data (AES): {self.encrypted_data}")

        # Step 2: Encrypt AES key using Rabin
        _, _, n = self.doctor_rabin_keys
        encrypted_aes_key = rabin_encrypt(n, aes_key.decode())
        print(f"Encrypted AES Key (Rabin): {encrypted_aes_key}")

        # Sign with ElGamal
        p, g, x, y = self.nurse_elgamal_keys
        self.signature = elgamal_sign(p, g, x, str(encrypted_aes_key))
        print(f"Digital Signature: (r: {self.signature[0]}, s: {self.signature[1]})")

        # Save unencrypted patient details, encrypted data, encrypted AES key, and signature to log
        log_data = read_log()
        log_data['nurse'] = {
            'patient_details': patient_details,  # Unencrypted data
            'encrypted_data': self.encrypted_data.decode(),  # AES-encrypted data
            'encrypted_aes_key': encrypted_aes_key,
            'signature': self.signature
        }
        write_log(log_data)

    def doctor(self):
        print("\nDoctor's Role:")

        # Verify Signature
        p, g, _, y = self.nurse_elgamal_keys
        r, s = self.signature
        encrypted_aes_key = read_log()['nurse']['encrypted_aes_key']
        valid = elgamal_verify(p, g, y, str(encrypted_aes_key), r, s)
        if not valid:
            print("Signature verification failed.")
            return

        print("Signature verified successfully.")

        # Step 1: Decrypt the AES key using Rabin
        p, q, n = self.doctor_rabin_keys
        decrypted_aes_key = rabin_decrypt(p, q, n, encrypted_aes_key)
        print(f"Decrypted AES Key: {decrypted_aes_key}")

        # Step 2: Decrypt the patient details using AES
        encrypted_data = read_log()['nurse']['encrypted_data']
        decrypted_data = aes_decrypt(decrypted_aes_key.encode(), encrypted_data.encode())
        print(f"Decrypted Data (Patient Details): {decrypted_data}")

        # Write prescription
        self.prescription = input("Write a prescription: ")

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
