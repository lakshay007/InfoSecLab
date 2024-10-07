import random
from sympy import isprime, randprime
from hashlib import sha512, sha256
import json


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
        patient_details = input("Enter patient details: ")

        # Encrypt with Rabin
        _, _, n = self.doctor_rabin_keys
        self.encrypted_data = rabin_encrypt(n, patient_details)
        print(f"Encrypted Data: {self.encrypted_data}")

        # Sign with ElGamal
        p, g, x, y = self.nurse_elgamal_keys
        self.signature = elgamal_sign(p, g, x, str(self.encrypted_data))
        print(f"Digital Signature: (r: {self.signature[0]}, s: {self.signature[1]})")

        # Save data to log
        log_data = read_log()
        log_data['nurse'] = {
            'encrypted_data': self.encrypted_data,
            'signature': self.signature
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
        self.signature = tuple(log_data['nurse']['signature'])

        # Verify Signature
        p, g, _, y = self.nurse_elgamal_keys
        r, s = self.signature
        valid = elgamal_verify(p, g, y, str(self.encrypted_data), r, s)
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
