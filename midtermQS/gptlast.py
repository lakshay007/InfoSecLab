import random
from sympy import isprime, randprime
from hashlib import sha512, sha256


# --- Rabin Encryption Functions ---
def rabin_keygen(bit_size=512):
    # Generate two large primes p and q
    p = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    q = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    n = p * q
    return (p, q, n)


def rabin_encrypt(n, message):
    m = int.from_bytes(message.encode(), 'big')  # Convert string to integer
    return (m * m) % n


def rabin_decrypt(p, q, n, ciphertext):
    # Decrypt the message using Rabin decryption
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # Use Chinese Remainder Theorem to find four potential solutions
    yp = q * modinv(q, p)
    yq = p * modinv(p, q)

    # Four possible roots
    r1 = (mp * yp + mq * yq) % n
    r2 = (mp * yp - mq * yq) % n
    r3 = (-mp * yp + mq * yq) % n
    r4 = (-mp * yp - mq * yq) % n

    # Try converting each root to a valid string
    possible_roots = [r1, r2, r3, r4]

    for root in possible_roots:
        try:
            # Ensure root is converted correctly by using byte padding
            decrypted_message = root.to_bytes((root.bit_length() + 7) // 8, 'big').decode()
            return decrypted_message  # Return the first valid string
        except:
            continue

    return "Decryption failed: Unable to convert decrypted data to a valid string."


# Helper functions for ElGamal and other cryptographic tasks
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

    def doctor(self):
        print("\nDoctor's Role:")

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

    def technician(self):
        print("\nTechnician's Role:")

        # Create Message Digest using SHA-512
        if self.prescription:
            digest = create_digest(self.prescription)
            print(f"Message Digest (SHA-512): {digest}")
        else:
            print("No prescription to create a digest from.")

    def run(self):
        while True:
            print("\nMenu:")
            print("1. Nurse")
            print("2. Doctor")
            print("3. Technician")
            print("4. Exit")

            choice = input("Choose an option: ")

            if choice == '1':
                # Nurse takes patient details, encrypts, and signs
                self.nurse()
            elif choice == '2':
                # Doctor verifies, decrypts, and writes prescription
                self.doctor()
            elif choice == '3':
                # Technician creates a message digest and sends to the doctor
                self.technician()
            elif choice == '4':
                break
            else:
                print("Invalid option, try again.")


# Instantiate the system and run
system = SecureSystem()
system.run()
