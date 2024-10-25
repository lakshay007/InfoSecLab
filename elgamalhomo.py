from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA512

# Step 1: Generate ElGamal key pair with reduced bits for testing
def generate_elgamal_keys(bits=512):  # Reduced to 512 bits
    key = ElGamal.generate(bits, get_random_bytes)
    return key, key.publickey()

# Step 2: Convert characters to integers
def char_to_int_conversion(char_input):
    return bytes_to_long(char_input.encode())

# Step 3: Encrypt an integer using ElGamal
def elgamal_encrypt(public_key, plaintext_int):
    k = random.randint(1, int(public_key.p) - 2)  # Ensure p is an integer
    c1 = pow(int(public_key.g), k, int(public_key.p))
    c2 = (plaintext_int * pow(int(public_key.y), k, int(public_key.p))) % int(public_key.p)
    return (c1, c2)

# Step 4: Homomorphic multiplication for ElGamal (multiply ciphertexts)
def elgamal_homomorphic_multiplication(cipher1, cipher2, p):
    p = int(p)  # Ensure p is a regular integer
    c1_new = (cipher1[0] * cipher2[0]) % p
    c2_new = (cipher1[1] * cipher2[1]) % p
    return (c1_new, c2_new)

# Step 5: Decrypt the ElGamal ciphertext
def elgamal_decrypt(private_key, ciphertext):
    c1, c2 = ciphertext
    s = pow(int(c1), int(private_key.x), int(private_key.p))
    s_inv = pow(s, int(private_key.p) - 2, int(private_key.p))  # Modular inverse
    plaintext_int = (c2 * s_inv) % int(private_key.p)
    return plaintext_int

# Step 6: Generate SHA-512 digest
def generate_sha512_digest(data):
    hash_obj = SHA512.new()
    hash_obj.update(data)
    return hash_obj.hexdigest()

# Example workflow
def main():
    # Key generation
    private_key, public_key = generate_elgamal_keys()  # Now using 512 bits for faster generation
    print("Generated ElGamal keys.")

    # User input
    char_input1 = input("Enter first character: ")
    char_input2 = input("Enter second character: ")

    # Convert characters to integers
    int_input1 = char_to_int_conversion(char_input1)
    int_input2 = char_to_int_conversion(char_input2)
    print(f"Character '{char_input1}' converted to int: {int_input1}")
    print(f"Character '{char_input2}' converted to int: {int_input2}")

    # Original multiplication
    original_multiplication = int_input1 * int_input2
    print(f"Original multiplication result: {original_multiplication}")

    # Encrypt integers
    encrypted1 = elgamal_encrypt(public_key, int_input1)
    encrypted2 = elgamal_encrypt(public_key, int_input2)
    print("Encrypted values obtained.")

    # Perform homomorphic multiplication
    encrypted_result = elgamal_homomorphic_multiplication(encrypted1, encrypted2, public_key.p)
    print("Homomorphic multiplication on encrypted data done.")

    # Decrypt the result
    decrypted_result = elgamal_decrypt(private_key, encrypted_result)
    print("Decrypted result after homomorphic multiplication:", decrypted_result)

    # Verify if decrypted result matches original multiplication
    if decrypted_result == original_multiplication:
        print("Success! The decrypted result matches the original multiplication.")
    else:
        print("Error! The decrypted result does not match the original multiplication.")

    # SHA-512 digest of the encrypted result
    encrypted_data_bytes = long_to_bytes(encrypted_result[0]) + long_to_bytes(encrypted_result[1])
    digest = generate_sha512_digest(encrypted_data_bytes)
    print("SHA-512 Digest of the encrypted result:", digest)

if __name__ == "__main__":
    main()
