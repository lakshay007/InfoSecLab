from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib

# Step 1: Generate RSA key pair
def generate_rsa_keys(bits=1024):
    key = RSA.generate(bits)
    return key, key.publickey()

# Step 2: Encrypt an integer using RSA
def rsa_encrypt(public_key, plaintext_int):
    # Encrypt using RSA: ciphertext = plaintext^e mod n
    ciphertext = pow(plaintext_int, public_key.e, public_key.n)
    return ciphertext

# Step 3: Decrypt the RSA ciphertext
def rsa_decrypt(private_key, ciphertext):
    # Decrypt using RSA: plaintext = ciphertext^d mod n
    plaintext_int = pow(ciphertext, private_key.d, private_key.n)
    return plaintext_int

# Step 4: Homomorphic multiplication for RSA
def rsa_homomorphic_multiplication(cipher1, cipher2, n):
    # Multiply ciphertexts: c1 * c2 mod n
    return (cipher1 * cipher2) % n

# Step 5: Generate SHA-512 digest using hashlib
def generate_sha512_digest(data):
    hash_obj = hashlib.sha512()
    hash_obj.update(data)
    return hash_obj.hexdigest()

# Example workflow
def main():
    # Key generation
    private_key, public_key = generate_rsa_keys()  # Using 512 bits for faster generation
    print("Generated RSA keys.")

    # User input
    char_input1 = input("Enter first character: ")
    char_input2 = input("Enter second character: ")

    # Convert characters to integers
    int_input1 = bytes_to_long(char_input1.encode())
    int_input2 = bytes_to_long(char_input2.encode())
    print(f"Character '{char_input1}' converted to int: {int_input1}")
    print(f"Character '{char_input2}' converted to int: {int_input2}")

    # Original multiplication
    original_multiplication = int_input1 * int_input2
    print(f"Original multiplication result: {original_multiplication}")

    # Encrypt integers
    encrypted1 = rsa_encrypt(public_key, int_input1)
    encrypted2 = rsa_encrypt(public_key, int_input2)
    print("Encrypted values obtained.")

    # Perform homomorphic multiplication
    encrypted_result = rsa_homomorphic_multiplication(encrypted1, encrypted2, public_key.n)
    print("Homomorphic multiplication on encrypted data done.")

    # Decrypt the result
    decrypted_result = rsa_decrypt(private_key, encrypted_result)
    print("Decrypted result after homomorphic multiplication:", decrypted_result)

    # Verify if decrypted result matches original multiplication
    if decrypted_result == original_multiplication:
        print("Success! The decrypted result matches the original multiplication.")
    else:
        print("Error! The decrypted result does not match the original multiplication.")

    # SHA-512 digest of the encrypted result
    encrypted_data_bytes = long_to_bytes(encrypted_result)
    digest = generate_sha512_digest(encrypted_data_bytes)
    print("SHA-512 Digest of the encrypted result:", digest)

if __name__ == "__main__":
    main()
