from phe import paillier
import hashlib

# Step 1: Generate Paillier key pair
def generate_paillier_keys():
    private_key, public_key = paillier.generate_paillier_keypair()
    return public_key, private_key

# Step 2: Convert characters to integers
def char_to_int_conversion(char_input):
    return ord(char_input)  # Convert character to integer (ASCII)

# Step 3: Encrypt an integer using Paillier
def paillier_encrypt(public_key, plaintext_int):
    return public_key.encrypt(plaintext_int)

# Step 4: Homomorphic addition for Paillier (add ciphertexts)
def paillier_homomorphic_addition(cipher1, cipher2):
    return cipher1 + cipher2  # Adds encrypted values homomorphically

# Step 5: Decrypt the Paillier ciphertext
def paillier_decrypt(private_key, ciphertext):
    return private_key.decrypt(ciphertext)

# Step 6: Generate SHA-512 digest
def generate_sha512_digest(data):
    hash_obj = hashlib.sha512(data).hexdigest()
    return hash_obj

# Example workflow
def main():
    # Key generation
    private_key, public_key = generate_paillier_keys()
    print("Generated Paillier keys.")

    # User input
    char_input1 = input("Enter first character: ")
    char_input2 = input("Enter second character: ")

    # Convert characters to integers
    int_input1 = char_to_int_conversion(char_input1)
    int_input2 = char_to_int_conversion(char_input2)
    print(f"Character '{char_input1}' converted to int: {int_input1}")
    print(f"Character '{char_input2}' converted to int: {int_input2}")

    # Original addition
    original_addition = int_input1 + int_input2
    print(f"Original addition result: {original_addition}")

    # Encrypt integers
    encrypted1 = paillier_encrypt(public_key, int_input1)
    encrypted2 = paillier_encrypt(public_key, int_input2)
    print("Encrypted values obtained.")

    # Perform homomorphic addition
    encrypted_result = paillier_homomorphic_addition(encrypted1, encrypted2)
    print("Homomorphic addition on encrypted data done.")

    # Decrypt the result
    decrypted_result = paillier_decrypt(private_key, encrypted_result)
    print("Decrypted result after homomorphic addition:", decrypted_result)

    # Verify if decrypted result matches original addition
    if decrypted_result == original_addition:
        print("Success! The decrypted result matches the original addition.")
    else:
        print("Error! The decrypted result does not match the original addition.")

    # SHA-512 digest of the encrypted result
    encrypted_data_bytes = encrypted_result.ciphertext().to_bytes((encrypted_result.ciphertext().bit_length() + 7) // 8, byteorder="big")
    digest = generate_sha512_digest(encrypted_data_bytes)
    print("SHA-512 Digest of the encrypted result:", digest)

if __name__ == "__main__":
    main()
