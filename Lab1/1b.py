from sympy import mod_inverse
import math
def mul_encrypt(plaintext, key):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted += chr(((ord(char) - base) * key) % 26 + base)
        else:
            encrypted += char
    return encrypted

def mul_decrypt(ciphertext, key):
    decrypted = ""
    mult_inv = mod_inverse(key, 26)
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted += chr(((ord(char) - base) * mult_inv) % 26 + base)
        else:
            decrypted += char
    return decrypted

message = "attack is today".replace(" ", "").upper()
key = 15

encrypted_message = mul_encrypt(message, key)
decrypted_message = mul_decrypt(encrypted_message, key)

print(f"Mul Cipher Encrypted: {encrypted_message}")
print(f"Mul Cipher Decrypted: {decrypted_message}")