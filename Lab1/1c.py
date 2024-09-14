from sympy import mod_inverse
def affine_encrypt(plaintext, key1, key2):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((((ord(char) - base)*key1) + key2) % 26 + base)
        else:
            encrypted += char
    return encrypted

def affine_decrypt(ciphertext, key1, key2):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted += chr((mod_inverse(key1,26)*(ord(char) - base - key2)) % 26 + base)
        else:
            decrypted += char
    return decrypted

message = input("enter message: ")
message.replace(" ", "").upper()
key1 = int(input("enter key 1: "))
key2 = int(input("enter key 2: "))

encrypted_message = affine_encrypt(message, key1, key2)
decrypted_message = affine_decrypt(encrypted_message, key1, key2)

print(f"Additive Cipher Encrypted: {encrypted_message}")
print(f"Additive Cipher Decrypted: {decrypted_message}")