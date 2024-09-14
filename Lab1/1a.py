def additive_encrypt(plaintext, key):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) - base + key) % 26 + base)
        else:
            encrypted += char
    return encrypted

def additive_decrypt(ciphertext, key):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - base - key) % 26 + base)
        else:
            decrypted += char
    return decrypted

message = "attack is today".replace(" ", "").upper()
key = 12

encrypted_message = additive_encrypt(message, key)
decrypted_message = additive_decrypt(encrypted_message, key)

print(f"Additive Cipher Encrypted: {encrypted_message}")
print(f"Additive Cipher Decrypted: {decrypted_message}")