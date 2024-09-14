def auto_key_encrypt(plaintext, key):
    encrypted = ""
    key_extended = key + plaintext
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            key_char = key_extended[key_index]
            key_shift = ord(key_char) - base
            encrypted += chr((ord(char) - base + key_shift) % 26 + base)
            key_index += 1
        else:
            encrypted += char

    return encrypted

def auto_key_decrypt(ciphertext, key):
    decrypted = ""
    key_extended = list(key)
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            key_char = key_extended[key_index]
            key_shift = ord(key_char) - base
            decrypted_char = chr((ord(char) - base - key_shift) % 26 + base)
            decrypted += decrypted_char
            key_extended.append(decrypted_char)
            key_index += 1
        else:
            decrypted += char

    return decrypted


message = "attack is today".replace(" ", "").upper()
key = "N"

encrypted_message = auto_key_encrypt(message, key)
decrypted_message = auto_key_decrypt(encrypted_message, key)

print(f"Auto-Key Cipher Encrypted: {encrypted_message}")
print(f"Auto-Key Cipher Decrypted: {decrypted_message}")
