from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = (b'FEDCBA9876543210FEDCBA9876543210'b'')
cipher = AES.new(key, AES.MODE_ECB)
pt = b'Top Secret Data'
padded_pt = pad(pt, AES.block_size)
ciphertext = cipher.encrypt(padded_pt)
cipher = AES.new(key, AES.MODE_ECB)
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
print(f'Ciphertext: {ciphertext}')
print(f'Decrypted plaintext: {decrypted_plaintext.decode()}')
