from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

key = b'1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF'
pt = b'Classified Text'
cipher = DES3.new(key, DES3.MODE_ECB)
ppt = pad(pt, DES3.block_size)
ciphertext = cipher.encrypt(ppt)
cipher = DES3.new(key, DES3.MODE_ECB)
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_plaintext = unpad(decrypted_padded_plaintext, DES3.block_size)
print(f'Ciphertext: {ciphertext}')
print(f'Decrypted plaintext: {decrypted_plaintext.decode()}')
