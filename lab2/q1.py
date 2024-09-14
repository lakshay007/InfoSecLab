from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b'A1B2C3D4'
pt = b'Confidential Data'
cipher = DES.new(key, DES.MODE_ECB)
ppt = pad(pt, DES.block_size)
ciphertext = cipher.encrypt(ppt)
cipher = DES.new(key, DES.MODE_ECB)
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size)
print(f'Ciphertext: {ciphertext}')
print(f'Decrypted plaintext: {decrypted_plaintext.decode()}')
