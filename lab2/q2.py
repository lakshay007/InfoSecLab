from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = (b'0123456789ABCDEF0123456789ABCDEF'
       b'')
pt = b'Sensitive Information'
cipher = AES.new(key, AES.MODE_ECB)
padded_pt = pad(pt, AES.block_size)
ciphertext = cipher.encrypt(padded_pt)
cipher = AES.new(key, AES.MODE_ECB)
decrypted_padded_pt = cipher.decrypt(ciphertext)
decrypted_plaintext = unpad(decrypted_padded_pt, AES.block_size)
print(f'Ciphertext: {ciphertext}')
print(f'Decrypted plaintext: {decrypted_plaintext.decode()}')
