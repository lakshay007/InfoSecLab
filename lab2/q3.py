from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from time import time

def des():
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

def aes():
    key = (b'0123456789ABCDEF0123456789ABCDEF'
           b'')
    pt = b'Sensitive Information'
    cipher = AES.new(key, AES.MODE_ECB)
    padded_pt = pad(pt, AES.block_size)
    ciphertext = cipher.encrypt(padded_pt)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    print(f'Ciphertext: {ciphertext}')
    print(f'Decrypted plaintext: {decrypted_plaintext.decode()}')

def main():
    destime = time()
    des()
    desfintime = time()
    aestime = time()
    aes()
    aesfintime = time()
    des_speed = desfintime - destime
    aes_speed = aesfintime - aestime
    print("des time: ", des_speed)
    print("aes time: ", aes_speed)

main()


