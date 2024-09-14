from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def gen_keys():
    k = RSA.generate(2048)
    priv = k.export_key()
    pub = k.publickey().export_key()
    return priv, pub

def enc_msg(msg, pub):
    pk = RSA.import_key(pub)
    cipher = PKCS1_OAEP.new(pk)
    enc = cipher.encrypt(msg.encode('utf-8'))
    return base64.b64encode(enc).decode('utf-8')

def dec_msg(enc, priv):
    enc = base64.b64decode(enc)
    sk = RSA.import_key(priv)
    cipher = PKCS1_OAEP.new(sk)
    dec = cipher.decrypt(enc)
    return dec.decode('utf-8')

def main():
    priv, pub = gen_keys()
    msg = input("Enter message: ")
    enc = enc_msg(msg, pub)
    print(f"Encrypted: {enc}")
    dec = dec_msg(enc, priv)
    print(f"Decrypted: {dec}")

main()
