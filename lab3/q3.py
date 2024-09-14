from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def gen_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = get_random_bytes(bits // 8)
    x = bytes_to_long(x) % (p - 1)
    h = pow(g, x, p)
    return (p, g, h), x

def encrypt(msg, pub_key):
    p, g, h = pub_key
    m = bytes_to_long(msg.encode('utf-8'))
    k = get_random_bytes(16)
    k = bytes_to_long(k) % (p - 1)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1, c2)

def decrypt(ciphertext, priv_key, pub_key):
    p, _, _ = pub_key
    c1, c2 = ciphertext
    x = priv_key
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    return long_to_bytes(m).decode('utf-8')

def main():
    pub_key, priv_key = gen_keys()
    msg = input("Enter message: ")
    ciphertext = encrypt(msg, pub_key)
    decrypted_msg = decrypt(ciphertext, priv_key, pub_key)
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted_msg}")

if __name__ == "__main__":
    main()
