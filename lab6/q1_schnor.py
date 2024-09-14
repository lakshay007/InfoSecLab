from sympy import mod_inverse, isprime
import random

def generate_schnorr_keypair(p, g):
    x = random.randint(1, p-2)
    y = pow(g, x, p)
    return (p, g, y), x

def sign_schnorr(p, g, x, message):
    k = random.randint(1, p-2)
    r = pow(g, k, p)
    h = int(hash(message) % p)
    k_inv = mod_inverse(k, p-1)
    s = (k - x * h) % (p-1)
    return r, s

def verify_schnorr(p, g, y, message, r, s):
    h = int(hash(message) % p)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


p = 31
g = 5

public_key, private_key = generate_schnorr_keypair(p, g)
message = "Hello, World!"

r, s = sign_schnorr(p, g, private_key, message)
print(f"Signature: r={r}, s={s}")

is_valid = verify_schnorr(p, g, public_key[2], message, r, s)
print(f"Signature valid: {is_valid}")
