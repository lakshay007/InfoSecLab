from sympy import mod_inverse, isprime
import random

def generate_elgamal_keypair(p, g):
    x = random.randint(1, p-2)
    y = pow(g, x, p)
    return (p, g, y), x

def sign_elgamal(p, g, x, message):
    k = random.randint(1, p-2)
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p-1)
    h = int(hash(message) % p)
    s = (k_inv * (h - x * r)) % (p-1)
    return r, s

def verify_elgamal(p, g, y, message, r, s):
    h = int(hash(message) % p)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


p = 23
g = 5
h = 27

public_key, private_key = generate_elgamal_keypair(p, g)
message = "Hello, World!"

r, s = sign_elgamal(p, g, private_key, message)
print(f"Signature: r={r}, s={s}")

is_valid = verify_elgamal(p, g, public_key[2], message, r, s)
print(f"Signature valid: {is_valid}")
