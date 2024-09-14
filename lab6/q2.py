import hashlib
import random
from sympy import mod_inverse

def generate_dsa_keypair(p, q, g):
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    return (p, q, g, y), x

def sign_dsa(p, q, g, x, message):
    k = random.randint(1, q-1)
    r = pow(g, k, p) % q
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
    k_inv = mod_inverse(k, q)
    s = (k_inv * (h + x * r)) % q
    return r, s

def verify_dsa(p, q, g, y, message, r, s):
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
    w = mod_inverse(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v1 = pow(g, u1, p)
    v2 = (pow(y, u2, p) * pow(r, 1, p)) % p
    v1 = v1 % q
    v2 = v2 % q
    return v1 == v2


p = 0xFFFFFFFFFFFFFFFF
q = 0xF000000000000001
g = 2

public_key, private_key = generate_dsa_keypair(p, q, g)
message = "Hello, World!"

r, s = sign_dsa(p, q, g, private_key, message)
print(f"Signature: r={r}, s={s}")

is_valid = verify_dsa(p, q, g, public_key[3], message, r, s)
print(f"Signature valid: {is_valid}")
