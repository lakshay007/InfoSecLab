import random
import hashlib

#from sympy import mod_inverse, isprime, primerange
transaction_list=[]
def encrypt_message(message, n, e):
    encrypted_message = []
    for char in message:
        m = ord(char)  # Convert character to its ASCII value
        c = pow(m, e, n)  # Encryption: c = m^e % n
        encrypted_message.append(c)
    return encrypted_message


def hash(data):
    k=hashlib.sha512(data).hexdigest()
    print(k)
    return hashlib.sha512(data).hexdigest()
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 0


def rabin():
    p = 61
    q = 53
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 2  # Public exponent

    # Compute the modular inverse for the private key
    d = mod_inverse(e,  phi_n)
    message = "Send 55,000 to Bob using MasterCard 3048 3303 3039 3783"
    encrypted_message = encrypt_message(message, n, e)
    print("Original Message:", "Send 55,000 to Bob using MasterCard 3048 3303 3039 3783")
    print("Encrypted Message:", encrypted_message)



def elgamal():
    # Function to generate a random prime number
    def generate_large_prime(bits=512):
        primes = list((2 ** (bits - 1), 2 ** bits))
        return random.choice(primes)

    # ElGamal parameters
    p = generate_large_prime(8)  # For demonstration, using a small prime; use a larger prime in practice
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2)  # Private key
    h = pow(g, x, p)  # Public key component

    # Message to be encrypted (converted to integer for encryption)
    message = "Send 55,000 to Bob using MasterCard 3048 3303 3039 3783".encode('utf-8')
    message_int = int.from_bytes(message, byteorder='big')

    # Encryption
    k = random.randint(2, p - 2)  # Random integer
    c1 = pow(g, k, p)  # c1 = g^k mod p
    s = pow(h, k, p)  # s = h^k mod p
    c2 = (message_int * s) % p  # c2 = m * s mod p

    # Decryption
    s_inv = mod_inverse(c1, p)
    c1=57
    c2=3# Compute modular inverse of c1
    message_int_decrypted = (c2 * s_inv) % p  # m = c2 * s_inv mod p

    # Convert integer back to bytes
    message_decrypted = message_int_decrypted.to_bytes((message_int_decrypted.bit_length() + 7) // 8,
                                                       byteorder='big').decode('utf-8')

    # Output results
    print("Original Message:", "Send 55,000 to Bob using MasterCard 3048 3303 3039 3783")
    print("Encrypted Message:")
    print("c1:", c1)
    print("c2:", c2)
    print("Decrypted Message:", message_decrypted)


# Encryption and Decryption functions

def decrypt_message(encrypted_message, n, d):
    decrypted_message = []
    for c in encrypted_message:
        m = pow(c, d, n)  # Decryption: m = c^d % n
        decrypted_message.append(chr(m))  # Convert ASCII value back to character
    return ''.join(decrypted_message)

# Encrypting the message


message="Send 55,000 to Bob using MasterCard 3048 3303 3039 3783"


while(True):
    print("1. For Rabin Encryption\n2. For El Gamal Signatures\n3. For SH512 Hashing\n4. For Exit")
    ch = int(input("Enter the choice"))

    if(ch==1):
        rabin()
    if(ch==2):
        elgamal()
    if(ch == 3):
        hash("Send 55,000 to Bob using MasterCard 3048 3303 3039 3783".encode())
    if (ch == 4):
        break
    if (ch != 4 or ch != 3 or ch != 2 or ch !=1 ):
        print("Wrong Choice")





# Decrypting the message"""
"""decrypted_message = decrypt_message(encrypted_message, n, d)
print("Decrypted Message:", decrypted_message) """



#if __name__=="__main__":














