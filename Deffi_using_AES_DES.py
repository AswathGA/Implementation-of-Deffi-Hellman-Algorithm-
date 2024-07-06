import random
import os
from sympy import randprime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

# Function to generate a large prime number
def generate_prime_number(length=512):
    return randprime(2**(length-1), 2**length)

# Function to calculate modular exponentiation
def modular_exponentiation(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# AES encryption function
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# AES decryption function
def aes_decrypt(key, data):
    iv = data[:AES.block_size]
    ct = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

# File encryption function
def encrypt_file(filename, key):
    with open(filename, 'rb') as f:
        plaintext = f.read()
    encrypted = aes_encrypt(key, plaintext)
    encrypted_filename = filename + '.enc'
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted)
    print(f"File '{filename}' encrypted and saved as '{encrypted_filename}'.")
    return encrypted_filename

# File decryption function
def decrypt_file(filename, key):
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
    decrypted = aes_decrypt(key, encrypted_data)
    decrypted_filename = filename.replace('.enc', '_decrypted.txt')
    with open(decrypted_filename, 'wb') as f:
        f.write(decrypted)
    print(f"File '{filename}' decrypted and saved as '{decrypted_filename}'.")
    return decrypted_filename

# Convert shared secret to AES key
def derive_aes_key(shared_secret):
    sha256 = SHA256.new()
    sha256.update(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big'))
    return sha256.digest()[:16]

# Diffie-Hellman Key Exchange Implementation
def diffie_hellman_key_exchange():
    prime_length = 512
    p = generate_prime_number(prime_length)
    g = 2

    # Alice's keys
    a = random.randint(1, p-1)
    A = modular_exponentiation(g, a, p)

    # Bob's keys
    b = random.randint(1, p-1)
    B = modular_exponentiation(g, b, p)

    print(f"Alice's private key: {a}")
    print(f"Alice's public key: {A}")
    print(f"Bob's private key: {b}")
    print(f"Bob's public key: {B}")

    # Shared secret
    shared_secret_Alice = modular_exponentiation(B, a, p)
    shared_secret_Bob = modular_exponentiation(A, b, p)

    if shared_secret_Alice == shared_secret_Bob:
        shared_secret = shared_secret_Alice
        print(f"Shared secret: {shared_secret}")
    else:
        raise AssertionError("Shared secrets do not match")

    # Derive AES key from shared secret
    aes_key = derive_aes_key(shared_secret)

    return aes_key

# Man-in-the-Middle Attack Simulation
def man_in_the_middle_attack():
    prime_length = 512
    p = generate_prime_number(prime_length)
    g = 2

    # Alice's keys
    a = random.randint(1, p-1)
    A = modular_exponentiation(g, a, p)

    # Bob's keys
    b = random.randint(1, p-1)
    B = modular_exponentiation(g, b, p)

    # Mallory's keys
    m = random.randint(1, p-1)
    M = modular_exponentiation(g, m, p)

    print(f"Mallory's public key (M): {M}")

    # Alice computes shared secret with Mallory's public key
    shared_secret_Alice_Mallory = modular_exponentiation(M, a, p)
    # Bob computes shared secret with Mallory's public key
    shared_secret_Bob_Mallory = modular_exponentiation(M, b, p)
    # Mallory computes shared secrets with both Alice's and Bob's public keys
    shared_secret_Mallory_Alice = modular_exponentiation(A, m, p)
    shared_secret_Mallory_Bob = modular_exponentiation(B, m, p)

    print(f"Mallory's shared secret with Alice: {shared_secret_Mallory_Alice}")
    print(f"Mallory's shared secret with Bob: {shared_secret_Mallory_Bob}")

    if shared_secret_Alice_Mallory == shared_secret_Mallory_Alice and shared_secret_Bob_Mallory == shared_secret_Mallory_Bob:
        print("Man-in-the-middle attack completed successfully.")
    else:
        raise AssertionError("Man-in-the-middle attack failed")

    # Derive AES key from shared secrets
    aes_key_mallory = derive_aes_key(shared_secret_Mallory_Alice)

    return aes_key_mallory

if __name__ == "__main__":
    print("Performing Diffie-Hellman key exchange...")
    aes_key = diffie_hellman_key_exchange()
    print("Diffie-Hellman key exchange completed.")

    # Encrypt and decrypt a file
    filename = 'example.txt'
    print(f"\nEncrypting file '{filename}'...")
    encrypted_filename = encrypt_file(filename, aes_key)
    print(f"\nDecrypting file '{encrypted_filename}'...")
    decrypt_file(encrypted_filename, aes_key)

    # Simulate man-in-the-middle attack
    print("\nSimulating man-in-the-middle attack...")
    aes_key_mallory = man_in_the_middle_attack()

    # Mallory attempts to decrypt the file
    try:
        print(f"\nMallory decrypting file '{encrypted_filename}'...")
        decrypt_file(encrypted_filename, aes_key_mallory)
    except Exception as e:
        print(f"Decryption:")
