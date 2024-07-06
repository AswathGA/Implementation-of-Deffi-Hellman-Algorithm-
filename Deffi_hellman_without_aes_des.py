import random
from sympy import randprime

# Function to generate a large prime number
def generate_prime_number(length=512):
    """Generate a prime number of given bit length."""
    # Generate a random prime number of the specified bit length
    prime_candidate = randprime(2**(length-1), 2**length)
    return prime_candidate

# Function to calculate modular exponentiation
def modular_exponentiation(base, exp, mod):
    """Perform modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Diffie-Hellman Key Exchange Implementation
def diffie_hellman_key_exchange():
    # Publicly agreed upon prime number and base (g)
    prime_length = 512  # Adjust for actual security needs
    p = generate_prime_number(prime_length)
    g = 2  # Commonly used base

    print(f"Publicly shared prime (p): {p}")
    print(f"Publicly shared base (g): {g}")

    # Alice generates her private and public keys
    a = random.randint(1, p-1)
    A = modular_exponentiation(g, a, p)

    # Bob generates his private and public keys
    b = random.randint(1, p-1)
    B = modular_exponentiation(g, b, p)

    print(f"Alice's public key (A): {A}")
    print(f"Bob's public key (B): {B}")

    # Alice and Bob compute the shared secret
    shared_secret_Alice = modular_exponentiation(B, a, p)
    shared_secret_Bob = modular_exponentiation(A, b, p)

    # Check if the shared secrets match and print the shared secret
    if shared_secret_Alice == shared_secret_Bob:
        print(f"Shared secret: {shared_secret_Alice}")
    else:
        raise AssertionError("Shared secrets do not match")

if __name__ == "__main__":
    diffie_hellman_key_exchange()