import unittest
from Deffi_hellman_ import modular_exponentiation, generate_prime_number
import random

class TestDiffieHellmanKeyExchange(unittest.TestCase):
    def test_diffie_hellman_key_exchange(self):
        p = generate_prime_number(512)
        g = 2
        a = random.randint(1, p-1)
        b = random.randint(1, p-1)
        A = modular_exponentiation(g, a, p)
        B = modular_exponentiation(g, b, p)
        shared_secret_Alice = modular_exponentiation(B, a, p)
        shared_secret_Bob = modular_exponentiation(A, b, p)
        self.assertEqual(shared_secret_Alice, shared_secret_Bob)

if __name__ == '__main__':
    unittest.main()
