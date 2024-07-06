import unittest
from sympy import isprime
from Deffi_hellman_without_aes_des import generate_prime_number

class TestPrimeGeneration(unittest.TestCase):
    def test_generate_prime_number(self):
        prime = generate_prime_number(512)
        self.assertEqual(len(bin(prime)) - 2, 512)
        self.assertTrue(isprime(prime))

if __name__ == '__main__':
    unittest.main()
