import unittest
from main import  modular_exponentiation

class TestModularExponentiation(unittest.TestCase):
    def test_modular_exponentiation(self):
        result = modular_exponentiation(3, 4, 7)
        self.assertEqual(result, 4)

if __name__ == '__main__':
    unittest.main()
