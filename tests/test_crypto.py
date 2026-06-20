import unittest
from throttlegear.crypto import get_key_and_iv, decrypt_aes_256_cbc, encrypt_aes_256_cbc

class TestCrypto(unittest.TestCase):
    def test_get_key_and_iv(self):
        # Test NB type key and IV derivation
        key, iv = get_key_and_iv("G614PR", "1.0.5", "NB")
        self.assertEqual(len(key), 32)
        self.assertEqual(len(iv), 16)
        self.assertEqual(key[0], 0)  # Type 'NB' starts with 0
        self.assertEqual(key[1:1+len("G614PR")], b"G614PR")
        
        # Test DT type key starts with 1
        key_dt, _ = get_key_and_iv("ModelDT", "1.0.5", "DT")
        self.assertEqual(key_dt[0], 1)
        
    def test_aes_encrypt_decrypt_roundtrip(self):
        plaintext = b"This is a test plaintext message for AES 256 CBC!"
        key = b"\x01" * 32
        iv = b"\x02" * 16
        
        ciphertext = encrypt_aes_256_cbc(plaintext, key, iv)
        self.assertNotEqual(ciphertext, plaintext)
        
        decrypted = decrypt_aes_256_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

if __name__ == "__main__":
    unittest.main()
