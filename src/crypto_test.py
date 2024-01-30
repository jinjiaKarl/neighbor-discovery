import unittest
import crypto


class TestCrpytoRSA(unittest.TestCase):
    def test_sign_verify_succ(self):
        msg = "hello wrold"
        crypto_rsa = crypto.CryptoRSA("vm1")
        impl = crypto.CryptoStrategy(crypto_rsa, "RSA")
        sig = impl.sign(msg)
        
        pk = impl.export_pk()
        impl.import_pk(pk)

        self.assertTrue(impl.verify(msg, sig)) 

    def test_sign_verify_failure(self):
        msg = b"hello wrold"
        crypto_rsa = crypto.CryptoRSA("vm1")
        impl = crypto.CryptoStrategy(crypto_rsa, "RSA")
        sig = impl.sign(msg)

        pk = impl.export_pk()
        impl.import_pk(pk)

        self.assertFalse(impl.verify("aa", sig)) 
    
    def test_encrypt_decrypt_succ(self):
        msg = "hello wrold"
        crypto_rsa = crypto.CryptoRSA("vm1")
        impl = crypto.CryptoStrategy(crypto_rsa, "RSA")

        pk = impl.export_pk()
        impl.import_pk(pk)

        cipher_text = impl.encrypt(msg)
        self.assertEqual(msg, impl.decrypt(cipher_text))

    def test_encrypt_decrypt_failure(self):
        msg = "hello wrold"
        crypto_rsa = crypto.CryptoRSA("vm1")
        impl = crypto.CryptoStrategy(crypto_rsa, "RSA")

        pk = impl.export_pk()
        impl.import_pk(pk)

        cipher_text = impl.encrypt(msg)
        self.assertNotEqual("aa", impl.decrypt(cipher_text))

    def test_encrypt_decrypt_sk_succ(self):
        msg = "hello wrold"
        crypto_rsa = crypto.CryptoRSA("vm1")
        impl = crypto.CryptoStrategy(crypto_rsa, "RSA")

        sk = impl.export_sk()
        impl.import_sk(sk)

        cipher_text, iv = impl.encrypt_sk(msg)
        self.assertEqual(msg, impl.decrypt_sk(cipher_text,iv, None))

class TestCrpytoECC(unittest.TestCase):
    def test_sign_verify_succ(self):
        msg = "hello wrold"
        crypto_ecc = crypto.CryptoECC("vm1")
        impl = crypto.CryptoStrategy(crypto_ecc, "ECC")
        sig = impl.sign(msg)
        
        pk = impl.export_pk()
        impl.import_pk(pk)

        self.assertTrue(impl.verify(msg, sig)) 

    def test_sign_verify_failure(self):
        msg = b"hello wrold"
        crypto_ecc = crypto.CryptoECC("vm1")
        impl = crypto.CryptoStrategy(crypto_ecc, "ECC")
        sig = impl.sign(msg)

        pk = impl.export_pk()
        impl.import_pk(pk)

        self.assertFalse(impl.verify("aa", sig)) 

    def test_generate_shared_key(self):
        crypto_ecc1 = crypto.CryptoECC("vm1")
        impl1 = crypto.CryptoStrategy(crypto_ecc1, "ECC")
        impl1.import_pk(impl1.export_pk())
        priv_key1 = impl1.export_priv_key()

        crypto_ecc2 = crypto.CryptoECC("vm2")
        impl2 = crypto.CryptoStrategy(crypto_ecc2, "ECC")
        impl2.import_pk(impl2.export_pk())
        priv_key2 = impl2.export_priv_key()

        impl1.import_sk(priv_key2)
        impl2.import_sk(priv_key1)
        mac1 = impl1.generate_mac("hello world")
        mac2 = impl2.generate_mac("hello world")
        self.assertEqual(mac1, mac2)

    def test_encrypt_decrypt_sk_succ(self):
        crypto_ecc = crypto.CryptoECC("vm1")
        impl = crypto.CryptoStrategy(crypto_ecc, "ECC")
        impl.import_pk(impl.export_pk())
        priv_key = impl.export_priv_key()
        impl.import_sk(priv_key)

        msg = "hello wrold"
        cipher_text, nonce, tag = impl.encrypt_sk(msg)
        self.assertEqual(msg, impl.decrypt_sk(cipher_text,nonce, tag))

if __name__ == "__main__":
    unittest.main()
