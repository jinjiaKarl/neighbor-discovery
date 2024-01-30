import unittest
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import utils
import constant

class TestCaVerify(unittest.TestCase):
    def test_create_certificate(self):
        ca_key = utils.load_key(os.path.join("key_pairs", constant.CA_KEY))
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        cert = utils.issue_cert(
            ca_common_name="Securitas CA",
            common_name="test",
            key=ca_key,
            pk=public_key,
            ca=False)

        ca_cert = utils.load_cert(os.path.join("key_pairs", constant.CA_CERT))
        cert.verify_directly_issued_by(ca_cert)


if __name__ == "__main__":
    unittest.main()
    