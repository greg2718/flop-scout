import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import flop_scout

class Tests(unittest.TestCase):
    def test_did(self):
        key = Ed25519PrivateKey.generate()
        self.assertTrue(flop_scout.public_did(key).startswith("did:key:z6Mk"))

    def test_normalize(self):
        self.assertEqual(flop_scout.normalize_text("hello\nworld\u200b"), "hello world")

    def test_signature(self):
        key = Ed25519PrivateKey.generate()
        payload = b"lobby|1234567890123|hello"
        sig = key.sign(payload)
        key.public_key().verify(sig, payload)
        self.assertEqual(len(flop_scout.b64u(sig)), 86)

if __name__ == "__main__":
    unittest.main()
