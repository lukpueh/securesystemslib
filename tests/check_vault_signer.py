"""Test AWSSigner

"""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import VaultSigner


class TestVaultSigner(unittest.TestCase):
    """Test VaultSigner"""

    def test_vault_import_sign_verify(self):
        # Test full signer flow with vault
        # - see tests/scripts/init-vault.sh for how keys are created
        # - see tox.ini for how credentials etc. are passed via env vars
        keys_and_schemes = [("test-key-ed25519", "ed25519")]
        for hv_key_name, scheme in keys_and_schemes:
            # Test import
            uri, public_key = VaultSigner.import_(hv_key_name)
            self.assertEqual(uri, f"{VaultSigner.SCHEME}:{hv_key_name}")
            self.assertEqual(scheme, public_key.scheme)

            # # Test load
            # signer = Signer.from_priv_key_uri(uri, public_key)
            # self.assertIsInstance(signer, VaultSigner)

            signer = VaultSigner(hv_key_name, 1, public_key)

            # Test sign and verify
            signature = signer.sign(b"DATA")
            self.assertIsNone(public_key.verify_signature(signature, b"DATA"))
            with self.assertRaises(UnverifiedSignatureError):
                public_key.verify_signature(signature, b"NOT DATA")


if __name__ == "__main__":
    unittest.main(verbosity=1)
