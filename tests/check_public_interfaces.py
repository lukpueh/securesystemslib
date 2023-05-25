"""
<Program Name>
  check_public_interfaces.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  January 6, 2020.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Public facing modules (e.g. interface.py and keys.py) must be
  importable, even if the optional dependencies are not installed.

  Each public facing function should always be callable and present
  meaningful user-feedback if an optional dependency that is required for
  that function is not installed.

  This test purposefully only checks the public functions with a native
  dependency, to avoid duplicated tests.

  NOTE: the filename is purposefully check_ rather than test_ so that test
  discovery doesn't find this unittest and the tests within are only run
  when explicitly invoked.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import securesystemslib.exceptions  # pylint: disable=wrong-import-position
import securesystemslib.gpg.constants  # pylint: disable=wrong-import-position
import securesystemslib.gpg.functions  # pylint: disable=wrong-import-position
import securesystemslib.gpg.util  # pylint: disable=wrong-import-position
import securesystemslib.interface  # pylint: disable=wrong-import-position
import securesystemslib.keys  # pylint: disable=wrong-import-position
from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    VerificationError,
)
from securesystemslib.signer import (
    GPGKey,
    Key,
    Signature,
    SpxKey,
    SpxSigner,
    SSlibKey,
)
from securesystemslib.signer._sigstore_signer import SigstoreKey


class TestPublicInterfaces(
    unittest.TestCase
):  # pylint: disable=missing-class-docstring
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(dir=os.getcwd())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir)

    def test_interface(self):
        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface._generate_and_write_rsa_keypair(  # pylint: disable=protected-access
                password="pw"
            )

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_rsa_keypair("pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_rsa_keypair("pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            # Mock entry on prompt which is presented before lower-level functions
            # raise UnsupportedLibraryError
            with mock.patch(
                "securesystemslib.interface.get_password", return_value=""
            ):
                securesystemslib.interface.generate_and_write_rsa_keypair_with_prompt()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_unencrypted_rsa_keypair()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            path = os.path.join(self.temp_dir, "rsa_key")
            with open(path, "a"):  # pylint: disable=unspecified-encoding
                securesystemslib.interface.import_rsa_privatekey_from_file(path)

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface._generate_and_write_ed25519_keypair(  # pylint: disable=protected-access
                password="pw"
            )

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_ed25519_keypair("pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            # Mock entry on prompt which is presented before lower-level functions
            # raise UnsupportedLibraryError
            with mock.patch(
                "securesystemslib.interface.get_password", return_value=""
            ):
                securesystemslib.interface.generate_and_write_ed25519_keypair_with_prompt()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_unencrypted_ed25519_keypair()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            path = os.path.join(self.temp_dir, "ed25519_priv.json")
            with open(path, "a") as f:  # pylint: disable=unspecified-encoding
                f.write("{}")
                securesystemslib.interface.import_ed25519_privatekey_from_file(
                    path, "pw"
                )

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface._generate_and_write_ecdsa_keypair(  # pylint: disable=protected-access
                password="pw"
            )

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_ecdsa_keypair("pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            # Mock entry on prompt which is presented before lower-level functions
            # raise UnsupportedLibraryError
            with mock.patch(
                "securesystemslib.interface.get_password", return_value=""
            ):
                securesystemslib.interface.generate_and_write_ecdsa_keypair_with_prompt()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.interface.generate_and_write_unencrypted_ecdsa_keypair()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            path = os.path.join(self.temp_dir, "ecddsa.priv")
            with open(path, "a") as f:  # pylint: disable=unspecified-encoding
                f.write("{}")
                securesystemslib.interface.import_ecdsa_privatekey_from_file(
                    path, password="pw"
                )

    def test_keys(self):
        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.generate_rsa_key()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.generate_ecdsa_key()

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.generate_ed25519_key()

        keydict = {
            "keyid": "f00",
            "keyval": {"private": "f001", "public": "b00f"},
        }

        keydict["keytype"] = "ecdsa"
        keydict["scheme"] = "ecdsa-sha2-nistp256"

        priv = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.import_rsakey_from_private_pem("")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.encrypt_key(keydict, "foo")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.decrypt_key("enc", "pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.create_rsa_encrypted_pem(priv, "pw")

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.import_ed25519key_from_private_json(
                "".encode("utf-8"), ""
            )

        with self.assertRaises(
            securesystemslib.exceptions.UnsupportedLibraryError
        ):
            securesystemslib.keys.import_ecdsakey_from_private_pem(priv)

    def test_gpg_functions(self):
        """Public GPG functions must raise error on missing cryptography lib."""
        expected_error = securesystemslib.exceptions.UnsupportedLibraryError
        expected_error_msg = securesystemslib.gpg.functions.NO_CRYPTO_MSG

        with self.assertRaises(expected_error) as ctx:
            securesystemslib.gpg.functions.create_signature("bar")
        self.assertEqual(expected_error_msg, str(ctx.exception))

        with self.assertRaises(expected_error) as ctx:
            securesystemslib.gpg.functions.verify_signature(None, "f00", "bar")
        self.assertEqual(expected_error_msg, str(ctx.exception))

        with self.assertRaises(expected_error) as ctx:
            securesystemslib.gpg.functions.export_pubkey("f00")
        self.assertEqual(expected_error_msg, str(ctx.exception))

    def test_signer_verify(self):
        """Assert generic VerificationError from UnsupportedLibraryError."""
        keyid = "aa"
        sig = Signature(keyid, "aaaaaaaa", {"other_headers": "aaaaaa"})

        keys = [
            GPGKey(keyid, "rsa", "pgp+rsa-pkcsv1.5", {"public": "val"}),
            SSlibKey(keyid, "rsa", "rsa-pkcs1v15-sha512", {"public": "val"}),
            SigstoreKey(
                keyid,
                "sigstore-oidc",
                "Fulcio",
                {"identity": "val", "issuer": "val"},
            ),
            SpxKey(keyid, "sphincs", "sphincs-shake-128s", {"public": "val"}),
        ]

        for key in keys:
            with self.assertRaises(VerificationError) as ctx:
                key.verify_signature(sig, b"data")

            self.assertIsInstance(
                ctx.exception.__cause__, (UnsupportedLibraryError, ImportError)
            )

    def test_signer_sign(self):
        """Assert UnsupportedLibraryError in sign."""
        signers = [
            SpxSigner(
                b"private",
                SpxKey(
                    "aa", "sphincs", "sphincs-shake-128s", {"public": "val"}
                ),
            )
        ]

        for signer in signers:
            with self.assertRaises(UnsupportedLibraryError):
                signer.sign(b"data")

    def test_signer_ed25519_fallback(self):
        """Assert ed25519 signature verification works in pure Python."""
        data = b"The quick brown fox jumps over the lazy dog"
        keyid = "aaa"
        sig = Signature.from_dict(
            {
                "keyid": keyid,
                "sig": "2ec7a5e295fa6265e10f3da7f1a432e7742f041f081b4faecab3a12bf0fc8f366c919c90c267e9ed1dfdeb7a7556b959a96dd0dcfea17da358622d39af36bf09",
            }
        )

        key = Key.from_dict(
            keyid,
            {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyval": {
                    "public": "beb75c268206554e963c45dcbf3c004140d1cb69bbfe9370ef736f19388c9b26"
                },
            },
        )

        self.assertIsNone(key.verify_signature(sig, data))

        with self.assertRaises(
            securesystemslib.exceptions.UnverifiedSignatureError
        ):
            key.verify_signature(sig, b"NOT DATA")


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
