"""
<Program Name>
  test_ed25519_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 11, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_ed25519_keys.py.
"""

import unittest

import securesystemslib.ed25519_keys
import securesystemslib.exceptions
import securesystemslib.formats

public, private = securesystemslib.ed25519_keys.generate_public_and_private()
FORMAT_ERROR_MSG = (
    "securesystemslib.exceptions.FormatError raised.  Check object's format."
)


class TestEd25519_keys(
    unittest.TestCase
):  # pylint: disable=missing-class-docstring,invalid-name
    def setUp(self):
        pass

    def test_generate_public_and_private(self):
        pub, priv = securesystemslib.ed25519_keys.generate_public_and_private()

        # Check format of 'pub' and 'priv'.
        self.assertEqual(
            True, securesystemslib.formats.ED25519PUBLIC_SCHEMA.matches(pub)
        )
        self.assertEqual(
            True, securesystemslib.formats.ED25519SEED_SCHEMA.matches(priv)
        )

    def test_create_signature(self):
        global public  # pylint: disable=global-variable-not-assigned
        global private  # pylint: disable=global-variable-not-assigned
        data = b"The quick brown fox jumps over the lazy dog"
        scheme = "ed25519"
        signature, scheme = securesystemslib.ed25519_keys.create_signature(
            public, private, data, scheme
        )

        # Verify format of returned values.
        self.assertEqual(
            True,
            securesystemslib.formats.ED25519SIGNATURE_SCHEMA.matches(signature),
        )

        self.assertEqual(
            True, securesystemslib.formats.ED25519_SIG_SCHEMA.matches(scheme)
        )
        self.assertEqual("ed25519", scheme)

        # Check for improperly formatted argument.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.ed25519_keys.create_signature,
            123,
            private,
            data,
            scheme,
        )

        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.ed25519_keys.create_signature,
            public,
            123,
            data,
            scheme,
        )

        # Check for invalid 'data'.
        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.ed25519_keys.create_signature,
            public,
            private,
            123,
            scheme,
        )


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
