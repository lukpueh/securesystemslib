"""
<Program Name>
  test_ecdsa_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  November 23, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_ecdsa_keys.py.
"""

import unittest

import securesystemslib.ecdsa_keys
import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.rsa_keys

public, private = securesystemslib.ecdsa_keys.generate_public_and_private()
FORMAT_ERROR_MSG = (
    "securesystemslib.exceptions.FormatError raised.  Check object's format."
)


class TestECDSA_keys(
    unittest.TestCase
):  # pylint: disable=missing-class-docstring,invalid-name
    def setUp(self):
        pass

    def test_generate_public_and_private(self):
        (
            public,  # pylint: disable=redefined-outer-name
            private,  # pylint: disable=redefined-outer-name
        ) = securesystemslib.ecdsa_keys.generate_public_and_private()

        # Check format of 'public' and 'private'.
        self.assertEqual(
            True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
        )
        self.assertEqual(
            True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
        )

        # Test for invalid argument.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.ecdsa_keys.generate_public_and_private,
            "bad_algo",
        )

    def test_create_ecdsa_public_and_private_from_pem(self):
        global public  # pylint: disable=global-statement
        global private  # pylint: disable=global-statement

        # Check format of 'public' and 'private'.
        self.assertEqual(
            True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
        )
        self.assertEqual(
            True, securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
        )

        # Check for a valid private pem.
        (
            public,
            private,
        ) = securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem(
            private
        )

        # Check for an invalid pem (non-private).
        self.assertRaises(
            securesystemslib.exceptions.CryptoError,
            securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem,
            public,
        )

        # Test for invalid argument.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            securesystemslib.ecdsa_keys.create_ecdsa_public_and_private_from_pem,
            123,
        )


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
