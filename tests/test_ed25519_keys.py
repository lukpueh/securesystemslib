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


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
