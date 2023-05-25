"""
<Program Name>
  ecdsa_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  November 22, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support ECDSA keys and signatures.  ECDSA is an
  elliptic-curve digital signature algorithm.  It grants a similar level of
  security as RSA, but uses smaller keys.  No subexponential-time algorithm is
  known for the elliptic curve discrete logarithm problem.

  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

  'securesystemslib.ecdsa_keys.py' calls the 'cryptography' library to perform
  all of the ecdsa-related operations.

  The 'cryptography' library is used by ecdsa_keys.py
  to perform the actual ECDSA computations, and the functions listed above can
  be viewed as an easy-to-use public interface.
 """

import logging

# Import cryptography modules to support ecdsa keys and signatures.
CRYPTO = True
NO_CRYPTO_MSG = "ECDSA key support requires the cryptography library"
try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    _SCHEME_HASHER = {
        "ecdsa-sha2-nistp256": ec.ECDSA(hashes.SHA256()),
        "ecdsa-sha2-nistp384": ec.ECDSA(hashes.SHA384()),
    }

except ImportError:
    CRYPTO = False

# Perform object format-checking and add ability to handle/raise exceptions.
from securesystemslib import (  # pylint: disable=wrong-import-position
    exceptions,
    formats,
)

_SUPPORTED_ECDSA_SCHEMES = ["ecdsa-sha2-nistp256"]

logger = logging.getLogger(__name__)


def generate_public_and_private(scheme="ecdsa-sha2-nistp256"):
    """
    <Purpose>
      Generate a pair of ECDSA public and private keys with one of the supported,
      external cryptography libraries.  The public and private keys returned
      conform to 'securesystemslib.formats.PEMECDSA_SCHEMA' and
      'securesystemslib.formats.PEMECDSA_SCHEMA', respectively.

      The public ECDSA public key has the PEM format:

      '-----BEGIN PUBLIC KEY-----

      ...

      '-----END PUBLIC KEY-----'



      The private ECDSA private key has the PEM format:

      '-----BEGIN EC PRIVATE KEY-----

      ...

      -----END EC PRIVATE KEY-----'

      >>> public, private = generate_public_and_private()
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
      True
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
      True

    <Arguments>
      scheme:
        A string indicating which algorithm to use for the generation of the
        public and private ECDSA keys.  'ecdsa-sha2-nistp256' is the only
        currently supported ECDSA algorithm, which is supported by OpenSSH and
        specified in RFC 5656 (https://tools.ietf.org/html/rfc5656).

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'algorithm' is improperly
      formatted.

      securesystemslib.exceptions.UnsupportedAlgorithmError, if 'scheme' is an
      unsupported algorithm.

      securesystemslib.exceptions.UnsupportedLibraryError, if the cryptography
      module is not available.

    <Side Effects>
      None.

    <Returns>
      A (public, private) tuple that conform to
      'securesystemslib.formats.PEMECDSA_SCHEMA' and
      'securesystemslib.formats.PEMECDSA_SCHEMA', respectively.
    """

    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    # Does 'scheme' have the correct format?
    # Verify that 'scheme' is of the correct type, and that it's one of the
    # supported ECDSA .  It must conform to
    # 'securesystemslib.formats.ECDSA_SCHEME_SCHEMA'.  Raise
    # 'securesystemslib.exceptions.FormatError' if the check fails.
    formats.ECDSA_SCHEME_SCHEMA.check_match(scheme)

    public_key = None
    private_key = None

    # An if-clause is strictly not needed, since 'ecdsa_sha2-nistp256' is the
    # only currently supported ECDSA signature scheme.  Nevertheness, include the
    # conditional statement to accomodate any schemes that might be added.
    if scheme == "ecdsa-sha2-nistp256":
        private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        public_key = private_key.public_key()

    # The ECDSA_SCHEME_SCHEMA.check_match() above should have detected any
    # invalid 'scheme'.  This is a defensive check.
    else:  # pragma: no cover
        raise exceptions.UnsupportedAlgorithmError(
            "An unsupported"
            " scheme specified: " + repr(scheme) + ".\n  Supported"
            " algorithms: " + repr(_SUPPORTED_ECDSA_SCHEMES)
        )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).strip()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).strip()

    return public_pem.decode("utf-8"), private_pem.decode("utf-8")


def create_ecdsa_public_and_private_from_pem(pem, password=None):
    """
    <Purpose>
      Create public and private ECDSA keys from a private 'pem'.  The public and
      private keys are strings in PEM format:

      public: '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----',
      private: '-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----'}}

      >>> junk, private = generate_public_and_private()
      >>> public, private = create_ecdsa_public_and_private_from_pem(private)
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
      True
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
      True
      >>> passphrase = 'secret'
      >>> encrypted_pem = create_ecdsa_encrypted_pem(private, passphrase)
      >>> public, private = create_ecdsa_public_and_private_from_pem(encrypted_pem, passphrase)
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(public)
      True
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(private)
      True

    <Arguments>
      pem:
        A string in PEM format.  The private key is extracted and returned in
        an ecdsakey object.

      password: (optional)
        The password, or passphrase, to decrypt the private part of the ECDSA key
        if it is encrypted.  'password' is not used directly as the encryption
        key, a stronger encryption key is derived from it.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      securesystemslib.exceptions.UnsupportedAlgorithmError, if the ECDSA key
      pair could not be extracted, possibly due to an unsupported algorithm.

      securesystemslib.exceptions.UnsupportedLibraryError, if the cryptography
      module is not available.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing the ECDSA keys and other identifying information.
      Conforms to 'securesystemslib.formats.ECDSAKEY_SCHEMA'.
    """

    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    # Does 'pem' have the correct format?
    # This check will ensure 'pem' conforms to
    # 'securesystemslib.formats.ECDSARSA_SCHEMA'.
    formats.PEMECDSA_SCHEMA.check_match(pem)

    if password is not None:
        formats.PASSWORD_SCHEMA.check_match(password)
        password = password.encode("utf-8")

    else:
        logger.debug(
            "The password/passphrase is unset.  The PEM is expected"
            " to be unencrypted."
        )

    public = None
    private = None

    # Generate the public and private ECDSA keys.  The pyca/cryptography library
    # performs the actual import operation.
    try:
        private = load_pem_private_key(
            pem.encode("utf-8"), password=password, backend=default_backend()
        )

    except (ValueError, UnsupportedAlgorithm) as e:
        raise exceptions.CryptoError(
            "Could not import private" " PEM.\n" + str(e)
        )

    public = private.public_key()

    # Serialize public and private keys to PEM format.
    private = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).strip()

    public = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).strip()

    return public.decode("utf-8"), private.decode("utf-8")


def create_ecdsa_encrypted_pem(private_pem, passphrase):
    """
    <Purpose>
      Return a string in PEM format, where the private part of the ECDSA key is
      encrypted. The private part of the ECDSA key is encrypted as done by
      pyca/cryptography: "Encrypt using the best available encryption for a given
      key's backend. This is a curated encryption choice and the algorithm may
      change over time."

      >>> junk, private = generate_public_and_private()
      >>> passphrase = 'secret'
      >>> encrypted_pem = create_ecdsa_encrypted_pem(private, passphrase)
      >>> securesystemslib.formats.PEMECDSA_SCHEMA.matches(encrypted_pem)
      True

    <Arguments>
      private_pem:
      The private ECDSA key string in PEM format.

      passphrase:
      The passphrase, or password, to encrypt the private part of the ECDSA
      key. 'passphrase' is not used directly as the encryption key, a stronger
      encryption key is derived from it.

      <Exceptions>
        securesystemslib.exceptions.FormatError, if the arguments are improperly
        formatted.

        securesystemslib.exceptions.CryptoError, if an ECDSA key in encrypted PEM
        format cannot be created.

      securesystemslib.exceptions.UnsupportedLibraryError, if the cryptography
      module is not available.

    <Side Effects>
      None.

    <Returns>
      A string in PEM format, where the private RSA portion is encrypted.
      Conforms to 'securesystemslib.formats.PEMECDSA_SCHEMA'.
    """

    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    # Does 'private_key' have the correct format?
    # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
    formats.PEMRSA_SCHEMA.check_match(private_pem)

    # Does 'passphrase' have the correct format?
    formats.PASSWORD_SCHEMA.check_match(passphrase)

    private = load_pem_private_key(
        private_pem.encode("utf-8"), password=None, backend=default_backend()
    )

    encrypted_private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    ).strip()

    return encrypted_private_pem


if __name__ == "__main__":
    # The interactive sessions of the documentation strings can
    # be tested by running 'ecdsa_keys.py' as a standalone module.
    # python -B ecdsa_keys.py
    import doctest

    doctest.testmod()
