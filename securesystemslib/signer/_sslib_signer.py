"""Default Key and Signer implementation for securesystemslib keys. """

import logging
import os
from typing import Any, Dict, Optional, Type, cast
from urllib import parse

import securesystemslib.keys as sslib_keys
from securesystemslib import exceptions
from securesystemslib._vendor.ed25519.ed25519 import (
    SignatureMismatch,
    checkvalid,
)
from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        AsymmetricPadding,
        RSAPrivateKey,
        RSAPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        generate_private_key as generate_private_rsa_key,
    )
    from cryptography.hazmat.primitives.asymmetric.types import (
        PrivateKeyTypes,
        PublicKeyTypes,
    )
    from cryptography.hazmat.primitives.hashes import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        HashAlgorithm,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
    )
except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"


logger = logging.getLogger(__name__)

_RSA_KEY_TYPE = "rsa"
_RSA_PUBLIC_EXPONENT = 65537
_RSA_DEFAULT_SCHEME = "rsassa-pss-sha256"
_RSA_DEFAULT_KEY_SIZE = 3072


def generate_rsa_key(
    key_size: int = _RSA_DEFAULT_KEY_SIZE, scheme: str = _RSA_DEFAULT_SCHEME
) -> Dict[str, Any]:
    """Generate RSA key pair and return as legacy keydict."""

    if CRYPTO_IMPORT_ERROR:
        raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

    private = generate_private_rsa_key(_RSA_PUBLIC_EXPONENT, key_size)

    private_pem = private.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    keyid = Signer._get_keyid(  # pylint: disable=protected-access
        _RSA_KEY_TYPE, scheme, {"public": public_pem}
    )

    return {
        "keytype": _RSA_KEY_TYPE,
        "scheme": scheme,
        "keyid": keyid,
        "keyval": {"public": public_pem, "private": private_pem},
    }


def generate_ecdsa_key():
    pass


def generate_ed25519_key():
    pass


class SSlibKey(Key):
    """Key implementation for RSA, Ed25519, ECDSA keys"""

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Internal helper, returns a classic securesystemslib keydict"""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "SSlibKey":
        """Constructor from classic securesystemslib keydict"""
        # ensure possible private keys are not included in keyval
        return SSlibKey(
            key_dict["keyid"],
            key_dict["keytype"],
            key_dict["scheme"],
            {"public": key_dict["keyval"]["public"]},
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "SSlibKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)

        if "public" not in keyval or not isinstance(keyval["public"], str):
            raise ValueError(f"public key string required for scheme {scheme}")

        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        return self._to_dict()

    def _from_pem(self) -> "PublicKeyTypes":
        """Helper to load public key instance from PEM-formatted keyval."""
        public_bytes = self.keyval["public"].encode("utf-8")
        return load_pem_public_key(public_bytes)

    @staticmethod
    def _hash_algo(name) -> Type["HashAlgorithm"]:
        """Helper to return hash algorithm class for name."""
        algos = {
            "sha224": SHA224,
            "sha256": SHA256,
            "sha384": SHA384,
            "sha512": SHA512,
        }
        return algos[name]

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            sig = bytes.fromhex(signature.signature)

            if CRYPTO_IMPORT_ERROR:
                if self.scheme == "ed25519":
                    # Verify using vendored ed25519 implementation
                    pub = bytes.fromhex(self.keyval["public"])
                    checkvalid(sig, data, pub)
                    return

                raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

            key: PublicKeyTypes
            if self.scheme in [
                "rsassa-pss-sha224",
                "rsassa-pss-sha256",
                "rsassa-pss-sha384",
                "rsassa-pss-sha512",
                "rsa-pkcs1v15-sha224",
                "rsa-pkcs1v15-sha256",
                "rsa-pkcs1v15-sha384",
                "rsa-pkcs1v15-sha512",
            ]:
                key = cast(RSAPublicKey, self._from_pem())
                padding_name, algo_name = self.scheme.split("-")[1:]
                algo = self._hash_algo(algo_name)()
                padding: AsymmetricPadding
                if padding_name == "pss":
                    padding = PSS(mgf=MGF1(algo), salt_length=PSS.AUTO)
                else:
                    padding = PKCS1v15()
                key.verify(sig, data, padding, algo)

            elif self.scheme in ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"]:
                key = cast(EllipticCurvePublicKey, self._from_pem())
                algo_name = f"sha{self.scheme[-3:]}"
                algo = self._hash_algo(algo_name)()
                key.verify(sig, data, ECDSA(algo))

            elif self.scheme in ["ed25519"]:
                public_bytes = bytes.fromhex(self.keyval["public"])
                key = Ed25519PublicKey.from_public_bytes(public_bytes)
                key.verify(sig, data)

            else:
                raise ValueError(f"unknown scheme '{self.scheme}'")

        # Workaround for 'except (SignatureMismatch, InvalidSignature)' to
        # conditionally evaluate the optional 'InvalidSignature':
        except Exception as e:
            if isinstance(e, SignatureMismatch) or (
                not CRYPTO_IMPORT_ERROR and isinstance(e, InvalidSignature)
            ):
                raise exceptions.UnverifiedSignatureError(
                    f"Failed to verify signature by {self.keyid}"
                ) from e

            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise exceptions.VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


class SSlibSigner(Signer):
    """A securesystemslib signer implementation.

    Provides a sign method to generate a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa key. See keys module
    for the supported types, schemes and hash algorithms.

    SSlibSigners should be instantiated with Signer.from_priv_key_uri().
    These private key URI schemes are supported:
    * "envvar:<VAR>":
        VAR is an environment variable with unencrypted private key content.
           envvar:MYPRIVKEY
    * "file:<PATH>?encrypted=[true|false]":
        PATH is a file path to a file with private key content. If
        encrypted=true, the file is expected to have been created with
        securesystemslib.keys.encrypt_key().
           file:path/to/file?encrypted=true
           file:/abs/path/to/file?encrypted=false

    Attributes:
        key_dict:
            A securesystemslib-style key dictionary. This is an implementation
            detail, not part of public API
    """

    ENVVAR_URI_SCHEME = "envvar"
    FILE_URI_SCHEME = "file"

    def __init__(self, key_dict: Dict):
        self.key_dict = key_dict

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "SSlibSigner":
        """Constructor for Signer to call

        Please refer to Signer.from_priv_key_uri() documentation.

        Additionally raises:
            OSError: Reading the file failed with "file:" URI
        """
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme == cls.ENVVAR_URI_SCHEME:
            # read private key from environment variable
            private = os.getenv(uri.path)
            if private is None:
                raise ValueError(f"Unset env var for {priv_key_uri}")

        elif uri.scheme == cls.FILE_URI_SCHEME:
            params = dict(parse.parse_qsl(uri.query))
            if "encrypted" not in params:
                raise ValueError(f"{uri.scheme} requires 'encrypted' parameter")

            # read private key (may be encrypted or not) from file
            with open(uri.path, "rb") as f:
                private = f.read().decode()

            if params["encrypted"] != "false":
                if not secrets_handler:
                    raise ValueError("encrypted key requires a secrets handler")

                secret = secrets_handler("passphrase")
                decrypted = sslib_keys.decrypt_key(private, secret)
                private = decrypted["keyval"]["private"]

        else:
            raise ValueError(f"SSlibSigner does not support {priv_key_uri}")

        keydict = public_key.to_securesystemslib_key()
        keydict["keyval"]["private"] = private
        return cls(keydict)

    def _from_pem(self) -> "PrivateKeyTypes":
        """Helper to load public key instance from PEM-formatted keyval."""
        private_bytes = self.key_dict["keyval"]["private"].encode("utf-8")
        return load_pem_private_key(private_bytes, password=None)

    @staticmethod
    def _hash_algo(name) -> Type["HashAlgorithm"]:
        """Helper to return hash algorithm class for name."""
        algos = {
            "sha224": SHA224,
            "sha256": SHA256,
            "sha384": SHA384,
            "sha512": SHA512,
        }
        return algos[name]

    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the SSlibSigner instance.

        Please see Signer.sign() documentation.

        Additionally raises:
            ValueError: scheme is unsupported
            TODO: list pyca/cryptography errors
        """
        if CRYPTO_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        scheme = self.key_dict["scheme"]
        key: PrivateKeyTypes
        if scheme in [
            "rsassa-pss-sha224",
            "rsassa-pss-sha256",
            "rsassa-pss-sha384",
            "rsassa-pss-sha512",
            "rsa-pkcs1v15-sha224",
            "rsa-pkcs1v15-sha256",
            "rsa-pkcs1v15-sha384",
            "rsa-pkcs1v15-sha512",
        ]:
            key = cast(RSAPrivateKey, self._from_pem())
            padding_name, algo_name = scheme.split("-")[1:]
            algo = self._hash_algo(algo_name)()
            padding: AsymmetricPadding
            if padding_name == "pss":
                padding = PSS(mgf=MGF1(algo), salt_length=PSS.DIGEST_LENGTH)
            else:
                padding = PKCS1v15()
            sig = key.sign(payload, padding, algo)

        elif scheme in ["ecdsa-sha2-nistp256"]:
            key = cast(EllipticCurvePrivateKey, self._from_pem())
            sig = key.sign(payload, ECDSA(SHA256()))

        elif scheme in ["ed25519"]:
            private_bytes = bytes.fromhex(self.key_dict["keyval"]["private"])
            key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            sig = key.sign(payload)
        else:
            raise ValueError(f"unknown scheme '{scheme}'")

        return Signature(self.key_dict["keyid"], sig.hex())
