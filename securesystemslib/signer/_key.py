"""Key interface and the default implementations"""
import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, Optional, Tuple, Type, Union

from securesystemslib import exceptions
from securesystemslib._vendor.ed25519.ed25519 import (
    SignatureMismatch,
    checkvalid,
)
from securesystemslib.signer._signature import Signature

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.hashes import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    )
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"


logger = logging.getLogger(__name__)

# NOTE Key dispatch table is defined here so it's usable by Key,
# but is populated in __init__.py (and can be appended by users).
KEY_FOR_TYPE_AND_SCHEME: Dict[Tuple[str, str], Type] = {}


class Key(metaclass=ABCMeta):
    """Abstract class representing the public portion of a key.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        keytype: Key type, e.g. "rsa", "ed25519" or "ecdsa-sha2-nistp256".
        scheme: Signature scheme. For example:
            "rsassa-pss-sha256", "ed25519", and "ecdsa-sha2-nistp256".
        keyval: Opaque key content
        unrecognized_fields: Dictionary of all attributes that are not managed
            by Securesystemslib

    Raises:
        TypeError: Invalid type for an argument.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: Dict[str, Any],
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        if not all(
            isinstance(at, str) for at in [keyid, keytype, scheme]
        ) or not isinstance(keyval, dict):
            raise TypeError("Unexpected Key attributes types!")
        self.keyid = keyid
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval

        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Key):
            return False

        return (
            self.keyid == other.keyid
            and self.keytype == other.keytype
            and self.scheme == other.scheme
            and self.keyval == other.keyval
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    @abstractmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "Key":
        """Creates ``Key`` object from a serialization dict

        Key implementations must override this factory constructor that is used
        as a deserialization helper.

        Users should call Key.from_dict(): it dispatches to the actual subclass
        implementation based on supported keys in KEY_FOR_TYPE_AND_SCHEME.

        Raises:
            KeyError, TypeError: Invalid arguments.
        """
        keytype = key_dict.get("keytype")
        scheme = key_dict.get("scheme")
        if (keytype, scheme) not in KEY_FOR_TYPE_AND_SCHEME:
            raise ValueError(f"Unsupported public key {keytype}/{scheme}")

        # NOTE: Explicitly not checking the keytype and scheme types to allow
        # intoto to use (None,None) to lookup GPGKey, see issue #450
        key_impl = KEY_FOR_TYPE_AND_SCHEME[(keytype, scheme)]  # type: ignore
        return key_impl.from_dict(keyid, key_dict)

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Returns a serialization dict.

        Key implementations must override this serialization helper.
        """
        raise NotImplementedError

    @abstractmethod
    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Raises if verification of signature over data fails.

        Args:
            signature: Signature object.
            data: Payload bytes.

        Raises:
            UnverifiedSignatureError: Failed to verify signature.
            VerificationError: Signature verification process error. If you
                are only interested in the verify result, just handle
                UnverifiedSignatureError: it contains VerificationError as well
        """
        raise NotImplementedError


class SSlibKey(Key):
    """Key implementation for RSA, Ed25519, ECDSA and Sphincs keys"""

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
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        if "public" not in keyval or not isinstance(keyval["public"], str):
            raise ValueError(f"public key string required for scheme {scheme}")

        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    def _load_key(
        self,
    ) -> Union["RSAPublicKey", "Ed25519PublicKey", "EllipticCurvePublicKey"]:
        """Helper to load public key instance based on keytype.

        NOTE: raises ValueError, if self.keytype is not recognized.
        """
        if self.keytype in [
            "rsa",
            "ecdsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
        ]:
            public_bytes = self.keyval["public"].encode("utf-8")
            return load_pem_public_key(public_bytes)

        elif self.keytype == "ed25519":
            public_bytes = bytes.fromhex(self.keyval["public"])
            return Ed25519PublicKey.from_public_bytes(public_bytes)

        else:
            raise ValueError(f"unknown keytype '{self.keytype}'")

    def _load_args(self) -> Tuple[Any]:
        """Helper to get additional verification arguments based on scheme.

        NOTE: returns empty tuple, if scheme is not recognized.
        """
        verify_args = {
            "rsassa-pss-sha224": (
                PSS(mgf=MGF1(SHA224()), salt_length=PSS.AUTO),
                SHA224(),
            ),
            "rsassa-pss-sha256": (
                PSS(mgf=MGF1(SHA256()), salt_length=PSS.AUTO),
                SHA256(),
            ),
            "rsassa-pss-sha384": (
                PSS(mgf=MGF1(SHA384()), salt_length=PSS.AUTO),
                SHA384(),
            ),
            "rsassa-pss-sha512": (
                PSS(mgf=MGF1(SHA512()), salt_length=PSS.AUTO),
                SHA512(),
            ),
            "rsa-pkcs1v15-sha224": (PKCS1v15(), SHA224()),
            "rsa-pkcs1v15-sha256": (PKCS1v15(), SHA256()),
            "rsa-pkcs1v15-sha384": (PKCS1v15(), SHA384()),
            "rsa-pkcs1v15-sha512": (PKCS1v15(), SHA512()),
            "ecdsa-sha2-nistp256": (ECDSA(SHA256()),),
            "ecdsa-sha2-nistp384": (ECDSA(SHA384()),),
        }
        return verify_args.get(self.scheme, ())

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            sig = bytes.fromhex(signature.signature)

            if CRYPTO_IMPORT_ERROR:
                if self.keytype == "ed25519":
                    # Verify using vendored ed25519 implementation
                    pub = bytes.fromhex(self.keyval["public"])
                    return checkvalid(sig, data, pub)

                raise exceptions.UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

            # Verify using pyca/cryptography
            key = self._load_key()
            args = self._load_args()
            key.verify(sig, data, *args)

        except Exception as e:
            # Workaround to support optional import of InvalidSignature
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
