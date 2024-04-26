"""Signer implementation for HashiCorp Vault (Transit secrets engine)"""

from base64 import b64decode, b64encode
from typing import Optional, Tuple
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer

VAULT_IMPORT_ERROR = None
try:
    import hvac
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

except ImportError:
    VAULT_IMPORT_ERROR = (
        "Signing with HashiCorp Vault requires hvac and cryptography."
    )


class VaultSigner(Signer):
    """HashiCorp Vault Signer (Transit secrets engine)"""

    SCHEME = "hv"

    def __init__(self, hv_key_name: str, hv_key_version: int, public_key: Key):
        if VAULT_IMPORT_ERROR:
            raise UnsupportedLibraryError(VAULT_IMPORT_ERROR)

        self.hv_key_name = hv_key_name
        self.hv_key_version = hv_key_version
        self._public_key = public_key
        self._client = hvac.Client()

    def sign(self, payload: bytes) -> Signature:
        resp = self._client.secrets.transit.sign_data(
            self.hv_key_name,
            hash_input=b64encode(payload).decode(),
            key_version=self.hv_key_version,
        )
        sig_b64 = resp["data"]["signature"].split(":")[2]
        sig = b64decode(sig_b64).hex()

        return Signature(self.public_key.keyid, sig)

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "VaultSigner":
        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"VaultSigner does not support {priv_key_uri}")

        name, version = uri.path.split("/")

        return cls(name, int(version), public_key)

    @classmethod
    def import_(cls, hv_key_name: str) -> Tuple[str, Key]:
        """Load key and signer details from vault.

        Supported keytypes:
        * ed25519

        """
        if VAULT_IMPORT_ERROR:
            raise UnsupportedLibraryError(VAULT_IMPORT_ERROR)

        client = hvac.Client()
        resp = client.secrets.transit.read_key(hv_key_name)

        # Assume we want the newest key for the passed name
        version, key_info = sorted(resp["data"]["keys"].items())[-1]
        crypto_key = Ed25519PublicKey.from_public_bytes(
            b64decode(key_info["public_key"])
        )

        key = SSlibKey.from_crypto(crypto_key)
        uri = f"{VaultSigner.SCHEME}:{hv_key_name}/{version}"

        return uri, key
