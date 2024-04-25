"""Signer implementation for HashiCorp Vault (Transit secrets engine)"""

from typing import Tuple
from base64 import b64decode

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid


VAULT_IMPORT_ERROR = None
try:
    import hvac
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

except ImportError:
    VAULT_IMPORT_ERROR = "Signing with HashiCorp Vault requires hvac and cryptography."


class VaultSigner(Signer):
    """HashiCorp Vault Signer (Transit secrets engine) """
    SCHEME = "hv"

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

        # Extract "newest" key from response
        pub_b64 = sorted(resp["data"]["keys"].items())[-1][1]["public_key"]
        pub_raw = b64decode(pub_b64)
        pub_crypto = Ed25519PublicKey.from_public_bytes(pub_raw)

        pub = SSlibKey.from_crypto(pub_crypto)
        uri = f"{VaultSigner.SCHEME}:{hv_key_name}"

        return uri, pub

