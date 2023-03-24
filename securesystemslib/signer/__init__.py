"""
The Signer API

This module provides extensible interfaces for public keys and signers:
Some implementations are provided by default but more can be added by users.
"""
from securesystemslib.signer._gcp_signer import GCPSigner
from securesystemslib.signer._gpg_signer import GPGKey, GPGSigner
from securesystemslib.signer._hsm_signer import HSMSigner
from securesystemslib.signer._key import (
    KEY_FOR_TYPE_AND_SCHEME,
    Key,
    SSlibECDSAKey,
    SSlibEd25519Key,
    SSlibKey,
    SSlibRSAKey,
)
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    SecretsHandler,
    Signer,
    SSlibSigner,
)
from securesystemslib.signer._sigstore_signer import SigstoreKey, SigstoreSigner

# Register supported private key uri schemes and the Signers implementing them
SIGNER_FOR_URI_SCHEME.update(
    {
        SSlibSigner.ENVVAR_URI_SCHEME: SSlibSigner,
        SSlibSigner.FILE_URI_SCHEME: SSlibSigner,
        GCPSigner.SCHEME: GCPSigner,
        HSMSigner.SCHEME: HSMSigner,
        GPGSigner.SCHEME: GPGSigner,
    }
)

# Register supported key types and schemes, and the Keys implementing them
KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("ecdsa", "ecdsa-sha2-nistp256"): SSlibECDSAKey,
        ("ecdsa", "ecdsa-sha2-nistp384"): SSlibECDSAKey,
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"): SSlibECDSAKey,
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"): SSlibECDSAKey,
        ("ed25519", "ed25519"): SSlibEd25519Key,
        ("rsa", "rsassa-pss-sha224"): SSlibRSAKey,
        ("rsa", "rsassa-pss-sha256"): SSlibRSAKey,
        ("rsa", "rsassa-pss-sha384"): SSlibRSAKey,
        ("rsa", "rsassa-pss-sha512"): SSlibRSAKey,
        ("rsa", "rsa-pkcs1v15-sha224"): SSlibRSAKey,
        ("rsa", "rsa-pkcs1v15-sha256"): SSlibRSAKey,
        ("rsa", "rsa-pkcs1v15-sha384"): SSlibRSAKey,
        ("rsa", "rsa-pkcs1v15-sha512"): SSlibRSAKey,
        ("sphincs", "sphincs-shake-128s"): SSlibKey,
        ("rsa", "pgp+rsa-pkcsv1.5"): GPGKey,
        ("dsa", "pgp+dsa-fips-180-2"): GPGKey,
        ("eddsa", "pgp+eddsa-ed25519"): GPGKey,
    }
)
