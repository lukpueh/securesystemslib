#!/usr/bin/env python
"""
<Program Name>
  test_hsm.py

<Author>
  Tansihq Jasoria

<Purpose>
  Test cases for hsm.py module.

"""

import os
import six
import shutil
import unittest
import tempfile


# We neither have these dependencies nor run the tests (see skipIf) on PY2
if not six.PY2:
  import PyKCS11
  from asn1crypto.keys import ECDomainParameters, NamedCurve

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.keys
import securesystemslib.hash
import securesystemslib.hsm
from securesystemslib.hsm import (ECDSA_SHA2_NISTP256, ECDSA_SHA2_NISTP384)

# TODO: remove
os.environ["PYKCS11LIB"] = "/usr/local/lib/softhsm/libsofthsm2.so"

@unittest.skipIf(six.PY2, "HSM interface not supported on Python 2")
class SoftHSMTestCase(unittest.TestCase):
  """
  Class to load PKCS11 dynamic library, set up SoftHSM in a temporary
  directory and initialize security officer (so_pin) and user pin (user_pin).
  Subclasses may use the class variable 'hsm_info' to identify the HSM.

  IMPORTANT:
  Requires the environment variable 'PYKCS11LIB' to point to the SoftHSM
  shared library, e.g.:
      /usr/local/lib/softhsm/libsofthsm2.so

  See https://github.com/opendnssec/SoftHSMv2 or your favorite system package
  manager for installation details.

  """
  so_pin = "654321"
  user_pin = "123456"
  hsm_info = None


  @classmethod
  def setUpClass(cls):
    cls.original_cwd = os.getcwd()
    cls.test_dir = os.path.realpath(tempfile.mkdtemp())
    os.chdir(cls.test_dir)

    with open("softhsm2.conf", "w") as f:
      f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))

    os.environ["SOFTHSM2_CONF"] = os.path.join(cls.test_dir, "softhsm2.conf")

    # Initializing the HSM
    # make sure to set PYKCS11LIB!!
    securesystemslib.hsm.load_pkcs11_lib()
    available_hsm = securesystemslib.hsm.get_hsms().pop()
    securesystemslib.hsm.PKCS11.initToken(
        available_hsm["slot_id"], cls.so_pin, "Test HSM (SoftHSM) Label")

    # After initializing the SoftHSM, the slot number changes (get_hsms again)
    cls.hsm_info = securesystemslib.hsm.get_hsms().pop()
    session = securesystemslib.hsm._setup_session(
        cls.hsm_info, cls.so_pin, PyKCS11.CKU_SO)
    session.initPin(cls.user_pin)
    securesystemslib.hsm._teardown_session(session)


  @classmethod
  def tearDownClass(cls):
    os.chdir(cls.original_cwd)
    shutil.rmtree(cls.test_dir)
    del os.environ["SOFTHSM2_CONF"]



class TestECDSA(SoftHSMTestCase):
  """Generate EC key pairs on SoftHSM for to test ECDSA signing. """

  @classmethod
  def _generate_key_pair(cls, session, hsm_key_id, scheme):
    """Using the passed PKCS11 HSM 'session', generate an elliptic curve key
    pair under 'hsm_key_id' on the curve we use for the passed 'scheme'.

    """
    # Get curve name corresponding to the passed scheme and encode it as
    # "domain parameters".
    curve = securesystemslib.hsm.SIGNING_SCHEMES[scheme]["curve"].name
    params = ECDomainParameters(name="named", value=NamedCurve(curve)).dump()

    # Define PyKCS11 templates for elliptic curve public private key pairs ...
    ec_public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_EC_PARAMS, params),
        (PyKCS11.CKA_LABEL, curve),
        (PyKCS11.CKA_ID, hsm_key_id),
      ]
    ec_private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_LABEL, curve),
        (PyKCS11.CKA_ID, hsm_key_id),
      ]

    # ... and generate it on the virtual HSM (SoftHSM).
    public_key, private_key = session.generateKeyPair(
        ec_public_template, ec_private_template,
        mecha=PyKCS11.MechanismECGENERATEKEYPAIR)



  @classmethod
  def setUpClass(cls):
    super(TestECDSA, cls).setUpClass()

    # Define hsm_key_ids and schemes for the keys we want to test with
    cls.hsm_keyid_scheme_tuples = [
      ((0x00, ), ECDSA_SHA2_NISTP256),
      ((0x01, ), ECDSA_SHA2_NISTP384)
    ]
    # Define backup dict for schemes (see usage below)
    cls.original_mechanisms = {}

    # Setup session on the SoftHSM token (see parent class)
    session = securesystemslib.hsm._setup_session(cls.hsm_info, cls.user_pin)

    for hsm_key_id, scheme in cls.hsm_keyid_scheme_tuples:
      # Generate test key pairs
      cls._generate_key_pair(session, hsm_key_id, scheme)

      # Back up and monkey-patch signing mechanism for testing with SoftHSM
      # NOTE: SoftHSM only support the unhashed CKM_ECDSA mechanism, to still
      # be able to test 'securesystemslib.hsm' we monkey-patch its supported
      # mechanisms and pre-hash the data in the tests below.
      cls.original_mechanisms[scheme] = \
          securesystemslib.hsm.SIGNING_SCHEMES[scheme]["mechanism"]
      securesystemslib.hsm.SIGNING_SCHEMES[scheme]["mechanism"] = \
          PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)

    securesystemslib.hsm._teardown_session(session)



  @classmethod
  def tearDownClass(cls):
    super(TestECDSA, cls).tearDownClass()

    # Restore signing mechanisms that were monkey-patched in setUpClass
    for scheme, mechanism in cls.original_mechanisms.items():
      securesystemslib.hsm.SIGNING_SCHEMES[scheme]["mechanism"] = mechanism



  def test_keys(self):
    sslib_key_id = "123456"
    data = b"Hello world"

    for hsm_key_id, scheme in self.hsm_keyid_scheme_tuples:
      public_key = securesystemslib.hsm.export_pubkey(
          self.hsm_info, hsm_key_id, scheme, sslib_key_id)
      # Create a signature
      # We have to prehash the data for SoftHSM, which only supports CKM_ECDSA
      # mechanism
      hasher = securesystemslib.hash.digest(algorithm="sha256")
      hasher.update(data)
      pre_hashed_data = hasher.digest()

      signature = securesystemslib.hsm.create_signature(
          self.hsm_info, hsm_key_id, self.user_pin, pre_hashed_data, scheme, sslib_key_id)

      # Verify signature
      result = securesystemslib.keys.verify_signature(public_key, signature, data)
      self.assertTrue(result)



# TODO: Remove here, add as example usage in README.md
@unittest.skipUnless(os.environ.get("LUKPUEH_YUBI_PIN", None), "tmp local testing")
class TestECDSAOnLUKPUEHsYubiKey(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.user_pin = os.environ["LUKPUEH_YUBI_PIN"]

    securesystemslib.hsm.load_pkcs11_lib(
        "/usr/local/Cellar/yubico-piv-tool/2.0.0/lib/libykcs11.dylib")
    cls.hsm_info = securesystemslib.hsm.get_hsms().pop()
    cls.sslib_key_id = "123456"
    cls.data = b"Hello world"

  def test_key(self):
    scheme = ECDSA_SHA2_NISTP256
    hsm_key_id = (0x02, )

    public_key = securesystemslib.hsm.export_pubkey(
        self.hsm_info, hsm_key_id, scheme, self.sslib_key_id)

    signature = securesystemslib.hsm.create_signature(
        self.hsm_info, hsm_key_id, self.user_pin, self.data, scheme,
        self.sslib_key_id)

    result = securesystemslib.keys.verify_signature(
        public_key, signature, self.data)
    self.assertTrue(result)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()

