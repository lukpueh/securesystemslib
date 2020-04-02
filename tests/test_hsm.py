#!/usr/bin/env python
"""
<Program Name>
  test_hsm.py

<Author>
  Tansihq Jasoria

<Purpose>
  Test cases for hsm.py module


  Requires PKCS11LIB envvar "/usr/local/lib/softhsm/libsofthsm2.so"

"""
import unittest
import logging

import os
import shutil
import tempfile
import six

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.keys
import securesystemslib.hash
from asn1crypto.keys import ECDomainParameters, NamedCurve

import PyKCS11
import securesystemslib.hsm

logger = logging.getLogger(__name__)



#  TODO: switch to envvar?
PKCS11LIB = "/usr/local/lib/softhsm/libsofthsm2.so"


class SoftHSMTestCase(unittest.TestCase):
  """
  I prefer an approach that uses a temporary directory, something like:
  in setupClass

  backup original cwd
  create and change into temporary directory
  create a tokens directory
  create a softhsm2.conf file with a line directories.tokendir = /path/to/tmpdir/tokens/
  init softhsm
  in tearDownClass

  deinit softhsm
  change back to original cwd
  remove temporary directory

  """
  user_pin = "123456"
  so_pin = "654321"
  hsm_label = "Virtual Test HSM"
  test_hsm = None


  @classmethod
  def setUpClass(cls):
    cls.original_cwd = os.getcwd()
    cls.test_dir = os.path.realpath(tempfile.mkdtemp())
    os.chdir(cls.test_dir)

    with open("softhsm2.conf", "w") as f:
      f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))

    os.environ["SOFTHSM2_CONF"] = os.path.join(cls.test_dir, "softhsm2.conf")


    # Initializing the HSM
    securesystemslib.hsm.load_pkcs11_lib(PKCS11LIB)
    available_hsm = securesystemslib.hsm.get_hsms().pop()
    securesystemslib.hsm.PKCS11.initToken(
        available_hsm["slot_id"], cls.so_pin, cls.hsm_label)

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
  @classmethod
  def setUpClass(cls):
    super(TestECDSA, cls).setUpClass()

    session = securesystemslib.hsm._setup_session(cls.hsm_info, cls.user_pin)

    # Patch mechanism securesystemslib signing schemes
    securesystemslib.hsm.SIGNING_SCHEMES[securesystemslib.hsm.ECDSA_SHA2_NISTP256]["mechanism"] = \
        PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)


    curves = [
      ((0x00, ), "secp256r1"),
      # ((0x01, ), "secp384r1")
    ]

    cls.keys = {}
    for hsm_key_id, curve in curves:
      domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
      ec_params = domain_params.dump()

      ec_public_template = [
          (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
          (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
          (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
          (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
          (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
          (PyKCS11.CKA_WRAP, PyKCS11.CK_FALSE),
          (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
          (PyKCS11.CKA_EC_PARAMS, ec_params),
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

      public_key, private_key = session.generateKeyPair(
          ec_public_template, ec_private_template,
          mecha=PyKCS11.MechanismECGENERATEKEYPAIR)

      cls.keys = {
        curve: {
          "hsm_key_id": hsm_key_id,
          "public": public_key,
          "private": private_key
        }
      }

    securesystemslib.hsm._teardown_session(session)

  @classmethod
  def tearDownClass(cls):
    super(TestECDSA, cls).tearDownClass()

    # Restore mechanism for TestECDSAOnYubiKey to work
    securesystemslib.hsm.SIGNING_SCHEMES[securesystemslib.hsm.ECDSA_SHA2_NISTP256]["mechanism"] = \
        PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256)

  def test_keys(self):
    scheme = "ecdsa-sha2-nistp256"
    hsm_key_id = (0x00, )
    sslib_key_id = "123456"
    data = b"Hello world"

    public_key = securesystemslib.hsm.export_pubkey(
        self.hsm_info, hsm_key_id, scheme, sslib_key_id)
    print(public_key)


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



class TestECDSAOnYubiKey(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.user_pin = os.environ["YUBI_PIN"]

    securesystemslib.hsm.load_pkcs11_lib(
        "/usr/local/Cellar/yubico-piv-tool/2.0.0/lib/libykcs11.dylib")
    cls.hsm_info = securesystemslib.hsm.get_hsms().pop()
    cls.sslib_key_id = "123456"
    cls.data = b"Hello world"

  def test_keys(self):
    scheme = "ecdsa-sha2-nistp256"
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

