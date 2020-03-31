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
from asn1crypto.keys import ECDomainParameters, NamedCurve

if not six.PY2:
  import PyKCS11
  from securesystemslib import hsm

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


  @classmethod
  def setUpClass(cls):
    cls.original_cwd = os.getcwd()
    cls.test_dir = os.path.realpath(tempfile.mkdtemp())
    os.chdir(cls.test_dir)

    with open("softhsm2.conf", "w") as f:
      f.write("directories.tokendir = " + os.path.join(cls.test_dir, ""))

    os.environ["SOFTHSM2_CONF"] = os.path.join(cls.test_dir, "softhsm2.conf")


    # Initializing the HSM
    hsm.load_pkcs11_lib(PKCS11LIB)
    available_hsm = hsm.get_hsms().pop()
    hsm.PKCS11.initToken(available_hsm["slot_id"], cls.so_pin, cls.hsm_label)

    # After initializing the SoftHSM, the slot number changes (get_hsms again)
    available_hsm = hsm.get_hsms().pop()
    session = hsm._setup_session(available_hsm, cls.so_pin, PyKCS11.CKU_SO)
    session.initPin(cls.user_pin)
    hsm._teardown_session(session)



  @classmethod
  def tearDownClass(cls):
    os.chdir(cls.original_cwd)
    shutil.rmtree(cls.test_dir)
    del os.environ["SOFTHSM2_CONF"]




class TestECDSA(SoftHSMTestCase):
  @classmethod
  def setUpClass(cls):
    super(TestECDSA, cls).setUpClass()


    available_hsm = hsm.get_hsms().pop()
    session = hsm._setup_session(available_hsm, cls.user_pin)


   # TODO: get supported curves from hsm module
    # "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"
    # CKM_ECDSA_SHA256, CKM_ECDSA_SHA384
    curves = [
      "secp256r1",
      "secp384r1"
    ]

    cls.keys = {}
    for idx, curve in enumerate(curves):
      domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
      ec_params = domain_params.dump()

      key_id = (idx, )

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
          (PyKCS11.CKA_ID, key_id),
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
          (PyKCS11.CKA_ID, key_id),
      ]

      public_key, private_key = session.generateKeyPair(
          ec_public_template, ec_private_template,
          mecha=PyKCS11.MechanismECGENERATEKEYPAIR)

      cls.keys = {
        curve: {
          "hsm_keyid": key_id,
          "public": public_key,
          "private": private_key
        }
      }

    hsm._teardown_session(session)



  def test_foo(self):
    print("foo")





# @unittest.skipIf(six.PY2, "HSM functionality not supported on Python 2")
# class TestHSM(unittest.TestCase):
#   @classmethod
#   def setUpClass(cls):

    # To carry out the tests even when the hardware token is not connected,
    # we would be emulating the hardware token using softHSM 2.0.
    # To carry out all the tests, SoftHSM needs to be initialized and
    # RSD, ECDSA key pairs must be generated on the SoftHSM.

    # Since we are using the default path for the SoftHSM creation
    # and storage, there might be tokens present already which were
    # create by the user. So, before carrying out the test we must save all
    # the existing token to a new directory

    # tokens_list = os.listdir(TOKENS_PATH)

    # # Make a new directory to store the already existing tokens
    # tokens_save_dir = os.path.join(TOKENS_PATH, 'tokens.save')

    # # If the directory already exists, do nothing and use the
    # # pre-existing directory to save the tokens
    # try:
    #   os.mkdir(tokens_save_dir)
    # except:
    #   logger.info("Directory 'tokens.save' already exists!")

    # # Move the tokens to the new directory
    # for token in tokens_list:
    #   token_dir = os.path.join(TOKENS_PATH,token)
    #   shutil.move(token_dir, tokens_save_dir)

    # Initializing the HSM
    # soft_pkcs11 = PyKCS11.PyKCS11Lib()
    # soft_pkcs11.load(PKCS11LIB)
    # available_hsm = soft_pkcs11.getSlotList()
    # soft_pkcs11.initToken(available_hsm.pop(), _SO_PIN, _HSM_LABEL)

    # # After initializing the SoftHSM, the slot number changes.
    # soft_pkcs11.load(PKCS11LIB)
    # available_hsm = soft_pkcs11.getSlotList()
    # session = soft_pkcs11.openSession(available_hsm[0],
    #     PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    # # Login as a SO User to initialize the pin.
    # session.login(_SO_PIN, PyKCS11.CKU_SO)
    # session.initPin(_USER_PIN)
    # session.logout()
    # # Login as admin to generate key pairs.
    # session.login(_USER_PIN)

    # Generate RSA Key Pair on the HSM
#     RSA_public_template = [
#         (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
#         (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
#         (PyKCS11.CKA_MODULUS_BITS, RSA_BITS),
#         (PyKCS11.CKA_PUBLIC_EXPONENT, RSA_EXPONENTS),
#         (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_LABEL, KEY_LABEL),
#         (PyKCS11.CKA_ID, RSA_KEY_ID),]
#     RSA_private_template = [
#         (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
#         (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_LABEL, KEY_LABEL),
#         (PyKCS11.CKA_ID, RSA_KEY_ID),]
#     (cls.RSA_public_key, cls.RSA_private_key) = session.generateKeyPair(
#       RSA_public_template, RSA_private_template, PyKCS11.MechanismRSAGENERATEKEYPAIR)

#     # Generate ECDSA key pair on the HSM
#     EC_public_template = [
#         (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
#         (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
#         (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
#         (PyKCS11.CKA_EC_PARAMS, EC_PARAMS),
#         (PyKCS11.CKA_LABEL, KEY_LABEL),
#         (PyKCS11.CKA_ID, EC_KEY_ID),]
#     EC_private_template = [
#         (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
#         (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
#         (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
#         (PyKCS11.CKA_LABEL, KEY_LABEL),
#         (PyKCS11.CKA_ID, EC_KEY_ID),]
#     (cls.EC_public_key, cls.EC_private_key) = session.generateKeyPair(
#       EC_public_template, EC_private_template, PyKCS11.MechanismECGENERATEKEYPAIR)

#     # Logout and close all sessions
#     session.logout()
#     session.closeSession()



#   @classmethod
#   def tearDownClass(cls):

#     # Remove any new tokens which were initialized to perform tests
#     tokens_list = os.listdir(TOKENS_PATH)
#     tokens_list.remove('tokens.save')
#     for token in tokens_list:
#       token_dir = os.path.join(TOKENS_PATH, token)
#       shutil.rmtree(token_dir)

#     # Move the saved tokens to their original directory
#     tokens_save_dir = os.path.join(TOKENS_PATH, 'tokens.save')
#     tokens_save_list = os.listdir(tokens_save_dir)
#     for token in tokens_save_list:
#       token_dir = os.path.join(tokens_save_dir, token)
#       shutil.move(token_dir, TOKENS_PATH)

#     # Delete the new directory, used to store existing tokens
#     shutil.rmtree(tokens_save_dir)



#   @classmethod
#   def setUp(self):

#     HSM.load_pkcs11_library(PKCS11LIB)


#   @classmethod
#   def tearDown(self):
#     pass






  # def test_load_pkcs11_library(self):

  #   PKCS11LIB_ERR = '/NO/LIBRARY/HERE'

  #   self.assertRaises(securesystemslib.exceptions.NotFoundError,
  #       HSM.load_pkcs11_library, PKCS11LIB_ERR)

  #   # Initialize with a correct library
  #   HSM.load_pkcs11_library(PKCS11LIB)



  # def test_get_available_HSMs(self):

  #   slot_list = HSM.get_available_HSMs()
  #   self.assertIsInstance(slot_list, list)

  #   slot_info = slot_list[0]
  #   self.assertIsInstance(slot_info, dict)

  #   slot_id = slot_info['slot_id']
  #   self.assertIsInstance(slot_id, int)



  # def test_get_private_key_objects(self):

  #   # Use the HSM on the first slot to retrieve private key objects
  #   hsm_info = HSM.get_available_HSMs()[0]


  #   private_key_info = HSM.get_private_key_objects(hsm_info, _USER_PIN)
  #   self.assertIsInstance(private_key_info, list)



  # def test_get_public_key_objects(self):

  #   # Use the HSM on the first slot to retrieve private key objects
  #   hsm_info = HSM.get_available_HSMs()[0]

  #   public_key_info = HSM.get_public_key_objects(hsm_info)
  #   self.assertIsInstance(public_key_info, list)



  # def test_export_pubkey(self):

  #   hsm_info = HSM.get_available_HSMs()[0]

  #   public_keys = HSM.get_public_key_objects(hsm_info)

  #   # Export public key value for all the keys present in the HSM
  #   for key_info in public_keys:
  #     # Exporting ECC public keys results into an exception if CKA_VALUE is None
  #     try:
  #       key_dict = HSM.export_pubkey(hsm_info, key_info)
  #       self.assertIsNone(
  #           securesystemslib.formats.PUBLIC_KEY_SCHEMA.check_match(key_dict))
  #     except securesystemslib.exceptions.UnsupportedAlgorithmError as e:
  #       logger.warning(e)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()

