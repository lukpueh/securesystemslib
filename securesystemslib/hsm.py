#!/usr/bin/env python
"""
<Program Name>
  hsm.py

<Started>
  June 19, 2019.

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Purpose>
  The goal of this module is to support hardware security modules through
  the PKCS#11 standard.

  This module uses PyKCS11, a python wrapper (SWIG) for PKCS#11 modules
  to communicate with the cryptographic tokens

TODO: Docstrings
TODO: Error handling
  - PyKCS11 openSession on a slot  requires prior call to get slots
    (can't just pass integer id)
  - handle hsm return invalid/incomplete data (e.g. getAttributeValue)

TODO: Exception taxonomy

TODO: Note about DRY with securesystemslib.keys and securesystemslib.gpg.{rsa,dsa,eddsa}

TODO: keyid and mechanisms: just pass to export_pubkey and create_signature? :)

"""

import logging
import binascii
import asn1crypto

import securesystemslib.formats
import securesystemslib.hash
from securesystemslib.exceptions import (
    UnsupportedLibraryError, PKCS11DynamicLibraryLoadingError)

logger = logging.getLogger(__name__)

CRYPTO = True
# TODO: Fix error message
NO_CRYPTO_MSG = "This operations requires cryptography."
try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives.asymmetric import padding
  from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
  from cryptography.hazmat.primitives.asymmetric.ec import (
      EllipticCurvePublicNumbers)

  from cryptography import x509

except ImportError:
  CRYPTO = False

# Default salt size in bytes
_SALT_SIZE = 16

# Key types
KEY_TYPE_RSA = "rsa"
KEY_TYPE_DSA = "dsa"
KEY_TYPE_ECC = "ecc"

# Signing schemes
RSASSA_PSS_SHA256 = "rsassa-pss-sha256"
# RSASSA_PKCS15_SHA256 = "rsa-pkcs1v15-sha256"
ECDSA_SIGN = "ecdsa-sign"

# Module global to hold an instance of PyKCS11.PyKCS11Lib. If it remains 'None'
# it means that the PyKCS11 library is not available.
PKCS11 = None

# Boolean to indicate if we have loaded the required dynamic library on the
# 'PKCS11' instance. (Note: It would would nicer to get this information from
# the object, but there doesn't seem to be a straight-forward way to to this.)
PKCS11_DYN_LIB = False

# TODO: write proper message / usage instructions for load
NO_PKCS11_PY_LIB_MSG = "HSM support requires PyKCS11 library"
NO_PKCS11_DYN_LIB_MSG = "HSM support requires PKCS11 shared object"

# Import python wrapper for PKCS#11 to communicate with the tokens
try:
  import PyKCS11
  PKCS11 = PyKCS11.PyKCS11Lib()

  # Create mechanisms constants
  # TODO: Check mechanism names / what are mechanisms again?
  # TODO: Check mechanism flexibility
  MECHANISMS = {
      RSASSA_PSS_SHA256: PyKCS11.RSA_PSS_Mechanism(
          PyKCS11.CKM_SHA256_RSA_PKCS_PSS,
          PyKCS11.CKM_SHA256,
          PyKCS11.CKG_MGF1_SHA256,
          _SALT_SIZE
        ),
      # RSASSA_PKCS15_SHA256: PyKCS11.Mechanism(
      #     PyKCS11.CKM_SHA256_RSA_PKCS,
      #     PyKCS11.CKM_SHA256,
      #     PyKCS11.CKG_MGF1_SHA256,
      #     _SALT_SIZE
      #   ),
      ECDSA_SIGN: PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
    }


  def _load_pkcs11_lib(path=None):
    """TODO  """
    global PKCS11_DYN_LIB
    try:
      # If path is not passed PyKCS11 consults the PYKCS11LIB env var
      PKCS11.load(path)
      PKCS11_DYN_LIB = True

    # TODO: Should we catch any exception
    except PyKCS11.PyKCS11Error as e:
      PKCS11_DYN_LIB = False
      # TODO: Add message "Could not load + e + NO_PKCS11_DYN_LIB_MSG
      raise PKCS11DynamicLibraryLoadingError(e)

  # Try loading PKCS#11 dynamic library from the path at PYKCS11LIB envvar
  # TODO: We do this to spare the user, who has PYKCS11LIB set, some state
  # handling. Is this too much magic? Should we require an explicit call?
  # _load_pkcs11_lib()

except ImportError as e:
  # Missing PyKCS11 python library. PKCS11 must remain 'None'.
  logger.debug(e)

except PKCS11DynamicLibraryLoadingError as e:
  # Missing PKCS#11 dynamic library. PKCS11_DYN_LIB must remain 'False'.
  logger.debug(e)



def load_pkcs11_lib(path=None):
  """
  <Purpose>
    Load PKCS#11 dynamic library on 'PKCS11' instance (module global).

    NOTE: Wraps _load_pkcs11_lib, which needs to be defined above in the import
    block because we also use there.

  <Arguments>
    path: (optional)
            Path to the PKCS#11 dynamic library shared object. If not passed
            the PyKCS11 will read the 'PYKCS11LIB' environment variable.

  <Exceptions>
    UnsupportedLibraryError
            I PyKCS11 is not available
    PKCS11DynamicLibraryLoadingError
            If the PKCS#11 dynamic library can not be loaded.

  <Side Effects>
    Loads the PKCS#11 shared object on the PKCS11 module global.
    Set module global PKCS11_DYN_LIB to True if loading was successful and to
    False if it failed.

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if path is not None:
    securesystemslib.formats.PATH_SCHEMA.check_match(path)

  _load_pkcs11_lib(path)


def get_hsms():
  """
  <Purpose>
    Iterate over hsm slots and return list with info for each HSM.

  <Return>
    List of dictionaries conforming to HSM_INFO_SCHEMA.
    TODO: SCHEMA

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  hsm_info_list = []
  for slot in PKCS11.getSlotList():
    slot_info = PKCS11.getSlotInfo(slot)
    hsm_info_list.append({
        "slot_id": slot,
        "slot_description": slot_info.slotDescription.strip(),
        "manufacturer_id": slot_info.manufacturerID.strip(),
        "hardware_version": slot_info.hardwareVersion,
        "firmware_version": slot_info.firmwareVersion,
        "flags": slot_info.flags2text(),
      })

  return hsm_info_list



def get_keys_on_hsm(hsm_info, user_pin=None):
  """
  <Purpose>
    Get handles of public and private keys stored on the HSM.
    To get private key handles login required before using this method.

  <Argument>
    hsm_info:
            A dictionary conforming to HSM_INFO_SCHEMA;

    user_pin:
            A string to log into the HSM. Required to get private keys.

  <Exceptions>
    TODO

  <Returns>
    List of dictionaries conforming to HSM_KEY_INFO_SCHEMA.

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO: HSM_INFO_SCHEMA.check_match(hsm_info)

  if user_pin:
    securesystemslib.formats.PASSWORD_SCHEMA.check_match(user_pin)

  # Create HSM session and, if pin is passed, login to access private objects
  session = _setup_session(hsm_info, user_pin)

  hsm_key_info_list = []
  # Iterate over public and private (if logged in) keys and construct key info
  for obj in session.findObjects(
      [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]) + session.findObjects(
      [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)]):

    # TODO: Assert len(return val of getAttributeValue) == 1 of ?
    # TODO: Add more human readable info? key type (CKA_KEY_TYPE),
    # only show one per id (public and private)?
    hsm_key_info_list.append({
      "key_id": session.getAttributeValue(obj, [PyKCS11.CKA_ID])[0],
      "label": session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])[0]
      })

  # Logout, if logged in, and close session
  _teardown_session(session)

  return hsm_key_info_list



def export_pubkey(hsm_info, hsm_key_id, mechanism, sslib_key_id):
  """
  <Purpose>
    Export a public key identified by the passed hsm_info and key_info
    into asecuresystemslib-like format.



    Cryptoki data types

    http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
    https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html

    Big integer
      a string of CK_BYTE (unsigned chas) representing an unsigned
      integer of arbitrary size, most-significant byte first (e.g., the integer
      32768 is represented as the 2-byte string 0x80 0x00)


  <Arguments>

  <Exceptions>
    TODO

  <Returns>
    A public key dictionary that conforms to 'PUBLIC_KEY_SCHEMA'.

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO: HSM_INFO_SCHEMA.check_match(hsm_info)
  # TODO: HSM_KEY_INFO_SCHEMA.check_match(key_info)
  # TODO: keyid check
  # mechanism check

  # Create HSM session, without logging in, which is not required for pubkeys
  session = _setup_session(hsm_info)

  # TODO: KeyError check
  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
      (PyKCS11.CKA_ID, hsm_key_id)])

  # TODO: is ValueError the right exception here?
  if len(key_objects) < 1:
    raise ValueError("cannot find key with keyid '{}' on hsm '{}'".format(
        hsm_key_id, hsm_info["slot_id"]))

  if len(key_objects) > 1:
    raise ValueError("found multiple keys with keyid '{}' on hsm '{}'".format(
        hsm_key_id, hsm_info["slot_id"]))

  key_object = key_objects.pop()

  key_type = session.getAttributeValue(key_object, [PyKCS11.CKA_KEY_TYPE])[0] # TODO: err

  if key_type == PyKCS11.CKK_RSA:
    modulus, exponent  = session.getAttributeValue(key_object, [
        PyKCS11.CKA_MODULUS,
        PyKCS11.CKA_PUBLIC_EXPONENT
      ]) # TODO: err

    # TODO: Use right scheme and create constants
    key_type = KEY_TYPE_RSA

    # TODO: convert public numbers ?
    public_key_value = {
        "e": binascii.hexlify(bytes(exponent)).decode("ascii"),
        "n": binascii.hexlify(bytes(modulus)).decode("ascii")
      }

  # elif key_type == PyKCS11.CKK_EC:
    # params, point  = session.getAttributeValue(key_object, [
    #     PyKCS11.CKA_EC_PARAMS,
    #     PyKCS11.CKA_EC_POINT
    #   ]) # TODO: err
    # CKA_EC_PARAMS (key type)
    # CKA_EC_POINT (value Q)

    # use asn1crypto

  # elif key_type == PyKCS11.CKK_DSA:
    # prime, subprime, base, value, = session.getAttributeValue(key_object, [
    #     PyKCS11.CKA_PRIME,
    #     PyKCS11.CKA_SUBPRIME,
    #     PyKCS11.CKA_BASE,
    #     PyKCS11.CKA_VALUE
    #   ]) # TODO: err
    # key_type = "dsa"
    # public_key_value = {
    #   "p": prime,
    #   "q": subprime,
    #   "g": base,
    #   "y": val
    # }
    # serialization.load_der_public_key?? (glaub ich ehe rnicht)

  else:
    raise ValueError("key type '{}' not supported".format(key_type))

  #TODO: method?
  return {
      "keyid": sslib_key_id,
      "keytype": key_type,
      "mechanism": mechanism,
      "keyval": {
        "public": public_key_value
      }
    }



def create_signature(hsm_info, hsm_key_id, user_pin, data, mechanism, sslib_key_id):
  """
  TODO

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO:  HSM_INFO.check_match(private_key_info)
  # TODO:  PRIVATE_KEY_INFO.check_match(private_key_info)
  # TODO:  Check supported mechanism
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(user_pin)

  # Create a session and login to generate signature using keys stored in hsm
  session = _setup_session(hsm_info, user_pin)


  #### DRY with export pubkey
  # TODO: KeyError check
  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
      (PyKCS11.CKA_ID,  hsm_key_id)])


  # TODO: is ValueError the right exception here?
  if len(key_objects) < 1:
    raise ValueError("cannot find key with CKA_ID '{}' on hsm '{}'".format(
        hsm_key_id, hsm_info["slot_id"]))

  if len(key_objects) > 1:
    raise ValueError("found multiple keys with CKA_ID '{}' on hsm '{}'".format(
        hsm_key_id, hsm_info["slot_id"]))

  key_object = key_objects.pop()
  key_type = session.getAttributeValue(key_object, [PyKCS11.CKA_KEY_TYPE])[0]
  #### DRY END

  signature = session.sign(key_object, data, MECHANISMS[mechanism]) # TODO err

  _teardown_session(session)

  return {
      "keyid": sslib_key_id,
      "sig": binascii.hexlify(bytes(signature)).decode("ascii")
    }
  # mechanism = None
  # private_key_object = session.findObjects([(PyKCS11.CKA_CLASS,
  #     PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, private_key_info[0])])[0]
  # key_type = session.getAttributeValue(private_key_object,
  #     [PyKCS11.CKA_KEY_TYPE])[0]

  # if PyKCS11.CKK[key_type] == 'CKK_RSA':
  #   mechanism = MECHANISMS["rsa-pkcs1v15-sha256"]

  # elif PyKCS11.CKK[key_type] == 'CKK_EC' or PyKCS11.CKK[key_type] == 'CKK_ECDSA':
  #   mechanism = MECHANISMS["ecdsa-sign"]

  # if mechanism is None:
  #   raise securesystemslib.exceptions.UnsupportedAlgorithmError(
  #     "The Key type " + repr(key_type) + " is currently not supported!")


  # signature = session.sign(private_key_object, data, mechanism)

  # signature_dict = {}
  # # TODO: This is not a key id, change this.
  # keyid = _to_hex(private_key_info[0])
  # sig = _to_hex(signature)

  # signature_dict['keyid'] = keyid
  # signature_dict['sig'] = sig

  # return signature_dict



def verify_signature(public_key, signature, data):
  """
  TODO

  """
  if not CRYPTO:
    raise UnsupportedLibraryError(NO_CRYPTO_MSG)

  # securesystemslib.formats.PUBLIC_KEY_SCHEMA.check_match(public_key)
  # securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)

  if public_key["keytype"] == KEY_TYPE_RSA:
    crytpo_public_key = RSAPublicNumbers(
        int(public_key["keyval"]["public"]["e"], 16), int(public_key["keyval"]["public"]["n"], 16)).public_key(
        default_backend())

    digest_obj = securesystemslib.hash.digest_from_rsa_scheme(
      public_key["mechanism"],  "pyca_crypto")

    crytpo_public_key.verify(
        binascii.unhexlify(signature["sig"]), data,
            padding.PSS(
                mgf=padding.MGF1(digest_obj.algorithm),
                salt_length=_SALT_SIZE),
                digest_obj.algorithm)

    

  # elif key_type == KEY_TYPE_DSA:
  # elif key_type == KEY_TYPE_ECC:



  else:
    raise ValueError("key type '{}' not supported".format(
        public_key["key_type"]))


  return public_key



def _setup_session(hsm_info, user_pin=None, user_type=PyKCS11.CKU_USER):
  """Create new hsm session, login if pin is passed and return session object.
  """
  try:
    session = PKCS11.openSession(
        hsm_info["slot_id"],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION) # TODO: parametrize RW (only needed for tests)

    if user_pin is not None:
      session.login(user_pin, user_type)

  except PyKCS11.PyKCS11Error as e:
    if PyKCS11.CKR[e.value] == "CKR_USER_ALREADY_LOGGED_IN":
      logger.debug(
          "CKU_USER already logged into HSM '{}'".format(hsm_info["slot_id"]))
    # TODO: elif?

    else:
      raise

  return session


def _teardown_session(session):
  """Close logout and close session no matter what. """
  for _teardown_func in [session.logout, session.closeSession]:
    try:
      _teardown_func()

    except Exception as e:
      logger.debug(e)


if __name__ == "__main__":
  main()