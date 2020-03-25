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

"""

import logging
import binascii
import asn1crypto

from securesystemslib.exceptions import (
    UnsupportedLibraryError, PKCS11DynamicLibraryLoadingError)

logger = logging.getLogger(__name__)

CRYPTO = True
# TODO: Fix error message
NO_CRYPTO_MSG = "This operations requires cryptography."
try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
  from cryptography.hazmat.primitives.asymmetric.ec import (
      EllipticCurvePublicNumbers)
  from cryptography import x509

except ImportError:
  CRYPTO = False

# Default salt size in bytes
_SALT_SIZE = 16

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
  RSA_PKCS1V15_SHA256 = PyKCS11.RSA_PSS_Mechanism(
      PyKCS11.CKM_SHA256_RSA_PKCS,
      PyKCS11.CKM_SHA256,
      PyKCS11.CKG_MGF1_SHA256,
      _SALT_SIZE
  )
  RSASSA_PSS_SHA256 = PyKCS11.RSA_PSS_Mechanism(
      PyKCS11.CKM_SHA1_RSA_PKCS_PSS,
      PyKCS11.CKM_SHA256,
      PyKCS11.CKG_MGF1_SHA256,
      _SALT_SIZE
  )
  ECDSA_SIGN = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA)
  MECHANISMS = {
    "rsa-pkcs1v15-sha256": RSA_PKCS1V15_SHA256,
    "rsassa-pss-sha256": RSASSA_PSS_SHA256,
    "ecdsa-sign": ECDSA_SIGN
  }

  # Try loading PKCS#11 dynamic library from the path at PYKCS11LIB envvar
  # TODO: We do this to spare the user, who has PYKCS11LIB set, some state
  # handling. Is this too much magic? Should we require an explicit call?
  load_pkcs11_library()



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
    raise UnsupportedLibraryError(
        NO_PKCS11_PY_LIB_MSG)

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


def get_smartcards():
  """
  <Purpose>
    Iterate over smart card slots and return list with info for each HSM.

  <Return>
    List of dictionaries conforming to HSM_INFO_SCHEMA.
    TODO: SCHEMA

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  slot_list = PKCS11.getSlotList()

  for slot in slot_list:
    slot_info = PKCS11.getSlotInfo(slot)
    hsm_info_list.append({
        "slot_id": slot,
        "slot_description": slot_info.slotDescription.strip(),
        "manufacturer_id": hsm_info.manufacturerID.strip(),
        "hardware_version": hsm_info.hardwareVersion,
        "firmware_version": hsm_info.firmwareVersion,
        "flags": hsm_info.flags2text(),
      })

  return hsm_info_list



def get_hsm_keys(hsm_info, user_pin=None):
  """
  <Purpose>
    Get handles of public and private keys stored on the HSM.
    To get private key handles login required before using this method.

  <Argument>
    hsm_info:
            A dictionary conforming to HSM_INFO_SCHEMA;

    user_pin:
            A string to log into the HSM. Required to get private keys.

  <Returns>
    List of dictionaries conforming to HSM_KEY_INFO_SCHEMA.

  """
  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO: HSM_INFO_SCHEMA.check_macht(hsm_info)
  securesystemslib.format.PASSWORD_SCHEMA.check(user_ping)

  # Create an HSM session and login to access private objects.
  session = _setup_session.

  if user_pin not None:
    _login(session, user_pin)






  # Retirve all the private key object present on the HSM
  private_key_objects = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PRIVATE_KEY)])

  # TODO: Find a better way to provide the details regarding the available keys.
  key_info = []
  for object_handle in private_key_objects:
    # Find and return the key_id(with resepect to the HSM) and the key modulus
    key_id, key_modulus = session.getAttributeValue(object_handle,
        [PyKCS11.CKA_ID, PyKCS11.CKA_MODULUS])
    key_info.append([key_id, key_modulus])

  return key_info




def get_public_key_objects(hsm_info):
  """
  <Purpose>
    Get object handles of public keys stored on the HSM.

  <Returns>
    List of  key_id and key_modulus for all the public keys in HSM
  """
  if not HSM_SUPPORT: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

  if not HSM_LIB: # pragma: no cover
    raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

  # Create an HSM session to access private objects.
  session = _create_session(hsm_info)

  # Retirve all the public key object present on the HSM.
  public_key_objects = session.findObjects([(PyKCS11.CKA_CLASS,
      PyKCS11.CKO_PUBLIC_KEY)])

  # TODO: Find a better way to provide the details regarding the available keys.
  key_info = []
  for object_handle in public_key_objects:
    # Find and return the key_id(with resepect to the HSM) and the key modulus
    key_id, key_modulus = session.getAttributeValue(object_handle,
        [PyKCS11.CKA_ID, PyKCS11.CKA_MODULUS])
    key_info.append([key_id, key_modulus])

  return key_info


# def export_pubkey(hsm_info, public_key_info):
#   """
#   <Purpose>
#     Get the public key value corresponding to the 'public_key_handle'

#   <Arguments>
#     public_key_info:
#       element of the list returned by get_public_key_objects().

#   <Exceptions>
#     securesystemslib.exceptions.UnsupportedLibraryError, if the cryptography
#     module is not available.

#   <Returns>
#     A dictionary containing the public key value and other identifying information.
#     Conforms to 'securesystemslib.formats.PUBLIC_KEY_SCHEMA'.
#   """

#   if not HSM_SUPPORT: # pragma: no cover
#     raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

#   if not HSM_LIB: # pragma: no cover
#     raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

#   if not CRYPTO: # pragma: no cover
#     raise securesystemslib.exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

#   # Create session with the HSM(corresponding to hsm_info) to retrieve public key value.
#   session = _create_session(hsm_info)

#   # Find the public key handle corresponding to the key_id.
#   public_key_object = session.findObjects([(PyKCS11.CKA_CLASS,
#       PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, public_key_info[0])])[0]

#   # Retrieve the public key bytes for the required public key
#   public_key_value, public_key_type = session.getAttributeValue(public_key_object,
#       [PyKCS11.CKA_VALUE, PyKCS11.CKA_KEY_TYPE])

#   public_key =""
#   if public_key_value:
#     public_key_value = bytes(public_key_value)
#     # Public key value exported from the HSM is der encoded
#     public_key = serialization.load_der_public_key(public_key_value,
#         default_backend())
#   else:
#     if PyKCS11.CKK[public_key_type] == 'CKK_RSA':
#       public_key_modulus, public_key_exponent = session.getAttributeValue(public_key_object,
#           [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT])
#       public_key_modulus = _to_hex(public_key_modulus)
#       public_key_exponent = _to_hex(public_key_exponent)
#       public_numbers = RSAPublicNumbers( int(public_key_exponent,16),
#           int(public_key_modulus,16))
#       public_key = public_numbers.public_key(default_backend())
#     elif PyKCS11.CKK[public_key_type] == 'CKK_EC' or PyKCS11.CKK[public_key_type] == 'CKK_ECDSA':
#       raise securesystemslib.exceptions.UnsupportedAlgorithmError(
#           "The public key for " + repr(PyKCS11.CKK[public_key_type]) + " cannot be generated "
#           "using parameters. This functionality is yet not supported"
#       )
#     else:
#       raise securesystemslib.exceptions.UnsupportedAlgorithmError(
#           "The Key type " + repr(PyKCS11.CKK[public_key_type]) + " is currently not supported!")

#   logger.error(public_key)
#   public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
#       format=serialization.PublicFormat.SubjectPublicKeyInfo)
#   # Strip any leading or trailing new line characters.
#   public = extract_pem(public.decode('utf-8'), private_pem=False)

#   key_value = {'public': public.replace('\r\n', '\n'),
#                'private': ''}

#   # Return the public key conforming to the securesystemslib.format.PUBLIC_KEY_SCHEMA
#   key_dict = {}
#   key_dict['keyval'] = key_value

#   if PyKCS11.CKK[public_key_type] == 'CKK_RSA':
#     key_dict['keytype'] = 'rsa'
#     # Currently keeping a default scheme
#     # TODO: Decide a way to provide user with options regarding various schemes available
#     key_dict['scheme'] = "rsa-pkcs1v15-sha256"
#   elif PyKCS11.CKK[public_key_type] == 'CKK_EC' or PyKCS11.CKK[public_key_type] == 'CKK_ECDSA':
#     key_dict['keytype'] = 'ecdsa'
#     key_dict['scheme'] = 'ecdsa-sign'
#   else:
#     raise securesystemslib.exceptions.UnsupportedAlgorithmError(
#         "The Key type " + repr(PyKCS11.CKK[public_key_type]) + " is currently not supported!")

#   return key_dict


# def create_signature(data, hsm_info, private_key_info, user_pin):
#   """
#   <Purpose>
#     Calculate signature over 'data' using the private key corresponding
#     to the 'private_key_info'

#     Supported Keys
#     1. RSA - rsassa-pss-sha256
#     2. ECDSA

#   <Arguments>
#     data:
#       bytes over which the signature is to be calculated
#       'data' should be encoded/serialized before it is passed here.

#     private_key_info:
#       element from the list returned by the get_private_key_objects()

#     user_pin:
#       PIN for the CKU_USER login.

#   <Exceptions>
#     securesystemslib.exceptions.UnsupportedAlgorithmError, when the
#     key type of the 'private_key_handle' is not supported

#   <Returns>
#     A signature dictionary conformant to
#     'securesystemslib_format.SIGNATURE_SCHEMA'.
#   """

#   if not HSM_SUPPORT: # pragma: no cover
#     raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_MSG)

#   if not HSM_LIB: # pragma: no cover
#     raise securesystemslib.exceptions.UnsupportedLibraryError(NO_HSM_LIB_MSG)

#   # Create a session and login to generate signature using keys stored in hsm
#   session = _create_session(hsm_info)
#   _login(session, str(user_pin))

#   mechanism = None
#   private_key_object = session.findObjects([(PyKCS11.CKA_CLASS,
#       PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, private_key_info[0])])[0]
#   key_type = session.getAttributeValue(private_key_object,
#       [PyKCS11.CKA_KEY_TYPE])[0]

#   if PyKCS11.CKK[key_type] == 'CKK_RSA':
#     mechanism = MECHANISMS["rsa-pkcs1v15-sha256"]

#   elif PyKCS11.CKK[key_type] == 'CKK_EC' or PyKCS11.CKK[key_type] == 'CKK_ECDSA':
#     mechanism = MECHANISMS["ecdsa-sign"]

#   if mechanism is None:
#     raise securesystemslib.exceptions.UnsupportedAlgorithmError(
#       "The Key type " + repr(key_type) + " is currently not supported!")


#   signature = session.sign(private_key_object, data, mechanism)

#   signature_dict = {}
#   # TODO: This is not a key id, change this.
#   keyid = _to_hex(private_key_info[0])
#   sig = _to_hex(signature)

#   signature_dict['keyid'] = keyid
#   signature_dict['sig'] = sig

#   return signature_dict




def _setup_session(hsm_info, pin=None):
  """Create new hsm session, login if pin is passed and return session object.
  """
  try:
    session = PKCS11.openSession(
        hsm_info["slot_id"],
        PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

    if pin not None:
      session.login(user_pin)

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
      log.debug(e)
