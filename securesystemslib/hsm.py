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
import asn1crypto.keys

import securesystemslib.formats
import securesystemslib.hash
from securesystemslib.exceptions import (
    UnsupportedLibraryError, PKCS11DynamicLibraryLoadingError)

logger = logging.getLogger(__name__)

#Boolean to indicate if optional pyca cryptography library is available
CRYPTO = True
# Module global to hold an instance of PyKCS11.PyKCS11Lib. If it remains 'None'
# it means that the PyKCS11 library is not available.
PKCS11 = None
# Boolean to indicate if we have loaded the required dynamic library on the
# 'PKCS11' instance. (Note: It would would nicer to get this information from
# the object, but there doesn't seem to be a straight-forward way to to this.)
PKCS11_DYN_LIB = False

# TODO: write proper message / usage instructions for load
NO_CRYPTO_MSG = "This operations requires cryptography."
NO_PKCS11_PY_LIB_MSG = "HSM support requires PyKCS11 library"
NO_PKCS11_DYN_LIB_MSG = "HSM support requires PKCS11 shared object"

try:
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding
  from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
  from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
  from cryptography.hazmat.primitives.asymmetric.ec import (
      EllipticCurvePublicKey, SECP256R1, SECP384R1, ECDSA)

  from cryptography import x509

except ImportError:
  CRYPTO = False

try:
  # Import python wrapper for PKCS#11 to communicate with the tokens
  import PyKCS11
  PKCS11 = PyKCS11.PyKCS11Lib()

except ImportError as e:
  # Missing PyKCS11 python library. PKCS11 must remain 'None'.
  logger.debug(e)

# TODO: Create securesystemslib-wide constants and use them everywhere
ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256"
ECDSA_SHA2_NISTP384 = "ecdsa-sha2-nistp384"

if PKCS11 is not None and CRYPTO:
  SIGNING_SCHEMES = {
    ECDSA_SHA2_NISTP256: {
      "mechanism": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256),
      "curve": SECP256R1
      },
    ECDSA_SHA2_NISTP384: {
      "mechanism": PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA384),
      "curve": SECP384R1
      }
    }




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

  global PKCS11_DYN_LIB

  try:
     # If path is not passed PyKCS11 consults the PYKCS11LIB env var
    if path is None:
      PKCS11.load()

    else:
      securesystemslib.formats.PATH_SCHEMA.check_match(path)
      PKCS11.load(path)

    PKCS11_DYN_LIB = True

  except PyKCS11.PyKCS11Error as e:
    PKCS11_DYN_LIB = False
    # TODO: Add message "Could not load + e + NO_PKCS11_DYN_LIB_MSG
    raise PKCS11DynamicLibraryLoadingError(e)


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
    To get private key handles login is required before using this method.

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



def export_pubkey(hsm_info, hsm_key_id, scheme, sslib_key_id):
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
  if not CRYPTO:
    raise UnsupportedLibraryError(NO_CRYPTO_MSG)

  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  if scheme not in SIGNING_SCHEMES.keys():
    raise ValueError("passed scheme {} not supported. choose one of {}".format(
        scheme, ",".join(SIGNING_SCHEMES.keys())))

  scheme_info = SIGNING_SCHEMES[scheme]

  # TODO: HSM_INFO_SCHEMA.check_match(hsm_info)
  # TODO: HSM_KEY_INFO_SCHEMA.check_match(key_info)
  # TODO: keyid check
  # scheme check

  # Create HSM session, without logging in, which is not required for pubkeys
  session = _setup_session(hsm_info)

  # TODO: KeyError check
  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
      (PyKCS11.CKA_ID, hsm_key_id)])

  _for_key_on_hsm = "for keyid '{}' on hsm '{}'".format(
      hsm_key_id, hsm_info["slot_id"])

  # TODO: is ValueError the right exception here?
  if len(key_objects) < 1:
    raise ValueError("cannot find key {}".format(_for_key_on_hsm))

  if len(key_objects) > 1:
    raise ValueError("found multiple keys {}".format(_for_key_on_hsm))

  key_object = key_objects.pop()
  hsm_key_type = session.getAttributeValue(key_object, [PyKCS11.CKA_KEY_TYPE])[0] # TODO: err


  if hsm_key_type != PyKCS11.CKK_EC:
    raise ValueError("passed scheme '{}' requires a key of type '{}', "
        "found key of type '{}' {}".format(
        scheme,
        PyKCS11.CKK[PyKCS11.CKK_EC],
        PyKCS11.CKK.get(hsm_key_type, None),
        _for_key_on_hsm))

  params, point = session.getAttributeValue(key_object, [
      PyKCS11.CKA_EC_PARAMS,
      PyKCS11.CKA_EC_POINT
    ])

  keytype = scheme
  ec_param_obj = asn1crypto.keys.ECDomainParameters.load(bytes(params))
  if ec_param_obj.chosen.native != scheme_info["curve"].name:
    raise ValueError("passed scheme '{}' requires key on curve '{}', found "
        "key on curve '{}' {}".format(
        scheme,
        scheme_info["curve"].name,
        ec_param_obj.chosen.native,
        _for_key_on_hsm))

  ec_point_obj = asn1crypto.keys.ECPoint().load(bytes(point))
  crypto_public_key = EllipticCurvePublicKey.from_encoded_point(
      scheme_info["curve"](), ec_point_obj.native)
  public_key_value = crypto_public_key.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo).decode()

  # NOTE: securesysmslib.formats.ECDSAKEY_SCHEMA uses the same string for
  # "keytype" and "scheme".
  return {
      "keyid": sslib_key_id,
      "keytype": scheme,
      "scheme": scheme,
      "keyval": {
        "public": public_key_value
      }
    }



def create_signature(hsm_info, hsm_key_id, user_pin, data, scheme, sslib_key_id):
  """
  TODO

  """
  if not CRYPTO:
    raise UnsupportedLibraryError(NO_CRYPTO_MSG)

  if PKCS11 is None:
    raise UnsupportedLibraryError(NO_PKCS11_PY_LIB_MSG)

  if not PKCS11_DYN_LIB:
    raise UnsupportedLibraryError(NO_PKCS11_DYN_LIB_MSG)

  # TODO: HSM_INFO.check_match(private_key_info)
  # TODO: PRIVATE_KEY_INFO.check_match(private_key_info)
  # TODO: Check supported scheme
  securesystemslib.formats.PASSWORD_SCHEMA.check_match(user_pin)

  # Create a session and login to generate signature using keys stored in hsm
  session = _setup_session(hsm_info, user_pin)


  #### DRY with export pubkey
  # TODO: KeyError check
  key_objects = session.findObjects([
      (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
      (PyKCS11.CKA_ID,  hsm_key_id)])

  key_object = key_objects.pop()
  key_type = session.getAttributeValue(key_object, [PyKCS11.CKA_KEY_TYPE])[0]

  # Including checks from above

  #### DRY END




  # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
  signature = session.sign(key_object, data, SIGNING_SCHEMES[scheme]["mechanism"]) # TODO err
  _teardown_session(session)

  # The PKCS11 signature octets correspond to the concatenation of the ECDSA
  # values r and s, both represented as an octet string of equal length of at
  # most nLen with the most significant byte first (i.e. big endian)
  # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
  r_s_len = int(len(signature) / 2)
  r = int.from_bytes(signature[:r_s_len], byteorder="big")
  s = int.from_bytes(signature[r_s_len:], byteorder="big")

  # Create an ASN.1 encoded Dss-Sig-Value to be used with pyca/cryptography
  dss_sig_value = binascii.hexlify(encode_dss_signature(r, s)).decode("ascii")

  return {
      "keyid": sslib_key_id,
      "sig": dss_sig_value
    }




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