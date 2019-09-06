#!/usr/bin/env python

"""
<Program Name>
  hsm_keys.py

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>

<Purpose>
  This module provides a high-level API for using hardware security modules
  for various cryptographic operations

  This module current supports
  1. Create and Verify signature using keys from a HSM
  2. Export public key and X509 certificates stored in HSM in PEM format.
"""

from securesystemslib.hsm import HSM
import securesystemslib.interface
import securesystemslib.exceptions
import binascii

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates in PEM format.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_library(PKCS11LIB_USER):
  """
  <Purpose>
    To load a custom library to interact with the hardware tokens.

  <Exceptions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified or the library is corrupt.
  """

  global smartcard
  smartcard = HSM(PKCS11LIB_USER)


def load_HSMs():
  """
  <Purpose>
    To get list of all the available HSMs

  <Exceptions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified in 'settings.py' or the library is corrupt

  <Returns>
    list of dictionaries corresponding to all the available HSMs
  """

  # All the functions must use the same object of the HSM class,
  # to use same session for all the operations.

  # Get information reagarding the available HSM
  available_HSM = smartcard.get_available_HSMs()
  return available_HSM





def load_private_keys(HSM_info, user_pin):
  """
  <Purpose>
    Get list of handles of private keys stored in the HSM
    corresponding to the 'HSM_info'

  <Arguments>
    HSM_info:
      element from the list generated by 'load_HSMs()'
    user_pin:
      user pin of the HSM, to access private object from the token

  <Exceptions>
    securesystemlib.exceptions.InvalidNameError, if the requested
    HSM is either not present or cannot be used.

    securesystemslib.exceptions.BadPasswordError, if the entered
    user pin is invalid.

  <Returns>
    list of handle of all the available private keys
  """

  # Use the HSM with the corresponding 'slot_info'
  smartcard.get_HSM_session(HSM_info)

  # Login to access the private key objects
  smartcard.login(user_pin)

  private_keys = smartcard.get_private_key_objects()

  return private_keys





def create_signature(data, private_key_handle):
  """
  <Purpose>
    Calculate a signature over the 'data' using the private key corresponding
    to the 'private_key_handle'

  <Arguments>
    data:
      Data over which the signature is to be calculated
      Data should be serialized/encoded before passing, it must be bytes object

    private_key_handle:
      element from the list generated by 'load_private_keys()'

  <Exceptions>
    securesystemslib.exceptions.UnsupportedAlgorithmError, when the
    key type of the 'private_key_handle' is not supported

  <Returns>
    HEX string of the calculates signature
  """

  signature = smartcard.generate_signature(data, private_key_handle)

  return signature





def load_public_keys(HSM_info):
  """
  <Purpose>
    Get list of handles of public keys stored in the HSM
    corresponding to the 'HSM_info'

  <Arguments>
    HSM_info:
      element from the list generated by 'load_HSMs()'

  <Exceptions>
    securesystemlib.exceptions.InvalidNameError, if the requested
    HSM is either not present or cannot be used.

  <Returns>
    list of handle of all the available public keys
  """
  # Use the HSM with the corresponding 'slot_info'
  smartcard.get_HSM_session(HSM_info)

  public_keys = smartcard.get_public_key_objects()

  return public_keys





def export_public_key_PEM(public_key_handle):
  """
  <Purpose>
    Export public key corresponding to the 'public_key_handle" in
    PEM format.

  <Arguments>
    public_key_handle:
      element from the list generated by 'load_public_keys()'.

  <Returns>
    PEM encoded public key
  """

  public_key = smartcard.get_public_key_value(public_key_handle)
  public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)

  return public_pem.decode('utf-8')





def verify_signature(signed_bytes, public_key_handle, signature):
  """
  <Purpose>
    Verify that the corresponding private key of 'public_key' generated
    'signature' over the 'signed_bytes'

  <Arguments>
    signed_bytes:
      Data that the signature is expected to be over.
      Data should be serialized/encoded before passing, it must be bytes object

    public_key_handle:
      element from the list generated by 'load_public_keys()'.

    signature:
      HEX string generated by 'generate_signature()'

  <Exceptions>
    securesystemslib.exceptions.UnsupportedAlgorithmError, when the
    key type of the 'public_key_handle' is not supported

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """

  return smartcard.verify_signature(signed_bytes, signature, public_key_handle)




