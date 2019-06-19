#!/usr/bin/env python

"""
<Program Name>
  hsm.py

<Author>
  Tanishq Jasoria <jasoriatanishq@gmail.com>

<Purpose>
  The goal of this module is to support hardware security modules through
  the PKCS#11 standard.

  This module use PyKCS11, a python wrapper (SWIG) for PKCS#11 modules
  to communicate with the cryptographic tokens
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Import python wrapper for PKCS#11 to communicate with the tokens
import PyKCS11

import binascii
import securesystemslib.exceptions

# Import cryptography routines needed to retrieve cryptographic
# keys and certificates in PEM format.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509


class HSM(object):
  """
  <Purpose>
    Provides a interface to use cryptographic tokens for various
    cryptographic operations.

  <Arguments>
    PKCS11Lib_path:
       path to the PKCS#11 library. This can be module specific or
       library by OpenSC(opensc-pkcs11.so) can be used.
  <Exceptions>
    securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
    library is not specified or the library is corrupt
  """

  def __init__(self, PKCS11Lib_path):

    self.PKCS11LIB = PKCS11Lib_path

    # Initialize the PyKCS11Lib, wrapper of PKCS#11 in Python.
    self.PKCS11 = PyKCS11.PyKCS11Lib()

    self.sess = None

    # Load the PKCS11 shared library file.
    self.refresh()





  def refresh(self):
    """
    <Purpose>
    This method refresh the list of available cryptographic tokens.

    <Exceptions>
      securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
      library is not specified or the library is corrupt
    """

    if self.PKCS11LIB is None:
      raise securesystemslib.exceptions.NotFoundError(
          "The PKCS11 Library not initialized in the settings.py file"
          "Initialize it to use HSMs compatible with PKCS#11")
    # Try to load the PKCS11 library
    try:
      # Load the PKCS#11 library and simultaneouslt update the list
      # of available HSM.
      self.PKCS11.load(self.PKCS11LIB)
    except PyKCS11.PyKCS11Error():
      raise securesystemslib.exceptions.NotFoundError(
          "PKS11 Library not found or is corrupt at " + repr(self.PKCS11LIB))





  def get_available_HSMs(self):
    """
    <Purpose>
      Generate the list of available cryptographic tokens for the user

    <Exceptions>
      securesystemslib.exceptions.NotFoundError, if the path of PKCS#11
      library is not specified or the library is corrupt

    <Returns>
      A list of dictionaries consisting of relevant information
      regarding all the available tokens
    """

    # Refresh the list of available slots for HSM
    self.refresh()

    # Get the list of slots on which HSMs are available
    slot_list = self.PKCS11.getSlotList()
    slot_info_list = []

    # For all the available HSMs available, add relevant information
    # to the slots dictionary
    for slot in slot_list:
      slot_dict = dict()
      slot_dict['slot_id'] = slot
      slot_info = self.PKCS11.getSlotInfo(slot)
      slot_dict['flags'] = slot_info.flags2text()
      slot_dict['manufacturer_id'] = slot_info.manufacturerID
      slot_dict['slot_description'] = slot_info.slotDescription
      slot_info_list.append(slot_dict)

    return slot_info_list





  def get_HSM_session(self, slot_info):
    """
    <Purpose>
      Open a session with the HSM of the given 'slot_info'

    <Arguments>
      slot_info:
        element from the list returned by get_available_HSMs().

    <Exceptions>
      securesystemlib.exceptions.InvaliNameError, if the requested
      is either not present or cannot be used.
    """
    try:
      self.sess = self.PKCS11.openSession(slot_info['slot_id'],
          PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    except:
      raise securesystemslib.exceptions.InvalidNameError(
          "The requested token is not available.")





  def login(self, user_pin):
    """
    <Purpose>
      User Login into the HSM. Required to access private objects.

    <Arguments>
      user_pin:
        PIN for the CKU_USER login.

    <Exceptions>
      securesystemslib.exceptions.BasPasswordError, if the entered
      user pin is invalid.
    """

    try:
      self.sess.login(user_pin)
    except PyKCS11.PyKCS11Error as error:
      if error.__str__() == 'CKR_USER_ALREADY_LOGGED_IN (0x00000100)':
        print('Already logged in as CKU_USER.')
      else:
        raise securesystemslib.exceptions.BadPasswordError("Wrong User Pin!")






  def get_private_key_objects(self):
    """
    <Purpose>
      Get object handles of private keys stored on the HSM.
      login required before using this method.

    <Returns>
      List of all available private key handles.
    """

    private_key_objects = self.sess.findObjects([(PyKCS11.CKA_CLASS,
        PyKCS11.CKO_PRIVATE_KEY)])
    return private_key_objects





  def get_public_key_objects(self):
    """
    <Purpose>
      Get object handles of public keys stored on the HSM.

    <Returns>
      List of all available public key handles.
    """

    try:
      public_key_objects = self.sess.findObjects([(PyKCS11.CKA_CLASS,
          PyKCS11.CKO_PUBLIC_KEY)])
    except:
      raise securesystemslib.exceptions
    return public_key_objects





  def get_public_key_value(self, public_key_handle):
    """
    <Purpose>
      Get the public key value corresponding to the 'public_key_handle'

    <Arguments>
      public_key_handle:
        element of the list returne by get_public_key_object().

    <Returns>
      'cryptography' public key object
    """

    public_key_value = self.sess.getAttributeValue(public_key_handle,
        [PyKCS11.CKA_VALUE])[0]
    public_key_value = bytes(public_key_value)

    # Public key value exported from the HSM is der encoded
    public_key = serialization.load_der_public_key(public_key_value,
        default_backend())
    return public_key





  def get_X509_objects(self):
    """
    <Purpose>
      Get object handle of the X509 certificates stored on the HSM.

    <Returns>
      List of all the available certificate handles.
    """

    x509_objects = self.sess.findObjects([(PyKCS11.CKA_CLASS,
        PyKCS11.CKO_CERTIFICATE)])
    return x509_objects





  def get_X509_value(self, x509_handle):
    """
    <Purpose>
      Get the certificate value corresponding to the 'x509_handle'.

    <Arguments>
      x509_handle:
        element from the list returned by get_X509_objects().

    <Returns>
      'cryptography' public key object.
    """

    x509_value = self.sess.getAttributeValue(x509_handle,
        [PyKCS11.CKA_VALUE])[0]
    x509_certificate = x509.load_der_x509_certificate(bytes(x509_value))

    return x509_certificate





  def logout(self):
    """
    <Purpose>
      Logout from the CKU_USER session
    """

    self.sess.logout()





  def close_session(self):
    """
    <Purpose>
      Close the communication session with the token.
    """

    self.sess.closeSession()





  def close(self):
    """
    <Purpose>
      To logout and terminate sessions with the HSM completely.
    """

    try:
      self.logout()
      self.close_session()
    except:
      # Exception is raised when user already logged out
      self.close_session()
