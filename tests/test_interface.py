#!/usr/bin/env python

"""
<Program Name>
  test_interface.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 5, 2017.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'interface.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import time
import datetime
import tempfile
import json
import shutil
import stat
import sys
import unittest

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

# Use external backport 'mock' on versions under 3.3
if sys.version_info >= (3, 3):
  import unittest.mock as mock

else:
  import mock

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.exceptions
import securesystemslib.hash
import securesystemslib.interface as interface

from securesystemslib import KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA
from securesystemslib.interface import (generate_and_write_rsa_keypair,
    import_rsa_privatekey_from_file, import_rsa_publickey_from_file)
from securesystemslib.formats import (RSAKEY_SCHEMA, PUBLIC_KEY_SCHEMA)
from securesystemslib.exceptions import Error, FormatError, CryptoError

import six



class TestInterfaceFunctions(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.test_data_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data")
    cls.orig_cwd = os.getcwd()

    # setUpClass() is called before tests in an individual class are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())



  @classmethod
  def tearDownClass(cls):

    # tearDownModule() is called after all the tests have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)


  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(dir=self.orig_cwd)
    os.chdir(self.tmp_dir)

  def tearDown(self):
    os.chdir(self.orig_cwd)
    shutil.rmtree(self.tmp_dir)


  def test_rsa(self):
    """Test RSA key generation and import interface functions. """

    # TEST: Generate default keys and import
    # Assert location and format
    path_default = "default"
    path_default_ret = generate_and_write_rsa_keypair(filepath=path_default)

    pub = import_rsa_publickey_from_file(path_default + ".pub")
    priv = import_rsa_privatekey_from_file(path_default)

    self.assertEqual(path_default, path_default_ret)
    self.assertTrue(RSAKEY_SCHEMA.matches(pub))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub))
    self.assertTrue(RSAKEY_SCHEMA.matches(priv))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Generate unencrypted keys with empty prompt
    # Assert importable without password
    path_empty_prompt = "empty_prompt"
    with mock.patch("securesystemslib.interface.get_password", return_value=""):
      generate_and_write_rsa_keypair(filepath=path_empty_prompt, prompt=True)
    import_rsa_privatekey_from_file(path_empty_prompt)


    # TEST: Generate keys with auto-filename, i.e. keyid
    # Assert filename is keyid
    path_keyid_name = generate_and_write_rsa_keypair()
    pub_keyid_name = import_rsa_publickey_from_file(path_keyid_name + ".pub")
    priv_keyid_name = import_rsa_privatekey_from_file(path_keyid_name)
    self.assertTrue(
        os.path.basename(path_keyid_name) ==
        pub_keyid_name["keyid"] == priv_keyid_name["keyid"])


    # TEST: Generate keys with custom bits
    # Assert length
    bits = 4096
    path_bits = "bits"
    generate_and_write_rsa_keypair(filepath=path_bits, bits=bits)

    priv_bits = import_rsa_privatekey_from_file(path_bits)
    # NOTE: Parse PEM with pyca/cryptography to get the key size property
    obj_bits = load_pem_private_key(
        priv_bits["keyval"]["private"].encode("utf-8"),
        password=None,
        backend=default_backend())

    self.assertEqual(obj_bits.key_size, bits)


    # TEST: Generate keys with encrypted private key using passed password
    # Assert importable with password
    pw = "pw"
    path_encrypted = "encrypted"
    generate_and_write_rsa_keypair(filepath=path_encrypted, password=pw)
    import_rsa_privatekey_from_file(path_encrypted, password=pw)


    # TEST: Generate keys with encrypted private key using prompted password
    # Assert load with password
    path_empty_prompt = "empty_prompt"
    with mock.patch("securesystemslib.interface.get_password", return_value=pw):
      generate_and_write_rsa_keypair(filepath=path_empty_prompt, prompt=True)
    import_rsa_privatekey_from_file(path_empty_prompt, password=pw)


    # TEST: Import existing keys with encrypted private key (test regression)
    # Assert format
    path_existing = os.path.join(self.test_data_dir, "keystore", "rsa_key")

    pub_existing = import_rsa_publickey_from_file(path_existing + ".pub")
    priv_existing = import_rsa_privatekey_from_file(path_existing, "password")

    self.assertTrue(RSAKEY_SCHEMA.matches(pub_existing))
    self.assertTrue(PUBLIC_KEY_SCHEMA.matches(pub_existing))
    self.assertTrue(RSAKEY_SCHEMA.matches(priv_existing))
    # NOTE: There is no private key schema, at least check it has a value
    self.assertTrue(priv["keyval"]["private"])


    # TEST: Generation errors
    for kwargs, err_msg in [
        # Error on empty password
        ({"password": ""},
          "encryption 'password' must be 1 or more characters long"),
        # Error on 'password' and 'prompt=True'
        ({"password": pw, "prompt"=True},
          "passing 'password' and 'prompt=True' is not allowed")]:

      with self.assertRaises(ValueError) as ctx:
        interface.generate_and_write_rsa_keypair(**kwargs)
      self.assertEqual(err_msg, str(ctx.exception))

    # Error on bad argument format
    for kwargs in [
        {"bits": 1024}, # Too low
        {"bits": "not-an-int"},
        {"filepath": 123456}, # Not a string
        {"password": 123456}]: # Not a string
      with self.assertRaises(FormatError):
        interface.generate_and_write_rsa_keypair(**kwargs)


    # TEST: Import errors (use keys from above)
    # Error on not a public key
    with self.assertRaises(Error) as ctx:
      import_rsa_publickey_from_file(path_default)
    self.assertTrue("Invalid public pem" in str(ctx.exception))

    for args, kwargs, err, err_msg in [
        # Error on not a private key
        ([path_default + ".pub"], {}, CryptoError,
          "Could not deserialize key data"),
        # Error on not encrypted
        ([path_default], {"password": pw}, CryptoError,
          "Password was given but private key is not encrypted"),
        # Error on encrypted but no pw
        ([path_encrypted], {}, CryptoError,
          "Password was not given but private key is encrypted"),
        # Error on encrypted but empty pw passed
        ([path_encrypted], {"password": ""}, CryptoError,
          "Password was not given but private key is encrypted"),
        # Error on encrypted but bad pw passed
        ([path_encrypted], {"password": "bad pw"}, CryptoError
          "Bad decrypt. Incorrect password?"),
        # Error on pw and prompt
        ([path_default], {"password": pw, "prompt": True}, ValueError,
          "passing 'password' and 'prompt=True' is not allowed")]:
      with self.assertRaises(err) as ctx:
        import_rsa_privatekey_from_file(*args, **kwargs)
      self.assertTrue(err_msg in str(ctx.exception))

    # Error on encrypted but bad pw prompted
    with self.assertRaises(CryptoError) as ctx, mock.patch(
        "securesystemslib.interface.get_password", return_value="bad_pw"):
      import_rsa_privatekey_from_file(path_encrypted, prompt=True)
    self.assertTrue("Bad decrypt. Incorrect password?" in str(ctx.exception))

    # Error on bad argument format
    for args, kwargs in [
          ([123456], {}), # bad path
          ([path_default], {"scheme": 123456}), # bad scheme
          ([path_default], {"scheme": "bad scheme"}) # bad scheme
        ]:
      with self.assertRaises(FormatError):
        import_rsa_publickey_from_file(*args, **kwargs)
        import_rsa_privatekey_from_file(*args, **kwargs)

    with self.assertRaises(FormatError): # bad password
      import_rsa_privatekey_from_file("path_default", password=123456)






  def test_generate_and_write_ed25519_keypair(self):

    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_keypath = os.path.join(temporary_directory, 'ed25519_key')
    test_keypath_unencrypted = os.path.join(temporary_directory,
                                            'ed25519_key_unencrypted')

    returned_path = interface.generate_and_write_ed25519_keypair(
        test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    self.assertEqual(returned_path, test_keypath)

    # If no 'password' is given, the private key file is written to disk
    # unencrypted
    interface.generate_and_write_ed25519_keypair(test_keypath_unencrypted)
    self.assertTrue(os.path.exists(test_keypath_unencrypted))
    self.assertTrue(os.path.exists(test_keypath_unencrypted + '.pub'))

    # Ensure the generated key files are importable.
    imported_pubkey = \
      interface.import_ed25519_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA\
                    .matches(imported_pubkey))

    imported_privkey = \
      interface.import_ed25519_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA\
                    .matches(imported_privkey))

    # Fail importing encrypted key passing password and prompt
    with self.assertRaises(ValueError):
      interface.import_ed25519_privatekey_from_file(test_keypath,
                                                    password='pw',
                                                    prompt=True)

    # Fail decryption with wrong passwd
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_ed25519_privatekey_from_file(test_keypath, password='')

    # Try to import the unencrypted key file, by not passing a password
    imported_privkey = \
        interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted)
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.\
                    matches(imported_privkey))

    # Try to import the unencrypted key file, by entering an empty password
    with mock.patch('securesystemslib.interface.get_password',
        return_value=''):
      imported_privkey = \
        interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted,
                                                      prompt=True)
      self.assertTrue(
          securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_privkey))

    # Fail importing unencrypted key passing a password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_ed25519_privatekey_from_file(test_keypath_unencrypted,
                                                    'pw')

    # Fail importing encrypted key passing no password
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_ed25519_privatekey_from_file(test_keypath)

    # Test for a default filepath.  If 'filepath' is not given, the key's
    # KEYID is used as the filename.  The key is saved to the current working
    # directory.
    default_keypath = interface.generate_and_write_ed25519_keypair(password='pw')
    self.assertTrue(os.path.exists(default_keypath))
    self.assertTrue(os.path.exists(default_keypath + '.pub'))

    written_key = interface.import_ed25519_publickey_from_file(default_keypath + '.pub')
    self.assertEqual(written_key['keyid'], os.path.basename(default_keypath))

    os.remove(default_keypath)
    os.remove(default_keypath + '.pub')


    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ed25519_keypair, 3, password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_rsa_keypair, test_keypath, password=3)

    # Test unallowed 'password' and 'prompt=True'
    with self.assertRaises(ValueError):
      interface.generate_and_write_ed25519_keypair(test_keypath, password='pw',
          prompt=True)


  def test_import_ed25519_publickey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key')
    interface.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')

    imported_ed25519_key = \
      interface.import_ed25519_publickey_from_file(ed25519_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        interface.import_ed25519_publickey_from_file, nonexistent_keypath)

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
        interface.import_ed25519_publickey_from_file, invalid_keyfile)

    # Invalid public key imported (contains unexpected keytype.)
    keytype = imported_ed25519_key['keytype']
    keyval = imported_ed25519_key['keyval']
    scheme = imported_ed25519_key['scheme']

    ed25519key_metadata_format = \
      securesystemslib.keys.format_keyval_to_metadata(keytype, scheme,
      keyval, private=False)

    ed25519key_metadata_format['keytype'] = 'invalid_keytype'
    with open(ed25519_keypath + '.pub', 'wb') as file_object:
      file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_publickey_from_file,
        ed25519_keypath + '.pub')



  def test_import_ed25519_privatekey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    scheme = 'ed25519'
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key')
    interface.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')

    imported_ed25519_key = \
      interface.import_ed25519_privatekey_from_file(ed25519_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        interface.import_ed25519_privatekey_from_file, nonexistent_keypath,
        'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
      interface.import_ed25519_privatekey_from_file, invalid_keyfile, 'pw')

    # Invalid private key imported (contains unexpected keytype.)
    imported_ed25519_key['keytype'] = 'invalid_keytype'

    # Use 'rsa_keys.py' to bypass the key format validation performed
    # by 'keys.py'.
    salt, iterations, derived_key = \
      securesystemslib.rsa_keys._generate_derived_key('pw')

    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
        'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = \
      securesystemslib.rsa_keys._encrypt(json.dumps(imported_ed25519_key),
          derived_key_information)

    with open(ed25519_keypath, 'wb') as file_object:
      file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ed25519_privatekey_from_file, ed25519_keypath, 'pw')



  def test_generate_and_write_ecdsa_keypair(self):

    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_keypath = os.path.join(temporary_directory, 'ecdsa_key')

    returned_path = interface.generate_and_write_ecdsa_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    self.assertEqual(returned_path, test_keypath)

    # Ensure the generated key files are importable.
    imported_pubkey = \
      interface.import_ecdsa_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_pubkey))

    imported_privkey = \
      interface.import_ecdsa_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_privkey))

    # Test for a default filepath.  If 'filepath' is not given, the key's
    # KEYID is used as the filename.  The key is saved to the current working
    # directory.
    default_keypath = interface.generate_and_write_ecdsa_keypair(password='pw')
    self.assertTrue(os.path.exists(default_keypath))
    self.assertTrue(os.path.exists(default_keypath + '.pub'))

    written_key = interface.import_ecdsa_publickey_from_file(default_keypath + '.pub')
    self.assertEqual(written_key['keyid'], os.path.basename(default_keypath))

    os.remove(default_keypath)
    os.remove(default_keypath + '.pub')

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ecdsa_keypair, 3, password='pw')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.generate_and_write_ecdsa_keypair, test_keypath, password=3)

    # Test unallowed 'password' and 'prompt=True'
    with self.assertRaises(ValueError):
      interface.generate_and_write_ecdsa_keypair(test_keypath, password='pw',
          prompt=True)


  def test_import_ecdsa_publickey_from_file(self):
    # Test normal case.
    # Generate ecdsa keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ecdsa_keypath = os.path.join(temporary_directory, 'ecdsa_key')
    interface.generate_and_write_ecdsa_keypair(ecdsa_keypath, password='pw')

    imported_ecdsa_key = \
      interface.import_ecdsa_publickey_from_file(ecdsa_keypath + '.pub')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_ecdsa_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
        'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        interface.import_ecdsa_publickey_from_file, nonexistent_keypath)

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
        interface.import_ecdsa_publickey_from_file, invalid_keyfile)

    # Invalid public key imported (contains unexpected keytype.)
    keytype = imported_ecdsa_key['keytype']
    keyval = imported_ecdsa_key['keyval']
    scheme = imported_ecdsa_key['scheme']

    ecdsakey_metadata_format = \
      securesystemslib.keys.format_keyval_to_metadata(keytype,
          scheme, keyval, private=False)

    ecdsakey_metadata_format['keytype'] = 'invalid_keytype'
    with open(ecdsa_keypath + '.pub', 'wb') as file_object:
      file_object.write(json.dumps(ecdsakey_metadata_format).encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_publickey_from_file,
        ecdsa_keypath + '.pub')



  def test_import_ecdsa_privatekey_from_file(self):
    # Test normal case.
    # Generate ecdsa keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ecdsa_keypath = os.path.join(temporary_directory, 'ecdsa_key')
    interface.generate_and_write_ecdsa_keypair(ecdsa_keypath, password='pw')

    imported_ecdsa_key = \
      interface.import_ecdsa_privatekey_from_file(ecdsa_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(imported_ecdsa_key))

    # Test import with prompted password
    with mock.patch('securesystemslib.interface.get_password',
        return_value='pw'):
      imported_ecdsa_key = interface.import_ecdsa_privatekey_from_file(
          ecdsa_keypath, prompt=True)
      self.assertTrue(securesystemslib.formats.ECDSAKEY_SCHEMA.matches(
          imported_ecdsa_key))

    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_privatekey_from_file, 3, 'pw')

    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory, 'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        interface.import_ecdsa_privatekey_from_file, nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
      interface.import_ecdsa_privatekey_from_file, invalid_keyfile, 'pw')

    # Invalid private key imported (contains unexpected keytype.)
    imported_ecdsa_key['keytype'] = 'invalid_keytype'

    # Use 'rsa_keys.py' to bypass the key format validation performed
    # by 'keys.py'.
    salt, iterations, derived_key = \
      securesystemslib.rsa_keys._generate_derived_key('pw')

    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
        'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = \
      securesystemslib.rsa_keys._encrypt(json.dumps(imported_ecdsa_key),
          derived_key_information)

    with open(ecdsa_keypath, 'wb') as file_object:
      file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        interface.import_ecdsa_privatekey_from_file, ecdsa_keypath, 'pw')

    # Test unallowed passing 'prompt' and 'password'
    with self.assertRaises(ValueError):
      interface.import_rsa_privatekey_from_file(ecdsa_keypath,
          password='pw', prompt=True)

    # Test decryption error with wrong (empty) 'password'
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      interface.import_rsa_privatekey_from_file(ecdsa_keypath, '')


  def test_import_public_keys_from_file(self):
    """Test import multiple public keys with different types. """
    path_rsa = "rsa_key"
    path_ed25519 = "ed25519_key"
    path_ecdsa = "ecdsa_key"

    interface.generate_and_write_rsa_keypair(path_rsa, password="pw")
    interface.generate_and_write_ed25519_keypair(path_ed25519, password="pw")
    interface.generate_and_write_ecdsa_keypair(path_ecdsa, password="pw")

    # Successfully import key dict with one key per supported key type
    key_dict = interface.import_public_keys_from_file([
        path_rsa + ".pub",
        path_ed25519 + ".pub",
        path_ecdsa + ".pub"],
        [KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA])

    securesystemslib.formats.ANY_PUBKEY_DICT_SCHEMA.check_match(key_dict)
    self.assertListEqual(
        sorted([key["keytype"] for key in key_dict.values()]),
        sorted([KEY_TYPE_RSA, KEY_TYPE_ED25519, KEY_TYPE_ECDSA])
      )

    # Successfully import default rsa key
    key_dict = interface.import_public_keys_from_file([path_rsa + ".pub"])
    securesystemslib.formats.ANY_PUBKEY_DICT_SCHEMA.check_match(key_dict)
    securesystemslib.formats.RSAKEY_SCHEMA.check_match(
        list(key_dict.values()).pop())

    # Bad default rsa key type for ed25519
    with self.assertRaises(securesystemslib.exceptions.Error):
      interface.import_public_keys_from_file([path_ed25519 + ".pub"])

    # Bad ed25519 key type for rsa key
    with self.assertRaises(securesystemslib.exceptions.Error):
      interface.import_public_keys_from_file(
          [path_rsa + ".pub"], [KEY_TYPE_ED25519])

    # Bad unsupported type
    with self.assertRaises(securesystemslib.exceptions.FormatError):
      interface.import_public_keys_from_file(
          [path_ed25519 + ".pub"], ["KEY_TYPE_UNSUPPORTED"])

    # Bad arguments length
    with self.assertRaises(securesystemslib.exceptions.FormatError):
      interface.import_public_keys_from_file(
          [path_rsa + ".pub", path_ed25519 + ".pub"],  [KEY_TYPE_ED25519])



# Run the test cases.
if __name__ == '__main__':
  unittest.main()
