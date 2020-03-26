import PyKCS11
from pprint import pprint
from securesystemslib import hsm
import os

user_pin = os.environ["YUBI_PIN"]

hsm.load_pkcs11_lib("/usr/local/Cellar/yubico-piv-tool/2.0.0/lib/libykcs11.dylib")
hsm_infos = hsm.get_hsms()
hsm_info = hsm_infos.pop()

key_infos = hsm.get_keys_on_hsm(hsm_info, user_pin)

hsm_key_id = (2,)
sslib_key_id = "deadbeef"
data = b"muaaaa"
mechanism = hsm.RSASSA_PSS_SHA256

public_key = hsm.export_pubkey(hsm_info, hsm_key_id, mechanism, sslib_key_id)
signature = hsm.create_signature(hsm_info, hsm_key_id, user_pin, data, mechanism, sslib_key_id)
print(public_key)
hsm.verify_signature(public_key, signature, data)
print(result)


# key_id =
# CKK

# for key_info in key_infos:
#   if key_info[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
#     key = hsm.export_pubkey(hsm_info, key_info, "deadbeef", hsm.)
#     break

# breakpoint()


# bytes(2,)