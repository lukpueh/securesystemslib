from pprint import pprint
from securesystemslib import hsm

hsm.load_pkcs11_lib("/usr/local/Cellar/yubico-piv-tool/2.0.0/lib/libykcs11.dylib")
hsm_infos = hsm.get_hsms()
hsm_info = hsm_infos.pop()

key_infos = hsm.get_keys_on_hsm(hsm_info)

for key_info in key_infos:
  print(hsm.export_pubkey(hsm_info, key_info))


