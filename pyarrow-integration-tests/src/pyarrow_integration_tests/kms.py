import base64

import pyarrow.parquet.encryption as pe
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class ExampleKmsClient(pe.KmsClient):
    """
    Test KMS client implementation that is compatible with
    parquet_key_management::test_kms::TestKmsClient
    """
    def __init__(self, _kms_connection_configuration):
      pe.KmsClient.__init__(self)
      self._keys = {
          'kf': b'0123456789012345',
          'kc1': b'1234567890123450',
          'kc2': b'1234567890123451',
      }

    def wrap_key(self, key_bytes, master_key_identifier):
        key = self._keys[master_key_identifier]
        aad = master_key_identifier.encode('utf-8')
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(aad)
        encrypted, tag = cipher.encrypt_and_digest(key_bytes)
        wrapped_key_bytes = bytes(cipher.nonce) + encrypted + tag
        return base64.b64encode(wrapped_key_bytes).decode('utf-8')

    def unwrap_key(self, wrapped_key, master_key_identifier):
        key = self._keys[master_key_identifier]
        aad = master_key_identifier.encode('utf-8')
        wrapped_key_bytes = base64.b64decode(wrapped_key)
        tag = wrapped_key_bytes[-16:]
        nonce = wrapped_key_bytes[:12]
        encrypted = wrapped_key_bytes[12:-16]
        assert len(encrypted) == 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(aad)
        return cipher.decrypt_and_verify(encrypted, tag)


def kms_client_factory(kms_connection_configuration):
   return ExampleKmsClient(kms_connection_configuration)
