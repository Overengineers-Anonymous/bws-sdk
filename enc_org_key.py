from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json

data = b"0" * 65
data = json.dumps({"encryptionKey": base64.b64encode(data).decode('utf-8')}).encode('utf-8')

padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

cipher = Cipher(algorithms.AES(b"0" * 32), modes.CBC(b"0" * 16))
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()


print(base64.b64encode(encrypted_data).decode('utf-8'))

