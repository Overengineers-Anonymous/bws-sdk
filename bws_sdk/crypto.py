import base64
from enum import Enum
import hashlib
import hmac
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from .errors import HmacError

class SymetricCryptoKey:
    def __init__(self, key: bytes):
        if len(key) == 64:
            self.key = key[:32]
            self.mac_key = key[32:64]
        elif len(key) == 32:
            self.key = key[:16]
            self.mac_key = key[16:32]
        else:
            raise ValueError("Key must be 64 bytes long")

    @classmethod
    def derive_symkey(cls, secret: bytes, name: str, info: str | None = None):
        """
        Python implementation of the Rust derive_shareable_key function.

        This function derives a shareable key using HMAC and HKDF-Expand
        from a secret and name, matching the Rust implementation behavior.

        Args:
            secret: A 16-byte secret
            name: The key name
            info: Optional info for HKDF

        Returns:
            A SymetricCryptoKey instance
        """
        if len(secret) != 16:
            raise ValueError("Secret must be exactly 16 bytes")

        # Create HMAC with "bitwarden-{name}" as the key
        key_material = f"bitwarden-{name}".encode("utf-8")
        hmac_obj = hmac.new(key_material, msg=secret, digestmod=hashlib.sha256)
        prk = hmac_obj.digest()

        # Manual implementation of HKDF-Expand to match Rust behavior
        info_bytes = info.encode("utf-8") if info else b""
        expanded_key = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=64,
            info=info_bytes,
        ).derive(prk)

        return cls(expanded_key)

    @classmethod
    def from_encryption_key(cls, encryption_key: bytes):
        if len(encryption_key) != 16:
            raise ValueError("Invalid encryption key length")

        return cls.derive_symkey(encryption_key, "accesstoken", "sm-access-token")

    def decrypt(self, data: bytes) -> bytes:
        # Implement decryption logic here
        cipher = Cipher(algorithms.AES(self.mac_key), modes.CBC(self.key))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def to_base64(self) -> str:
        return base64.b64encode(self.key + self.mac_key).decode("utf-8")

class AlgoEnum(Enum):
    AES128 = "1"
    AES256 = "2"

class EncryptedValue:
    def __init__(self, algo: AlgoEnum, iv: bytes, data: bytes, mac: bytes):
        self.iv = iv
        self.data = data
        self.mac = mac
        self.algo = algo

    @staticmethod
    def decode(encoded_data: str) -> tuple[AlgoEnum, str, str, str]:
        parts= encoded_data.split('.', 1)
        if len(parts) == 2: # the encrypted data has a header
            iv, data, mac = parts[1].split('|')
            if parts[0] == AlgoEnum.AES128.value or parts[0] == AlgoEnum.AES256.value:
                return (AlgoEnum(parts[0]), iv, data, mac)
        else:
            iv, data, mac = encoded_data.split('|')
            if len(parts) == 3:
                return (AlgoEnum.AES128, iv, data, mac)

        raise ValueError("Invalid encrypted data format")

    @classmethod
    def from_str(cls, encrypted_str: str):
        algo, iv, data, mac = cls.decode(encrypted_str)
        return cls(algo=algo, iv=base64.b64decode(iv), data=base64.b64decode(data), mac=base64.b64decode(mac))

    def generate_mac(self, key: bytes) -> bytes:
        hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
        hmac_obj.update(self.iv)
        hmac_obj.update(self.data)

        return hmac_obj.digest()

    def _unpad(self, data: bytes, key: bytes) -> bytes:
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data)
        unpadded_data += unpadder.finalize()
        return unpadded_data

    def _decrypt_aes(self, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        data =  decryptor.update(self.data) + decryptor.finalize()
        return self._unpad(data, key)

    def decrypt(self, key: SymetricCryptoKey) -> bytes:
        mac = self.generate_mac(key.mac_key)
        if not hmac.compare_digest(mac, self.mac):
            raise HmacError("MAC verification failed")

        return self._decrypt_aes(key.key)
