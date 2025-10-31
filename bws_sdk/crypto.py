"""
Cryptographic utilities for the BWS SDK.

This module provides cryptographic functionality for the BWS SDK, including
symmetric encryption/decryption, key derivation, and encrypted value handling.
It implements the same cryptographic protocols used by the Bitwarden client
applications.

Classes:
    SymmetricCryptoKey: Handles symmetric encryption keys with MAC keys
    AlgoEnum: Enumeration of supported encryption algorithms
    EncryptedValue: Represents and handles encrypted data with metadata

"""

import base64
import hashlib
import hmac
import logging
import os
from enum import Enum

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .errors import HmacError, InvalidEncryptedFormat, InvalidEncryptionKeyError

logger = logging.getLogger(__name__)


class SymmetricCryptoKey:
    """
    Symmetric encryption key with separate encryption and MAC components.

    This class handles symmetric encryption keys used in Bitwarden's cryptographic
    protocol. It automatically splits provided keys into encryption and MAC
    components and provides methods for key derivation.

    Attributes:
        key (bytes): The encryption key component
        mac_key (bytes): The MAC (Message Authentication Code) key component

    Note:
        The class supports two key sizes:
        - 64 bytes: key[:32] for encryption, key[32:64] for MAC
        - 32 bytes: key[:16] for encryption, key[16:32] for MAC
    """

    def __init__(self, key: bytes):
        """
        Initialize a SymmetricCryptoKey from raw key bytes.

        Args:
            key (bytes): Raw key material (32 or 64 bytes)

        Raises:
            InvalidEncryptionKeyError: If key length is not 32 or 64 bytes
        """
        if len(key) == 64:
            self.key = key[:32]
            self.mac_key = key[32:64]
        elif len(key) == 32:
            self.key = key[:16]
            self.mac_key = key[16:32]
        else:
            raise InvalidEncryptionKeyError("Key must be 64 or 32 bytes long")

    @classmethod
    def derive_symkey(
        cls, secret: bytes, name: str, info: str | None = None
    ) -> "SymmetricCryptoKey":
        """
        Derive a symmetric key using HMAC and HKDF-Expand.

        This function derives a shareable key using HMAC and HKDF-Expand
        from a secret and name, matching the Rust implementation behavior
        used by Bitwarden clients.

        Args:
            secret (bytes): A 16-byte secret for key derivation
            name (str): The key name used in the derivation process
            info (str | None): Optional info parameter for HKDF

        Returns:
            SymmetricCryptoKey: A new SymmetricCryptoKey instance with derived key material

        Raises:
            ValueError: If the secret is not exactly 16 bytes
            InvalidEncryptionKeyError: If key derivation fails

        Note:
            The derivation process:
            1. Creates HMAC with "bitwarden-{name}" as the key
            2. Uses the secret as the message
            3. Applies HKDF-Expand to get 64 bytes of key material
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
    def from_encryption_key(cls, encryption_key: bytes) -> "SymmetricCryptoKey":
        """
        Create a SymmetricCryptoKey from a BWS access token encryption key.

        This method derives a symmetric key specifically for BWS access token
        purposes using the standard Bitwarden key derivation process.

        Args:
            encryption_key (bytes): A 16-byte encryption key from a BWS access token

        Returns:
            SymmetricCryptoKey: A derived key suitable for BWS operations

        Raises:
            ValueError: If the encryption_key is not exactly 16 bytes
            InvalidEncryptionKeyError: If key derivation fails
        """
        if len(encryption_key) != 16:
            raise ValueError("Invalid encryption key length")

        return cls.derive_symkey(encryption_key, "accesstoken", "sm-access-token")

    def __eq__(self, other: object) -> bool:
        """
        Check equality between SymmetricCryptoKey instances.

        Args:
            other: Another object to compare with

        Returns:
            bool: True if both keys have identical key and mac_key components

        Raises:
            ValueError: If the other object is not a SymmetricCryptoKey instance
        """
        if not isinstance(other, SymmetricCryptoKey):
            raise ValueError(
                "Comparison is only supported between SymmetricCryptoKey instances"
            )
        return self.key == other.key and self.mac_key == other.mac_key

    def to_base64(self) -> str:
        """
        Convert the key to a base64-encoded string.

        Concatenates the encryption key and MAC key, then base64-encodes the result.

        Returns:
            str: Base64-encoded representation of the combined key material
        """
        return base64.b64encode(self.key + self.mac_key).decode("utf-8")


class AlgoEnum(Enum):
    """
    Enumeration of supported encryption algorithms.

    This enum defines the encryption algorithms supported by Bitwarden's
    cryptographic protocol. Each algorithm is identified by a string value
    that corresponds to the algorithm identifier used in encrypted data.

    Values:
        AES128: AES-128 encryption algorithm (identifier: "1")
        AES256: AES-256 encryption algorithm (identifier: "2")

    Note:
        Currently, the BWS SDK primarily uses AES-128 for compatibility
        with existing Bitwarden client implementations.
    """

    AES128 = "1"
    AES256 = "2"


class EncryptedValue:
    """
    Represents an encrypted value with authentication in Bitwarden's format.

    This class handles encrypted data according to Bitwarden's authenticated
    encryption protocol, which includes the algorithm identifier, initialization
    vector (IV), encrypted data, and message authentication code (MAC).

    Attributes:
        iv (bytes): 16-byte initialization vector
        data (bytes): The encrypted data payload
        mac (bytes): 32-byte message authentication code
        algo (AlgoEnum): The encryption algorithm used

    The encrypted value format follows Bitwarden's standard:
    - Algorithm identifier (optional prefix)
    - Base64-encoded IV, data, and MAC separated by "|"
    - Format: "algorithm.iv|data|mac" or "iv|data|mac"
    """

    def __init__(self, algo: AlgoEnum, iv: bytes, data: bytes, mac: bytes):
        """
        Initialize an EncryptedValue with cryptographic components.

        Args:
            algo (AlgoEnum): The encryption algorithm used
            iv (bytes): 16-byte initialization vector
            data (bytes): The encrypted data payload
            mac (bytes): 32-byte message authentication code

        Raises:
            ValueError: If any component has invalid length or type
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes long")
        if len(data) == 0:
            raise ValueError("Data cannot be empty")
        if len(mac) != 32:
            raise ValueError("MAC must be 32 bytes long")
        if algo not in [item.value for item in AlgoEnum] and algo not in [
            item for item in AlgoEnum
        ]:
            raise ValueError("Invalid algorithm specified")
        self.iv = iv
        self.data = data
        self.mac = mac
        self.algo = algo

    @staticmethod
    def decode_internal(data: str) -> tuple[str, str, str]:
        """
        Parse the internal format of encrypted data.

        Splits encrypted data string into its three components: IV, data, and MAC.

        Args:
            data (str): Encrypted data string in format "iv|data|mac"

        Returns:
            tuple[str, str, str]: A tuple containing (iv, data, mac) as base64 strings

        Raises:
            ValueError: If the data format is invalid (not exactly 3 parts)
        """
        parts = data.split("|")
        if len(parts) != 3:
            raise ValueError("Invalid encrypted data format")
        return parts[0], parts[1], parts[2]

    @classmethod
    def decode(cls, encoded_data: str) -> tuple[AlgoEnum, str, str, str]:
        """
        Decode an encrypted data string into its components.

        Parses a Bitwarden encrypted string format and extracts the algorithm,
        IV, data, and MAC components. Handles both formats with and without
        algorithm prefixes.

        Args:
            encoded_data (str): Encrypted string in Bitwarden format

        Returns:
            tuple[AlgoEnum, str, str, str]: Tuple containing (algorithm, iv, data, mac)

        Raises:
            ValueError: If the encrypted data format is invalid

        Note:
            Supports two formats:
            - With algorithm: "algorithm.iv|data|mac"
            - Without algorithm: "iv|data|mac" (defaults to AES128)
        """
        parts: list[str] = encoded_data.split(".", 1)
        if len(parts) == 2:  # the encrypted data has a header
            iv, data, mac = cls.decode_internal(parts[1])
            if parts[0] == AlgoEnum.AES128.value or parts[0] == AlgoEnum.AES256.value:
                return (AlgoEnum(parts[0]), iv, data, mac)
        else:
            iv, data, mac = cls.decode_internal(encoded_data)
            return (AlgoEnum.AES128, iv, data, mac)

        raise ValueError("Invalid encrypted data format")

    @classmethod
    def from_str(cls, encrypted_str: str) -> "EncryptedValue":
        """
        Create an EncryptedValue from a Bitwarden encrypted string.

        Parses a complete Bitwarden encrypted string and creates an EncryptedValue
        instance with all components decoded from base64.

        Args:
            encrypted_str (str): Complete encrypted string in Bitwarden format

        Returns:
            EncryptedValue: New instance with decoded cryptographic components

        Raises:
            InvalidEncryptedFormat: If the string format is invalid or decoding fails
            ValueError: If base64 decoding fails for any component
        """
        try:
            algo, iv, data, mac = cls.decode(encrypted_str)
            return cls(
                algo=algo,
                iv=base64.b64decode(iv),
                data=base64.b64decode(data),
                mac=base64.b64decode(mac),
            )
        except ValueError as e:
            logger.debug("Failed to decode encrypted string: %s", encrypted_str)
            raise InvalidEncryptedFormat("Invalid encrypted format") from e

    @classmethod
    def from_data(cls, key: SymmetricCryptoKey, data: str) -> "EncryptedValue":
        """
        Create an EncryptedValue from raw encrypted data string.

        This method decodes the encrypted data string and verifies the MAC
        using the provided symmetric key. It raises an error if MAC verification
        fails.

        Args:
            key (SymmetricCryptoKey): The symmetric key for MAC verification
            data (str): Encrypted data string in Bitwarden format
        Returns:
            EncryptedValue: New EncryptedValue instance with verified components
        """
        iv = os.urandom(16)
        padded_data = cls._pad(data.encode("utf-8"))
        enc_data = cls.encrypt_aes(key.key, padded_data, iv)
        mac = cls.generate_mac(key.mac_key, iv, enc_data)
        algo = AlgoEnum.AES256 if len(key.key) == 32 else AlgoEnum.AES128
        return cls(algo=algo, iv=iv, data=enc_data, mac=mac)

    def to_str(self) -> str:
        """
        Convert the EncryptedValue to a Bitwarden encrypted string.

        Constructs the encrypted string format used by Bitwarden, including
        the algorithm identifier, base64-encoded IV, data, and MAC.

        Returns:
            str: Encrypted string in Bitwarden format
        """
        iv_b64 = base64.b64encode(self.iv).decode("utf-8")
        data_b64 = base64.b64encode(self.data).decode("utf-8")
        mac_b64 = base64.b64encode(self.mac).decode("utf-8")
        return f"{self.algo.value}.{iv_b64}|{data_b64}|{mac_b64}"

    @staticmethod
    def generate_mac(key: bytes, iv: bytes, encrypted_data: bytes) -> bytes:
        """
        Generate a message authentication code for the encrypted data.

        Creates an HMAC-SHA256 of the IV and encrypted data using the provided key.
        This MAC is used to verify the integrity and authenticity of the encrypted data.

        Args:
            key (bytes): The MAC key for HMAC generation

        Returns:
            bytes: 32-byte HMAC-SHA256 digest

        Note:
            The MAC is computed over the concatenation of IV + encrypted_data.
        """
        hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
        hmac_obj.update(iv)
        hmac_obj.update(encrypted_data)

        return hmac_obj.digest()

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """
        Remove PKCS7 padding from decrypted data.

        Args:
            data (bytes): Padded data to unpad
            key (bytes): The encryption key (unused but kept for signature compatibility)

        Returns:
            bytes: Unpadded data

        Raises:
            ValueError: If padding is invalid or corrupted
        """
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data)
        unpadded_data += unpadder.finalize()
        return unpadded_data

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data for AES encryption.

        Args:
            data (bytes): Data to be padded
        Returns:
            bytes: Padded data suitable for AES block size
        """
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        return padded_data

    def _decrypt_aes(self, key: bytes) -> bytes:
        """
        Decrypt the encrypted data using AES-CBC.

        Performs AES decryption in CBC mode using the stored IV and removes
        PKCS7 padding from the result.

        Args:
            key (bytes): The encryption key for AES decryption

        Returns:
            bytes: Decrypted and unpadded data

        Raises:
            ValueError: If decryption fails or padding is invalid
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(self.data) + decryptor.finalize()
        return self._unpad(data)

    @staticmethod
    def encrypt_aes(key: bytes, padded_data: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using AES-CBC with PKCS7 padding.

        Args:
            key (bytes): The encryption key for AES
            padded_data (bytes): The plaintext data to encrypt
            iv (bytes): The initialization vector for AES

        Returns:
            bytes: Encrypted data

        Note:
            You must ensure that `padded_data` is already padded to the AES block size.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    def decrypt(self, key: SymmetricCryptoKey) -> bytes:
        """
        Decrypt the encrypted value with authentication verification.

        Performs authenticated decryption by first verifying the MAC,
        then decrypting the data using the appropriate algorithm.

        Args:
            key (SymmetricCryptoKey): The symmetric key containing both
                                     encryption and MAC components

        Returns:
            bytes: The decrypted plaintext data

        Raises:
            HmacError: If MAC verification fails (indicates tampering or wrong key)
            ValueError: If decryption fails or data is corrupted
            InvalidEncryptionKeyError: If the key is invalid for the algorithm

        Note:
            This method ensures authenticated encryption by verifying the MAC
            before performing decryption, preventing tampering attacks.
        """
        mac = self.generate_mac(key.mac_key, self.iv, self.data)
        if not hmac.compare_digest(mac, self.mac):
            raise HmacError("MAC verification failed")

        return self._decrypt_aes(key.key)
