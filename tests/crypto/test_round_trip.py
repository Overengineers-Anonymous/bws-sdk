"""
Round-trip encryption/decryption tests for the BWS SDK crypto module.

These tests validate that newly created encrypted values can be properly
decrypted, ensuring the integrity of the encryption/decryption process.
"""

import os

import pytest

from bws_sdk.crypto import (
    AlgoEnum,
    EncryptedValue,
    SymmetricCryptoKey,
)
from bws_sdk.errors import HmacError


class TestRoundTripEncryption:
    """Test suite for round-trip encryption/decryption validation."""

    @pytest.fixture
    def aes128_key(self):
        """Create a 32-byte key for AES128 testing."""
        return SymmetricCryptoKey(b"0" * 32)

    @pytest.fixture
    def aes256_key(self):
        """Create a 64-byte key for AES256 testing."""
        return SymmetricCryptoKey(b"1" * 64)

    @pytest.fixture
    def random_key(self):
        """Create a random key for additional testing."""
        return SymmetricCryptoKey(os.urandom(64))

    def test_encrypt_decrypt_simple_string(self, aes256_key):
        """Test encryption and decryption of a simple string."""
        original_data = "Hello, World!"

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        # Create encrypted value using from_data method

        # Verify the encrypted value has proper structure
        assert isinstance(encrypted_value, EncryptedValue)
        assert len(encrypted_value.iv) == 16
        assert len(encrypted_value.mac) == 32
        assert len(encrypted_value.data) > 0
        assert encrypted_value.algo == AlgoEnum.AES256

        # Decrypt and verify
        decrypted_data = encrypted_value.decrypt(aes256_key)
        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_empty_string(self, aes256_key):
        """Test encryption and decryption of an empty string."""
        original_data = ""

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data = encrypted_value.decrypt(aes256_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_unicode_string(self, aes256_key):
        """Test encryption and decryption of unicode characters."""
        original_data = "Hello 世界! 🌍 Testing émojis and spëcial cháracters"

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data = encrypted_value.decrypt(aes256_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_long_string(self, aes256_key):
        """Test encryption and decryption of a long string."""
        original_data = "A" * 10000  # 10KB of data

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data = encrypted_value.decrypt(aes256_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_binary_data(self, aes256_key):
        """Test encryption and decryption of binary data."""
        original_data = os.urandom(1024)  # Random binary data

        # Manually create encrypted value for binary data
        iv = os.urandom(16)
        padded_data = EncryptedValue._pad(original_data)
        encrypted_data = EncryptedValue.encrypt_aes(aes256_key.key, padded_data, iv)
        mac = EncryptedValue.generate_mac(aes256_key.mac_key, iv, encrypted_data)

        encrypted_value = EncryptedValue(algo=AlgoEnum.AES256, iv=iv, data=encrypted_data, mac=mac)

        decrypted_data = encrypted_value.decrypt(aes256_key)
        assert decrypted_data == original_data

    def test_encrypt_decrypt_with_aes128_key(self, aes128_key):
        """Test encryption and decryption using AES128 key."""
        original_data = "Testing with AES128 key"

        encrypted_value = EncryptedValue.from_data(aes128_key, original_data)

        # Verify it uses AES128 algorithm
        assert encrypted_value.algo == AlgoEnum.AES128

        decrypted_data = encrypted_value.decrypt(aes128_key)
        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_multiple_rounds(self, aes256_key):
        """Test multiple rounds of encryption/decryption."""
        original_data = "Multi-round test data"

        # First round
        encrypted_value1 = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data1 = encrypted_value1.decrypt(aes256_key)
        assert decrypted_data1 == original_data.encode("utf-8")

        # Second round with decrypted data
        encrypted_value2 = EncryptedValue.from_data(aes256_key, decrypted_data1.decode("utf-8"))
        decrypted_data2 = encrypted_value2.decrypt(aes256_key)
        assert decrypted_data2 == original_data.encode("utf-8")

    def test_encrypt_decrypt_different_keys_fail(self, aes256_key):
        """Test that decryption fails with wrong key."""
        original_data = "Secret data"
        wrong_key = SymmetricCryptoKey(b"2" * 64)

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)

        # Should fail with MAC verification error
        with pytest.raises(HmacError, match="MAC verification failed"):
            encrypted_value.decrypt(wrong_key)

    def test_encrypt_decrypt_random_keys(self, random_key):
        """Test encryption/decryption with randomly generated keys."""
        original_data = "Random key test"

        encrypted_value = EncryptedValue.from_data(random_key, original_data)
        decrypted_data = encrypted_value.decrypt(random_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_to_string_round_trip(self, aes256_key):
        """Test round-trip through string serialization."""
        original_data = "String serialization test"

        # Encrypt
        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)

        # Serialize to string
        encrypted_string = encrypted_value.to_str()

        # Deserialize from string
        deserialized_value = EncryptedValue.from_str(encrypted_string)

        # Decrypt and verify
        decrypted_data = deserialized_value.decrypt(aes256_key)
        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_derived_keys(self):
        """Test encryption/decryption with derived keys."""
        # Test with derive_symkey
        secret = os.urandom(16)
        derived_key = SymmetricCryptoKey.derive_symkey(secret, "test", "info")

        original_data = "Derived key test"
        encrypted_value = EncryptedValue.from_data(derived_key, original_data)
        decrypted_data = encrypted_value.decrypt(derived_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_from_encryption_key(self):
        """Test encryption/decryption with keys from encryption key."""
        encryption_key = os.urandom(16)
        key = SymmetricCryptoKey.from_encryption_key(encryption_key)

        original_data = "Encryption key derived test"
        encrypted_value = EncryptedValue.from_data(key, original_data)
        decrypted_data = encrypted_value.decrypt(key)

        assert decrypted_data == original_data.encode("utf-8")

    @pytest.mark.parametrize("data_size", [1, 15, 16, 17, 31, 32, 33, 64, 100, 1000])
    def test_encrypt_decrypt_various_sizes(self, aes256_key, data_size):
        """Test encryption/decryption with various data sizes."""
        original_data = "x" * data_size

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data = encrypted_value.decrypt(aes256_key)

        assert decrypted_data == original_data.encode("utf-8")

    def test_encrypt_decrypt_same_data_different_ivs(self, aes256_key):
        """Test that same data encrypted multiple times produces different ciphertext."""
        original_data = "Same data test"

        encrypted_value1 = EncryptedValue.from_data(aes256_key, original_data)
        encrypted_value2 = EncryptedValue.from_data(aes256_key, original_data)

        # IVs should be different (random)
        assert encrypted_value1.iv != encrypted_value2.iv

        # Encrypted data should be different due to different IVs
        assert encrypted_value1.data != encrypted_value2.data

        # MACs should be different due to different IVs
        assert encrypted_value1.mac != encrypted_value2.mac

        # But both should decrypt to the same original data
        decrypted_data1 = encrypted_value1.decrypt(aes256_key)
        decrypted_data2 = encrypted_value2.decrypt(aes256_key)

        assert decrypted_data1 == original_data.encode("utf-8")
        assert decrypted_data2 == original_data.encode("utf-8")
        assert decrypted_data1 == decrypted_data2

    def test_encrypt_decrypt_special_characters(self, aes256_key):
        """Test encryption/decryption with special characters and control codes."""
        # Include various special characters and control codes
        original_data = "Special: \n\t\r\0\x01\x02\xff"

        encrypted_value = EncryptedValue.from_data(aes256_key, original_data)
        decrypted_data = encrypted_value.decrypt(aes256_key)

        assert decrypted_data == original_data.encode("utf-8")
