import pytest
from bws_sdk.crypto import SymetricCryptoKey, InvalidEncryptionKeyError

def test_init():
    key = SymetricCryptoKey(b"0" * 64)
    assert key.key == b"0" * 32
    assert key.mac_key == b"0" * 32

    key = SymetricCryptoKey(b"1" * 32)
    assert key.key == b"1" * 16
    assert key.mac_key == b"1" * 16

    with pytest.raises(InvalidEncryptionKeyError, match="Key must be 64 or 32 bytes long"):
        SymetricCryptoKey(b"0" * 15)

def test_derive_symkey():
    secret = b"0" * 16
    key = SymetricCryptoKey.derive_symkey(secret, "test_name", "test_info")
    assert key.key == b"\x0c\xd9\xb2\xc5\x9dlE\xde\xfb\xb3\xd3\x06>(k\xb2\x8c<{\xeb\xe8\xcd0\x8f\x7f2\x87f\xf3\xcb\x132"
    assert key.mac_key == b"\"\x04m9\x19\xc1w\xa6\xdb\xea\x89\xb4u\xe1\xdf\xb2\xbbN'A\xae3\xf7\tt\xaa\xba\x95\xde(c\xe0"

    with pytest.raises(ValueError, match="Secret must be exactly 16 bytes"):
        SymetricCryptoKey.derive_symkey(b"0" * 15, "test_name", "test_info")

def test_from_encryption_key():
    encryption_key = b"0" * 16
    key = SymetricCryptoKey.from_encryption_key(encryption_key)
    assert key.key == b"\x8c\xb1\xd5\xc21j\x17 _\x9e\x1a\x08\x05r\x9b\xcdN\xe9\x1b;,7\x85Es2\x83\xcaA\x86\x03\xa3"
    assert key.mac_key == b'\xe6\x85\xd7\x16\x11\r\x131"\xc9*\xd7H\x99\xdc#G\xabL\t\x12]g{\x91Hq\x16>\xae\x86u'

    with pytest.raises(ValueError, match="Invalid encryption key length"):
        SymetricCryptoKey.from_encryption_key(b"0" * 15)

def test_eq():
    key1 = SymetricCryptoKey(b"0" * 64)
    key2 = SymetricCryptoKey(b"0" * 64)
    key3 = SymetricCryptoKey(b"1" * 64)
    assert key1 == key2
    assert key1 != key3

    with pytest.raises(ValueError, match="Comparison is only supported between SymetricCryptoKey instances"):
        key4 = "not_a_key"
        d = key1 == key4

def test_to_base64():
    key = SymetricCryptoKey(b"0" * 64)
    base64_key = key.to_base64()
    assert base64_key == "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA=="
