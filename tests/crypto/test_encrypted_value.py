from re import S
from bws_sdk.crypto import HmacError, SymetricCryptoKey, EncryptedValue, AlgoEnum, InvalidEncryptedFormat
import pytest


def test_init():
    key = EncryptedValue(
        algo=AlgoEnum.AES256,
        iv=b"0" * 16,
        data=b"1" * 32,
        mac=b"2" * 32,
    )
    assert key.algo == AlgoEnum.AES256
    assert key.iv == b"0" * 16
    assert key.data == b"1" * 32
    assert key.mac == b"2" * 32
    with pytest.raises(ValueError, match="IV must be 16 bytes long"):
        EncryptedValue(
            algo=AlgoEnum.AES256,
            iv=b"0" * 15,
            data=b"1" * 32,
            mac=b"2" * 32,
        )
    with pytest.raises(ValueError, match="Data cannot be empty"):
        EncryptedValue(
            algo=AlgoEnum.AES256,
            iv=b"0" * 16,
            data=b"",
            mac=b"2" * 32,
        )
    with pytest.raises(ValueError, match="MAC must be 32 bytes long"):
        EncryptedValue(
            algo=AlgoEnum.AES256,
            iv=b"0" * 16,
            data=b"1" * 32,
            mac=b"2" * 31,
        )
    with pytest.raises(ValueError, match="Invalid algorithm specified"):
        EncryptedValue(
            algo="invalid_algo",  # This should be an AlgoEnum value
            iv=b"0" * 16,
            data=b"1" * 32,
            mac=b"2" * 32,
        )


def test_decrypt():
    enc_data = EncryptedValue(
        AlgoEnum.AES256,
        b"0" * 16,
        b";\x8c\xe2\x0e?F\x01\xb6\x9a\xa2\x03\xbaT\x87<\xe0\xedw&%\x83\xbf\xd4\xf81I5R\xa8d!\xa9Z\x15\x8e\xc1S\xff\x8bP\x91\xd3\x83\xecbU\xaa\x99",
        b"s\x8e_n\xfbp\x0b\xd7\x9d\xf4\xed\xd2\xb3%\xd7u0\x03\xe1\xbb\x12>d?}\xc5\xb7\x8dr\xfej\xcc",
    )
    enc_data2 = EncryptedValue(
        AlgoEnum.AES256,
        b"0" * 16,
        b";\x8c\xe2\x0e?F\x01\xb6\x9a\xa2\x03\xbaT\x87<\xe0\xedw&%\x83\xbf\xd4\xf81I5R\xa8d!\xa9Z\x15\x8e\xc1S\xff\x8bP\x91\xd3\x83\xecbU\xaa\x99",
        b"s\x8e_n\xfbp\x0b\xd7\x9d\xf4\xed\xd2\xb3%\xd7u0\x03\xe1\xbb\x12>d?}\xc5\xb7\x8dr\xfejp",
    )
    keys = SymetricCryptoKey(b"0" * 64)
    data = enc_data.decrypt(keys)
    assert data == b"0" * 32
    with pytest.raises(HmacError, match="MAC verification failed"):
        enc_data2.decrypt(keys)


def test_from_str():
    enc_str = (
        "2.MDAwMDAwMDAwMDAwMDAwMA==|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=|MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="
    )
    enc_data = EncryptedValue.from_str(enc_str)
    assert enc_data.algo == AlgoEnum.AES256
    assert enc_data.iv == b"0" * 16
    assert enc_data.data == b"1" * 32
    assert enc_data.mac == b"2" * 32

    enc_str2 = (
        "MDAwMDAwMDAwMDAwMDAwMA==|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=|MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="
    )
    enc_data2 = EncryptedValue.from_str(enc_str2)
    assert enc_data2.algo == AlgoEnum.AES128
    assert enc_data2.iv == b"0" * 16
    assert enc_data2.data == b"1" * 32
    assert enc_data2.mac == b"2" * 32


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            "4.MDAwMDAwMDAwMDAwMDAwMA==|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=|MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=",
            id="invalid_version",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=",
            id="missing_part",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMDA=|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=|MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=",
            id="invalid_length_iv",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=|MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy",
            id="invalid_length_mac",
        ),
    ],
)
def test_from_str_invalid(data):
    with pytest.raises(InvalidEncryptedFormat, match="Invalid encrypted format"):
        EncryptedValue.from_str(data)
