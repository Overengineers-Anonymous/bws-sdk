from bws_sdk.crypto import SymetricCryptoKey
from bws_sdk.token import ClientToken, InvalidTokenError
import pytest

def test_client_token():
    sem_key = SymetricCryptoKey(b"0"*64)
    token = ClientToken("test_client_id", "test_client_secret", sem_key)
    assert token.access_token_id == "test_client_id"
    assert token.client_secret == "test_client_secret"
    assert token.encryption_key == sem_key

def test_client_token_from_str():
    token_str = "0.test_client_id.test_client_secret:MDAwMDAwMDAwMDAwMDAwMA=="
    token = ClientToken.from_str(token_str)
    assert token.access_token_id == "test_client_id"
    assert token.client_secret == "test_client_secret"
    assert token.encryption_key == SymetricCryptoKey(
        b'\x8c\xb1\xd5\xc21j\x17 _\x9e\x1a\x08\x05r\x9b\xcdN\xe9\x1b;,7\x85Es2\x83\xcaA\x86\x03\xa3\xe6\x85\xd7\x16\x11\r\x131"\xc9*\xd7H\x99\xdc#G\xabL\t\x12]g{\x91Hq\x16>\xae\x86u'
    )

def test_client_token_invalid_version():
    token_str = "1.test_client_id.test_client_secret:b'MDAwMDAwMDAwMDAwMDAwMA=="
    with pytest.raises(InvalidTokenError, match="Unsupported Token Version"):
        ClientToken.from_str(token_str)

def test_client_token_invalid_token_format():
    token_str = "0.test_client_id.test_client_secret:b'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
    with pytest.raises(InvalidTokenError, match="Invalid Token"):
        ClientToken.from_str(token_str)
