from re import S
from bws_sdk.client import BWSecretClient, UnauthorisedError
import pytest
from unittest.mock import MagicMock, patch, Mock
from bws_sdk.token import Auth
from bws_sdk.crypto import SymetricCryptoKey
from bws_sdk.bws_types import Region, BitwardenSecret
from bws_sdk.errors import ApiError, SecretParseError
from datetime import datetime
import requests


@pytest.fixture
def symkey():
    return MagicMock(spec=SymetricCryptoKey)


@pytest.fixture
def auth():
    auth = MagicMock(spec=Auth)
    auth.bearer_token = "test_bearer_token"
    auth.org_enc_key = MagicMock()
    auth.org_id = "test_org_id"
    return auth


@pytest.fixture
def region():
    region = MagicMock(spec=Region)
    region.api_url = "https://api.test.com"
    return region


@pytest.fixture
def mock_secret():
    return BitwardenSecret(
        id="secret_id",
        organizationId="org_id",
        key="encrypted_key",
        value="encrypted_value",
        creationDate=datetime.now(),
        revisionDate=datetime.now(),
    )


def test_client_initialization():
    region = MagicMock(spec=Region)
    with patch("bws_sdk.client.Auth.from_token") as mock_auth:
        mock_auth.return_value.bearer_token = "test_token"
        client = BWSecretClient(region, "access_token")
        assert client.region == region
        mock_auth.assert_called_once_with("access_token", region, None)


def test_client_initialization_invalid_region():
    with pytest.raises(ValueError, match="Region must be an instance of Reigon"):
        BWSecretClient("invalid_region", "access_token")


def test_client_initialization_invalid_access_token():
    region = MagicMock(spec=Region)
    with pytest.raises(ValueError, match="Access token must be a string"):
        BWSecretClient(region, 123)


def test_client_initialization_invalid_state_file():
    region = MagicMock(spec=Region)
    with pytest.raises(ValueError, match="State file must be a string or None"):
        BWSecretClient(region, "access_token", 123)


@patch("bws_sdk.client.Auth.from_token")
def test_get_by_id_success(mock_auth, region, mock_secret):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_enc_key = MagicMock()

    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "secret_id",
            "organizationId": "org_id",
            "key": "encrypted_key",
            "value": "encrypted_value",
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-01T00:00:00Z",
        }
        mock_get.return_value = mock_response

        with patch.object(client, "_parse_secret") as mock_parse:
            mock_parse.return_value = mock_secret
            result = client.get_by_id("secret_id")
            assert result == mock_secret
            mock_get.assert_called_once_with(f"{region.api_url}/secrets/secret_id")


def test_get_by_id_invalid_secret_id(region):
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Secret ID must be a string"):
            client.get_by_id(123)


@patch("bws_sdk.client.Auth.from_token")
def test_get_by_id_unauthorized(mock_auth, region):
    mock_auth.return_value.bearer_token = "test_token"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response

        with pytest.raises(UnauthorisedError):
            client.get_by_id("secret_id")


@patch("bws_sdk.client.Auth.from_token")
def test_get_by_id_api_error(mock_auth, region):
    mock_auth.return_value.bearer_token = "test_token"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        with pytest.raises(ApiError):
            client.get_by_id("secret_id")


@patch("bws_sdk.client.Auth.from_token")
def test_sync_success(mock_auth, region, mock_secret):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "secrets": {
                "data": [
                    {
                        "id": "secret_id",
                        "organizationId": "org_id",
                        "key": "encrypted_key",
                        "value": "encrypted_value",
                        "creationDate": "2023-01-01T00:00:00Z",
                        "revisionDate": "2023-01-01T00:00:00Z",
                    }
                ]
            }
        }
        mock_get.return_value = mock_response

        with patch.object(client, "_parse_secret") as mock_parse:
            mock_parse.return_value = mock_secret
            last_sync = datetime(2023, 1, 1)
            result = client.sync(last_sync)
            assert len(result) == 1
            assert result[0] == mock_secret


def test_sync_invalid_date(region):
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Last synced date must be a datetime object"):
            client.sync("invalid_date")


@patch("bws_sdk.client.Auth.from_token")
def test_sync_unauthorized(mock_auth, region):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response

        with pytest.raises(UnauthorisedError):
            client.sync(datetime.now())


@patch("bws_sdk.client.Auth.from_token")
def test_sync_empty_response(mock_auth, region):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"secrets": {}}
        mock_get.return_value = mock_response

        result = client.sync(datetime.now())
        assert result == []


@patch("bws_sdk.client.Auth.from_token")
@patch("bws_sdk.client.EncryptedValue")
def test_decrypt_secret_success(mock_encrypted_value, mock_auth, region, mock_secret):
    mock_auth.return_value.org_enc_key = MagicMock()
    client = BWSecretClient(region, "access_token")

    mock_decrypt = MagicMock()
    mock_decrypt.decode.return_value = "decrypted_value"
    mock_encrypted_value.from_str.return_value.decrypt.return_value = mock_decrypt

    result = client._decrypt_secret(mock_secret)
    assert result.key == "decrypted_value"
    assert result.value == "decrypted_value"


@patch("bws_sdk.client.Auth.from_token")
@patch("bws_sdk.client.EncryptedValue")
def test_decrypt_secret_unicode_error(mock_encrypted_value, mock_auth, region, mock_secret):
    mock_auth.return_value.org_enc_key = MagicMock()
    client = BWSecretClient(region, "access_token")

    mock_encrypted_value.from_str.return_value.decrypt.return_value.decode.side_effect = UnicodeDecodeError(
        "utf-8", b"", 0, 1, "error"
    )

    with pytest.raises(SecretParseError, match="Failed to decode secret value or key"):
        client._decrypt_secret(mock_secret)
