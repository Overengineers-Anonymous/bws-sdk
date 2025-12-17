from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from bws_sdk.bws_types import (
    BitwardenSecret,
    BitwardenSecretResponse,
    BitwardenSecretRT,
    BitwardenSync,
    Region,
)
from bws_sdk.client import BWSecretClient
from bws_sdk.crypto import SymmetricCryptoKey
from bws_sdk.errors import ApiError, SecretParseError, UnauthorisedError
from bws_sdk.token import Auth


@pytest.fixture
def symkey():
    return MagicMock(spec=SymmetricCryptoKey)


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
def mock_secret_response():
    """Mock BitwardenSecretResponse for API responses"""
    return BitwardenSecretResponse(
        id="secret_id",
        organizationId="org_id",
        key="encrypted_key",
        value="encrypted_value",
        projects=[],
        creationDate=datetime.now(),
        revisionDate=datetime.now(),
    )


@pytest.fixture
def mock_secret():
    """Mock BitwardenSecret for decrypted responses"""
    return BitwardenSecret(
        id="secret_id",
        organizationId="org_id",
        key="decrypted_key",
        value="decrypted_value",
        project=None,
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
def test_get_by_id_success(mock_auth, region, mock_secret_response):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_enc_key = MagicMock()

    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "100",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "id": "secret_id",
            "organizationId": "org_id",
            "key": "encrypted_key",
            "value": "encrypted_value",
            "projects": [],
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-01T00:00:00Z",
        }
        mock_get.return_value = mock_response

        with patch.object(client, "_parse_secret") as mock_parse:
            mock_parse.return_value = mock_secret_response
            result = client.get_by_id("secret_id")
            assert result is not None
            assert isinstance(result, BitwardenSecretRT)
            assert result.id == mock_secret_response.id
            assert result.ratelimit.remaining == 100
            mock_get.assert_called_once_with(f"{region.api_url}/secrets/secret_id")


@patch("bws_sdk.client.Auth.from_token")
def test_get_by_id_not_found(mock_auth, region, mock_secret):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_enc_key = MagicMock()

    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {
            "error": "Not Found",
        }
        mock_get.return_value = mock_response

        result = client.get_by_id("secret_id")
        assert result is None


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
def test_sync_success(mock_auth, region, mock_secret_response):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "95",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "hasChanges": True,
            "secrets": {
                "data": [
                    {
                        "id": "secret_id",
                        "organizationId": "org_id",
                        "key": "encrypted_key",
                        "value": "encrypted_value",
                        "projects": [],
                        "creationDate": "2023-01-01T00:00:00Z",
                        "revisionDate": "2023-01-01T00:00:00Z",
                    }
                ]
            },
        }
        mock_get.return_value = mock_response

        with patch.object(client, "_parse_secret") as mock_parse:
            mock_parse.return_value = mock_secret_response
            last_sync = datetime(2023, 1, 1)
            result = client.sync(last_sync)
            assert result is not None
            assert isinstance(result, BitwardenSync)
            assert result.secrets is not None
            assert len(result.secrets) == 1
            assert result.secrets[0] == mock_secret_response
            assert result.ratelimit.remaining == 95


@patch("bws_sdk.client.Auth.from_token")
def test_sync_no_changes(mock_auth, region, mock_secret_response):
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "98",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "hasChanges": False,
            "secrets": {"data": []},
        }
        mock_get.return_value = mock_response

        with patch.object(client, "_parse_secret") as mock_parse:
            mock_parse.return_value = mock_secret_response
            last_sync = datetime(2023, 1, 1)
            result = client.sync(last_sync)
            assert result is not None
            assert isinstance(result, BitwardenSync)
            assert result.secrets is None
            assert result.ratelimit.remaining == 98


def test_sync_invalid_date(region):
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(
            ValueError, match="Last synced date must be a datetime object"
        ):
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
        headers_dict = {
            "X-RateLimit-Limit": "1m",
            "X-RateLimit-Remaining": "97",
            "X-RateLimit-Reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {"secrets": {}, "hasChanges": False}
        mock_get.return_value = mock_response

        result = client.sync(datetime.now())
        assert result is not None
        assert isinstance(result, BitwardenSync)
        assert result.secrets is None


@patch("bws_sdk.client.Auth.from_token")
@patch("bws_sdk.client.EncryptedValue")
def test_decrypt_secret_success(
    mock_encrypted_value, mock_auth, region, mock_secret_response
):
    mock_auth.return_value.org_enc_key = MagicMock()
    client = BWSecretClient(region, "access_token")

    mock_decrypt = MagicMock()
    mock_decrypt.decode.return_value = "decrypted_value"
    mock_encrypted_value.from_str.return_value.decrypt.return_value = mock_decrypt

    result = client._decrypt_secret(mock_secret_response)
    assert result.key == "decrypted_value"
    assert result.value == "decrypted_value"


@patch("bws_sdk.client.Auth.from_token")
@patch("bws_sdk.client.EncryptedValue")
def test_decrypt_secret_unicode_error(
    mock_encrypted_value, mock_auth, region, mock_secret_response
):
    mock_auth.return_value.org_enc_key = MagicMock()
    client = BWSecretClient(region, "access_token")

    mock_encrypted_value.from_str.return_value.decrypt.return_value.decode.side_effect = UnicodeDecodeError(
        "utf-8", b"", 0, 1, "error"
    )

    with pytest.raises(SecretParseError, match="Failed to decode secret value or key"):
        client._decrypt_secret(mock_secret_response)


# Test create method
@patch("bws_sdk.client.Auth.from_token")
def test_create_success(mock_auth, region, mock_secret_response):
    """Test successful secret creation"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "100",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "id": "created_secret_id",
            "organizationId": "org_id",
            "key": "encrypted_key",
            "value": "encrypted_value",
            "projects": [],
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-01T00:00:00Z",
        }
        mock_post.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {
                "key": "encrypted",
                "value": "encrypted",
                "note": "encrypted",
                "projectIds": ["project1"],
            }

            with patch.object(client, "_parse_secret") as mock_parse:
                mock_parse.return_value = mock_secret_response

                result = client.create(
                    "test_key", "test_value", "test_note", "project1"
                )

                assert result is not None
                assert isinstance(result, BitwardenSecretRT)
                mock_post.assert_called_once_with(
                    f"{region.api_url}/organizations/org_id/secrets",
                    json={
                        "key": "encrypted",
                        "value": "encrypted",
                        "note": "encrypted",
                        "projectIds": ["project1"],
                    },
                )


def test_create_invalid_key(region):
    """Test create with invalid key type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Key must be a string"):
            client.create(123, "test_value", "test_note", "project1")


def test_create_invalid_value(region):
    """Test create with invalid value type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Value must be a string"):
            client.create("test_key", 123, "test_note", "project1")


def test_create_invalid_note(region):
    """Test create with invalid note type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Note must be a string"):
            client.create("test_key", "test_value", 123, "project1")


def test_create_invalid_project_id_type(region):
    """Test create with invalid project_id type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Project ID must be a string"):
            client.create("test_key", "test_value", "test_note", 123)


@patch("bws_sdk.client.Auth.from_token")
def test_create_unauthorized(mock_auth, region):
    """Test create with unauthorized response"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {"key": "encrypted"}

            with pytest.raises(UnauthorisedError):
                client.create("test_key", "test_value", "test_note", "project1")


@patch("bws_sdk.client.Auth.from_token")
def test_create_api_error(mock_auth, region):
    """Test create with API error response"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {"key": "encrypted"}

            with pytest.raises(ApiError):
                client.create("test_key", "test_value", "test_note", "project1")


@patch("bws_sdk.client.Auth.from_token")
@patch("bws_sdk.client.requests")
def test_create_network_error(mock_requests, mock_auth, region):
    """Test create with network error"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    # Mock session.post to raise RequestException
    mock_requests.RequestException = Exception
    client.session.post.side_effect = mock_requests.RequestException("Network error")

    with patch.object(client, "_encrypt_secret") as mock_encrypt:
        mock_encrypt.return_value.model_dump.return_value = {"key": "encrypted"}

        from bws_sdk.errors import SendRequestError

        with pytest.raises(SendRequestError, match="Failed to send create request"):
            client.create("test_key", "test_value", "test_note", "project1")


@patch("bws_sdk.client.Auth.from_token")
def test_create_encrypt_secret_called_correctly(mock_auth, region):
    """Test that _encrypt_secret is called with correct BitwardenSecretCreate object"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "100",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "id": "test",
            "organizationId": "org_id",
            "key": "enc_key",
            "value": "enc_value",
            "projects": [],
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-01T00:00:00Z",
        }
        mock_post.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {"test": "data"}

            with patch.object(client, "_parse_secret") as mock_parse:
                from bws_sdk.bws_types import BitwardenSecretResponse

                mock_parse.return_value = BitwardenSecretResponse(
                    id="test",
                    organizationId="org_id",
                    key="decrypted_key",
                    value="decrypted_value",
                    projects=[],
                    creationDate=datetime(2023, 1, 1),
                    revisionDate=datetime(2023, 1, 1),
                )

                client.create("test_key", "test_value", "test_note", "proj1")

                # Verify _encrypt_secret was called with correct BitwardenSecretCreate
                mock_encrypt.assert_called_once()
                secret_arg = mock_encrypt.call_args[0][0]

                from bws_sdk.bws_types import BitwardenSecretCreate

                assert isinstance(secret_arg, BitwardenSecretCreate)
                assert secret_arg.key == "test_key"
                assert secret_arg.value == "test_value"
                assert secret_arg.note == "test_note"
                assert secret_arg.projectIds == ["proj1"]


@patch("bws_sdk.client.Auth.from_token")
def test_create_reload_auth_called(mock_auth, region):
    """Test that _reload_auth is called before making the request"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "100",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "id": "test",
            "organizationId": "org_id",
            "key": "enc_key",
            "value": "enc_value",
            "projects": [],
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-01T00:00:00Z",
        }
        mock_post.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {"test": "data"}

            with patch.object(client, "_parse_secret") as mock_parse:
                from bws_sdk.bws_types import BitwardenSecretResponse

                mock_parse.return_value = BitwardenSecretResponse(
                    id="test",
                    organizationId="org_id",
                    key="decrypted_key",
                    value="decrypted_value",
                    projects=[],
                    creationDate=datetime(2023, 1, 1),
                    revisionDate=datetime(2023, 1, 1),
                )

                with patch.object(client, "_reload_auth") as mock_reload:
                    client.create("test_key", "test_value", "test_note", "project1")
                    mock_reload.assert_called_once()


# Update method tests
@patch("bws_sdk.client.Auth.from_token")
def test_update_success(mock_auth, region, mock_secret_response):
    """Test successful secret update"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "put") as mock_put:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "90",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {
            "id": "secret_id",
            "organizationId": "org_id",
            "key": "updated_key",
            "value": "updated_value",
            "projects": [],
            "creationDate": "2023-01-01T00:00:00Z",
            "revisionDate": "2023-01-02T00:00:00Z",
        }
        mock_put.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {
                "key": "encrypted_updated",
                "value": "encrypted_updated",
                "note": "encrypted_note",
                "projectIds": ["project1"],
            }

            with patch.object(client, "_parse_secret") as mock_parse:
                mock_parse.return_value = mock_secret_response

                result = client.update(
                    "secret_id",
                    "updated_key",
                    "updated_value",
                    "updated_note",
                    "project1",
                )

                assert result is not None
                assert isinstance(result, BitwardenSecretRT)
                mock_put.assert_called_once_with(
                    f"{region.api_url}/secrets/secret_id",
                    json={
                        "key": "encrypted_updated",
                        "value": "encrypted_updated",
                        "note": "encrypted_note",
                        "projectIds": ["project1"],
                    },
                )


def test_update_invalid_secret_id(region):
    """Test update with invalid secret_id type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Secret ID must be a string"):
            client.update(123, "key", "value", "note", "project1")


def test_update_invalid_key(region):
    """Test update with invalid key type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Key must be a string"):
            client.update("secret_id", 123, "value", "note", "project1")


def test_update_invalid_value(region):
    """Test update with invalid value type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Value must be a string"):
            client.update("secret_id", "key", 123, "note", "project1")


def test_update_invalid_note(region):
    """Test update with invalid note type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Note must be a string"):
            client.update("secret_id", "key", "value", 123, "project1")


def test_update_invalid_project_id(region):
    """Test update with invalid project_id type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Project ID must be a string"):
            client.update("secret_id", "key", "value", "note", 123)


@patch("bws_sdk.client.Auth.from_token")
def test_update_unauthorized(mock_auth, region):
    """Test update with unauthorized response"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "put") as mock_put:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_put.return_value = mock_response

        with patch.object(client, "_encrypt_secret") as mock_encrypt:
            mock_encrypt.return_value.model_dump.return_value = {"key": "encrypted"}

            with pytest.raises(UnauthorisedError):
                client.update("secret_id", "key", "value", "note", "project1")


# Delete method tests
@patch("bws_sdk.client.Auth.from_token")
def test_delete_success(mock_auth, region):
    """Test successful secret deletion"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        headers_dict = {
            "x-rate-limit-limit": "1m",
            "x-rate-limit-remaining": "85",
            "x-rate-limit-reset": "2023-01-01T00:00:00Z",
        }
        mock_response.headers.get = lambda k, d=None: headers_dict.get(k, d)
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        result = client.delete(["secret_id_1", "secret_id_2"])

        from bws_sdk.bws_types import RatelimitInfo

        assert isinstance(result, RatelimitInfo)
        assert result.remaining == 85
        mock_post.assert_called_once_with(
            f"{region.api_url}/secrets/delete",
            json=["secret_id_1", "secret_id_2"],
        )


def test_delete_invalid_type(region):
    """Test delete with invalid secret_ids type"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Secret IDs must be a list of strings"):
            client.delete("not_a_list")


def test_delete_invalid_element(region):
    """Test delete with invalid secret_id elements"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Each secret ID must be a string"):
            client.delete(["secret_id", 123])


def test_delete_empty_list(region):
    """Test delete with empty list"""
    with patch("bws_sdk.client.Auth.from_token"):
        client = BWSecretClient(region, "access_token")
        with pytest.raises(ValueError, match="Secret IDs list cannot be empty"):
            client.delete([])


@patch("bws_sdk.client.Auth.from_token")
def test_delete_unauthorized(mock_auth, region):
    """Test delete with unauthorized response"""
    mock_auth.return_value.bearer_token = "test_token"
    mock_auth.return_value.org_id = "org_id"
    client = BWSecretClient(region, "access_token")

    with patch.object(client.session, "post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        with pytest.raises(UnauthorisedError):
            client.delete(["secret_id"])
