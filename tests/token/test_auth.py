import datetime
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bws_sdk.bws_types import Region
from bws_sdk.crypto import SymetricCryptoKey
from bws_sdk.token import Auth, ClientToken, InvalidIdentityResponseError


@pytest.fixture
def client_token():
    return ClientToken(
        access_token_id="test_client_id",
        client_secret="test_client_secret",
        encryption_key=SymetricCryptoKey(b"0" * 64),
    )


@pytest.fixture
def region():
    return Region(
        api_url="https://api.example.com",
        identity_url="https://identity.example.com",
    )


def test_auth_initialization(client_token, region):
    with (
        patch("requests.post") as mock_post,
        patch(
            "bws_sdk.token.Auth._identity_from_state_file"
        ) as mock_identity_from_state_file,
        patch("builtins.open") as mock_open,
        patch("jwt.decode_complete") as mock_jwt_decode,
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "encrypted_payload": "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=",
        }
        mock_post.return_value = mock_response
        mock_jwt_decode.return_value = {
            "payload": {
                "exp": int(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(seconds=3600 * 24)
                    ).timestamp()
                ),
                "organization": "test_org_id",
            }
        }

        auth = Auth(client_token=client_token, region=region)

        mock_post.assert_called_once_with(
            f"{region.identity_url}/connect/token",
            data="scope=api.secrets&grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret",  # The actual data is not important for this test
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Device-Type": "21",
            },
        )

        mock_open.assert_not_called()
        mock_identity_from_state_file.assert_not_called()
        assert auth.state_file is None
        assert auth.region == region
        assert auth.client_token == client_token
        assert auth.bearer_token == "test_access_token"
        assert auth.org_id == "test_org_id"
        assert auth.org_enc_key == SymetricCryptoKey(b"0" * 64)


def test_auth_initialization_state_file(client_token, region):
    with (
        patch("requests.post") as mock_post,
        patch("bws_sdk.token.Auth._identity_request") as mock_identity_request,
        patch("jwt.decode_complete") as mock_jwt_decode,
        tempfile.NamedTemporaryFile(mode="w", delete_on_close=False) as state_file,
    ):
        state_file.write(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=|test_access_token"
        )
        state_file.flush()

        mock_jwt_decode.return_value = {
            "payload": {
                "exp": int(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(seconds=3600 * 24)
                    ).timestamp()
                ),
                "organization": "test_org_id",
            }
        }

        auth = Auth(
            client_token=client_token, region=region, state_file=state_file.name
        )

        mock_post.assert_not_called()
        mock_identity_request.assert_not_called()
        assert auth.state_file == Path(state_file.name)
        assert auth.region == region
        assert auth.client_token == client_token
        assert auth.bearer_token == "test_access_token"
        assert auth.org_id == "test_org_id"
        assert auth.org_enc_key == SymetricCryptoKey(b"0" * 64)


@pytest.mark.parametrize(
    "invalid_data",
    [
        pytest.param("invalid_token", id="invalid_token"),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=|test_access_token",
            id="invalid_enc_iv_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=|test_access_token",
            id="invalid_enc_data_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI|test_access_token",
            id="invalid_enc_mac_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|AEOCkEbAsccmfGDv9Bh0Uv5bi2gUIDySPwsUdO67kS3EDrvf4UZS8KGLgGeSt2iqNIgn0/Y7K8+2hCn5P9DE6RLBZPSHW+WMvziKvJ2+EcO/yFHboIRAQXpJTfVj2GLpKmSD+OYBlFpstbemo3O+HA==|iL+NlUtVhrz1lQdR1di5xLVQo6IHVRNgF7Fw04I/0X8=|test_access_token",
            id="invalid_dcrpt_payload",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHFUWauyJJcggcfH91yRpOlQ==|om+95qmgKZ4nh36D6thK/wLqRC4J0572MbsNFvULxnA=|test_access_token",
            id="invalid_dcrpt_payload_base64",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|iL+NlUtVhrz1lQdR1di5xLVQo6IHVRNgF7Fw04I/0X8=|test_access_token",
            id="invalid_mac_sig",
        ),
    ],
)
def test_auth_initialization_state_file_invalid(client_token, region, invalid_data):
    with (
        patch("requests.post") as mock_post,
        patch("jwt.decode_complete") as mock_jwt_decode,
        tempfile.NamedTemporaryFile(mode="w", delete_on_close=False) as state_file,
    ):
        state_file.write(invalid_data)
        state_file.flush()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "encrypted_payload": "2.'MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=",
        }
        mock_post.return_value = mock_response
        mock_jwt_decode.return_value = {
            "payload": {
                "exp": int(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(seconds=3600 * 24)
                    ).timestamp()
                ),
                "organization": "test_org_id",
            }
        }

        auth = Auth(
            client_token=client_token, region=region, state_file=state_file.name
        )

        mock_post.assert_called_once_with(
            f"{region.identity_url}/connect/token",
            data="scope=api.secrets&grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret",  # The actual data is not important for this test
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Device-Type": "21",
            },
        )

        assert auth.state_file == Path(state_file.name)
        assert auth.region == region
        assert auth.client_token == client_token
        assert auth.bearer_token == "test_access_token"
        assert auth.org_id == "test_org_id"
        assert auth.org_enc_key == SymetricCryptoKey(b"0" * 64)


@pytest.mark.parametrize(
    "invalid_data",
    [
        pytest.param("invalid_token", id="invalid_token"),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=",
            id="invalid_enc_iv_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI=",
            id="invalid_enc_data_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|dSaC3pJYzxNZNgEDx+rZFpV/MDlJNbQR31jkQWi5fXI",
            id="invalid_enc_mac_encoding",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|AEOCkEbAsccmfGDv9Bh0Uv5bi2gUIDySPwsUdO67kS3EDrvf4UZS8KGLgGeSt2iqNIgn0/Y7K8+2hCn5P9DE6RLBZPSHW+WMvziKvJ2+EcO/yFHboIRAQXpJTfVj2GLpKmSD+OYBlFpstbemo3O+HA==|iL+NlUtVhrz1lQdR1di5xLVQo6IHVRNgF7Fw04I/0X8=",
            id="invalid_dcrpt_payload",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHFUWauyJJcggcfH91yRpOlQ==|om+95qmgKZ4nh36D6thK/wLqRC4J0572MbsNFvULxnA=",
            id="invalid_dcrpt_payload_base64",
        ),
        pytest.param(
            "2.MDAwMDAwMDAwMDAwMDAwMA==|Rf21twoJicVfk3W2YblNBs7fZuQkVoJhcAv3r1TrXlKGXn4qf/djHhTGFzlDGqhzFArAFgFuWhRW5o/NSLVSr0olShtlp1K9te+7EHTu5+eOfMYExpRtuFmBrU1rp8IHlZvYmF0LKNryuOreCgg5hg==|iL+NlUtVhrz1lQdR1di5xLVQo6IHVRNgF7Fw04I/0X8=",
            id="invalid_mac_sig",
        ),
    ],
)
def test_auth_initialization_invalid_identity_response(
    client_token, region, invalid_data
):
    with (
        patch("requests.post") as mock_post,
        patch("jwt.decode_complete") as mock_jwt_decode,
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "encrypted_payload": invalid_data,
        }
        mock_post.return_value = mock_response
        mock_jwt_decode.return_value = {
            "payload": {
                "exp": int(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(seconds=3600 * 24)
                    ).timestamp()
                ),
                "organization": "test_org_id",
            }
        }

        with pytest.raises(
            InvalidIdentityResponseError,
            match="BWS API returned an invalid identity response",
        ):
            Auth(client_token=client_token, region=region)

        mock_post.assert_called_once_with(
            f"{region.identity_url}/connect/token",
            data="scope=api.secrets&grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret",  # The actual data is not important for this test
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Device-Type": "21",
            },
        )
