from datetime import datetime
from typing import Any

import requests

from .bws_types import BitwardenSecret, Region
from .crypto import (
    EncryptedValue,
)
from .errors import ApiError, SendRequestError
from .token import (
    Auth,
    InvalidIdentityResponseError,
    UnauthorisedToken,
)
from .token import (
    InvalidTokenError as TokenInvalidTokenError,
)


class SecretParseError(ApiError): ...


class UnauthorisedError(ApiError): ...


class SecretNotFoundError(ApiError): ...


class APIRateLimitError(ApiError): ...


class InvalidTokenError(ApiError): ...


class BWSecretClient:
    """
    BWSSecretClient provides methods to interact with the Bitwarden Secrets Manager API, enabling retrieval of secrets for a given access_token.
    """

    def __init__(
        self, region: Region, access_token: str, state_file: str | None = None
    ):
        if not isinstance(region, Region):
            raise ValueError("Region must be an instance of Reigon")
        if not isinstance(access_token, str):
            raise ValueError("Access token must be a string")
        if state_file is not None and not isinstance(state_file, str):
            raise ValueError("State file must be a string or None")

        self.region = region
        try:
            self.auth = Auth.from_token(access_token, region, state_file)
        except TokenInvalidTokenError as e:
            raise InvalidTokenError("Invalid access token format") from e
        except InvalidIdentityResponseError as e:
            raise InvalidTokenError("Invalid access token") from e
        except UnauthorisedToken as e:
            raise InvalidTokenError("Access token unauthorized") from e
        except (SendRequestError, ApiError) as e:
            raise InvalidTokenError("Failed to authenticate with token") from e
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.auth.bearer_token}",
                "User-Agent": "Bitwarden Rust-SDK",
                "Device-Type": "21",
            }
        )

    def _decrypt_secret(self, secret: BitwardenSecret) -> BitwardenSecret:
        try:
            return BitwardenSecret(
                id=secret.id,
                organizationId=secret.organizationId,
                key=EncryptedValue.from_str(secret.key)
                .decrypt(self.auth.org_enc_key)
                .decode("utf-8"),
                value=EncryptedValue.from_str(secret.value)
                .decrypt(self.auth.org_enc_key)
                .decode("utf-8"),
                creationDate=secret.creationDate,
                revisionDate=secret.revisionDate,
            )
        except UnicodeDecodeError as e:
            raise SecretParseError("Failed to decode secret value or key") from e

    def _parse_secret(self, data: dict[str, Any]) -> BitwardenSecret:
        undec_secret = BitwardenSecret.model_validate(data)
        return self._decrypt_secret(undec_secret)

    def get_by_id(self, secret_id: str) -> BitwardenSecret:
        """
        Retrieve a secret by its unique identifier.
        Args:
            secret_id (str): The unique identifier of the secret to retrieve.
        Returns:
            BitwardenSecret: The parsed and decrypted secret data.
        Raises:
            ValueError: If the provided secret_id is not a string.
            UnauthorisedError: If the request is unauthorized (HTTP 401).
            SecretParseError: If a secret cannot be parsed or decrypted.
        """

        if not isinstance(secret_id, str):
            raise ValueError("Secret ID must be a string")
        response = self.session.get(f"{self.region.api_url}/secrets/{secret_id}")
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        if response.status_code != 200:
            raise ApiError(
                f"Failed to retrieve secret: {response.status_code} {response.text}"
            )
        return self._parse_secret(response.json())

    def raise_errors(self, response: requests.Response):
        """
        Raises appropriate exceptions based on the response status code.
        Args:
            response (requests.Response): The HTTP response object.
        Raises:
            UnauthorisedError: If the response status code is 401.
            SecretNotFoundError: If the response status code is 404.
            APIRateLimitError: If the response status code is 429.
            SendRequestError: For other non-200 status codes.
        """
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        elif response.status_code == 404:
            raise SecretNotFoundError("Secret not found")
        elif response.status_code == 429:
            raise APIRateLimitError("API rate limit exceeded")
        elif response.status_code != 200:
            raise ApiError(f"Unexpected error: {response.status_code} {response.text}")

    def sync(self, last_synced_date: datetime) -> list[BitwardenSecret]:
        """
        Synchronizes secrets from the Bitwarden server since the specified last synced date.
        Args:
            last_synced_date (datetime): The datetime object representing the last time secrets were synced.
        Returns:
            list[BitwardenSecret]: The parsed and decrypted secrets data.

        Raises:
            ValueError: If last_synced_date is not a datetime object.
            UnauthorisedError: If the server returns a 401 Unauthorized response.
            SecretParseError: If a secret cannot be parsed or decrypted.
        """

        if not isinstance(last_synced_date, datetime):
            raise ValueError("Last synced date must be a datetime object")

        lsd: str = last_synced_date.isoformat()
        try:
            response = self.session.get(
                f"{self.region.api_url}/organizations/{self.auth.org_id}/secrets/sync",
                params={"lastSyncedDate": lsd},
            )
        except requests.RequestException as e:
            raise SendRequestError(f"Failed to send sync request: {e}")
        self.raise_errors(response)
        unc_secrets = response.json().get("secrets", {})
        decrypted_secrets = []
        if unc_secrets:
            for secret in unc_secrets.get("data", []):
                decrypted_secrets.append(self._parse_secret(secret))
        return decrypted_secrets
