"""
BWS API client for interacting with Bitwarden Secrets Manager.

This module provides the main client class for interacting with the Bitwarden
Secrets Manager API. It handles authentication, encryption/decryption of secrets,
and provides methods for retrieving and synchronizing secrets.

Classes:
    BWSecretClient: Main client for BWS API interactions
"""

from datetime import datetime
from typing import Any

import requests

from .bws_types import BitwardenSecret, Region
from .crypto import (
    EncryptedValue,
)
from .errors import (
    ApiError,
    APIRateLimitError,
    CryptographyError,
    SecretNotFoundError,
    SecretParseError,
    SendRequestError,
    UnauthorisedError,
)
from .token import Auth


class BWSecretClient:
    """
    Client for interacting with the Bitwarden Secrets Manager API.

    This class provides methods to retrieve and synchronize secrets from the
    Bitwarden Secrets Manager. It handles authentication, automatic token refresh,
    and encryption/decryption of secret data.

    Attributes:
        region (Region): The BWS region configuration
        auth (Auth): Authentication handler
        session (requests.Session): HTTP session for API requests
    """

    def __init__(
        self, region: Region, access_token: str, state_file: str | None = None
    ):
        """
        Initialize the BWSecretClient.

        Args:
            region (Region): The BWS region configuration
            access_token (str): The BWS access token for authentication
            state_file (str | None): Optional path to state file for token persistence

        Raises:
            ValueError: If any of the input parameters are of incorrect type
            InvalidTokenError: If the access token format is invalid
            BWSSDKError: If authentication fails during initialization
            SendRequestError: If the initial authentication request fails
            UnauthorisedTokenError: If the token is invalid or expired
            ApiError: If the API returns an error during authentication
        """
        if not isinstance(region, Region):
            raise ValueError("Region must be an instance of Reigon")
        if not isinstance(access_token, str):
            raise ValueError("Access token must be a string")
        if state_file is not None and not isinstance(state_file, str):
            raise ValueError("State file must be a string or None")

        self.region = region
        self.auth = Auth.from_token(access_token, region, state_file)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.auth.bearer_token}",
                "User-Agent": "Bitwarden Rust-SDK",
                "Device-Type": "21",
            }
        )

    def _reload_auth(self) -> None:
        """
        Reload the authentication headers for the current session.

        Updates the session headers with the current bearer token from the auth object.
        This method is typically called when the authentication token has been refreshed
        or updated and needs to be applied to subsequent HTTP requests.

        Returns:
            None
        """
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.auth.bearer_token}",
            }
        )

    def _decrypt_secret(self, secret: BitwardenSecret) -> BitwardenSecret:
        """
        Decrypt an encrypted BitwardenSecret.

        Takes a BitwardenSecret with encrypted key and value fields and returns
        a new BitwardenSecret with decrypted key and value fields.

        Args:
            secret (BitwardenSecret): The encrypted secret to decrypt

        Returns:
            BitwardenSecret: A new BitwardenSecret with decrypted key and value

        Raises:
            SecretParseError: If the decrypted data cannot be decoded as UTF-8
        """
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
        except (UnicodeDecodeError, CryptographyError) as e:
            raise SecretParseError("Failed to decode secret value or key") from e

    def _parse_secret(self, data: dict[str, Any]) -> BitwardenSecret:
        """
        Parse and decrypt a secret from API response data.

        Validates the raw API response data into a BitwardenSecret model
        and then decrypts the secret's key and value fields.

        Args:
            data (dict[str, Any]): Raw secret data from the API response

        Returns:
            BitwardenSecret: The parsed and decrypted secret

        Raises:
            SecretParseError: If the secret cannot be decrypted or decoded
        """
        undec_secret = BitwardenSecret.model_validate(data)
        return self._decrypt_secret(undec_secret)

    def get_by_id(self, secret_id: str) -> BitwardenSecret:
        """
        Retrieve a secret by its unique identifier.

        Makes an authenticated request to the BWS API to retrieve a specific secret
        by its UUID. The returned secret will have its key and value automatically
        decrypted.

        Args:
            secret_id (str): The unique identifier (UUID) of the secret to retrieve

        Returns:
            BitwardenSecret: The retrieved and decrypted secret

        Raises:
            ValueError: If the provided secret_id is not a string
            UnauthorisedError: If the request is unauthorized (HTTP 401)
            ApiError: If the API returns a non-200 status code
            SecretParseError: If the secret cannot be parsed or decrypted
            SendRequestError: If the network request fails

        Example:
            ```python
            secret = client.get_by_id("550e8400-e29b-41d4-a716-446655440000")
            print(f"Secret key: {secret.key}")
            print(f"Secret value: {secret.value}")
            ```
        """

        if not isinstance(secret_id, str):
            raise ValueError("Secret ID must be a string")
        self._reload_auth()
        response = self.session.get(f"{self.region.api_url}/secrets/{secret_id}")
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        if response.status_code != 200:
            raise ApiError(
                f"Failed to retrieve secret: {response.status_code} {response.text}"
            )
        return self._parse_secret(response.json())

    def raise_errors(self, response: requests.Response) -> None:
        """
        Raise appropriate exceptions based on HTTP response status codes.

        Analyzes the HTTP response and raises specific BWS SDK exceptions
        based on the status code to provide meaningful error handling.

        Args:
            response (requests.Response): The HTTP response object to analyze

        Raises:
            UnauthorisedError: If the response status code is 401 (Unauthorized)
            SecretNotFoundError: If the response status code is 404 (Not Found)
            APIRateLimitError: If the response status code is 429 (Too Many Requests)
            ApiError: For any other non-200 status codes

        Note:
            This method does not return anything when the status code is 200.
            It only raises exceptions for error status codes.
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
        Synchronize secrets from the Bitwarden server since a specified date.

        Retrieves all secrets that have been created or modified since the provided
        last synced date. This method is useful for keeping local secret caches
        up to date with the server state.

        Args:
            last_synced_date (datetime): The datetime representing when secrets were last synced

        Returns:
            list[BitwardenSecret]: List of secrets created or modified since the last sync date

        Raises:
            ValueError: If last_synced_date is not a datetime object
            SendRequestError: If the network request fails
            UnauthorisedError: If the server returns a 401 Unauthorized response
            ApiError: If the API returns a non-200 status code
            SecretParseError: If any secret cannot be parsed or decrypted

        Example:
            ```python
            from datetime import datetime
            last_sync = datetime(2024, 1, 1)
            secrets = client.sync(last_sync)
            for secret in secrets:
                print(f"Secret: {secret.key} = {secret.value}")
            ```
        """

        if not isinstance(last_synced_date, datetime):
            raise ValueError("Last synced date must be a datetime object")

        lsd: str = last_synced_date.isoformat()
        try:
            self._reload_auth()

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
