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

from .bws_types import (
    BitwardenSecProject,
    BitwardenSecretCreate,
    BitwardenSecretResponse,
    BitwardenSecretRT,
    BitwardenSync,
    RatelimitInfo,
    Region,
)
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
                "User-Agent": "Bitwarden Python-SDK",
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

    def _decrypt_secret(
        self, secret: BitwardenSecretResponse
    ) -> BitwardenSecretResponse:
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
            projects_ids: list[BitwardenSecProject] = []
            for project in secret.projects:
                new_project = BitwardenSecProject(
                    id=project.id,
                    name=EncryptedValue.from_str(project.name)
                    .decrypt(self.auth.org_enc_key)
                    .decode("utf-8")
                    if project.name
                    else None,
                )
                projects_ids.append(new_project)
            return BitwardenSecretResponse(
                id=secret.id,
                organizationId=secret.organizationId,
                key=EncryptedValue.from_str(secret.key)
                .decrypt(self.auth.org_enc_key)
                .decode("utf-8"),
                value=EncryptedValue.from_str(secret.value)
                .decrypt(self.auth.org_enc_key)
                .decode("utf-8"),
                projects=projects_ids,
                creationDate=secret.creationDate,
                revisionDate=secret.revisionDate,
            )
        except (UnicodeDecodeError, CryptographyError) as e:
            raise SecretParseError("Failed to decode secret value or key") from e

    def _encrypt_secret(self, secret: BitwardenSecretCreate) -> BitwardenSecretCreate:
        """
        Encrypt a BitwardenSecretCreate.

        Takes a BitwardenSecretCreate with plaintext key and value fields and returns
        a new BitwardenSecretCreate with encrypted key and value fields.

        Args:
            secret (BitwardenSecretCreate): The plaintext secret to encrypt

        Returns:
            BitwardenSecretCreate: A new BitwardenSecretCreate with encrypted key and value

        Raises:
            SecretParseError: If the encryption process fails
        """
        try:
            encrypted_key = EncryptedValue.from_data(
                self.auth.org_enc_key, secret.key
            ).to_str()
            encrypted_value = EncryptedValue.from_data(
                self.auth.org_enc_key, secret.value
            ).to_str()
            encrypted_note = EncryptedValue.from_data(
                self.auth.org_enc_key, secret.note
            ).to_str()
            return BitwardenSecretCreate(
                key=encrypted_key,
                value=encrypted_value,
                note=encrypted_note,
                accessPoliciesRequests=secret.accessPoliciesRequests,
                projectIds=secret.projectIds,
            )
        except CryptographyError as e:
            raise SecretParseError("Failed to encrypt secret value or key") from e

    def _parse_secret(self, data: dict[str, Any]) -> BitwardenSecretResponse:
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
        undec_secret = BitwardenSecretResponse.model_validate(data)
        return self._decrypt_secret(undec_secret)

    def _parse_secret_rt(self, response: requests.Response) -> BitwardenSecretRT:
        """
        Parse and decrypt a secret from an HTTP response.

        Validates the API response data into a BitwardenSecret model
        and then decrypts the secret's key and value fields.

        Args:
            response (requests.Response): The HTTP response containing secret data
        Returns:
            BitwardenSecret: The parsed and decrypted secret
        Raises:
            SecretParseError: If the secret cannot be decrypted or decoded
        """
        parsed_secret = self._parse_secret(response.json())
        project = None
        if parsed_secret.projects and len(parsed_secret.projects) > 0:
            project = parsed_secret.projects[0]

        return BitwardenSecretRT(
            id=parsed_secret.id,
            organizationId=parsed_secret.organizationId,
            key=parsed_secret.key,
            value=parsed_secret.value,
            creationDate=parsed_secret.creationDate,
            revisionDate=parsed_secret.revisionDate,
            project=project,
            ratelimit=self._get_ratelimit_info(response),
        )

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
            raise SecretNotFoundError(response.text)
        elif response.status_code == 429:
            raise APIRateLimitError(response.text)
        elif response.status_code != 200:
            raise ApiError(f"Unexpected error: {response.status_code} {response.text}")

    def _get_ratelimit_info(self, response: requests.Response) -> RatelimitInfo:
        """
        Extract rate limit information from HTTP response headers.

        Args:
            response (requests.Response): The HTTP response object to extract headers from
        Returns:
            RatelimitInfo: The extracted rate limit information
        """
        return RatelimitInfo(
            limit=response.headers.get("x-rate-limit-limit", "1m"),
            remaining=int(response.headers.get("x-rate-limit-remaining", 0)),
            reset=datetime.fromisoformat(
                response.headers.get("x-rate-limit-reset", "1970-01-01T00:00:00Z")
            ),
        )

    def get_by_id(self, secret_id: str) -> BitwardenSecretRT | None:
        """
        Retrieve a secret by its unique identifier.

        Makes an authenticated request to the BWS API to retrieve a specific secret
        by its UUID. The returned secret will have its key and value automatically
        decrypted.

        Args:
            secret_id (str): The unique identifier (UUID) of the secret to retrieve

        Returns:
            BitwardenSecret | None: The retrieved and decrypted secret, or None if not found

        Raises:
            UnauthorisedError: If the response status code is 401 (Unauthorized)
            ValueError: If the provided secret_id is not a string
            UnauthorisedError: If the request is unauthorized (HTTP 401)
            ApiError: If the API returns a non-200 status code
            SecretParseError: If the secret cannot be parsed or decrypted
            SendRequestError: If the network request fails
            APIRateLimitError: If the response status code is 429 (Too Many Requests)

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
        if response.status_code == 404:
            return None
        self.raise_errors(response)
        return self._parse_secret_rt(response)

    def sync(self, last_synced_date: datetime) -> BitwardenSync:
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

        response_data = response.json()
        unc_secrets = response_data.get("secrets", {})
        ratelimit_info = RatelimitInfo(
            limit=response.headers.get("x-rate-limit-limit", "1m"),
            remaining=int(response.headers.get("x-rate-limit-remaining", 0)),
            reset=datetime.fromisoformat(
                response.headers.get("x-rate-limit-reset", "1970-01-01T00:00:00Z")
            ),
        )
        if response_data.get("hasChanges", False) is False:
            return BitwardenSync(secrets=None, ratelimit=ratelimit_info)

        decrypted_secrets = []
        if unc_secrets:
            for secret in unc_secrets.get("data", []):
                decrypted_secrets.append(self._parse_secret(secret))
        return BitwardenSync(
            secrets=decrypted_secrets, ratelimit=self._get_ratelimit_info(response)
        )

    def create(
        self, key: str, value: str, note: str, project_id: str
    ) -> BitwardenSecretRT:
        """
        Create a new secret on the Bitwarden server.

        Takes a BitwardenSecretCreate with plaintext key and value, encrypts it,
        and creates it on the server. Returns the created secret with decrypted values.

        Args:
            key (str): The key for the secret
            value (str): The value for the secret
            note (str): A note for the secret
            project_ids (list[str] | None): A list of project IDs the secret is associated with

        Returns:
            BitwardenSecret: The created secret with decrypted key and value

        Raises:
            ValueError: If the provided secret is not a BitwardenSecretCreate object
            UnauthorisedError: If the request is unauthorized (HTTP 401)
            ApiError: If the API returns a non-200 status code
            SecretParseError: If the secret cannot be encrypted or the response cannot be parsed
            SendRequestError: If the network request fails

        Example:
            ```python
            new_secret = BitwardenSecretCreate(
                key="api_key",
                value="secret_value_123",
                note="API key for external service"
            )
            created_secret = client.create(new_secret)
            print(f"Created secret with ID: {created_secret.id}")
            ```
        """
        if not isinstance(key, str):
            raise ValueError("Key must be a string")
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        if not isinstance(note, str):
            raise ValueError("Note must be a string")
        if not isinstance(project_id, str):
            raise ValueError("Project ID must be a string")

        # Encrypt the secret before sending to API
        secret = BitwardenSecretCreate(
            key=key,
            value=value,
            note=note,
            projectIds=[project_id],
        )
        encrypted_secret = self._encrypt_secret(secret)

        try:
            self._reload_auth()

            # Prepare the request payload

            response = self.session.post(
                f"{self.region.api_url}/organizations/{self.auth.org_id}/secrets",
                json=encrypted_secret.model_dump(exclude_none=True),
            )
        except requests.RequestException as e:
            raise SendRequestError(f"Failed to send create request: {e}")

        self.raise_errors(response)
        return self._parse_secret_rt(response)

    def update(
        self, secret_id: str, key: str, value: str, note: str, project_id: str
    ) -> BitwardenSecretRT:
        """
        Update an existing secret on the Bitwarden server.

        Args:
            secret_id (str): The unique identifier (UUID) of the secret to update
            key (str): The key for the secret
            value (str): The value for the secret
            note (str): A note for the secret
            project_ids (list[str] | None): A list of project IDs the secret is associated with

        Returns:
            BitwardenSecret: The updated secret with decrypted key and value

        Raises:
            ValueError: If the provided secret is not a BitwardenSecretUpdate object
            UnauthorisedError: If the request is unauthorized (HTTP 401)
            ApiError: If the API returns a non-200 status code
            SecretParseError: If the secret cannot be encrypted or the response cannot be parsed
            SendRequestError: If the network request fails

        Example:
            ```python
            updated_secret = BitwardenSecretUpdate(
                key="api_key",
                value="new_secret_value_456",
                note="Updated API key for external service"
            )
            result_secret = client.update(updated_secret)
            print(f"Updated secret with ID: {result_secret.id}")
            ```
        """
        if not isinstance(secret_id, str):
            raise ValueError("Secret ID must be a string")
        if not isinstance(key, str):
            raise ValueError("Key must be a string")
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        if not isinstance(note, str):
            raise ValueError("Note must be a string")
        if not isinstance(project_id, str):
            raise ValueError("Project ID must be a string")

        # Encrypt the secret before sending to API
        secret = BitwardenSecretCreate(
            key=key,
            value=value,
            note=note,
            projectIds=[project_id],
        )
        encrypted_secret = self._encrypt_secret(secret)

        try:
            self._reload_auth()

            # Prepare the request payload

            response = self.session.put(
                f"{self.region.api_url}/secrets/{secret_id}",
                json=encrypted_secret.model_dump(exclude_none=True),
            )
        except requests.RequestException as e:
            raise SendRequestError(f"Failed to send create request: {e}")

        self.raise_errors(response)
        return self._parse_secret_rt(response)

    def delete(self, secret_ids: list[str]) -> RatelimitInfo:
        """
        Delete secrets by their unique identifiers.

        Makes an authenticated request to the BWS API to delete specific secrets
        by their UUIDs.

        Args:
            secret_ids (list[str]): A list of unique identifiers (UUIDs) of the secrets to delete

        Returns:
            None

        Raises:
            ValueError: If secret_ids is not a list of strings
            UnauthorisedError: If the request is unauthorized (HTTP 401)
            ApiError: If the API returns a non-200 status code
            SendRequestError: If the network request fails

        Example:
            ```python
            client.delete(["550e8400-e29b-41d4-a716-446655440000"])
            print("Secret deleted successfully.")
            ```
        """

        if not isinstance(secret_ids, list):
            raise ValueError("Secret IDs must be a list of strings")
        if not all(isinstance(sid, str) for sid in secret_ids):
            raise ValueError("Each secret ID must be a string")
        if len(secret_ids) == 0:
            raise ValueError("Secret IDs list cannot be empty")

        try:
            self._reload_auth()

            response = self.session.post(
                f"{self.region.api_url}/secrets/delete",
                json=secret_ids,
            )
        except requests.RequestException as e:
            raise SendRequestError(f"Failed to send delete request: {e}")

        self.raise_errors(response)
        return self._get_ratelimit_info(response)
