"""
Token management module for the BWS SDK.

This module provides authentication and token management functionality for the
Bitwarden Web Service (BWS) SDK. It handles client token parsing, identity
requests, and OAuth token management with automatic refresh capabilities.

Classes:
    ClientToken: Represents a BWS client authentication token
    IdentityRequest: Model for OAuth identity requests
    Auth: Main authentication handler with token management
"""

import base64
import binascii
import datetime
import json
from pathlib import Path
from urllib.parse import urlencode

import jwt
import requests
from pydantic import BaseModel

from .bws_types import Region
from .crypto import (
    EncryptedValue,
    InvalidEncryptionKeyError,
    SymmetricCryptoKey,
)
from .errors import (
    ApiError,
    BWSSDKError,
    InvalidIdentityResponseError,
    InvalidStateFileError,
    InvalidTokenError,
    SendRequestError,
    UnauthorisedTokenError,
)


class ClientToken:
    """
    Represents a BWS client authentication token.

    This class encapsulates the client token components required for
    authenticating with the BWS API, including the access token ID,
    client secret, and encryption key.

    Attributes:
        access_token_id (str): The unique identifier for the access token
        client_secret (str): The client secret for authentication
        encryption_key (SymmetricCryptoKey): The encryption key for data encryption/decryption
    """

    def __init__(
        self,
        access_token_id: str,
        client_secret: str,
        encryption_key: SymmetricCryptoKey,
    ):
        """
        Initialize a ClientToken instance.

        Args:
            access_token_id (str): The unique identifier for the access token
            client_secret (str): The client secret for authentication
            encryption_key (SymmetricCryptoKey): The encryption key for data encryption/decryption
        """
        self.access_token_id = access_token_id
        self.client_secret = client_secret
        self.encryption_key = encryption_key

    @classmethod
    def from_str(cls, token_str: str) -> "ClientToken":
        """
        Create a ClientToken instance from a token string.

        Parses a BWS token string in the format "version.access_token_id.client_secret:encryption_key"
        and creates a ClientToken instance with the extracted components.

        Args:
            token_str (str): The BWS token string to parse

        Returns:
            ClientToken: A new ClientToken instance

        Raises:
            InvalidTokenError: If the token version is unsupported (not "0")
            InvalidTokenError: If the encryption key length is invalid (not 16 bytes)
            ValueError: If the token string format is invalid or cannot be split properly
        """
        token_info, encryption_key = token_str.split(":")
        version, access_token_id, client_secret = token_info.split(
            ".",
        )
        encryption_key = base64.b64decode(encryption_key)
        if version != "0":
            raise InvalidTokenError("Unsupported Token Version")
        if len(encryption_key) != 16:
            raise InvalidTokenError("Invalid Token")
        return cls(
            access_token_id=access_token_id,
            client_secret=client_secret,
            encryption_key=SymmetricCryptoKey.from_encryption_key(encryption_key),
        )


class IdentityRequest(BaseModel):
    """
    Model for OAuth identity requests to the BWS API.

    This Pydantic model represents the data structure required for
    authentication requests to obtain OAuth tokens from the BWS identity service.

    Attributes:
        scope (str): The OAuth scope for the request (default: "api.secrets")
        grant_type (str): The OAuth grant type (default: "client_credentials")
        client_id (str): The client identifier for authentication
        client_secret (str): The client secret for authentication
    """

    scope: str = "api.secrets"
    grant_type: str = "client_credentials"
    client_id: str
    client_secret: str

    def to_query_string(self) -> str:
        """
        Convert the identity request to a URL-encoded query string.

        Returns:
            str: URL-encoded string representation of the request data
        """
        return urlencode(self.model_dump())


class Auth:
    """
    Main authentication handler for the BWS SDK.

    This class manages OAuth authentication with the BWS API, including
    token refresh, state file management, and organization encryption
    key handling. It provides automatic token refresh and persistent
    authentication state.

    Attributes:
        state_file (Path | None): Optional path to the state file for token persistence
        region (Region): The BWS region configuration
        client_token (ClientToken): The client authentication token
        oauth_jwt (dict): Decoded OAuth JWT token information
        org_enc_key (SymmetricCryptoKey): Organization encryption key
    """

    def __init__(
        self, client_token: ClientToken, region: Region, state_file: str | None = None
    ):
        """
        Initialize the Auth instance.

        Args:
            client_token (ClientToken): The client authentication token
            region (Region): The BWS region configuration
            state_file (str | None): Optional path to state file for token persistence

        Raises:
            BWSSDKError: If authentication fails
            InvalidIdentityResponseError: If the identity response is invalid
            SendRequestError: If the network request fails
            UnauthorisedTokenError: If the token is invalid or expired
            ApiError: If the API returns an error response
        """
        self.state_file = Path(state_file) if state_file else None
        self.region = region
        self.client_token = client_token
        self._authenticate()

    def _authenticate(self) -> None:
        """
        Perform initial authentication.

        Attempts to load authentication state from the state file if available,
        otherwise performs a new identity request to authenticate with the BWS API.

        Raises:
            BWSSDKError: If authentication fails
            InvalidStateFileError: If the state file format is invalid
            InvalidIdentityResponseError: If the identity response is invalid
            SendRequestError: If the network request fails
            UnauthorisedTokenError: If the token is invalid or expired
            ApiError: If the API returns an error response
        """
        try:
            if self.state_file and self.state_file.exists():
                return self._identity_from_state_file()
        except BWSSDKError:
            pass
        self._identity_request()

    @property
    def bearer_token(self) -> str:
        """
        Get the current bearer token, refreshing if necessary.

        Checks if the current token is expired (within 60 seconds of expiry)
        and automatically refreshes it if needed.

        Returns:
            str: The current valid bearer token

        Raises:
            InvalidIdentityResponseError: If token refresh fails due to invalid response
            SendRequestError: If the network request for token refresh fails
            UnauthorisedTokenError: If the token is invalid during refresh
            ApiError: If the API returns an error during refresh
        """
        expiry = datetime.datetime.fromtimestamp(
            self.oauth_jwt["payload"]["exp"], tz=datetime.timezone.utc
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        if expiry < now - datetime.timedelta(seconds=60):
            self._identity_request()

        return self._bearer_token

    @property
    def org_id(self) -> str:
        """
        Get the organization ID from the OAuth JWT token.

        Returns:
            str: The organization identifier

        Raises:
            KeyError: If the JWT token doesn't contain organization information
        """
        return self.oauth_jwt["payload"]["organization"]

    def _identity_request(self) -> None:
        """
        Perform an identity request to obtain OAuth tokens.

        Makes a POST request to the BWS identity service to obtain an access token
        and encrypted organization key. Saves the response to the state file if configured.

        Raises:
            SendRequestError: If the network request fails
            UnauthorisedTokenError: If the client credentials are invalid (401 response)
            ApiError: If the API returns a non-200 status code
            InvalidIdentityResponseError: If the response format is invalid or missing required fields
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Device-Type": "21",
        }

        identity_request = IdentityRequest(
            client_id=self.client_token.access_token_id,
            client_secret=self.client_token.client_secret,
        )
        try:
            response = requests.post(
                f"{self.region.identity_url}/connect/token",
                data=identity_request.to_query_string(),
                headers=headers,
            )
        except requests.RequestException as e:
            raise SendRequestError(f"Failed to send identity request: {e}")
        if response.status_code == 401:
            raise UnauthorisedTokenError(response.text)
        if response.status_code != 200:
            raise ApiError(
                f"Failed to retrieve secret: {response.status_code} {response.text}"
            )
        response.raise_for_status()
        response_data = response.json()
        if response_data is None:
            raise InvalidIdentityResponseError(
                "BWS API returned an invalid identity response"
            )
        try:
            if self.state_file:
                with open(self.state_file, "w") as f:
                    f.write(
                        f"{response_data['encrypted_payload']}|{response_data['access_token']}"
                    )
            self._save_identity(
                response_data["encrypted_payload"], response_data["access_token"]
            )
        except BWSSDKError as e:
            raise InvalidIdentityResponseError(
                "BWS API returned an invalid identity response"
            ) from e

    def _identity_from_state_file(self) -> None:
        """
        Load authentication state from the state file.

        Reads the encrypted payload and access token from the state file
        and restores the authentication state.

        Raises:
            ValueError: If the state file path is not set
            InvalidStateFileError: If the state file format is invalid
            FileNotFoundError: If the state file doesn't exist
            PermissionError: If the state file cannot be read
            InvalidIdentityResponseError: If the data in the state file is invalid
            InvalidEncryptionKeyError: If the encryption key cannot decrypt the data
        """
        if self.state_file:
            with open(self.state_file, "r") as f:
                try:
                    encrypted_data, access_token = f.read().rsplit("|", 1)
                except ValueError:
                    raise InvalidStateFileError("Invalid state file format")
            self._save_identity(encrypted_data, access_token)
        else:
            raise ValueError("State file path is not set")

    def _save_identity(self, encrypted_data: str, access_token: str) -> None:
        """
        Save the identity information and parse the organization encryption key.

        Stores the bearer token, decrypts and parses the organization encryption key,
        and decodes the OAuth JWT token for future use.

        Args:
            encrypted_data (str): The encrypted data containing organization encryption key
            access_token (str): The OAuth access token

        Raises:
            InvalidIdentityResponseError: If the encrypted data is invalid or empty
            InvalidEncryptionKeyError: If the encryption key cannot decrypt the data
            jwt.InvalidTokenError: If the JWT token format is invalid
        """
        self._bearer_token = access_token
        self.org_enc_key = self._parse_enc_org_key(encrypted_data)
        self.oauth_jwt = jwt.decode_complete(
            self._bearer_token,
            algorithms=["RS256"],
            options={
                "verify_signature": False
            },  # FIXME: This should be verified with the public key from the region pyopenssl
        )

    def _parse_enc_org_key(self, encrypted_data: str) -> SymmetricCryptoKey:
        """
        Parse the encrypted organization encryption key from encrypted data.

        Decrypts the provided encrypted data using the client token's encryption key
        and extracts the organization encryption key from the JSON payload.

        Args:
            encrypted_data (str): The encrypted data containing the organization encryption key

        Returns:
            SymmetricCryptoKey: The decrypted organization encryption key

        Raises:
            InvalidIdentityResponseError: If the encrypted data is empty, invalid format,
                                        or decryption fails
            InvalidEncryptionKeyError: If the encryption key is invalid
            json.JSONDecodeError: If the decrypted payload is not valid JSON
            KeyError: If the expected 'encryptionKey' field is missing
            binascii.Error: If the base64 decoding fails
        """
        if not encrypted_data:
            raise InvalidIdentityResponseError("Encrypted data cannot be empty")

        encrypted_payload = EncryptedValue.from_str(encrypted_data).decrypt(
            self.client_token.encryption_key
        )
        try:
            enc_key_b64 = json.loads(encrypted_payload)["encryptionKey"]
            return SymmetricCryptoKey(base64.b64decode(enc_key_b64))
        except (
            KeyError,
            json.JSONDecodeError,
            binascii.Error,
            InvalidEncryptionKeyError,
        ):
            raise InvalidIdentityResponseError(
                "invalid encrypted payload format or decryption failed"
            )

    @classmethod
    def from_token(
        cls, token_str: str, region: Region, state_file_path: str | None = None
    ) -> "Auth":
        """
        Create an Auth instance from a token string.

        Factory method that creates a ClientToken from the provided token string
        and initializes an Auth instance with it.

        Args:
            token_str (str): The BWS token string to parse
            region (Region): The BWS region configuration
            state_file_path (str | None): Optional path to state file for token persistence

        Returns:
            Auth: A new Auth instance

        Raises:
            InvalidTokenError: If the token version is unsupported or format is invalid
            BWSSDKError: If authentication fails during initialization
            InvalidIdentityResponseError: If the identity response is invalid
            SendRequestError: If the network request fails
            UnauthorisedTokenError: If the token is invalid or expired
            ApiError: If the API returns an error response
        """
        client_token = ClientToken.from_str(token_str)

        return cls(
            client_token=client_token,
            region=region,
            state_file=state_file_path,
        )
