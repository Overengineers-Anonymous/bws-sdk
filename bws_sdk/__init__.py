"""
BWS SDK - Bitwarden Secrets Manager Python SDK.

This package provides a Python SDK for interacting with the Bitwarden Secrets Manager API.
It enables secure retrieval and management of secrets through the BWS (Bitwarden Web Service) API.

The SDK handles authentication, encryption/decryption, and provides a simple interface
for accessing secrets stored in Bitwarden's Secrets Manager.

Classes:
    BWSecretClient: Main client for interacting with the BWS API
    BitwardenSecret: Data model representing a Bitwarden secret
    Region: Configuration for BWS API regions

Exceptions:
    ApiError: Base class for API-related errors
    APIRateLimitError: Raised when API rate limits are exceeded
    InvalidTokenError: Raised when authentication tokens are invalid
    SecretNotFoundError: Raised when requested secrets are not found
    SecretParseError: Raised when secret data cannot be parsed
    SendRequestError: Raised when network requests fail
    UnauthorisedError: Raised when authentication fails

Example:
    ```python
    from bws_sdk import BWSecretClient, Region

    region = Region(
        api_url="https://api.bitwarden.com",
        identity_url="https://identity.bitwarden.com"
    )

    client = BWSecretClient(region=region, access_token="your_token")
    secret = client.get_by_id("secret-id")
    ```
"""

from .bws_types import BitwardenSecretResponse, Region
from .client import BWSecretClient
from .errors import (
    ApiError,
    APIRateLimitError,
    AuthError,
    BWSSDKError,
    InvalidIdentityResponseError,
    InvalidTokenError,
    SecretNotFoundError,
    SecretParseError,
    SendRequestError,
    UnauthorisedError,
    UnauthorisedTokenError,
)

__all__ = [
    "APIRateLimitError",
    "ApiError",
    "AuthError",
    "BWSSDKError",
    "BWSecretClient",
    "BitwardenSecretResponse",
    "InvalidIdentityResponseError",
    "InvalidTokenError",
    "Region",
    "SecretNotFoundError",
    "SecretParseError",
    "SendRequestError",
    "UnauthorisedError",
    "UnauthorisedTokenError",
]
