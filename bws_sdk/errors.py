"""
Exception classes for the BWS SDK.

This module defines the exception hierarchy for the BWS SDK, providing
specific error types for different failure scenarios including API errors,
authentication failures, and cryptographic errors.

Exception Hierarchy:
    BWSSDKError (base)
    ├── ApiError
    │   ├── SendRequestError
    │   ├── SecretParseError
    │   ├── UnauthorisedError
    │   ├── SecretNotFoundError
    │   └── APIRateLimitError
    ├── AuthError
    │   ├── InvalidTokenError
    │   ├── UnauthorisedTokenError
    │   ├── InvalidStateFileError
    │   └── InvalidIdentityResponseError
    └── CryptographyError
        ├── HmacError
        ├── InvalidEncryptedFormat
        └── InvalidEncryptionKeyError
"""


class BWSSDKError(Exception):
    """
    Base exception class for all BWS SDK related errors.

    This is the root exception class for the BWS SDK. All other SDK-specific
    exceptions inherit from this class, allowing for broad exception handling
    when needed.
    """


# BWS SDK API Errors


class ApiError(BWSSDKError):
    """
    Base class for errors stemming from interaction with the BWS API.

    This exception is raised for general API-related errors, including
    unexpected HTTP status codes and malformed API responses.
    """


class SendRequestError(ApiError):
    """
    Raised when a network request to the BWS API fails.

    This exception indicates that the HTTP request itself failed,
    typically due to network connectivity issues, DNS resolution
    failures, or connection timeouts.
    """


class SecretParseError(ApiError):
    """
    Raised when a secret cannot be parsed or decrypted.

    This exception occurs when the API returns secret data that
    cannot be properly parsed into a BitwardenSecret object or
    when decryption of the secret data fails.
    """


class UnauthorisedError(ApiError):
    """
    Raised when the API returns a 401 Unauthorized response.

    This exception indicates that the current authentication
    credentials are invalid or have expired.
    """


class SecretNotFoundError(ApiError):
    """
    Raised when a requested secret is not found (404 response).

    This exception occurs when attempting to retrieve a secret
    that doesn't exist or that the current user doesn't have
    permission to access.
    """


class APIRateLimitError(ApiError):
    """
    Raised when the API rate limit is exceeded (429 response).

    This exception indicates that too many requests have been
    made in a short time period and the client should wait
    before making additional requests.
    """


# Auth Errors


class AuthError(BWSSDKError):
    """
    Base class for authentication-related errors.

    This exception covers all authentication and authorization
    failures within the BWS SDK.
    """


class InvalidTokenError(AuthError):
    """
    Raised when a BWS access token has an invalid format.

    This exception occurs when parsing a BWS token string that
    doesn't conform to the expected format or contains invalid
    components.
    """


class UnauthorisedTokenError(AuthError):
    """
    Raised when a BWS access token is rejected by the identity service.

    This exception indicates that the token format is correct but
    the credentials are invalid or the token has been revoked.
    """


class InvalidStateFileError(AuthError):
    """
    Raised when a state file has an invalid format or is corrupted.

    This exception occurs when attempting to load authentication
    state from a file that doesn't contain the expected format
    or has been corrupted.
    """


class InvalidIdentityResponseError(AuthError):
    """
    Raised when the identity service returns an invalid response.

    This exception occurs when the BWS identity service response
    cannot be parsed or doesn't contain the expected fields for
    authentication.
    """


# Cryptography Errors


class CryptographyError(BWSSDKError):
    """
    Base class for cryptographic operation failures.

    This exception covers all errors related to encryption,
    decryption, key derivation, and other cryptographic operations.
    """


class HmacError(CryptographyError):
    """
    Raised when HMAC verification fails during decryption.

    This exception indicates that the message authentication code
    verification failed, suggesting the data has been tampered with
    or the wrong decryption key was used.
    """


class InvalidEncryptedFormat(CryptographyError):
    """
    Raised when encrypted data has an invalid format.

    This exception occurs when encrypted data strings don't conform
    to the expected Bitwarden encrypted format or contain invalid
    base64 encoding.
    """


class InvalidEncryptionKeyError(CryptographyError):
    """
    Raised when an encryption key has invalid length or format.

    This exception occurs when attempting to use encryption keys
    that don't meet the required specifications for the cryptographic
    algorithms used by Bitwarden.
    """
