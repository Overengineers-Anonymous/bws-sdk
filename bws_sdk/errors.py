class BWSSDKError(Exception):
    """
    Subclass for all BWS SDK related errors
    """


# BWS SDK API Errors


class ApiError(BWSSDKError):
    """
    Subclass for errors steming from interaction with the bws-sdk api
    """


class SendRequestError(ApiError): ...


class SecretParseError(ApiError): ...


class UnauthorisedError(ApiError): ...


class SecretNotFoundError(ApiError): ...


class APIRateLimitError(ApiError): ...


# Auth Errors


class AuthError(BWSSDKError): ...


class InvalidTokenError(AuthError): ...


class UnauthorisedToken(AuthError): ...


class InvalidStateFileError(AuthError): ...


class InvalidIdentityResponseError(AuthError): ...


# Cryptography Errors


class CryptographyError(BWSSDKError): ...


class HmacError(CryptographyError): ...


class InvalidEncryptedFormat(CryptographyError): ...


class InvalidEncryptionKeyError(CryptographyError): ...
