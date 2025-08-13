# Errors API Reference

This page documents all the custom exceptions that BWS SDK can raise.

## Exception Hierarchy

BWS SDK defines several custom exceptions to help you handle different error conditions:

```
Exception
├── BWSSDKError (base class for all BWS SDK errors)
│   ├── ApiError
│   │   ├── SendRequestError
│   │   ├── SecretParseError
│   │   ├── UnauthorisedError
│   │   ├── SecretNotFoundError
│   │   └── APIRateLimitError
│   ├── AuthError
│   │   ├── InvalidTokenError
│   │   ├── UnauthorisedTokenError
│   │   ├── InvalidStateFileError
│   │   └── InvalidIdentityResponseError
│   └── CryptographyError
│       ├── HmacError
│       ├── InvalidEncryptedFormat
│       └── InvalidEncryptionKeyError
```

## Base Exceptions

::: bws_sdk.errors.BWSSDKError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

## API Errors

::: bws_sdk.errors.ApiError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.SendRequestError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.SecretParseError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.UnauthorisedError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.SecretNotFoundError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.APIRateLimitError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

## Authentication Errors

::: bws_sdk.errors.AuthError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.InvalidTokenError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.UnauthorisedTokenError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.InvalidStateFileError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.InvalidIdentityResponseError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

## Cryptography Errors

::: bws_sdk.errors.CryptographyError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.HmacError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.InvalidEncryptedFormat
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

::: bws_sdk.errors.InvalidEncryptionKeyError
    options:
      show_root_heading: true
      show_source: false
      docstring_style: google

## Error Handling Examples

### Basic Error Handling

```python
from bws_sdk import BWSecretClient, Region
from bws_sdk.errors import UnauthorisedError, SecretNotFoundError, APIRateLimitError

region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

try:
    client = BWSecretClient(region, "your-access-token")
    secret = client.get_by_id("secret-id")
    print(f"Retrieved: {secret.key}")

except UnauthorisedError:
    print("Authentication failed - check your access token")
except SecretNotFoundError:
    print("Secret not found - check the secret ID")
except APIRateLimitError:
    print("Rate limit exceeded - wait before retrying")
```

### Comprehensive Error Handling

```python
from bws_sdk import BWSecretClient, Region
from bws_sdk.errors import (
    BWSSDKError, ApiError, CryptographyError,
    SendRequestError, InvalidTokenError
)

try:
    client = BWSecretClient(region, access_token)
    secret = client.get_by_id(secret_id)

except InvalidTokenError:
    print("Invalid token format")
except UnauthorisedError:
    print("Token expired or invalid")
except SecretNotFoundError:
    print("Secret does not exist")
except APIRateLimitError as e:
    print(f"Rate limited. Retry after: {e.retry_after} seconds")
except CryptographyError:
    print("Failed to decrypt secret")
except SendRequestError as e:
    print(f"Network error: {e}")
except ApiError as e:
    print(f"API error: {e.status_code} - {e}")
except BWSSDKError as e:
    print(f"BWS SDK error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Retry Logic with Rate Limiting

```python
import time
from bws_sdk.errors import APIRateLimitError

def get_secret_with_retry(client, secret_id, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.get_by_id(secret_id)
        except APIRateLimitError as e:
            if attempt < max_retries - 1:
                sleep_time = getattr(e, 'retry_after', 60)
                print(f"Rate limited, waiting {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                raise
        except Exception:
            # Don't retry on other errors
            raise
```
