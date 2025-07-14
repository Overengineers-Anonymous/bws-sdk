# BWS SDK (Bitwarden Secrets SDK)

A pure Python implementation of the Bitwarden Secrets Manager API, allowing secure access to and management of Bitwarden secrets.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)

## Overview

BWS SDK provides a simple, Pythonic interface to interact with the Bitwarden Secrets Manager. It handles authentication, decryption, and secure communication with the Bitwarden API, allowing you to easily integrate Bitwarden Secrets into your Python applications.

## Features

- Secure authentication with Bitwarden Secrets Manager
- Automatic decryption of secrets (encryption not yet supported)
- Optional state persistence for improved performance
- Support for different Bitwarden regions
- Synchronization capabilities for efficient secret updates
- Comprehensive error handling

## Installation

```bash
# Using pip
pip install bws-sdk

# Using poetry
poetry add bws-sdk
```

## Quick Start

```python
from bws_sdk import BWSSecretClient, Reigon
from datetime import datetime

# Define the Bitwarden region
region = Reigon(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

# Create a client instance with your access token
# Optionally provide a state file path for token persistence
client = BWSSecretClient(
    region=region,
    access_token="your-access-token",
    state_file="./path/to/state.file"  # Optional
)

# Retrieve a secret by ID
secret = client.get_by_id("your-secret-id")
print(f"Secret key: {secret.key}")
print(f"Secret value: {secret.value}")

# Sync secrets updated since a specific time
last_sync_date = datetime.fromisoformat("2025-01-01T00:00:00")
updated_secrets = client.sync(last_sync_date)
for secret in updated_secrets:
    print(f"Updated secret: {secret.key}")
```

## API Reference

### `BWSSecretClient`

The main client class for interacting with the Bitwarden Secrets Manager API.

#### Constructor

```python
BWSSecretClient(region: Reigon, access_token: str, state_file: str | None = None)
```

- `region`: A `Reigon` object specifying the API endpoints
- `access_token`: Your Bitwarden access token
- `state_file`: Optional path to a file for persisting authentication state

#### Methods

- `get_by_id(secret_id: str) -> BitwardenSecret`: Retrieves a secret by its ID
- `sync(last_synced_date: datetime) -> list[BitwardenSecret]`: Retrieves secrets updated since the specified date

> **Note**: The SDK currently only supports decryption of secrets. Methods for creating and encrypting new secrets are planned for future releases.

### `Reigon`

A class representing a Bitwarden region configuration.

```python
Reigon(api_url: str, identity_url: str)
```

- `api_url`: The base URL for the region's API endpoint
- `identity_url`: The URL for the region's identity service

### Error Types

- `UnauthorisedError`: Raised when authentication fails
- `InvalidTokenError`: Raised when the provided token is invalid
- `SecretParseError`: Raised when a secret cannot be parsed or decrypted
- `HmacError`: Raised when MAC verification fails during decryption

## Examples

### Using Environment Variables for Secrets

```python
import os
from bws_sdk import BWSSecretClient, Reigon

# Get access token from environment variable
access_token = os.environ.get("BITWARDEN_ACCESS_TOKEN")

# Define the region
region = Reigon(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

# Create the client
client = BWSSecretClient(region, access_token)

# Retrieve a secret
secret = client.get_by_id(os.environ.get("SECRET_ID"))
print(f"Retrieved secret: {secret.key}")
```

### Error Handling

```python
from bws_sdk import BWSSecretClient, Reigon, UnauthorisedError, SecretParseError

region = Reigon(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

try:
    client = BWSSecretClient(region, "your-access-token")
    secret = client.get_by_id("your-secret-id")
    print(f"Secret retrieved: {secret.key}")
except UnauthorisedError:
    print("Authentication failed. Please check your access token.")
except SecretParseError:
    print("Failed to parse or decrypt the secret.")
except Exception as e:
    print(f"An unexpected error occurred: {str(e)}")
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

- Maintainer: rippleFCL
- Email: github@ripple.contact
- Organization: Overengineers-Anonymous

## References

- [Bitwarden Secrets Manager Documentation](https://bitwarden.com/help/secrets-manager/)





