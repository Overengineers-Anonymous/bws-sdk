# BWS SDK Documentation

Welcome to the BWS SDK documentation! BWS SDK is a pure Python implementation of the Bitwarden Secrets Manager API, allowing secure access to and management of Bitwarden secrets.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)

## Overview

BWS SDK provides a simple, Pythonic interface to interact with the Bitwarden Secrets Manager. It handles authentication, decryption, and secure communication with the Bitwarden API, allowing you to easily integrate Bitwarden Secrets into your Python applications.

## Features

- **Secure Authentication**: Robust authentication with Bitwarden Secrets Manager
- **Automatic Decryption**: Seamless decryption of secrets (encryption support coming soon)
- **State Persistence**: Optional state persistence for improved performance
- **Multi-Region Support**: Support for different Bitwarden regions
- **Synchronization**: Efficient secret updates with sync capabilities
- **Error Handling**: Comprehensive error handling and reporting

## Quick Start

Get started with BWS SDK in just a few lines of code:

```python
from bws_sdk import BWSecretClient, Region

# Define the Bitwarden region
region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

# Create a client instance
client = BWSecretClient(
    region=region,
    access_token="your-access-token"
)

# Retrieve a secret
secret = client.get_by_id("your-secret-id")
print(f"Secret: {secret.key} = {secret.value}")
```

## Installation

Install BWS SDK using your preferred package manager:

=== "pip"
    ```bash
    pip install bws-sdk
    ```

=== "poetry"
    ```bash
    poetry add bws-sdk
    ```

## Next Steps

- [Getting Started](getting-started.md) - Detailed setup guide
- [API Reference](api/client.md) - Complete API documentation
- [Examples](examples.md) - Practical usage examples

## Support

- **Documentation**: You're reading it! 📖
- **Issues**: [GitHub Issues](https://github.com/Overengineers-Anonymous/bws-sdk/issues)
- **Source Code**: [GitHub Repository](https://github.com/Overengineers-Anonymous/bws-sdk)

## License

This project is licensed under the MIT License. See the [full license](https://github.com/Overengineers-Anonymous/bws-sdk/blob/main/LICENSE) for details.
