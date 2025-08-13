# Getting Started

This guide will help you get up and running with BWS SDK in your Python project.

## Prerequisites

- Python 3.13 or higher
- A Bitwarden Secrets Manager access token
- Access to a Bitwarden organization with Secrets Manager enabled

## Installation

Choose your preferred installation method:

=== "pip"
    ```bash
    pip install bws-sdk
    ```

=== "poetry"
    ```bash
    poetry add bws-sdk
    ```

=== "conda"
    ```bash
    # BWS SDK is not yet available on conda-forge
    # Use pip in your conda environment
    pip install bws-sdk
    ```

## Obtaining an Access Token

1. Log in to your Bitwarden web vault
2. Navigate to **Organizations** > **Your Organization** > **Settings** > **Secrets Manager**
3. Go to **Service Accounts** and create a new service account
4. Generate an access token for the service account
5. Copy the access token (keep it secure!)

!!! warning "Security Note"
    Never commit access tokens to version control. Use environment variables or secure configuration management.

## Basic Setup

### 1. Import the SDK

```python
from bws_sdk import BWSecretClient, Region
from datetime import datetime
import os
```

### 2. Configure the Region

BWS SDK supports multiple Bitwarden regions. Choose the appropriate region for your organization:

```python
# US region (default)
region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

# EU region
region = Region(
    api_url="https://api.bitwarden.eu",
    identity_url="https://identity.bitwarden.eu"
)

# Self-hosted (example)
region = Region(
    api_url="https://your-domain.com/api",
    identity_url="https://your-domain.com/identity"
)
```

### 3. Create a Client

```python
# Get token from environment variable (recommended)
access_token = os.environ.get("BITWARDEN_ACCESS_TOKEN")

# Create client
client = BWSecretClient(
    region=region,
    access_token=access_token,
    state_file="./bitwarden_state.json"  # Optional: for token persistence
)
```

### 4. Retrieve Your First Secret

```python
try:
    # Replace with your actual secret ID
    secret_id = "your-secret-id-here"
    secret = client.get_by_id(secret_id)

    print(f"Secret Name: {secret.key}")
    print(f"Secret Value: {secret.value}")
    print(f"Last Modified: {secret.revision_date}")

except Exception as e:
    print(f"Error retrieving secret: {e}")
```

## Environment Variables

For better security, use environment variables to store sensitive information:

```bash
# .env file or shell environment
export BITWARDEN_ACCESS_TOKEN="your-access-token-here"
export BITWARDEN_API_URL="https://api.bitwarden.com"
export BITWARDEN_IDENTITY_URL="https://identity.bitwarden.com"
```

```python
import os
from bws_sdk import BWSecretClient, Region

# Load from environment
region = Region(
    api_url=os.environ.get("BITWARDEN_API_URL", "https://api.bitwarden.com"),
    identity_url=os.environ.get("BITWARDEN_IDENTITY_URL", "https://identity.bitwarden.com")
)

client = BWSecretClient(
    region=region,
    access_token=os.environ["BITWARDEN_ACCESS_TOKEN"]
)
```

## Complete Example

Here's a complete working example:

```python
import os
from datetime import datetime, timedelta
from bws_sdk import BWSecretClient, Region, UnauthorisedError, SecretParseError

def main():
    # Configure region
    region = Region(
        api_url="https://api.bitwarden.com",
        identity_url="https://identity.bitwarden.com"
    )

    # Get access token from environment
    access_token = os.environ.get("BITWARDEN_ACCESS_TOKEN")
    if not access_token:
        print("Please set BITWARDEN_ACCESS_TOKEN environment variable")
        return

    try:
        # Create client
        client = BWSecretClient(
            region=region,
            access_token=access_token,
            state_file="./bw_state.json"
        )

        # Get a specific secret
        secret_id = os.environ.get("SECRET_ID")
        if secret_id:
            secret = client.get_by_id(secret_id)
            print(f"Retrieved secret: {secret.key}")

        # Sync recent changes (last 24 hours)
        yesterday = datetime.now() - timedelta(days=1)
        updated_secrets = client.sync(yesterday)
        print(f"Found {len(updated_secrets)} updated secrets")

        for secret in updated_secrets:
            print(f"- {secret.key} (updated: {secret.revision_date})")

    except UnauthorisedError:
        print("Authentication failed. Check your access token.")
    except SecretParseError as e:
        print(f"Failed to parse secret: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
```

## Next Steps

Now that you have BWS SDK set up, explore these resources:

- [API Reference](api/client.md) - Detailed API documentation
- [Examples](examples.md) - More practical examples
- [Error Handling](api/errors.md) - Understanding and handling errors

## Troubleshooting

### Common Issues

**"UnauthorisedError" when creating client**
: Check that your access token is correct and hasn't expired

**"SecretParseError" when retrieving secrets**
: Ensure your service account has permission to access the secret

**Import errors**
: Verify BWS SDK is installed in the correct Python environment

### Getting Help

If you encounter issues:

1. Check the [API Reference](api/client.md) for detailed documentation
2. Look at the [Examples](examples.md) for working code samples
3. Search existing [GitHub Issues](https://github.com/Overengineers-Anonymous/bws-sdk/issues)
4. Create a new issue if needed
