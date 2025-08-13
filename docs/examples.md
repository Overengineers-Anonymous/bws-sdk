# Examples

This page provides practical examples of using BWS SDK in different scenarios.

## Basic Usage

### Simple Secret Retrieval

```python
from bws_sdk import BWSecretClient, Region
import os

# Set up the region and client
region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

client = BWSecretClient(
    region=region,
    access_token=os.environ["BITWARDEN_ACCESS_TOKEN"]
)

# Get a secret
secret = client.get_by_id("your-secret-id")
print(f"Database password: {secret.value}")
```

### Using Different Regions

```python
from bws_sdk import BWSecretClient, Region

# US region (default)
us_region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

# EU region
eu_region = Region(
    api_url="https://api.bitwarden.eu",
    identity_url="https://identity.bitwarden.eu"
)

# Self-hosted instance
self_hosted_region = Region(
    api_url="https://vault.company.com/api",
    identity_url="https://vault.company.com/identity"
)

client = BWSecretClient(eu_region, access_token)
```

## Configuration Management

### Loading Database Configuration

```python
import os
from bws_sdk import BWSecretClient, Region
from bws_sdk.errors import SecretNotFoundError

class DatabaseConfig:
    def __init__(self, bw_client: BWSecretClient):
        self.client = bw_client
        self._load_config()

    def _load_config(self):
        """Load database configuration from Bitwarden secrets."""
        try:
            # Retrieve database connection secrets
            db_host = self.client.get_by_id(os.environ["DB_HOST_SECRET_ID"])
            db_user = self.client.get_by_id(os.environ["DB_USER_SECRET_ID"])
            db_pass = self.client.get_by_id(os.environ["DB_PASS_SECRET_ID"])

            self.host = db_host.value
            self.username = db_user.value
            self.password = db_pass.value
            self.port = 5432  # Default port

        except SecretNotFoundError as e:
            raise ValueError(f"Required database secret not found: {e}")

    @property
    def connection_string(self):
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/mydb"

# Usage
region = Region(
    api_url="https://api.bitwarden.com",
    identity_url="https://identity.bitwarden.com"
)

client = BWSecretClient(region, os.environ["BITWARDEN_ACCESS_TOKEN"])
db_config = DatabaseConfig(client)

print(f"Connecting to: {db_config.connection_string}")
```

### API Keys Management

```python
from bws_sdk import BWSecretClient, Region
from dataclasses import dataclass
from typing import Dict
import os

@dataclass
class APIKeys:
    stripe: str
    sendgrid: str
    aws_access: str
    aws_secret: str

class APIKeyManager:
    def __init__(self, bw_client: BWSecretClient):
        self.client = bw_client
        self.keys = self._load_api_keys()

    def _load_api_keys(self) -> APIKeys:
        """Load all API keys from Bitwarden."""
        key_ids = {
            'stripe': os.environ["STRIPE_SECRET_ID"],
            'sendgrid': os.environ["SENDGRID_SECRET_ID"],
            'aws_access': os.environ["AWS_ACCESS_SECRET_ID"],
            'aws_secret': os.environ["AWS_SECRET_SECRET_ID"],
        }

        keys = {}
        for name, secret_id in key_ids.items():
            secret = self.client.get_by_id(secret_id)
            keys[name] = secret.value

        return APIKeys(**keys)

    def get_aws_credentials(self) -> Dict[str, str]:
        """Get AWS credentials as a dictionary."""
        return {
            'aws_access_key_id': self.keys.aws_access,
            'aws_secret_access_key': self.keys.aws_secret
        }

# Usage
client = BWSecretClient(region, access_token)
api_manager = APIKeyManager(client)

# Use with boto3
import boto3
s3_client = boto3.client('s3', **api_manager.get_aws_credentials())
```

## Synchronization and Caching

### Secret Caching with Sync

```python
from bws_sdk import BWSecretClient, Region
from datetime import datetime, timedelta
import json
import os
from typing import Dict, Optional

class SecretCache:
    def __init__(self, bw_client: BWSecretClient, cache_file: str = "secret_cache.json"):
        self.client = bw_client
        self.cache_file = cache_file
        self.cache: Dict[str, dict] = {}
        self.last_sync: Optional[datetime] = None
        self._load_cache()

    def _load_cache(self):
        """Load cache from file if it exists."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.cache = data.get('secrets', {})
                    last_sync_str = data.get('last_sync')
                    if last_sync_str:
                        self.last_sync = datetime.fromisoformat(last_sync_str)
            except (json.JSONDecodeError, ValueError):
                self.cache = {}
                self.last_sync = None

    def _save_cache(self):
        """Save cache to file."""
        data = {
            'secrets': self.cache,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None
        }
        with open(self.cache_file, 'w') as f:
            json.dump(data, f, indent=2)

    def sync_secrets(self, max_age_hours: int = 1):
        """Sync secrets that are older than max_age_hours."""
        now = datetime.now()

        # Determine sync point
        if self.last_sync:
            sync_point = max(
                self.last_sync,
                now - timedelta(hours=max_age_hours)
            )
        else:
            sync_point = now - timedelta(days=30)  # Initial sync

        try:
            # Get updated secrets
            updated_secrets = self.client.sync(sync_point)

            # Update cache
            for secret in updated_secrets:
                self.cache[secret.id] = {
                    'key': secret.key,
                    'value': secret.value,
                    'revision_date': secret.revision_date.isoformat(),
                    'cached_at': now.isoformat()
                }

            self.last_sync = now
            self._save_cache()

            print(f"Synced {len(updated_secrets)} secrets")

        except Exception as e:
            print(f"Sync failed: {e}")

    def get_secret(self, secret_id: str, use_cache: bool = True) -> str:
        """Get a secret value, optionally using cache."""
        if use_cache and secret_id in self.cache:
            cached = self.cache[secret_id]
            cached_at = datetime.fromisoformat(cached['cached_at'])

            # Use cache if less than 1 hour old
            if datetime.now() - cached_at < timedelta(hours=1):
                return cached['value']

        # Fetch from API
        secret = self.client.get_by_id(secret_id)

        # Update cache
        self.cache[secret_id] = {
            'key': secret.key,
            'value': secret.value,
            'revision_date': secret.revision_date.isoformat(),
            'cached_at': datetime.now().isoformat()
        }
        self._save_cache()

        return secret.value

# Usage
client = BWSecretClient(region, access_token)
cache = SecretCache(client)

# Sync recent changes
cache.sync_secrets(max_age_hours=6)

# Get secrets (will use cache if available)
db_password = cache.get_secret("db-password-secret-id")
api_key = cache.get_secret("api-key-secret-id")
```

## Environment-Specific Configuration

### Multi-Environment Setup

```python
from bws_sdk import BWSecretClient, Region
from enum import Enum
import os

class Environment(Enum):
    DEVELOPMENT = "dev"
    STAGING = "staging"
    PRODUCTION = "prod"

class EnvironmentConfig:
    def __init__(self, env: Environment):
        self.env = env
        self.region = Region(
            api_url="https://api.bitwarden.com",
            identity_url="https://identity.bitwarden.com"
        )

        # Different access tokens per environment
        token_key = f"BITWARDEN_TOKEN_{env.value.upper()}"
        self.access_token = os.environ[token_key]

        self.client = BWSecretClient(
            region=self.region,
            access_token=self.access_token,
            state_file=f"./bw_state_{env.value}.json"
        )

    def get_secret_id(self, secret_name: str) -> str:
        """Get environment-specific secret ID."""
        env_key = f"{secret_name.upper()}_{self.env.value.upper()}_SECRET_ID"
        return os.environ[env_key]

    def get_secret_value(self, secret_name: str) -> str:
        """Get secret value for current environment."""
        secret_id = self.get_secret_id(secret_name)
        secret = self.client.get_by_id(secret_id)
        return secret.value

# Usage
current_env = Environment(os.environ.get("ENVIRONMENT", "development"))
config = EnvironmentConfig(current_env)

# Get environment-specific secrets
database_url = config.get_secret_value("database_url")
redis_url = config.get_secret_value("redis_url")
jwt_secret = config.get_secret_value("jwt_secret")

print(f"Running in {current_env.value} environment")
```

## Error Handling Patterns

### Graceful Degradation

```python
from bws_sdk import BWSecretClient, Region
from bws_sdk.errors import BWSSDKError, APIRateLimitError
import time
import logging

logger = logging.getLogger(__name__)

class ResilientSecretManager:
    def __init__(self, bw_client: BWSecretClient):
        self.client = bw_client
        self.fallback_values = {}

    def set_fallback(self, secret_name: str, fallback_value: str):
        """Set a fallback value for a secret."""
        self.fallback_values[secret_name] = fallback_value

    def get_secret_safe(self, secret_id: str, secret_name: str = None,
                       max_retries: int = 3) -> str:
        """
        Get a secret with retry logic and fallback support.
        """
        for attempt in range(max_retries):
            try:
                secret = self.client.get_by_id(secret_id)
                return secret.value

            except APIRateLimitError as e:
                if attempt < max_retries - 1:
                    sleep_time = getattr(e, 'retry_after', 60)
                    logger.warning(f"Rate limited, waiting {sleep_time}s")
                    time.sleep(sleep_time)
                    continue
                else:
                    logger.error("Max retries exceeded for rate limit")
                    break

            except BWSSDKError as e:
                logger.error(f"BWS error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    break

        # Use fallback if available
        if secret_name and secret_name in self.fallback_values:
            logger.warning(f"Using fallback value for {secret_name}")
            return self.fallback_values[secret_name]

        raise RuntimeError(f"Failed to retrieve secret {secret_id} after {max_retries} attempts")

# Usage
client = BWSecretClient(region, access_token)
manager = ResilientSecretManager(client)

# Set fallbacks for critical secrets
manager.set_fallback("database_password", "default_dev_password")
manager.set_fallback("api_key", "development_key")

# Get secrets with fallback support
try:
    db_password = manager.get_secret_safe(
        secret_id="db-password-id",
        secret_name="database_password"
    )
    api_key = manager.get_secret_safe(
        secret_id="api-key-id",
        secret_name="api_key"
    )
except RuntimeError as e:
    logger.critical(f"Critical secret retrieval failed: {e}")
    raise
```

## Integration Examples

### Flask Application Integration

```python
from flask import Flask
from bws_sdk import BWSecretClient, Region
import os

def create_app():
    app = Flask(__name__)

    # Set up BWS client
    region = Region(
        api_url=os.environ.get("BITWARDEN_API_URL", "https://api.bitwarden.com"),
        identity_url=os.environ.get("BITWARDEN_IDENTITY_URL", "https://identity.bitwarden.com")
    )

    bw_client = BWSecretClient(
        region=region,
        access_token=os.environ["BITWARDEN_ACCESS_TOKEN"]
    )

    # Load configuration from Bitwarden
    try:
        db_url_secret = bw_client.get_by_id(os.environ["DATABASE_URL_SECRET_ID"])
        secret_key_secret = bw_client.get_by_id(os.environ["SECRET_KEY_SECRET_ID"])

        app.config['DATABASE_URL'] = db_url_secret.value
        app.config['SECRET_KEY'] = secret_key_secret.value

    except Exception as e:
        app.logger.error(f"Failed to load secrets: {e}")
        raise

    # Store client for use in views
    app.bw_client = bw_client

    @app.route('/health')
    def health():
        return {'status': 'healthy', 'secrets_loaded': True}

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
```

### Django Settings Integration

```python
# settings.py
import os
from bws_sdk import BWSecretClient, Region

# BWS Setup
BITWARDEN_REGION = Region(
    api_url=os.environ.get("BITWARDEN_API_URL", "https://api.bitwarden.com"),
    identity_url=os.environ.get("BITWARDEN_IDENTITY_URL", "https://identity.bitwarden.com")
)

_bw_client = BWSecretClient(
    region=BITWARDEN_REGION,
    access_token=os.environ["BITWARDEN_ACCESS_TOKEN"]
)

def get_secret(secret_id_env_var: str) -> str:
    """Helper to get secret from environment variable containing secret ID."""
    secret_id = os.environ[secret_id_env_var]
    secret = _bw_client.get_by_id(secret_id)
    return secret.value

# Django settings using secrets
SECRET_KEY = get_secret("DJANGO_SECRET_KEY_SECRET_ID")

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'myapp',
        'USER': get_secret("DB_USER_SECRET_ID"),
        'PASSWORD': get_secret("DB_PASSWORD_SECRET_ID"),
        'HOST': get_secret("DB_HOST_SECRET_ID"),
        'PORT': '5432',
    }
}

# Email settings
EMAIL_HOST_PASSWORD = get_secret("EMAIL_PASSWORD_SECRET_ID")

# Third-party API keys
STRIPE_SECRET_KEY = get_secret("STRIPE_SECRET_KEY_SECRET_ID")
```

These examples demonstrate various patterns for integrating BWS SDK into your applications, from simple secret retrieval to complex caching and resilience strategies.
