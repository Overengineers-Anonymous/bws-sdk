"""
Data types and models for the BWS SDK.

This module defines the core data structures used throughout the BWS SDK,
including region configurations and secret representations.

Classes:
    Region: Configuration for BWS API endpoints
    BitwardenSecret: Model representing a Bitwarden secret
"""

from datetime import datetime

from pydantic import BaseModel


class Region(BaseModel):
    """
    Represents a region configuration with associated API and identity service URLs.

    This class defines the endpoints for a specific Bitwarden region,
    including the main API URL and the identity service URL used for authentication.

    Attributes:
        api_url (str): The base URL for the region's API endpoint
        identity_url (str): The URL for the region's identity service

    Example:
        ```python
        region = Region(
            api_url="https://api.bitwarden.com",
            identity_url="https://identity.bitwarden.com"
        )
        ```
    """

    api_url: str
    identity_url: str


class RatelimitInfo(BaseModel):
    """
    Model representing rate limit information from the BWS API.

    This class encapsulates the rate limiting details provided by the Bitwarden API,
    including the maximum number of requests allowed, remaining requests, and reset time.

    Attributes:
        limit (int): The maximum number of requests allowed in the current time
    """

    limit: str
    remaining: int
    reset: datetime


class BitwardenSecProject(BaseModel):
    id: str
    name: str | None


class BitwardenSecretResponse(BaseModel):
    """
    Model representing a Bitwarden secret.

    This class represents a secret stored in Bitwarden's Secrets Manager,
    containing both metadata and the encrypted/decrypted secret data.

    Attributes:
        id (str): Unique identifier for the secret
        organizationId (str): ID of the organization that owns the secret
        key (str): The secret's key/name (encrypted when retrieved, decrypted after processing)
        value (str): The secret's value (encrypted when retrieved, decrypted after processing)
        creationDate (datetime): When the secret was created
        revisionDate (datetime): When the secret was last modified

    Note:
        The `key` and `value` fields are typically encrypted when first retrieved from the API
        and are automatically decrypted by the BWSecretClient before being returned to the user.
    """

    id: str
    organizationId: str
    key: str
    value: str
    projects: list[BitwardenSecProject]
    creationDate: datetime
    revisionDate: datetime


class BitwardenSecret(BaseModel):
    """
    Model representing a Bitwarden secret.

    This class represents a secret stored in Bitwarden's Secrets Manager,
    containing both metadata and the encrypted/decrypted secret data.

    Attributes:
        id (str): Unique identifier for the secret
        organizationId (str): ID of the organization that owns the secret
        key (str): The secret's key/name (encrypted when retrieved, decrypted after processing)
        value (str): The secret's value (encrypted when retrieved, decrypted after processing)
        creationDate (datetime): When the secret was created
        revisionDate (datetime): When the secret was last modified

    Note:
        The `key` and `value` fields are typically encrypted when first retrieved from the API
        and are automatically decrypted by the BWSecretClient before being returned to the user.
    """

    id: str
    organizationId: str
    key: str
    value: str
    project: BitwardenSecProject | None = None
    creationDate: datetime
    revisionDate: datetime


class BitwardenSecretRT(BitwardenSecret):
    ratelimit: RatelimitInfo


class BitwardenSync(BaseModel):
    secrets: list[BitwardenSecretResponse] | None
    ratelimit: RatelimitInfo


class BitwardenSecretCreate(BaseModel):
    """
    Model for creating a new Bitwarden secret.

    This class represents the data required to create a new secret in Bitwarden's Secrets Manager.

    Attributes:
        key (str): The secret's key/name (plaintext)
        value (str): The secret's value (plaintext)
    """

    key: str
    value: str
    note: str
    accessPoliciesRequests: None = None
    projectIds: list[str] | None = None


class BitwardenSecretUpdate(BitwardenSecretCreate):
    pass
