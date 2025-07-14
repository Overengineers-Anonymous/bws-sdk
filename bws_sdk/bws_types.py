from pydantic import BaseModel
from datetime import datetime


class Region(BaseModel):
    """
    Represents a region configuration with associated API and identity service URLs.
    Attributes:
        api_url (str): The base URL for the region's API endpoint.
        identity_url (str): The URL for the region's identity service.
    """

    api_url: str
    identity_url: str


class BitwardenSecret(BaseModel):
    id: str
    organizationId: str
    key: str
    value: str
    creationDate: datetime
    revisionDate: datetime
