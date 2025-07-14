from datetime import datetime
from typing import Any
from wsgiref import headers
from pydantic import BaseModel
from pydantic.type_adapter import P
from .token import Auth
from .bws_types import Reigon, BitwardenSecret
from .crypto import EncryptedValue
import requests
from .errors import UnauthorisedError, SecretParseError

class BWSSecretClient:
    """
    BWSSecretClient provides methods to interact with the Bitwarden Secrets Manager API, enabling retrieval of secrets for a given access_token.
    """
    def __init__(self, region: Reigon, access_token: str, state_file: str | None = None):
        if not isinstance(region, Reigon):
            raise ValueError("Region must be an instance of Reigon")
        if not isinstance(access_token, str):
            raise ValueError("Access token must be a string")
        if state_file is not None and not isinstance(state_file, str):
            raise ValueError("State file must be a string or None")

        self.region = region
        self.auth = Auth.from_token(access_token, region, state_file)
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.auth.bearer_token}", "User-Agent": "Bitwarden Rust-SDK", "Device-Type": "21"})

    def _decrypt_secret(self, secret: BitwardenSecret) -> BitwardenSecret:
        try:
            return BitwardenSecret(
                id=secret.id,
                organizationId=secret.organizationId,
                key=EncryptedValue.from_str(secret.key).decrypt(self.auth.org_enc_key).decode("utf-8"),
                value=EncryptedValue.from_str(secret.value).decrypt(self.auth.org_enc_key).decode("utf-8"),
                creationDate=secret.creationDate,
                revisionDate=secret.revisionDate,
            )
        except UnicodeDecodeError as e:
            raise SecretParseError("Failed to decode secret value or key") from e

    def _parse_secret(self, data: dict[str, Any]) -> BitwardenSecret:
        undec_secret = BitwardenSecret.model_validate(data)
        return self._decrypt_secret(undec_secret)

    def get_by_id(self, secret_id: str) -> BitwardenSecret:
        """
        Retrieve a secret by its unique identifier.
        Args:
            secret_id (str): The unique identifier of the secret to retrieve.
        Returns:
            BitwardenSecret: The parsed and decrypted secret data.
        Raises:
            ValueError: If the provided secret_id is not a string.
            UnauthorisedError: If the request is unauthorized (HTTP 401).
            SecretParseError: If a secret cannot be parsed or decrypted.
        """

        if not isinstance(secret_id, str):
            raise ValueError("Secret ID must be a string")
        response = self.session.get(
            f"{self.region.api_url}/secrets/{secret_id}"
        )
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        return self._parse_secret(response.json())

    def sync(self, last_synced_date: datetime) -> list[BitwardenSecret]:
        """
        Synchronizes secrets from the Bitwarden server since the specified last synced date.
        Args:
            last_synced_date (datetime): The datetime object representing the last time secrets were synced.
        Returns:
            list[BitwardenSecret]: The parsed and decrypted secrets data.

        Raises:
            ValueError: If last_synced_date is not a datetime object.
            UnauthorisedError: If the server returns a 401 Unauthorized response.
            SecretParseError: If a secret cannot be parsed or decrypted.
        """

        if not isinstance(last_synced_date, datetime):
            raise ValueError("Last synced date must be a datetime object")

        lsd: str = last_synced_date.isoformat()
        response = self.session.get(
            f"{self.region.api_url}/organizations/{self.auth.org_id}/secrets/sync", params={"lastSyncedDate": lsd}
        )
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        unc_secrets = response.json().get("secrets", {}).get("data", [])
        decrypted_secrets = []
        for secret in unc_secrets:
            decrypted_secrets.append(self._parse_secret(secret))
        return decrypted_secrets
