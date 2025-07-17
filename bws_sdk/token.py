import base64
import datetime
import json
from pathlib import Path
from urllib.parse import urlencode

import jwt
import requests
from pydantic import BaseModel

from .bws_types import Region
from .crypto import EncryptedValue, SymetricCryptoKey
from .errors import ApiError, InvalidEncryptedFormat, InvalidTokenError, UnauthorisedError


class InvalidStateFileError(Exception): ...

class ClientToken:
    def __init__(self, access_token_id: str, client_secret: str, encryption_key: SymetricCryptoKey):
        self.access_token_id = access_token_id
        self.client_secret = client_secret
        self.encryption_key = encryption_key

    @classmethod
    def from_str(cls, token_str: str):
        token_info, encryption_key = token_str.split(":")
        version, access_token_id, client_secret = token_info.split(
            ".",
        )
        encryption_key = base64.b64decode(encryption_key)
        if version != "0":
            raise InvalidTokenError("Unsupported Token Version")
        if len(encryption_key) != 16:
            raise InvalidTokenError("Invalid Token")
        return cls(
            access_token_id=access_token_id,
            client_secret=client_secret,
            encryption_key=SymetricCryptoKey.from_encryption_key(encryption_key),
        )


class IdentityRequest(BaseModel):
    scope: str = "api.secrets"
    grant_type: str = "client_credentials"
    client_id: str
    client_secret: str

    def to_query_string(self):
        return urlencode(self.model_dump())


class Auth:
    def __init__(
        self, client_token: ClientToken, region: Region, state_file: str | None = None
    ):
        self.state_file = Path(state_file) if state_file else None
        self.region = region
        self.client_token = client_token
        self._authenticate()

    def _authenticate(self):
        try:
            if self.state_file and self.state_file.exists():
                return self._identity_from_state_file()
        except (InvalidEncryptedFormat, InvalidStateFileError):
            pass
        self._identity_request()

    @property
    def bearer_token(self) -> str:
        expiry = datetime.datetime.fromtimestamp(self.oauth_jwt["payload"]["exp"], tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        if expiry < now - datetime.timedelta(seconds=20):
            self._identity_request()

        return self._bearer_token

    @property
    def org_id(self) -> str:
        return self.oauth_jwt["payload"]["organization"]

    def _identity_request(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "Device-Type": "21"}

        identity_request = IdentityRequest(client_id=self.client_token.access_token_id, client_secret=self.client_token.client_secret)

        response = requests.post(
            f"{self.region.identity_url}/connect/token",
            data=identity_request.to_query_string(),
            headers=headers,
        )
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        if response.status_code != 200:
            raise ApiError(f"Failed to retrieve secret: {response.status_code} {response.text}")
        response.raise_for_status()
        response_data = response.json()

        if self.state_file:
            with open(self.state_file, "w") as f:
                f.write(f"{response_data['encrypted_payload']}|{response_data['access_token']}")

        self._save_identity(response_data["encrypted_payload"], response_data["access_token"])


    def _identity_from_state_file(self):
        if self.state_file:
            with open(self.state_file, "r") as f:
                try:
                    encrypted_data, access_token = f.read().rsplit("|", 1)
                except ValueError:
                    raise InvalidStateFileError("Invalid state file format")
            self._save_identity(encrypted_data, access_token)
        else:
            raise ValueError("State file path is not set")

    def _save_identity(self, encrypted_data: str, access_token: str):
        """
        Saves the identity information to the state file.
        Args:
            encrypted_data (str): The encrypted data containing organization encryption key.
            access_token (str): The access token to be saved.
        """
        self._bearer_token = access_token
        self.org_enc_key = self._parse_enc_org_key(encrypted_data)
        self.oauth_jwt = jwt.decode_complete(
            self._bearer_token,
            algorithms=["RS256"],
            options={
                "verify_signature": False
            },  # FIXME: This should be verified with the public key from the region pyopenssl
        )

    def _parse_enc_org_key(self, encrypted_data: str) -> SymetricCryptoKey:
        """
        Parses the encrypted organization encryption key from the provided encrypted data.
        Args:
            encrypted_data (str): The encrypted data containing the organization encryption key.
        Returns:
            bytes: The decrypted organization encryption key.
        Raises:
            ValueError: If the encrypted data is invalid or cannot be decrypted.
        """
        if not encrypted_data:
            raise ValueError("Encrypted data cannot be empty")

        encrypted_payload = EncryptedValue.from_str(encrypted_data).decrypt(self.client_token.encryption_key)
        enc_key_b64 = json.loads(encrypted_payload)["encryptionKey"]
        return SymetricCryptoKey(base64.b64decode(enc_key_b64))

    @classmethod
    def from_token(cls, token_str: str, region: Region, state_file_path: str | None = None):
        client_token = ClientToken.from_str(token_str)


        return cls(
            client_token=client_token,
            region=region,
            state_file=state_file_path,
        )
