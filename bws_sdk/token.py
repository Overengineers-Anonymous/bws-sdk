import datetime
import json
from pathlib import Path
from re import S
from typing import Any
from urllib.parse import urlencode
from pydantic import BaseModel
import base64
import requests
from .bws_types import Region
from .crypto import SymetricCryptoKey, EncryptedValue
import jwt
from .errors import InvalidTokenError, UnauthorisedError


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
        self, client_token: ClientToken, org_enc_key: bytes, bearer_token: str, region: Region, state_file: str | None = None
    ):
        self.state_file = Path(state_file) if state_file else None
        self.region = region
        self.client_token = client_token
        self.org_enc_key = SymetricCryptoKey(org_enc_key)
        self._bearer_token = bearer_token
        self.oauth_jwt = jwt.decode_complete(
            bearer_token,
            algorithms=["RS256"],
            options={
                "verify_signature": False
            },  # FIXME: This should be verified with the public key from the region pyopenssl
        )

    @property
    def bearer_token(self) -> str:
        expiry = datetime.datetime.fromtimestamp(self.oauth_jwt["payload"]["exp"], tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        if expiry < now - datetime.timedelta(seconds=20):
            _, self._bearer_token = self._identity_request(self.client_token, self.region)
            if self.state_file:
                with open(self.state_file, "w") as f:
                    f.write(f"{self._bearer_token}|{self.org_enc_key.to_base64()}")
        return self._bearer_token

    @property
    def org_id(self) -> str:
        return self.oauth_jwt["payload"]["organization"]

    @staticmethod
    def _identity_request(client_token: ClientToken, region: Region):
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "Device-Type": "21"}

        identity_request = IdentityRequest(client_id=client_token.access_token_id, client_secret=client_token.client_secret)

        response = requests.post(
            f"{region.identity_url}/connect/token",
            data=identity_request.to_query_string(),
            headers=headers,
        )
        if response.status_code == 401:
            raise UnauthorisedError(response.text)
        response_data = response.json()
        return response_data["encrypted_payload"], response_data["access_token"]

    @classmethod
    def from_token(cls, token_str: str, region: Region, state_file_path: str | None = None):
        client_token = ClientToken.from_str(token_str)
        if state_file_path:
            state_file = Path(state_file_path)
            if not state_file.exists():
                encrypted_data, access_token = cls._identity_request(client_token, region)
                with open(state_file, "w") as f:
                    f.write(f"{encrypted_data}|{access_token}")
            else:
                with open(state_file_path, "r") as f:
                    encrypted_data, access_token = f.read().rsplit("|", 1)
        else:
            encrypted_data, access_token = cls._identity_request(client_token, region)

        encrypted_payload = EncryptedValue.from_str(encrypted_data).decrypt(client_token.encryption_key)
        enc_key_b64 = json.loads(encrypted_payload)["encryptionKey"]
        org_enc_key = base64.b64decode(enc_key_b64)

        return cls(
            client_token=client_token,
            org_enc_key=org_enc_key,
            bearer_token=access_token,
            region=region,
            state_file=state_file_path,
        )
