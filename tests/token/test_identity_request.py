from bws_sdk.token import IdentityRequest

def test_identity_request_qs():
    req = IdentityRequest(client_id="test_client_id", client_secret="test_client_secret")
    qs = req.to_query_string()
    assert qs == "scope=api.secrets&grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret"
