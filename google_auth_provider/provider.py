import logging
import secrets
import sys
import time
import urllib.parse


from starlette.exceptions import HTTPException

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


class GoogleOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self, settings: dict):
        self.settings = settings
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        self.token_mapping: dict[str, str] = {}

        # Configure logging
        logging.basicConfig(
            level=logging.getLevelName(self.settings["log_level"]),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        self.logger = logging.getLogger(__name__)

        self.logger.info("GoogleOAuthProvider initialized")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client = self.clients.get(client_id)
        if client:
            self.logger.info(f"Client found: {client_id}")
        else:
            self.logger.info(f"Client not found: {client_id}")
        return client

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.logger.debug(f"Registering new OAuth client: {client_info.client_id}")
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        state = params.state

        if not state:
            self.logger.error("State parameter is required")
            raise HTTPException(400, "State parameter is required")

        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(
                params.redirect_uri_provided_explicitly
            ),
            "client_id": client.client_id,
        }

        auth_url = (
            f"{self.settings['auth_url']}"
            f"?client_id={self.settings['google_client_id']}"
            f"&redirect_uri={self.settings['callback_path']}"
            f"&response_type=code"
            f"&scope={self.settings['scope']}"
            f"&state={state}"
        )
        self.logger.debug(f"Auth URL: {auth_url}")

        return auth_url

    async def handle_callback(self, code: str, state: str) -> str:
        state_data = self.state_mapping.get(state)
        if not state_data:
            self.logger.error(f"Invalid state parameter: {state}")
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = (
            state_data["redirect_uri_provided_explicitly"] == "True"
        )
        client_id = state_data["client_id"]

        self.logger.info("Exchanging authorization code for access token with Google")
        access_token_url = self.settings["token_url"]

        try:
            http_response = await create_mcp_http_client().post(
                access_token_url,
                data=urllib.parse.urlencode(
                    {
                        "client_id": self.settings["google_client_id"],
                        "client_secret": self.settings["google_client_secret"],
                        "code": code,
                        "redirect_uri": self.settings["callback_path"],
                        "grant_type": "authorization_code",
                    }
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            http_response.raise_for_status()
            access_response = http_response.json()
            self.logger.info(
                "Successfully exchanged authorization code for access token"
            )
        except Exception as e:
            self.logger.error(f"Failed to exchange authorization code with Google: {e}")
            raise

        token = access_response.get("access_token")
        if not token:
            self.logger.error("No access token in Google response")
            raise HTTPException(500, "No access token received from Google")

        new_code = f"srv_{secrets.token_hex(16)}"

        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=str(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=self.settings["scope"].split(),
            code_challenge=code_challenge,
        )
        self.auth_codes[new_code] = auth_code

        self.tokens[token] = AccessToken(
            token=token,
            client_id=client_id,
            scopes=self.settings["scope"].split(),
            expires_at=None,
            **access_response,
        )

        del self.state_mapping[state]

        redirect_url = construct_redirect_uri(redirect_uri, code=new_code, state=state)
        return redirect_url

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self.auth_codes.get(authorization_code)
        if code:
            self.logger.debug("Authorization code found")
        else:
            self.logger.debug("Authorization code not found")

        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self.logger.info("Exchanging authorization code for OAuth token")
        if authorization_code.code not in self.auth_codes:
            self.logger.error("Invalid authorization code")
            raise ValueError("Invalid authorization code")

        srv_token = f"srv_{secrets.token_hex(32)}"

        self.tokens[srv_token] = AccessToken(
            token=srv_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        self.logger.info("Searching for Google token for this client...")

        google_token = next(
            (
                token
                for token, data in self.tokens.items()
                if (not token.startswith("srv_")) and data.client_id == client.client_id
            ),
            None,
        )

        if google_token:
            self.token_mapping[srv_token] = google_token
        else:
            self.logger.info(f"No Google token found for client: {client.client_id}")

        del self.auth_codes[authorization_code.code]

        oauth_token = OAuthToken(
            access_token=srv_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

        self.logger.info(
            f"Successfully exchanged authorization code for OAuth token for client: {client.client_id}"
        )
        return oauth_token

    async def load_access_token(self, token: str) -> AccessToken | None:
        self.logger.debug("Loading access token...")
        access_token = self.tokens.get(token)
        if not access_token:
            self.logger.debug("Access token not found...")
            return None

        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        self.logger.info(
            f"Refresh token requested for client: {client.client_id} - not supported"
        )
        raise NotImplementedError("Not supported")

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self.logger.info(
            f"Refresh token exchange requested for client: {client.client_id} - not supported"
        )
        raise NotImplementedError("Not supported")

    async def revoke_token(
        self, token: str, token_type_hint: str | None = None
    ) -> None:
        if token in self.tokens:
            del self.tokens[token]
        else:
            self.logger.debug("Token not found for revocation:...")
