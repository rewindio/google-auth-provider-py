"""Unit tests for GoogleOAuthProvider."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.exceptions import HTTPException

from google_auth_provider.provider import GoogleOAuthProvider


@pytest.mark.unit
class TestGoogleOAuthProvider:
    """Test cases for GoogleOAuthProvider class."""

    def test_initialization(self, oauth_provider: GoogleOAuthProvider, mock_settings):
        """Test that GoogleOAuthProvider initializes correctly."""
        assert oauth_provider.settings == mock_settings
        assert oauth_provider.clients == {}
        assert oauth_provider.auth_codes == {}
        assert oauth_provider.tokens == {}
        assert oauth_provider.state_mapping == {}
        assert oauth_provider.token_mapping == {}

    @pytest.mark.asyncio
    async def test_get_client_existing(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test getting an existing client."""
        # Register a client first
        await oauth_provider.register_client(sample_client)

        # Get the client
        result = await oauth_provider.get_client(sample_client.client_id)

        assert result == sample_client

    @pytest.mark.asyncio
    async def test_get_client_nonexistent(self, oauth_provider: GoogleOAuthProvider):
        """Test getting a non-existent client."""
        result = await oauth_provider.get_client("nonexistent_client")
        assert result is None

    @pytest.mark.asyncio
    async def test_register_client(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test registering a new client."""
        await oauth_provider.register_client(sample_client)

        assert sample_client.client_id in oauth_provider.clients
        assert oauth_provider.clients[sample_client.client_id] == sample_client

    @pytest.mark.asyncio
    async def test_authorize(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_params
    ):
        """Test the authorize method."""
        auth_url = await oauth_provider.authorize(sample_client, sample_auth_params)

        # Check that state mapping was created
        assert sample_auth_params.state in oauth_provider.state_mapping
        state_data = oauth_provider.state_mapping[sample_auth_params.state]
        assert state_data["redirect_uri"] == str(sample_auth_params.redirect_uri)
        assert state_data["code_challenge"] == sample_auth_params.code_challenge
        assert state_data["client_id"] == sample_client.client_id

        # Check that auth URL contains expected parameters
        assert oauth_provider.settings["auth_url"] in auth_url
        assert (
            f"client_id={oauth_provider.settings['google_client_id']}" in auth_url
        )
        assert (
            f"redirect_uri={oauth_provider.settings['callback_path']}" in auth_url
        )
        assert "response_type=code" in auth_url
        assert f"scope={oauth_provider.settings['scope']}" in auth_url
        assert f"state={sample_auth_params.state}" in auth_url

    @pytest.mark.asyncio
    async def test_authorize_missing_state(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_params
    ):
        """Test that authorize raises HTTP 400 if state parameter is missing."""
        from mcp.server.auth.provider import AuthorizationParams

        # Create params with state set to None
        params_no_state = AuthorizationParams(
            redirect_uri=sample_auth_params.redirect_uri,
            state=None,
            code_challenge=sample_auth_params.code_challenge,
            redirect_uri_provided_explicitly=sample_auth_params.redirect_uri_provided_explicitly,
            scopes=sample_auth_params.scopes,
        )
        with pytest.raises(HTTPException) as exc_info:
            await oauth_provider.authorize(sample_client, params_no_state)
        assert exc_info.value.status_code == 400
        assert "State parameter is required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_handle_callback_success(
        self,
        oauth_provider: GoogleOAuthProvider,
        sample_client,
        sample_auth_params,
        mock_http_client,
    ):
        """Test successful callback handling."""
        # First authorize to set up state mapping
        await oauth_provider.authorize(sample_client, sample_auth_params)

        # Mock the HTTP client
        with patch(
            "google_auth_provider.provider.create_mcp_http_client",
            return_value=mock_http_client,
        ):
            redirect_url = await oauth_provider.handle_callback(
                "test_code", sample_auth_params.state
            )

        # Check that state mapping was cleaned up
        assert sample_auth_params.state not in oauth_provider.state_mapping

        # Check that auth code was created
        assert len(oauth_provider.auth_codes) == 1
        auth_code = list(oauth_provider.auth_codes.values())[0]
        assert auth_code.client_id == sample_client.client_id
        assert str(auth_code.redirect_uri) == str(sample_auth_params.redirect_uri)

        # Check that access token was stored
        assert len(oauth_provider.tokens) == 1
        access_token = list(oauth_provider.tokens.values())[0]
        assert access_token.client_id == sample_client.client_id

        # Check redirect URL
        assert str(sample_auth_params.redirect_uri) in redirect_url
        assert "code=" in redirect_url
        assert f"state={sample_auth_params.state}" in redirect_url

    @pytest.mark.asyncio
    async def test_handle_callback_invalid_state(
        self, oauth_provider: GoogleOAuthProvider
    ):
        """Test callback handling with invalid state."""
        with pytest.raises(HTTPException) as exc_info:
            await oauth_provider.handle_callback("test_code", "invalid_state")

        assert exc_info.value.status_code == 400
        assert "Invalid state parameter" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_handle_callback_http_error(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_params
    ):
        """Test callback handling with HTTP error."""
        # First authorize to set up state mapping
        await oauth_provider.authorize(sample_client, sample_auth_params)

        # Mock HTTP client to raise an exception
        mock_http_client = AsyncMock()
        mock_http_client.post.side_effect = Exception("HTTP Error")

        with patch(
            "google_auth_provider.provider.create_mcp_http_client",
            return_value=mock_http_client,
        ):
            with pytest.raises(Exception) as exc_info:
                await oauth_provider.handle_callback(
                    "test_code", sample_auth_params.state
                )

            assert "HTTP Error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_handle_callback_no_access_token(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_params
    ):
        """Test callback handling when Google doesn't return access token."""
        # First authorize to set up state mapping
        await oauth_provider.authorize(sample_client, sample_auth_params)

        # Mock HTTP response without access token
        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status.return_value = None

        mock_http_client = AsyncMock()
        mock_http_client.post.return_value = mock_response

        with patch(
            "google_auth_provider.provider.create_mcp_http_client",
            return_value=mock_http_client,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await oauth_provider.handle_callback(
                    "test_code", sample_auth_params.state
                )

            assert exc_info.value.status_code == 500
            assert "No access token received from Google" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_load_authorization_code_existing(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_code
    ):
        """Test loading an existing authorization code."""
        # Add auth code to provider
        oauth_provider.auth_codes[sample_auth_code.code] = sample_auth_code

        result = await oauth_provider.load_authorization_code(
            sample_client, sample_auth_code.code
        )

        assert result == sample_auth_code

    @pytest.mark.asyncio
    async def test_load_authorization_code_nonexistent(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test loading a non-existent authorization code."""
        result = await oauth_provider.load_authorization_code(
            sample_client, "nonexistent_code"
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_success(
        self,
        oauth_provider: GoogleOAuthProvider,
        sample_client,
        sample_auth_code,
        mock_secrets,
    ):
        """Test successful authorization code exchange."""
        # Add auth code to provider
        oauth_provider.auth_codes[sample_auth_code.code] = sample_auth_code

        # Add a Google token for this client
        oauth_provider.tokens["google_token_123"] = MagicMock(
            client_id=sample_client.client_id, scopes=sample_auth_code.scopes
        )

        result = await oauth_provider.exchange_authorization_code(
            sample_client, sample_auth_code
        )

        # Check that auth code was removed
        assert sample_auth_code.code not in oauth_provider.auth_codes

        # Check that service token was created
        assert len(oauth_provider.tokens) == 2  # Google token + service token
        srv_tokens = [
            token for token in oauth_provider.tokens.keys() if token.startswith("srv_")
        ]
        assert len(srv_tokens) == 1

        # Check OAuth token result
        assert result.access_token == srv_tokens[0]
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.scope == " ".join(sample_auth_code.scopes)

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_invalid(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_code
    ):
        """Test authorization code exchange with invalid code."""
        with pytest.raises(ValueError) as exc_info:
            await oauth_provider.exchange_authorization_code(
                sample_client, sample_auth_code
            )

        assert "Invalid authorization code" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_load_access_token_existing(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test loading an existing access token."""
        # Add token to provider
        oauth_provider.tokens["test_token"] = MagicMock(
            client_id=sample_client.client_id, expires_at=None
        )

        result = await oauth_provider.load_access_token("test_token")

        assert result is not None
        assert result.client_id == sample_client.client_id

    @pytest.mark.asyncio
    async def test_load_access_token_nonexistent(
        self, oauth_provider: GoogleOAuthProvider
    ):
        """Test loading a non-existent access token."""
        result = await oauth_provider.load_access_token("nonexistent_token")
        assert result is None

    @pytest.mark.asyncio
    async def test_load_access_token_expired(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test loading an expired access token."""
        # Add expired token to provider
        oauth_provider.tokens["expired_token"] = MagicMock(
            client_id=sample_client.client_id,
            expires_at=time.time() - 3600,  # Expired 1 hour ago
        )

        result = await oauth_provider.load_access_token("expired_token")

        assert result is None
        # Token should be removed
        assert "expired_token" not in oauth_provider.tokens

    @pytest.mark.asyncio
    async def test_load_refresh_token_not_implemented(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test that refresh token loading is not implemented."""
        with pytest.raises(NotImplementedError) as exc_info:
            await oauth_provider.load_refresh_token(sample_client, "refresh_token")

        assert "Not supported" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_exchange_refresh_token_not_implemented(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test that refresh token exchange is not implemented."""
        refresh_token = MagicMock()

        with pytest.raises(NotImplementedError) as exc_info:
            await oauth_provider.exchange_refresh_token(
                sample_client, refresh_token, ["openid"]
            )

        assert "Not supported" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_revoke_token_existing(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test revoking an existing token."""
        # Add token to provider
        oauth_provider.tokens["test_token"] = MagicMock(
            client_id=sample_client.client_id
        )

        await oauth_provider.revoke_token("test_token")

        # Token should be removed
        assert "test_token" not in oauth_provider.tokens

    @pytest.mark.asyncio
    async def test_revoke_token_nonexistent(self, oauth_provider: GoogleOAuthProvider):
        """Test revoking a non-existent token."""
        # Should not raise an exception
        await oauth_provider.revoke_token("nonexistent_token")

        # No tokens should exist
        assert len(oauth_provider.tokens) == 0
