"""Integration tests for Google OAuth provider."""

import time
import pytest
from unittest.mock import MagicMock, patch

from google_auth_provider.provider import GoogleOAuthProvider


@pytest.mark.integration
class TestGoogleOAuthProviderIntegration:
    """Integration tests for GoogleOAuthProvider."""

    @pytest.mark.asyncio
    async def test_full_oauth_flow(
        self,
        oauth_provider: GoogleOAuthProvider,
        sample_client,
        sample_auth_params,
        mock_http_client,
    ):
        """Test the complete OAuth flow from authorization to token exchange."""
        # Step 1: Register client
        await oauth_provider.register_client(sample_client)

        # Step 2: Authorize (get auth URL)
        auth_url = await oauth_provider.authorize(sample_client, sample_auth_params)
        assert oauth_provider.settings["auth_url"] in auth_url

        # Step 3: Handle callback (simulate user returning from Google)
        with patch(
            "google_auth_provider.provider.create_mcp_http_client",
            return_value=mock_http_client,
        ):
            await oauth_provider.handle_callback(
                "google_auth_code", sample_auth_params.state
            )

        # Verify auth code was created
        assert len(oauth_provider.auth_codes) == 1
        auth_code = list(oauth_provider.auth_codes.values())[0]

        # Step 4: Exchange authorization code for OAuth token
        oauth_token = await oauth_provider.exchange_authorization_code(
            sample_client, auth_code
        )

        # Verify OAuth token
        assert oauth_token.access_token.startswith("srv_")
        assert oauth_token.token_type == "Bearer"
        assert oauth_token.expires_in == 3600

        # Step 5: Load access token
        loaded_token = await oauth_provider.load_access_token(oauth_token.access_token)
        assert loaded_token is not None
        assert loaded_token.client_id == sample_client.client_id

    @pytest.mark.asyncio
    async def test_multiple_clients(self, oauth_provider: GoogleOAuthProvider):
        """Test handling multiple OAuth clients."""
        from mcp.shared.auth import OAuthClientInformationFull

        # Create multiple clients
        client1 = OAuthClientInformationFull(
            client_id="client_1",
            client_secret="secret_1",
            redirect_uris=["http://localhost:3000/callback1"],
            scopes=["openid", "email"],
        )

        client2 = OAuthClientInformationFull(
            client_id="client_2",
            client_secret="secret_2",
            redirect_uris=["http://localhost:3000/callback2"],
            scopes=["openid", "profile"],
        )

        # Register both clients
        await oauth_provider.register_client(client1)
        await oauth_provider.register_client(client2)

        # Verify both clients are registered
        assert await oauth_provider.get_client("client_1") == client1
        assert await oauth_provider.get_client("client_2") == client2
        assert await oauth_provider.get_client("nonexistent") is None

    @pytest.mark.asyncio
    async def test_token_cleanup_on_expiry(
        self, oauth_provider: GoogleOAuthProvider, sample_client
    ):
        """Test that expired tokens are cleaned up."""
        import time

        # Add an expired token
        expired_token = MagicMock(
            client_id=sample_client.client_id,
            expires_at=time.time() - 3600,  # Expired 1 hour ago
        )
        oauth_provider.tokens["expired_token"] = expired_token

        # Add a valid token
        valid_token = MagicMock(
            client_id=sample_client.client_id,
            expires_at=time.time() + 3600,  # Valid for 1 hour
        )
        oauth_provider.tokens["valid_token"] = valid_token

        # Try to load the expired token
        result = await oauth_provider.load_access_token("expired_token")
        assert result is None
        assert "expired_token" not in oauth_provider.tokens

        # Try to load the valid token
        result = await oauth_provider.load_access_token("valid_token")
        assert result is not None
        assert "valid_token" in oauth_provider.tokens

    @pytest.mark.asyncio
    async def test_state_cleanup_after_callback(
        self,
        oauth_provider: GoogleOAuthProvider,
        sample_client,
        sample_auth_params,
        mock_http_client,
    ):
        """Test that state mapping is cleaned up after callback."""
        # Authorize to create state mapping
        await oauth_provider.authorize(sample_client, sample_auth_params)
        assert sample_auth_params.state in oauth_provider.state_mapping

        # Handle callback
        with patch(
            "google_auth_provider.provider.create_mcp_http_client",
            return_value=mock_http_client,
        ):
            await oauth_provider.handle_callback("test_code", sample_auth_params.state)

        # State should be cleaned up
        assert sample_auth_params.state not in oauth_provider.state_mapping

    @pytest.mark.asyncio
    async def test_authorization_code_cleanup_after_exchange(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_code
    ):
        """Test that authorization codes are cleaned up after exchange."""
        # Add auth code
        oauth_provider.auth_codes[sample_auth_code.code] = sample_auth_code
        assert sample_auth_code.code in oauth_provider.auth_codes

        # Exchange the code
        await oauth_provider.exchange_authorization_code(
            sample_client, sample_auth_code
        )

        # Auth code should be cleaned up
        assert sample_auth_code.code not in oauth_provider.auth_codes

    @pytest.mark.asyncio
    async def test_error_handling_in_flow(
        self, oauth_provider: GoogleOAuthProvider, sample_client, sample_auth_params
    ):
        """Test error handling throughout the OAuth flow."""
        # Test invalid state in callback
        with pytest.raises(Exception):
            await oauth_provider.handle_callback("test_code", "invalid_state")

        # Test invalid authorization code exchange
        from mcp.server.auth.provider import AuthorizationCode

        invalid_code = AuthorizationCode(
            code="invalid_code",
            client_id=sample_client.client_id,
            redirect_uri="http://localhost:3000/callback",
            redirect_uri_provided_explicitly=True,
            expires_at=time.time() + 300,
            scopes=["openid"],
            code_challenge="test",
        )

        with pytest.raises(ValueError):
            await oauth_provider.exchange_authorization_code(
                sample_client, invalid_code
            )

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, oauth_provider: GoogleOAuthProvider):
        """Test concurrent operations on the provider."""
        import asyncio
        from mcp.shared.auth import OAuthClientInformationFull

        # Create multiple clients
        clients = []
        for i in range(5):
            client = OAuthClientInformationFull(
                client_id=f"concurrent_client_{i}",
                client_secret=f"secret_{i}",
                redirect_uris=[f"http://localhost:3000/callback{i}"],
                scopes=["openid", "email"],
            )
            clients.append(client)

        # Register all clients concurrently
        await asyncio.gather(
            *[oauth_provider.register_client(client) for client in clients]
        )

        # Verify all clients are registered
        for client in clients:
            retrieved_client = await oauth_provider.get_client(client.client_id)
            assert retrieved_client == client
