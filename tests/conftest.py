"""Pytest configuration and fixtures for Google OAuth provider tests."""

import asyncio
import logging
import secrets
import time
from typing import Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationCode, AuthorizationParams

from google_auth_provider.provider import GoogleOAuthProvider


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_settings() -> dict:
    """Create mock server settings for testing."""
    return {
        "google_client_id": "test_client_id",
        "google_client_secret": "test_client_secret",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "callback_path": "http://localhost:3000/callback",
        "scope": "openid email profile",
        "log_level": "DEBUG",
        "host": "localhost",
        "port": 3000,
    }


@pytest.fixture
def oauth_provider(mock_settings: dict) -> GoogleOAuthProvider:
    """Create a GoogleOAuthProvider instance for testing."""
    # Set global settings for the provider
    return GoogleOAuthProvider(mock_settings)


@pytest.fixture
def sample_client() -> OAuthClientInformationFull:
    """Create a sample OAuth client for testing."""
    return OAuthClientInformationFull(
        client_id="test_client_123",
        client_secret="test_secret_456",
        redirect_uris=["http://localhost:3000/callback"],
        scopes=["openid", "email", "profile"],
    )


@pytest.fixture
def sample_auth_params() -> AuthorizationParams:
    """Create sample authorization parameters for testing."""
    return AuthorizationParams(
        redirect_uri="http://localhost:3000/callback",
        state="test_state_123",
        code_challenge="test_challenge",
        code_challenge_method="S256",
        redirect_uri_provided_explicitly=True,
        scopes=["openid", "email", "profile"],
    )


@pytest.fixture
def sample_auth_code() -> AuthorizationCode:
    """Create a sample authorization code for testing."""
    return AuthorizationCode(
        code="test_auth_code_123",
        client_id="test_client_123",
        redirect_uri="http://localhost:3000/callback",
        redirect_uri_provided_explicitly=True,
        expires_at=time.time() + 300,
        scopes=["openid", "email", "profile"],
        code_challenge="test_challenge",
    )


@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response for testing."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "access_token": "google_access_token_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }
    mock_response.raise_for_status.return_value = None
    return mock_response


@pytest.fixture
def mock_http_client(mock_http_response):
    """Create a mock HTTP client for testing."""
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_http_response
    return mock_client


@pytest.fixture(autouse=True)
def disable_logging():
    """Disable logging during tests to reduce noise."""
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture
def mock_secrets():
    """Mock the secrets module for predictable token generation."""
    with pytest.MonkeyPatch().context() as m:
        m.setattr(secrets, "token_hex", lambda n: "mocked" + "0" * (n * 2 - 7))
        yield m
