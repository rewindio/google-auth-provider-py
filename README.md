# google-auth-provider-py

Python package for implementing Google OAuth 2.0

## Features

- Google OAuth 2.0 implementation
- Secure token management and storage
- Authorization code flow implementation
- Comprehensive test suite with pytest

## Installation

```bash
# Install the package
pip install -e .

# Install with test dependencies
pip install -e .[test]
```

## Testing

This project uses pytest for testing with comprehensive unit and integration tests.

### Quick Start

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run comprehensive test suite
make run-tests
```

### Test Categories

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test complete workflows and component interactions
- **Slow Tests**: Tests that take longer to run (marked with `@pytest.mark.slow`)

### Running Specific Tests

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run tests for a specific file
pytest tests/test_google_auth_provider.py

# Run a specific test
pytest tests/test_google_auth_provider.py::TestGoogleOAuthProvider::test_initialization
```

### Coverage

The test suite includes coverage reporting:

```bash
# Generate HTML coverage report
pytest --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

### Available Commands

- `make help` - Show all available commands
- `make install` - Install package and dependencies
- `make test` - Run all tests
- `make test-unit` - Run unit tests only
- `make test-integration` - Run integration tests only
- `make test-coverage` - Run tests with coverage
- `make lint` - Run linting checks
- `make clean` - Clean up generated files
- `make run-tests` - Run comprehensive test suite

## Configuration

The service accepts the following settings:

- `google_client_id` - Google OAuth client ID
- `google_client_secret` - Google OAuth client secret
- `auth_url` - Google OAuth authorization URL (default: https://accounts.google.com/o/oauth2/v2/auth)
- `token_url` - Google OAuth token URL (default: https://oauth2.googleapis.com/token)
- `callback_path` - OAuth callback URL (default: http://localhost:3000/callback)
- `scope` - OAuth scopes (default: openid email profile)
- `log_level` - Logging level (default: INFO)
- `host` - Server host (default: localhost)
- `port` - Server port (default: 3000)
