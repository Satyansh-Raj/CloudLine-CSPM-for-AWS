"""Shared test fixtures."""

import boto3
import pytest
from moto import mock_aws

from app.auth.dependencies import get_current_user
from app.auth.models import User, UserRole
from app.config import Settings
from app.dependencies import get_settings
from app.main import app

# Synthetic Admin returned for all tests unless overridden.
_TEST_ADMIN = User(
    sk="test-admin",
    email="admin@cloudline.test",
    full_name="Test Admin",
    password_hash="",
    role=UserRole.ADMIN,
)


@pytest.fixture(autouse=True)
def disable_auth_for_tests():
    """Bypass auth for all tests.

    Two overrides are set:
    1. get_current_user → synthetic Admin. This covers all
       HTTP endpoints even when a test's setup_method
       re-overrides get_settings.
    2. get_settings → auth_enabled=False. This covers the
       WebSocket handler which reads cfg.auth_enabled from
       the injected Settings object.

    Auth-specific tests (test_auth/) may pop these overrides
    to test real auth behaviour.
    """
    def _no_auth_settings() -> Settings:
        return Settings(
            aws_region="us-east-1",
            aws_account_id="832843292195",
            api_key="test-api-key",
            app_env="testing",
            auth_enabled=False,
        )

    app.dependency_overrides[get_current_user] = (
        lambda: _TEST_ADMIN
    )
    app.dependency_overrides[get_settings] = (
        _no_auth_settings
    )
    yield
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_settings, None)


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def mock_session(aws_credentials):
    """Create a moto-mocked boto3 session."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield session


@pytest.fixture
def test_settings():
    """Test application settings."""
    return Settings(
        aws_region="us-east-1",
        aws_account_id="832843292195",
        api_key="test-api-key",
        app_env="testing",
    )
