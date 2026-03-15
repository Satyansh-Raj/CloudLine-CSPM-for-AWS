"""Shared test fixtures."""

import boto3
import pytest
from moto import mock_aws

from app.config import Settings


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
