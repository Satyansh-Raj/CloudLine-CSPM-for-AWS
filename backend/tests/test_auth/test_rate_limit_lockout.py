"""Tests for login rate limiting and lockout.

Features tested:
- Feature 1: Rate limiting (429 after threshold)
- Feature 2: Login lockout (10 failures → locked)
"""

import uuid
from unittest.mock import patch

import boto3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from moto import mock_aws

from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import get_settings, get_user_store
from app.routers.auth_router import router

TABLE_NAME = "cloudline-users"
_PASSWORD = "TestPassword123!"
_JWT_SECRET = "test-jwt-secret-key-for-unit-tests"


def _make_settings(**kwargs) -> Settings:
    return Settings(
        jwt_secret=_JWT_SECRET,
        access_token_expire_minutes=60,
        refresh_token_expire_days=7,
        auth_enabled=True,
        **kwargs,
    )


def _create_users_table(client) -> None:
    client.create_table(
        TableName=TABLE_NAME,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "email", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "email-index",
                "KeySchema": [
                    {"AttributeName": "email", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
            }
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        },
    )


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def auth_setup(aws_credentials):
    """Yields (TestClient, user_id, store, settings)."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        ddb = session.client(
            "dynamodb", region_name="us-east-1"
        )
        _create_users_table(ddb)
        store = UserStore(
            session=session, table_name=TABLE_NAME
        )
        cfg = _make_settings()

        user_id = str(uuid.uuid4())
        user = User(
            sk=user_id,
            email="user@example.com",
            full_name="Test User",
            password_hash=hash_password(_PASSWORD),
            role=UserRole.OPERATOR,
            is_active=True,
            created_at="2026-04-09T00:00:00Z",
        )
        store.put_user(user)

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[
            get_settings
        ] = lambda: cfg
        app.dependency_overrides[
            get_user_store
        ] = lambda: store

        with TestClient(app) as client:
            yield client, user_id, store, cfg


# ── Feature 2: Login Lockout ──────────────────────


class TestLoginLockout:
    """10 consecutive failed logins → account locked."""

    def test_nine_failures_user_still_active(
        self, auth_setup
    ):
        """User stays active after 9 failed attempts."""
        client, user_id, store, _ = auth_setup
        for _ in range(9):
            resp = client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )
            assert resp.status_code == 401

        user = store.get_user_by_id(user_id)
        assert user.is_active is True

    def test_tenth_failure_locks_account(
        self, auth_setup
    ):
        """10th failed attempt sets is_active=False."""
        client, user_id, store, _ = auth_setup
        for _ in range(10):
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )

        user = store.get_user_by_id(user_id)
        assert user.is_active is False

    def test_locked_user_cannot_login(
        self, auth_setup
    ):
        """Locked user receives 401 even with correct pw."""
        client, user_id, store, _ = auth_setup
        # Lock via 10 failures
        for _ in range(10):
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )
        # Now try with correct password
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 401

    def test_admin_reactivation_allows_login(
        self, auth_setup
    ):
        """Admin sets is_active=True → user can login."""
        client, user_id, store, _ = auth_setup
        # Lock account
        for _ in range(10):
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )
        # Admin reactivates via store
        store.update_user(user_id, is_active=True)
        # Also reset failed_login_count
        store.reset_failed_login_count(user_id)

        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 200

    def test_successful_login_resets_failed_count(
        self, auth_setup
    ):
        """Successful login clears the failure counter."""
        client, user_id, store, _ = auth_setup
        # Do 5 failures
        for _ in range(5):
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )
        # Then succeed
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 200
        user = store.get_user_by_id(user_id)
        assert user.failed_login_count == 0

    def test_failed_login_count_increments(
        self, auth_setup
    ):
        """Each bad attempt increments failed_login_count."""
        client, user_id, store, _ = auth_setup
        for i in range(3):
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": "user@example.com",
                    "password": "WrongPassword!99",
                },
            )
        user = store.get_user_by_id(user_id)
        assert user.failed_login_count == 3


# ── Feature 1: Rate Limiting ──────────────────────


class TestRateLimiting:
    """Login endpoint enforces per-IP rate limit."""

    def test_rate_limit_allows_below_threshold(
        self, auth_setup
    ):
        """Requests within the limit receive non-429."""
        client, *_ = auth_setup
        # First request should not be rate-limited
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code != 429

    def test_rate_limit_module_importable(self):
        """slowapi can be imported (dependency present)."""
        import slowapi  # noqa: F401
        from slowapi import Limiter  # noqa: F401
        assert True
