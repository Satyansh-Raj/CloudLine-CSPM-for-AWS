"""Tests for /api/v1/auth/* endpoints."""

import uuid

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
_JWT_SECRET = (
    "test-jwt-secret-key-for-unit-tests-only"
)


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
            {
                "AttributeName": "pk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "sk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "email",
                "AttributeType": "S",
            },
        ],
        KeySchema=[
            {
                "AttributeName": "pk",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "sk",
                "KeyType": "RANGE",
            },
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "email-index",
                "KeySchema": [
                    {
                        "AttributeName": "email",
                        "KeyType": "HASH",
                    },
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
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
    monkeypatch.setenv(
        "AWS_ACCESS_KEY_ID", "testing"
    )
    monkeypatch.setenv(
        "AWS_SECRET_ACCESS_KEY", "testing"
    )
    monkeypatch.setenv(
        "AWS_SECURITY_TOKEN", "testing"
    )
    monkeypatch.setenv(
        "AWS_SESSION_TOKEN", "testing"
    )
    monkeypatch.setenv(
        "AWS_DEFAULT_REGION", "us-east-1"
    )


@pytest.fixture
def auth_setup(aws_credentials):
    """Yields (TestClient, user_id, store, settings)."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        ddb = session.client(
            "dynamodb", region_name="us-east-1"
        )
        _create_users_table(ddb)
        store = UserStore(
            session=session, table_name=TABLE_NAME
        )
        cfg = _make_settings()

        # Active user
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

        # Disabled user
        disabled_id = str(uuid.uuid4())
        disabled = User(
            sk=disabled_id,
            email="disabled@example.com",
            full_name="Disabled User",
            password_hash=hash_password(_PASSWORD),
            role=UserRole.VIEWER,
            is_active=False,
            created_at="2026-04-09T00:00:00Z",
        )
        store.put_user(disabled)

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


# ── Helpers ──────────────────────────────────────


def _login(client) -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "email": "user@example.com",
            "password": _PASSWORD,
        },
    )
    assert resp.status_code == 200
    return resp.json()


def _access_token(client) -> str:
    return _login(client)["access_token"]


# ── Login ─────────────────────────────────────────


class TestLogin:
    def test_success_returns_token_pair(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_wrong_password_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": "WrongPassword999!",
            },
        )
        assert resp.status_code == 401

    def test_nonexistent_email_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nobody@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 401

    def test_disabled_user_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "email": "disabled@example.com",
                "password": _PASSWORD,
            },
        )
        assert resp.status_code == 401

    def test_updates_last_login_on_success(
        self, auth_setup
    ):
        client, user_id, store, _ = auth_setup
        _login(client)
        user = store.get_user_by_id(user_id)
        assert user.last_login is not None


# ── Refresh ───────────────────────────────────────


class TestRefresh:
    def test_success_returns_new_access_token(
        self, auth_setup
    ):
        client, *_ = auth_setup
        tokens = _login(client)
        resp = client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": tokens["refresh_token"]
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        # New token is different from the original
        assert (
            data["access_token"] != tokens["access_token"]
        )

    def test_invalid_token_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "not.a.valid.token"},
        )
        assert resp.status_code == 401

    def test_access_token_as_refresh_returns_401(
        self, auth_setup
    ):
        """Prevents token-type confusion attacks."""
        client, *_ = auth_setup
        tokens = _login(client)
        resp = client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": tokens["access_token"]
            },
        )
        assert resp.status_code == 401


# ── Me ────────────────────────────────────────────


class TestMe:
    def test_returns_current_user(self, auth_setup):
        client, user_id, *_ = auth_setup
        token = _access_token(client)
        resp = client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}"
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "user@example.com"
        assert data["role"] == "operator"
        assert "password_hash" not in data

    def test_missing_token_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": "Bearer invalidtoken"
            },
        )
        assert resp.status_code == 401


# ── Logout ────────────────────────────────────────


class TestLogout:
    def test_returns_200(self, auth_setup):
        client, *_ = auth_setup
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 200


# ── Change Password ───────────────────────────────


class TestChangePassword:
    def test_correct_current_password(
        self, auth_setup
    ):
        client, user_id, store, _ = auth_setup
        token = _access_token(client)
        resp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {token}"
            },
            json={
                "current_password": _PASSWORD,
                "new_password": "NewSecurePass456!",
            },
        )
        assert resp.status_code == 200

    def test_wrong_current_password_returns_400(
        self, auth_setup
    ):
        client, *_ = auth_setup
        token = _access_token(client)
        resp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {token}"
            },
            json={
                "current_password": "WrongOldPass999!",
                "new_password": "NewSecurePass456!",
            },
        )
        assert resp.status_code == 400

    def test_new_password_too_short_returns_400(
        self, auth_setup
    ):
        client, *_ = auth_setup
        token = _access_token(client)
        resp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {token}"
            },
            json={
                "current_password": _PASSWORD,
                "new_password": "short",
            },
        )
        assert resp.status_code == 400

    def test_reset_allowed_skips_current_password(
        self, auth_setup
    ):
        """Admin-approved reset: skip current pw check."""
        client, user_id, store, _ = auth_setup
        store.approve_reset(
            user_id, "admin-user", "2026-04-25T00:00:00Z"
        )
        token = _access_token(client)
        resp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {token}"
            },
            json={
                "current_password": "WrongPassword999!",
                "new_password": "BrandNewPass123!",
            },
        )
        assert resp.status_code == 200
        updated = store.get_user_by_id(user_id)
        assert updated.reset_allowed is False

    def test_missing_token_returns_401(
        self, auth_setup
    ):
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": _PASSWORD,
                "new_password": "NewSecurePass456!",
            },
        )
        assert resp.status_code == 401


# ── Request Reset ─────────────────────────────────


class TestRequestReset:
    def test_returns_202_for_existing_email(
        self, auth_setup
    ):
        client, user_id, store, _ = auth_setup
        resp = client.post(
            "/api/v1/auth/request-reset",
            json={"email": "user@example.com"},
        )
        assert resp.status_code == 202
        user = store.get_user_by_id(user_id)
        assert user.reset_requested_at is not None

    def test_returns_202_for_unknown_email(
        self, auth_setup
    ):
        """Always 202 — must not leak whether email exists."""
        client, *_ = auth_setup
        resp = client.post(
            "/api/v1/auth/request-reset",
            json={"email": "nobody@example.com"},
        )
        assert resp.status_code == 202
