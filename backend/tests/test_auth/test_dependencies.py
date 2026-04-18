"""Tests for auth dependencies and permissions.

Covers get_current_user, require_role factory,
convenience helpers (require_admin, etc.), and
the feature-flag bypass (auth_enabled=False).
"""

import uuid
from datetime import timedelta

import boto3
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from moto import mock_aws

from app.auth.dependencies import (
    get_current_user,
    require_admin,
    require_admin_or_operator,
    require_any_authenticated,
)
from app.auth.jwt_handler import create_access_token
from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.permissions import PERMISSIONS
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import get_settings, get_user_store

TABLE_NAME = "cloudline-users"
_JWT_SECRET = "test-dep-secret-key-long-enough"
_PASSWORD = "DepTestPass123!"


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


def _make_settings(auth_enabled: bool) -> Settings:
    return Settings(
        jwt_secret=_JWT_SECRET,
        auth_enabled=auth_enabled,
        access_token_expire_minutes=60,
    )


def _make_token(user_id: str, role: UserRole) -> str:
    return create_access_token(
        user_id=user_id,
        role=role,
        secret=_JWT_SECRET,
        expires_delta=timedelta(hours=1),
    )


def _build_probe_app(
    store: UserStore,
    settings: Settings,
    dep,
    route: str = "/probe",
) -> FastAPI:
    """Tiny test app that exposes one endpoint
    depending on the given dependency."""
    app = FastAPI()
    app.dependency_overrides[
        get_settings
    ] = lambda: settings
    app.dependency_overrides[
        get_user_store
    ] = lambda: store

    @app.get(route)
    async def _probe(
        user: User = Depends(dep),
    ) -> dict:
        return {
            "sk": user.sk,
            "role": user.role.value,
        }

    return app


@pytest.fixture
def dep_setup(aws_credentials):
    """Yields (store, admin_user_id) in moto context."""
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

        # Seed one user of each role
        users = {}
        for role in UserRole:
            uid = str(uuid.uuid4())
            store.put_user(
                User(
                    sk=uid,
                    email=f"{role.value}@test.com",
                    full_name=role.value.capitalize(),
                    password_hash=hash_password(
                        _PASSWORD
                    ),
                    role=role,
                    is_active=True,
                    created_at="2026-04-10T00:00:00Z",
                )
            )
            users[role] = uid

        yield store, users


# ── get_current_user ──────────────────────────────


class TestGetCurrentUser:
    def test_auth_disabled_returns_synthetic_admin(
        self, dep_setup
    ):
        store, _ = dep_setup
        cfg = _make_settings(auth_enabled=False)
        app = _build_probe_app(
            store, cfg, get_current_user
        )
        with TestClient(app) as c:
            resp = c.get("/probe")
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_valid_token_returns_user(
        self, dep_setup
    ):
        store, users = dep_setup
        admin_id = users[UserRole.ADMIN]
        token = _make_token(admin_id, UserRole.ADMIN)
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, get_current_user
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 200
        assert resp.json()["sk"] == admin_id

    def test_missing_token_returns_401_when_enabled(
        self, dep_setup
    ):
        store, _ = dep_setup
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, get_current_user
        )
        with TestClient(app) as c:
            resp = c.get("/probe")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(
        self, dep_setup
    ):
        store, _ = dep_setup
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, get_current_user
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": "Bearer bad.token"
                },
            )
        assert resp.status_code == 401


# ── require_admin ─────────────────────────────────


class TestRequireAdmin:
    def test_admin_passes(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.ADMIN], UserRole.ADMIN
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_operator_blocked(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.OPERATOR],
            UserRole.OPERATOR,
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 403

    def test_viewer_blocked(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.VIEWER], UserRole.VIEWER
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 403


# ── require_admin_or_operator ─────────────────────


class TestRequireAdminOrOperator:
    def test_admin_passes(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.ADMIN], UserRole.ADMIN
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin_or_operator
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 200

    def test_operator_passes(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.OPERATOR],
            UserRole.OPERATOR,
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin_or_operator
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 200

    def test_viewer_blocked(self, dep_setup):
        store, users = dep_setup
        token = _make_token(
            users[UserRole.VIEWER], UserRole.VIEWER
        )
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_admin_or_operator
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 403


# ── require_any_authenticated ─────────────────────


class TestRequireAnyAuthenticated:
    @pytest.mark.parametrize(
        "role",
        [UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER],
    )
    def test_all_roles_pass(self, role, dep_setup):
        store, users = dep_setup
        token = _make_token(users[role], role)
        cfg = _make_settings(auth_enabled=True)
        app = _build_probe_app(
            store, cfg, require_any_authenticated
        )
        with TestClient(app) as c:
            resp = c.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}"
                },
            )
        assert resp.status_code == 200


# ── permissions.py ────────────────────────────────


class TestPermissions:
    def test_admin_has_all_permissions(self):
        admin_perms = PERMISSIONS[UserRole.ADMIN]
        assert "manage_users" in admin_perms
        assert "manage_accounts" in admin_perms
        assert "approve_password_reset" in admin_perms
        assert "trigger_scan" in admin_perms
        assert "create_jira_ticket" in admin_perms
        assert "view_all" in admin_perms

    def test_operator_cannot_manage_users(self):
        op_perms = PERMISSIONS[UserRole.OPERATOR]
        assert "manage_users" not in op_perms
        assert "manage_accounts" not in op_perms
        assert "trigger_scan" in op_perms
        assert "create_jira_ticket" in op_perms

    def test_viewer_is_read_only(self):
        viewer_perms = PERMISSIONS[UserRole.VIEWER]
        assert "view_all" in viewer_perms
        assert "change_own_password" in viewer_perms
        assert "trigger_scan" not in viewer_perms
        assert "create_jira_ticket" not in viewer_perms
        assert "manage_users" not in viewer_perms
