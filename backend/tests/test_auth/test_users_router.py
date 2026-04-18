"""Tests for /api/v1/users/* endpoints (Admin-only)."""

import uuid

import boto3
import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from moto import mock_aws

from app.auth.dependencies import require_admin
from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import get_user_store
from app.routers.users import router

TABLE_NAME = "cloudline-users"
_PASSWORD = "AdminPass123!"


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


_ADMIN_USER = User(
    sk="admin-001",
    email="admin@example.com",
    full_name="System Admin",
    password_hash=hash_password(_PASSWORD),
    role=UserRole.ADMIN,
    is_active=True,
    created_at="2026-04-10T00:00:00Z",
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


def _build_app(store: UserStore, admin: bool) -> FastAPI:
    """Build test FastAPI app with optional 403 guard."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[
        get_user_store
    ] = lambda: store
    if admin:
        app.dependency_overrides[
            require_admin
        ] = lambda: _ADMIN_USER
    else:
        async def _forbidden():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        app.dependency_overrides[
            require_admin
        ] = _forbidden
    return app


@pytest.fixture
def setup(aws_credentials):
    """Yields (admin_client, store) inside moto context."""
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
        store.put_user(_ADMIN_USER)

        admin_app = _build_app(store, admin=True)
        with TestClient(admin_app) as ac:
            yield ac, store


@pytest.fixture
def non_admin_client(aws_credentials):
    """Client whose requests are blocked by 403."""
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
        na_app = _build_app(store, admin=False)
        with TestClient(na_app) as c:
            yield c


# ── CRUD happy path ───────────────────────────────


class TestCreateUser:
    def test_creates_user_returns_201(self, setup):
        client, store = setup
        resp = client.post(
            "/api/v1/users",
            json={
                "email": "new@example.com",
                "full_name": "New User",
                "role": "viewer",
                "initial_password": "NewUserPass123!",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@example.com"
        assert data["role"] == "viewer"
        assert "password_hash" not in data

    def test_email_collision_returns_409(self, setup):
        client, _ = setup
        payload = {
            "email": "admin@example.com",
            "full_name": "Dup",
            "role": "viewer",
            "initial_password": "NewUserPass123!",
        }
        resp = client.post("/api/v1/users", json=payload)
        assert resp.status_code == 409

    def test_short_password_returns_400(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/users",
            json={
                "email": "short@example.com",
                "full_name": "Short",
                "role": "viewer",
                "initial_password": "short",
            },
        )
        assert resp.status_code == 400


class TestListUsers:
    def test_returns_all_users(self, setup):
        client, _ = setup
        resp = client.get("/api/v1/users")
        assert resp.status_code == 200
        emails = [u["email"] for u in resp.json()]
        assert "admin@example.com" in emails

    def test_no_password_hash_in_response(
        self, setup
    ):
        client, _ = setup
        resp = client.get("/api/v1/users")
        for user in resp.json():
            assert "password_hash" not in user


class TestGetUser:
    def test_returns_user(self, setup):
        client, _ = setup
        resp = client.get(
            f"/api/v1/users/{_ADMIN_USER.sk}"
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "admin@example.com"

    def test_nonexistent_returns_404(self, setup):
        client, _ = setup
        resp = client.get(
            "/api/v1/users/does-not-exist"
        )
        assert resp.status_code == 404


class TestUpdateUser:
    def test_updates_role(self, setup):
        client, store = setup
        # Create a viewer first
        viewer_id = str(uuid.uuid4())
        viewer = User(
            sk=viewer_id,
            email="viewer@example.com",
            full_name="Viewer",
            password_hash=hash_password(_PASSWORD),
            role=UserRole.VIEWER,
            is_active=True,
            created_at="2026-04-10T00:00:00Z",
        )
        store.put_user(viewer)

        resp = client.put(
            f"/api/v1/users/{viewer_id}",
            json={"role": "operator"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "operator"

    def test_nonexistent_returns_404(self, setup):
        client, _ = setup
        resp = client.put(
            "/api/v1/users/ghost",
            json={"full_name": "Ghost"},
        )
        assert resp.status_code == 404


class TestDeleteUser:
    def test_soft_deletes_non_admin(self, setup):
        client, store = setup
        uid = str(uuid.uuid4())
        store.put_user(
            User(
                sk=uid,
                email="op@example.com",
                full_name="Op",
                password_hash=hash_password(_PASSWORD),
                role=UserRole.OPERATOR,
                is_active=True,
                created_at="2026-04-10T00:00:00Z",
            )
        )
        resp = client.delete(f"/api/v1/users/{uid}")
        assert resp.status_code == 200
        assert (
            resp.json()["status"] == "deactivated"
        )
        updated = store.get_user_by_id(uid)
        assert updated.is_active is False

    def test_cannot_delete_last_admin(self, setup):
        """Deleting the sole active Admin → 400."""
        client, _ = setup
        resp = client.delete(
            f"/api/v1/users/{_ADMIN_USER.sk}"
        )
        assert resp.status_code == 400

    def test_can_delete_admin_when_another_exists(
        self, setup
    ):
        client, store = setup
        second_admin_id = str(uuid.uuid4())
        store.put_user(
            User(
                sk=second_admin_id,
                email="admin2@example.com",
                full_name="Admin2",
                password_hash=hash_password(_PASSWORD),
                role=UserRole.ADMIN,
                is_active=True,
                created_at="2026-04-10T00:00:00Z",
            )
        )
        resp = client.delete(
            f"/api/v1/users/{_ADMIN_USER.sk}"
        )
        assert resp.status_code == 200


class TestResetRequests:
    def test_returns_pending_resets(self, setup):
        client, store = setup
        store.set_reset_requested(
            _ADMIN_USER.sk, "2026-04-10T08:00:00Z"
        )
        resp = client.get(
            "/api/v1/users/reset-requests"
        )
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_approve_reset(self, setup):
        client, store = setup
        uid = str(uuid.uuid4())
        store.put_user(
            User(
                sk=uid,
                email="requester@example.com",
                full_name="Requester",
                password_hash=hash_password(_PASSWORD),
                role=UserRole.VIEWER,
                is_active=True,
                created_at="2026-04-10T00:00:00Z",
                reset_requested_at=(
                    "2026-04-10T08:00:00Z"
                ),
            )
        )
        resp = client.post(
            f"/api/v1/users/{uid}/approve-reset"
        )
        assert resp.status_code == 200
        updated = store.get_user_by_id(uid)
        assert updated.reset_allowed is True
        assert (
            updated.reset_approved_by == _ADMIN_USER.sk
        )


# ── Non-admin 403 guard ───────────────────────────


class TestNonAdminBlocked:
    def test_list_users_blocked(
        self, non_admin_client
    ):
        resp = non_admin_client.get("/api/v1/users")
        assert resp.status_code == 403

    def test_create_user_blocked(
        self, non_admin_client
    ):
        resp = non_admin_client.post(
            "/api/v1/users",
            json={
                "email": "x@x.com",
                "full_name": "X",
                "role": "viewer",
                "initial_password": "XPassword123!",
            },
        )
        assert resp.status_code == 403

    def test_approve_reset_blocked(
        self, non_admin_client
    ):
        resp = non_admin_client.post(
            "/api/v1/users/some-id/approve-reset"
        )
        assert resp.status_code == 403
