"""Tests for Feature 4: Login Audit Log.

Tests:
  - AuditLogStore.log_login writes an entry
  - AuditLogStore.get_recent_logins retrieves entries
  - GET /users/{user_id}/login-history (Admin only)
  - Both success and failure events are logged
"""

import uuid
from datetime import datetime, timezone

import boto3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from moto import mock_aws

from app.auth.audit_log import AuditLogStore
from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import (
    get_settings,
    get_user_store,
)
from app.routers.auth_router import router as auth_router
from app.routers.users import router as users_router

USERS_TABLE = "cloudline-users"
AUDIT_TABLE = "cloudline-audit-log"
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


@pytest.fixture
def aws_creds(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv(
        "AWS_SECRET_ACCESS_KEY", "testing"
    )
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _create_users_table(client) -> None:
    client.create_table(
        TableName=USERS_TABLE,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {
                "AttributeName": "email",
                "AttributeType": "S",
            },
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
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


def _create_audit_table(client) -> None:
    """Create cloudline-audit-log table."""
    client.create_table(
        TableName=AUDIT_TABLE,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ── AuditLogStore unit tests ──────────────────────


class TestAuditLogStore:
    @pytest.fixture
    def store(self, aws_creds):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            ddb = session.client(
                "dynamodb", region_name="us-east-1"
            )
            _create_audit_table(ddb)
            yield AuditLogStore(
                session=session,
                table_name=AUDIT_TABLE,
            )

    def test_log_login_creates_entry(self, store):
        """log_login writes a record to DynamoDB."""
        user_id = str(uuid.uuid4())
        ts = datetime.now(tz=timezone.utc).isoformat()
        result = store.log_login(
            user_id=user_id,
            ip="1.2.3.4",
            user_agent="test-agent",
            success=True,
            ts=ts,
            jti="jti-abc",
        )
        assert result is True

    def test_get_recent_logins_returns_entries(
        self, store
    ):
        """get_recent_logins retrieves logged events."""
        user_id = str(uuid.uuid4())
        ts = datetime.now(tz=timezone.utc).isoformat()
        store.log_login(
            user_id=user_id,
            ip="10.0.0.1",
            user_agent="Mozilla/5.0",
            success=True,
            ts=ts,
            jti="jti-1",
        )
        entries = store.get_recent_logins(user_id)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["ip"] == "10.0.0.1"
        assert entry["success"] is True
        assert entry["user_agent"] == "Mozilla/5.0"

    def test_log_failed_login(self, store):
        """Failure events are stored with success=False."""
        user_id = str(uuid.uuid4())
        ts = datetime.now(tz=timezone.utc).isoformat()
        store.log_login(
            user_id=user_id,
            ip="5.5.5.5",
            user_agent="curl",
            success=False,
            ts=ts,
            jti="",
        )
        entries = store.get_recent_logins(user_id)
        assert entries[0]["success"] is False

    def test_get_recent_logins_respects_limit(
        self, store
    ):
        """Returns at most `limit` entries."""
        user_id = str(uuid.uuid4())
        for i in range(5):
            store.log_login(
                user_id=user_id,
                ip=f"1.1.1.{i}",
                user_agent="agent",
                success=True,
                ts=f"2026-04-10T{i:02d}:00:00Z",
                jti=f"jti-{i}",
            )
        entries = store.get_recent_logins(
            user_id, limit=3
        )
        assert len(entries) <= 3

    def test_get_recent_logins_empty(self, store):
        """Returns [] when no entries exist."""
        entries = store.get_recent_logins("no-such-user")
        assert entries == []

    def test_multiple_users_independent(self, store):
        """Each user's audit log is separate."""
        uid_a = str(uuid.uuid4())
        uid_b = str(uuid.uuid4())
        ts = datetime.now(tz=timezone.utc).isoformat()
        store.log_login(
            user_id=uid_a,
            ip="1.1.1.1",
            user_agent="a",
            success=True,
            ts=ts,
            jti="jti-a",
        )
        store.log_login(
            user_id=uid_b,
            ip="2.2.2.2",
            user_agent="b",
            success=False,
            ts=ts,
            jti="",
        )
        entries_a = store.get_recent_logins(uid_a)
        entries_b = store.get_recent_logins(uid_b)
        assert len(entries_a) == 1
        assert len(entries_b) == 1
        assert entries_a[0]["ip"] == "1.1.1.1"
        assert entries_b[0]["ip"] == "2.2.2.2"


# ── Login History endpoint tests ──────────────────


@pytest.fixture
def history_setup(aws_creds):
    """Set up full stack for login-history endpoint."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        ddb = session.client(
            "dynamodb", region_name="us-east-1"
        )
        _create_users_table(ddb)
        _create_audit_table(ddb)

        store = UserStore(
            session=session, table_name=USERS_TABLE
        )
        audit = AuditLogStore(
            session=session, table_name=AUDIT_TABLE
        )
        cfg = _make_settings()

        target_id = str(uuid.uuid4())
        target = User(
            sk=target_id,
            email="target@example.com",
            full_name="Target User",
            password_hash=hash_password(_PASSWORD),
            role=UserRole.OPERATOR,
            is_active=True,
        )
        store.put_user(target)

        admin_id = str(uuid.uuid4())
        admin_user = User(
            sk=admin_id,
            email="admin@example.com",
            full_name="Admin",
            password_hash=hash_password(_PASSWORD),
            role=UserRole.ADMIN,
            is_active=True,
        )
        store.put_user(admin_user)

        # Seed some audit entries for target_id
        ts = datetime.now(tz=timezone.utc).isoformat()
        audit.log_login(
            user_id=target_id,
            ip="192.168.1.1",
            user_agent="browser",
            success=True,
            ts=ts,
            jti="jti-test",
        )

        from app.auth.dependencies import require_admin

        app = FastAPI()
        app.include_router(
            auth_router, prefix="/api/v1"
        )
        app.include_router(
            users_router, prefix="/api/v1"
        )

        app.dependency_overrides[
            get_settings
        ] = lambda: cfg
        app.dependency_overrides[
            get_user_store
        ] = lambda: store
        # Inject admin user into require_admin
        app.dependency_overrides[
            require_admin
        ] = lambda: admin_user

        from app.dependencies import get_audit_log_store
        app.dependency_overrides[
            get_audit_log_store
        ] = lambda: audit

        with TestClient(app) as client:
            yield (
                client,
                target_id,
                admin_id,
                store,
                audit,
                cfg,
            )


class TestLoginHistoryEndpoint:
    def test_admin_gets_login_history(
        self, history_setup
    ):
        """Admin can fetch login history for any user."""
        client, target_id, *_ = history_setup
        resp = client.get(
            f"/api/v1/users/{target_id}/login-history"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "ip" in data[0]
        assert "success" in data[0]

    def test_login_history_returns_correct_fields(
        self, history_setup
    ):
        """Response entries have required fields."""
        client, target_id, *_ = history_setup
        resp = client.get(
            f"/api/v1/users/{target_id}/login-history"
        )
        assert resp.status_code == 200
        entry = resp.json()[0]
        required = {"ip", "user_agent", "success", "ts"}
        assert required.issubset(entry.keys())

    def test_login_history_unknown_user_returns_404(
        self, history_setup
    ):
        """404 for non-existent user_id."""
        client, *_ = history_setup
        resp = client.get(
            "/api/v1/users/no-such-id/login-history"
        )
        assert resp.status_code == 404


# ── Audit logging on login attempts ──────────────


class TestAuditOnLogin:
    """Login endpoint writes audit log entries."""

    @pytest.fixture
    def audit_login_setup(self, aws_creds):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            ddb = session.client(
                "dynamodb", region_name="us-east-1"
            )
            _create_users_table(ddb)
            _create_audit_table(ddb)

            store = UserStore(
                session=session, table_name=USERS_TABLE
            )
            audit = AuditLogStore(
                session=session, table_name=AUDIT_TABLE
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
            )
            store.put_user(user)

            app = FastAPI()
            app.include_router(
                auth_router, prefix="/api/v1"
            )
            app.dependency_overrides[
                get_settings
            ] = lambda: cfg
            app.dependency_overrides[
                get_user_store
            ] = lambda: store

            from app.dependencies import (
                get_audit_log_store,
            )
            app.dependency_overrides[
                get_audit_log_store
            ] = lambda: audit

            with TestClient(app) as client:
                yield client, user_id, store, audit, cfg

    def test_successful_login_creates_audit_entry(
        self, audit_login_setup
    ):
        """Successful login writes success=True audit."""
        client, user_id, _, audit, _ = (
            audit_login_setup
        )
        client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": _PASSWORD,
            },
        )
        entries = audit.get_recent_logins(user_id)
        assert len(entries) >= 1
        success_entries = [
            e for e in entries if e["success"]
        ]
        assert len(success_entries) >= 1

    def test_failed_login_creates_audit_entry(
        self, audit_login_setup
    ):
        """Failed login writes success=False audit entry."""
        client, user_id, _, audit, _ = (
            audit_login_setup
        )
        client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": "WrongPassword!99",
            },
        )
        entries = audit.get_recent_logins(user_id)
        assert len(entries) >= 1
        failure_entries = [
            e for e in entries if not e["success"]
        ]
        assert len(failure_entries) >= 1
