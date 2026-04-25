"""Integration tests — account access enforcement in routers.

Each test overrides get_current_user with a restricted viewer
(all_accounts_access=False, allowed_account_ids=["111111111111"])
then calls an account-scoped endpoint with a different account ID.
Expects 403.  Also tests that the allowed account returns 200/data.
"""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import get_current_user
from app.auth.models import User, UserRole
from app.dependencies import (
    get_account_store,
    get_settings,
    get_snapshot_manager,
    get_state_manager,
)
from app.main import app
from app.config import Settings

ALLOWED_ACCOUNT = "111111111111"
FORBIDDEN_ACCOUNT = "999999999999"


def _restricted_viewer() -> User:
    return User(
        sk="viewer-1",
        email="viewer@test.com",
        full_name="Viewer",
        password_hash="x",
        role=UserRole.VIEWER,
        all_accounts_access=False,
        allowed_account_ids=[ALLOWED_ACCOUNT],
    )


def _test_settings() -> Settings:
    return Settings(
        aws_region="us-east-1",
        aws_account_id=ALLOWED_ACCOUNT,
        api_key="test",
        app_env="testing",
        auth_enabled=True,
    )


@pytest.fixture
def restricted_client(disable_auth_for_tests):
    """TestClient with a restricted viewer identity."""
    app.dependency_overrides[get_current_user] = (
        _restricted_viewer
    )
    app.dependency_overrides[get_settings] = (
        _test_settings
    )
    yield TestClient(app)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_settings, None)


# ── GET /violations ──────────────────────────────────


class TestViolationsEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            "/api/v1/violations",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_account_store, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            "/api/v1/violations",
            params={"account_id": ALLOWED_ACCOUNT},
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_account_store, None
        )


# ── GET /compliance/score ─────────────────────────────


class TestComplianceScoreEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            "/api/v1/compliance/score",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_account_store, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            "/api/v1/compliance/score",
            params={"account_id": ALLOWED_ACCOUNT},
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_account_store, None
        )


# ── GET /compliance/framework/{name} ─────────────────


class TestComplianceFrameworkEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            "/api/v1/compliance/framework/cis_aws",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_account_store, None
        )


# ── GET /trends/history ───────────────────────────────


class TestTrendsEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        mock_snap = MagicMock()
        mock_snap.get_snapshots.return_value = []
        app.dependency_overrides[get_snapshot_manager] = (
            lambda: mock_snap
        )
        resp = restricted_client.get(
            "/api/v1/trends/history",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_snapshot_manager, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        mock_snap = MagicMock()
        mock_snap.get_snapshots.return_value = []
        app.dependency_overrides[get_snapshot_manager] = (
            lambda: mock_snap
        )
        resp = restricted_client.get(
            "/api/v1/trends/history",
            params={"account_id": ALLOWED_ACCOUNT},
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_snapshot_manager, None
        )


# ── GET /accounts ─────────────────────────────────────


class TestAccountsListEnforcement:
    def test_list_filtered_to_allowed_accounts(
        self, restricted_client
    ):
        from app.models.account import TargetAccount

        acct_allowed = TargetAccount(
            sk=ALLOWED_ACCOUNT,
            account_id=ALLOWED_ACCOUNT,
            account_name="Allowed",
            role_arn=(
                f"arn:aws:iam::{ALLOWED_ACCOUNT}:role/S"
            ),
        )
        acct_forbidden = TargetAccount(
            sk=FORBIDDEN_ACCOUNT,
            account_id=FORBIDDEN_ACCOUNT,
            account_name="Forbidden",
            role_arn=(
                f"arn:aws:iam::{FORBIDDEN_ACCOUNT}:role/S"
            ),
        )
        mock_as = MagicMock()
        mock_as.list_active.return_value = [
            acct_allowed,
            acct_forbidden,
        ]
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get("/api/v1/accounts")
        assert resp.status_code == 200
        data = resp.json()
        ids = [a["account_id"] for a in data]
        assert ALLOWED_ACCOUNT in ids
        assert FORBIDDEN_ACCOUNT not in ids
        app.dependency_overrides.pop(
            get_account_store, None
        )


# ── GET /accounts/{account_id} ────────────────────────


class TestAccountGetEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        from app.models.account import TargetAccount

        acct = TargetAccount(
            sk=FORBIDDEN_ACCOUNT,
            account_id=FORBIDDEN_ACCOUNT,
            account_name="Forbidden",
            role_arn=(
                f"arn:aws:iam::{FORBIDDEN_ACCOUNT}:role/S"
            ),
        )
        mock_as = MagicMock()
        mock_as.get_account.return_value = acct
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            f"/api/v1/accounts/{FORBIDDEN_ACCOUNT}"
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_account_store, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        from app.models.account import TargetAccount

        acct = TargetAccount(
            sk=ALLOWED_ACCOUNT,
            account_id=ALLOWED_ACCOUNT,
            account_name="Allowed",
            role_arn=(
                f"arn:aws:iam::{ALLOWED_ACCOUNT}:role/S"
            ),
        )
        mock_as = MagicMock()
        mock_as.get_account.return_value = acct
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        resp = restricted_client.get(
            f"/api/v1/accounts/{ALLOWED_ACCOUNT}"
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_account_store, None
        )


# ── GET /drift/alerts ─────────────────────────────────


class TestDriftEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_status.return_value = []
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        resp = restricted_client.get(
            "/api/v1/drift/alerts",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        mock_sm = MagicMock()
        mock_sm.query_by_status.return_value = []
        app.dependency_overrides[get_state_manager] = (
            lambda: mock_sm
        )
        resp = restricted_client.get(
            "/api/v1/drift/alerts",
            params={"account_id": ALLOWED_ACCOUNT},
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_state_manager, None
        )


# ── GET /inventory ────────────────────────────────────


class TestInventoryEnforcement:
    def test_forbidden_account_returns_403(
        self, restricted_client
    ):
        from app.dependencies import (
            get_resource_store,
        )
        mock_rs = MagicMock()
        mock_as = MagicMock()
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        app.dependency_overrides[get_resource_store] = (
            lambda: mock_rs
        )
        resp = restricted_client.get(
            "/api/v1/inventory",
            params={"account_id": FORBIDDEN_ACCOUNT},
        )
        assert resp.status_code == 403
        app.dependency_overrides.pop(
            get_account_store, None
        )
        app.dependency_overrides.pop(
            get_resource_store, None
        )

    def test_allowed_account_returns_200(
        self, restricted_client
    ):
        from app.dependencies import (
            get_resource_store,
        )
        mock_rs = MagicMock()
        mock_rs.query_by_account.return_value = []
        mock_as = MagicMock()
        app.dependency_overrides[get_account_store] = (
            lambda: mock_as
        )
        app.dependency_overrides[get_resource_store] = (
            lambda: mock_rs
        )
        resp = restricted_client.get(
            "/api/v1/inventory",
            params={"account_id": ALLOWED_ACCOUNT},
        )
        assert resp.status_code == 200
        app.dependency_overrides.pop(
            get_account_store, None
        )
        app.dependency_overrides.pop(
            get_resource_store, None
        )
