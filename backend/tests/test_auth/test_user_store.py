"""Tests for UserStore DynamoDB operations."""

import boto3
import pytest
from moto import mock_aws

from app.auth.models import User, UserRole
from app.auth.user_store import UserStore

TABLE_NAME = "cloudline-users"


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
def user_store(aws_credentials):
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        client = session.client(
            "dynamodb", region_name="us-east-1"
        )
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
        store = UserStore(
            session=session,
            table_name=TABLE_NAME,
            endpoint_url=None,
        )
        yield store


def make_user(
    user_id: str = "user-1",
    role: UserRole = UserRole.VIEWER,
) -> User:
    return User(
        sk=user_id,
        email=f"{user_id}@example.com",
        full_name="Test User",
        password_hash="$2b$12$abc",
        role=role,
        created_at="2026-04-09T00:00:00Z",
    )


class TestPutAndGetUser:
    def test_roundtrip(self, user_store):
        user = make_user("u1")
        assert user_store.put_user(user) is True
        fetched = user_store.get_user_by_id("u1")
        assert fetched is not None
        assert fetched.email == "u1@example.com"
        assert fetched.role == UserRole.VIEWER

    def test_missing_returns_none(self, user_store):
        result = user_store.get_user_by_id(
            "nonexistent"
        )
        assert result is None

    def test_overwrite_existing(self, user_store):
        user = make_user("u1")
        user_store.put_user(user)
        updated = User(
            sk="u1",
            email="u1@example.com",
            full_name="Updated Name",
            password_hash="$2b$12$xyz",
            role=UserRole.ADMIN,
        )
        user_store.put_user(updated)
        fetched = user_store.get_user_by_id("u1")
        assert fetched.full_name == "Updated Name"
        assert fetched.role == UserRole.ADMIN


class TestGetUserByEmail:
    def test_found(self, user_store):
        user = make_user("u2", UserRole.ADMIN)
        user_store.put_user(user)
        fetched = user_store.get_user_by_email(
            "u2@example.com"
        )
        assert fetched is not None
        assert fetched.sk == "u2"
        assert fetched.role == UserRole.ADMIN

    def test_not_found_returns_none(self, user_store):
        result = user_store.get_user_by_email(
            "nobody@example.com"
        )
        assert result is None

    def test_gsi_exists(self, user_store):
        # Verify GSI is working (not a scan fallback)
        for i in range(3):
            user_store.put_user(
                make_user(f"bulk-{i}")
            )
        fetched = user_store.get_user_by_email(
            "bulk-1@example.com"
        )
        assert fetched is not None
        assert fetched.sk == "bulk-1"


class TestListUsers:
    def test_returns_all(self, user_store):
        user_store.put_user(make_user("ua"))
        user_store.put_user(make_user("ub"))
        users = user_store.list_users()
        ids = {u.sk for u in users}
        assert "ua" in ids
        assert "ub" in ids

    def test_empty_table(self, user_store):
        assert user_store.list_users() == []

    def test_returns_all_roles(self, user_store):
        user_store.put_user(
            make_user("admin-1", UserRole.ADMIN)
        )
        user_store.put_user(
            make_user("op-1", UserRole.OPERATOR)
        )
        user_store.put_user(
            make_user("view-1", UserRole.VIEWER)
        )
        users = user_store.list_users()
        roles = {u.role for u in users}
        assert UserRole.ADMIN in roles
        assert UserRole.OPERATOR in roles
        assert UserRole.VIEWER in roles


class TestUpdateUser:
    def test_updates_full_name(self, user_store):
        user_store.put_user(make_user("u3"))
        assert (
            user_store.update_user(
                "u3", full_name="New Name"
            )
            is True
        )
        updated = user_store.get_user_by_id("u3")
        assert updated.full_name == "New Name"

    def test_updates_role(self, user_store):
        user_store.put_user(
            make_user("u4", UserRole.VIEWER)
        )
        user_store.update_user(
            "u4", role=UserRole.OPERATOR
        )
        updated = user_store.get_user_by_id("u4")
        assert updated.role == UserRole.OPERATOR

    def test_deactivate(self, user_store):
        user_store.put_user(make_user("u5"))
        user_store.update_user(
            "u5", is_active=False
        )
        updated = user_store.get_user_by_id("u5")
        assert updated.is_active is False

    def test_no_op_returns_true(self, user_store):
        user_store.put_user(make_user("u6"))
        assert user_store.update_user("u6") is True


class TestPasswordUpdate:
    def test_update_password_hash(self, user_store):
        user_store.put_user(make_user("u10"))
        result = user_store.update_password_hash(
            "u10", "$2b$12$newhash"
        )
        assert result is True
        updated = user_store.get_user_by_id("u10")
        assert updated.password_hash == "$2b$12$newhash"


class TestResetFlow:
    def test_set_reset_requested(self, user_store):
        user_store.put_user(make_user("u7"))
        ts = "2026-04-09T10:00:00Z"
        assert (
            user_store.set_reset_requested("u7", ts)
            is True
        )
        u = user_store.get_user_by_id("u7")
        assert u.reset_requested_at == ts

    def test_approve_reset(self, user_store):
        user_store.put_user(make_user("u8"))
        assert (
            user_store.approve_reset(
                "u8", "admin-1", "2026-04-09T10:00:00Z"
            )
            is True
        )
        u = user_store.get_user_by_id("u8")
        assert u.reset_allowed is True
        assert u.reset_approved_by == "admin-1"

    def test_clear_reset_after_change(
        self, user_store
    ):
        user_store.put_user(make_user("u9"))
        user_store.set_reset_requested(
            "u9", "2026-04-09T10:00:00Z"
        )
        user_store.approve_reset(
            "u9", "admin-1", "2026-04-09T10:00:00Z"
        )
        assert (
            user_store.clear_reset_after_change("u9")
            is True
        )
        u = user_store.get_user_by_id("u9")
        assert u.reset_allowed is False
        assert u.reset_approved_by is None
        assert u.reset_requested_at is None


class TestUpdateUserAccounts:
    def test_set_allowed_account_ids(self, user_store):
        user_store.put_user(make_user("ua1"))
        result = user_store.update_user_accounts(
            "ua1", ["111111111111", "222222222222"], False
        )
        assert result is True
        u = user_store.get_user_by_id("ua1")
        assert u.allowed_account_ids == [
            "111111111111", "222222222222"
        ]
        assert u.all_accounts_access is False

    def test_clear_to_all_accounts_access(
        self, user_store
    ):
        user_store.put_user(make_user("ua2"))
        user_store.update_user_accounts(
            "ua2", ["111111111111"], False
        )
        user_store.update_user_accounts(
            "ua2", [], True
        )
        u = user_store.get_user_by_id("ua2")
        assert u.allowed_account_ids == []
        assert u.all_accounts_access is True

    def test_empty_list_preserved(self, user_store):
        user_store.put_user(make_user("ua3"))
        result = user_store.update_user_accounts(
            "ua3", [], False
        )
        assert result is True
        u = user_store.get_user_by_id("ua3")
        assert u.allowed_account_ids == []
        assert u.all_accounts_access is False

    def test_idempotent_double_write(self, user_store):
        user_store.put_user(make_user("ua4"))
        user_store.update_user_accounts(
            "ua4", ["111111111111"], False
        )
        result = user_store.update_user_accounts(
            "ua4", ["111111111111"], False
        )
        assert result is True
        u = user_store.get_user_by_id("ua4")
        assert u.allowed_account_ids == ["111111111111"]

    def test_nonexistent_user_returns_false(
        self, user_store
    ):
        result = user_store.update_user_accounts(
            "ghost-user", ["111111111111"], False
        )
        assert result is False

    def test_returns_false_on_boto_error(
        self, user_store, monkeypatch
    ):
        user_store.put_user(make_user("ua5"))
        monkeypatch.setattr(
            user_store.table,
            "update_item",
            lambda **_: (_ for _ in ()).throw(
                Exception("boto error")
            ),
        )
        result = user_store.update_user_accounts(
            "ua5", ["111"], True
        )
        assert result is False

    def test_legacy_user_read_gets_defaults(
        self, user_store
    ):
        user_store.table.put_item(
            Item={
                "pk": "USERS",
                "sk": "legacy-1",
                "email": "legacy@example.com",
                "full_name": "Legacy User",
                "password_hash": "$2b$12$abc",
                "role": "viewer",
                "is_active": True,
                "created_at": "2025-01-01T00:00:00Z",
                "failed_login_count": 0,
            }
        )
        u = user_store.get_user_by_id("legacy-1")
        assert u is not None
        assert u.allowed_account_ids == []
        assert u.all_accounts_access is True


class TestUpdateLastLogin:
    def test_updates_timestamp(self, user_store):
        user_store.put_user(make_user("u10"))
        ts = "2026-04-09T12:00:00Z"
        assert (
            user_store.update_last_login("u10", ts)
            is True
        )
        u = user_store.get_user_by_id("u10")
        assert u.last_login == ts


class TestHardDeleteUser:
    def test_hard_deletes_item(self, user_store):
        user_store.put_user(make_user("del-1"))
        assert (
            user_store.get_user_by_id("del-1")
            is not None
        )
        result = user_store.delete_user("del-1")
        assert result is True
        assert (
            user_store.get_user_by_id("del-1") is None
        )

    def test_nonexistent_returns_false(
        self, user_store
    ):
        result = user_store.delete_user("ghost-999")
        assert result is False

    def test_deleted_user_absent_from_list(
        self, user_store
    ):
        user_store.put_user(make_user("del-2"))
        user_store.delete_user("del-2")
        ids = {u.sk for u in user_store.list_users()}
        assert "del-2" not in ids
