"""Tests for bootstrap_admin function."""

import boto3
import pytest
from moto import mock_aws

from app.auth.bootstrap import bootstrap_admin
from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.user_store import UserStore
from app.config import Settings

TABLE_NAME = "cloudline-users"
_BOOTSTRAP_EMAIL = "admin@cloudline.io"
_BOOTSTRAP_PW = "BootstrapPass123!"  # 16 chars


def _create_users_table(client):
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
def store_and_settings(aws_credentials):
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1"
        )
        client = session.client(
            "dynamodb", region_name="us-east-1"
        )
        _create_users_table(client)
        store = UserStore(
            session=session, table_name=TABLE_NAME
        )
        cfg = Settings(
            jwt_secret="test-secret",
            admin_bootstrap_email=_BOOTSTRAP_EMAIL,
            admin_bootstrap_password=_BOOTSTRAP_PW,
        )
        yield store, cfg


class TestBootstrapAdmin:
    def test_creates_admin_when_no_users(
        self, store_and_settings
    ):
        store, cfg = store_and_settings
        bootstrap_admin(store, cfg)
        users = store.list_users()
        assert len(users) == 1
        assert users[0].email == _BOOTSTRAP_EMAIL
        assert users[0].role == UserRole.ADMIN
        assert users[0].is_active is True

    def test_idempotent_second_call_noop(
        self, store_and_settings
    ):
        store, cfg = store_and_settings
        bootstrap_admin(store, cfg)
        bootstrap_admin(store, cfg)
        users = store.list_users()
        assert len(users) == 1

    def test_no_op_when_email_not_set(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            client = session.client(
                "dynamodb", region_name="us-east-1"
            )
            _create_users_table(client)
            store = UserStore(
                session=session,
                table_name=TABLE_NAME,
            )
            cfg = Settings(
                jwt_secret="test-secret",
                admin_bootstrap_email="",
                admin_bootstrap_password=_BOOTSTRAP_PW,
            )
            bootstrap_admin(store, cfg)
            assert store.list_users() == []

    def test_no_op_when_password_not_set(
        self, aws_credentials
    ):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            client = session.client(
                "dynamodb", region_name="us-east-1"
            )
            _create_users_table(client)
            store = UserStore(
                session=session,
                table_name=TABLE_NAME,
            )
            cfg = Settings(
                jwt_secret="test-secret",
                admin_bootstrap_email=_BOOTSTRAP_EMAIL,
                admin_bootstrap_password="",
            )
            bootstrap_admin(store, cfg)
            assert store.list_users() == []

    def test_no_op_when_users_already_exist(
        self, store_and_settings
    ):
        """Does not add bootstrap user if any user exists."""
        store, cfg = store_and_settings
        existing = User(
            sk="existing-user",
            email="other@example.com",
            full_name="Other User",
            password_hash=hash_password(
                "ExistingPass123!"
            ),
            role=UserRole.OPERATOR,
            created_at="2026-04-09T00:00:00Z",
        )
        store.put_user(existing)

        bootstrap_admin(store, cfg)

        users = store.list_users()
        assert len(users) == 1
        assert users[0].email == "other@example.com"
