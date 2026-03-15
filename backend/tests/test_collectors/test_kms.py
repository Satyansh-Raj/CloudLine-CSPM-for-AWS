"""Tests for KMS collector using moto."""

import pytest

from app.collectors.kms import KMSCollector


@pytest.fixture
def kms_setup(mock_session):
    """Set up KMS resources for testing."""
    kms = mock_session.client("kms")

    # Create a customer-managed key
    key = kms.create_key(
        Description="Test encryption key",
    )
    key_id = key["KeyMetadata"]["KeyId"]

    # Enable key rotation
    kms.enable_key_rotation(KeyId=key_id)

    # Create a secret
    sm = mock_session.client("secretsmanager")
    sm.create_secret(
        Name="prod/db-password",
        SecretString="supersecret",
    )

    return {
        "session": mock_session,
        "key_id": key_id,
    }


class TestKMSCollector:
    def test_collect_returns_kms_key(
        self, kms_setup
    ):
        collector = KMSCollector(
            kms_setup["session"]
        )
        key, data = collector.collect()
        assert key == "kms"

    def test_collect_finds_keys(self, kms_setup):
        collector = KMSCollector(
            kms_setup["session"]
        )
        _, data = collector.collect()
        key_ids = [
            k["key_id"] for k in data["keys"]
        ]
        assert kms_setup["key_id"] in key_ids

    def test_key_rotation_enabled(self, kms_setup):
        collector = KMSCollector(
            kms_setup["session"]
        )
        _, data = collector.collect()
        key = next(
            k
            for k in data["keys"]
            if k["key_id"] == kms_setup["key_id"]
        )
        assert (
            key["key_rotation_enabled"] is True
        )

    def test_collect_full(self, kms_setup):
        collector = KMSCollector(
            kms_setup["session"]
        )
        result = collector.collect_full()
        assert "kms" in result
        assert "secrets_manager" in result
        assert "backup" in result

    def test_secrets_collected(self, kms_setup):
        collector = KMSCollector(
            kms_setup["session"]
        )
        result = collector.collect_full()
        names = [
            s["name"]
            for s in result["secrets_manager"][
                "secrets"
            ]
        ]
        assert "prod/db-password" in names

    def test_collect_resource(self, kms_setup):
        collector = KMSCollector(
            kms_setup["session"]
        )
        result = collector.collect_resource(
            kms_setup["key_id"]
        )
        assert (
            result["key_id"]
            == kms_setup["key_id"]
        )

    def test_collect_resource_not_found(
        self, kms_setup
    ):
        collector = KMSCollector(
            kms_setup["session"]
        )
        result = collector.collect_resource(
            "nonexistent-key"
        )
        assert result == {}

    def test_no_keys(self, mock_session):
        collector = KMSCollector(mock_session)
        _, data = collector.collect()
        assert data["keys"] == []
