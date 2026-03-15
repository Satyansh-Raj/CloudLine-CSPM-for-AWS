"""Tests for IAM collector using moto."""

import json

import pytest

from app.collectors.iam import IAMCollector


@pytest.fixture
def iam_setup(mock_session):
    """Set up IAM resources for testing."""
    client = mock_session.client("iam")

    # Set password policy
    client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=24,
        HardExpiry=False,
    )

    # Create users
    client.create_user(UserName="admin")
    client.create_user(UserName="developer")

    # Create access key for admin
    client.create_access_key(UserName="admin")

    # Create and attach policy to admin
    policy = client.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    client.attach_user_policy(
        UserName="admin",
        PolicyArn=policy["Policy"]["Arn"],
    )

    return mock_session


class TestIAMCollector:
    def test_collect_returns_iam_key(
        self, iam_setup
    ):
        collector = IAMCollector(iam_setup)
        key, data = collector.collect()
        assert key == "iam"

    def test_collect_has_all_sections(
        self, iam_setup
    ):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        assert "account_summary" in data
        assert "password_policy" in data
        assert "users" in data
        assert "access_analyzer" in data

    def test_password_policy_values(
        self, iam_setup
    ):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        pp = data["password_policy"]
        assert pp["minimum_length"] == 14
        assert pp["require_symbols"] is True
        assert pp["require_numbers"] is True
        assert pp["require_uppercase"] is True
        assert pp["require_lowercase"] is True
        assert pp["max_age_days"] == 90
        assert pp["password_reuse_prevention"] == 24

    def test_users_collected(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        names = [u["name"] for u in data["users"]]
        assert "admin" in names
        assert "developer" in names

    def test_admin_has_access_key(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        admin = next(
            u
            for u in data["users"]
            if u["name"] == "admin"
        )
        assert len(admin["access_keys"]) == 1
        assert (
            admin["access_keys"][0]["status"]
            == "Active"
        )

    def test_admin_has_policy(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        admin = next(
            u
            for u in data["users"]
            if u["name"] == "admin"
        )
        policy_names = [
            p["policy_name"]
            for p in admin["attached_policies"]
        ]
        assert "AdministratorAccess" in policy_names

    def test_developer_no_mfa(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        dev = next(
            u
            for u in data["users"]
            if u["name"] == "developer"
        )
        assert dev["mfa_enabled"] is False

    def test_collect_resource(self, iam_setup):
        collector = IAMCollector(iam_setup)
        result = collector.collect_resource("admin")
        assert result["name"] == "admin"
        assert "access_keys" in result

    def test_collect_resource_not_found(
        self, iam_setup
    ):
        collector = IAMCollector(iam_setup)
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}

    def test_no_password_policy(self, mock_session):
        """Test when no password policy is set."""
        collector = IAMCollector(mock_session)
        _, data = collector.collect()
        pp = data["password_policy"]
        assert pp["minimum_length"] == 8
        assert pp["require_symbols"] is False

    def test_account_summary(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        summary = data["account_summary"]
        assert "mfa_enabled" in summary
        assert "users" in summary
        assert isinstance(summary["users"], int)
