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
        assert pp["minimum_password_length"] == 14
        assert pp["require_symbols"] is True
        assert pp["require_numbers"] is True
        assert pp["require_uppercase_characters"] is True
        assert pp["require_lowercase_characters"] is True
        assert pp["max_password_age"] == 90
        assert pp["password_reuse_prevention"] == 24

    def test_users_collected(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        names = [u["username"] for u in data["users"]]
        assert "admin" in names
        assert "developer" in names

    def test_admin_has_access_key(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        admin = next(
            u
            for u in data["users"]
            if u["username"] == "admin"
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
            if u["username"] == "admin"
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
            if u["username"] == "developer"
        )
        assert dev["mfa_enabled"] is False

    def test_collect_resource(self, iam_setup):
        collector = IAMCollector(iam_setup)
        result = collector.collect_resource("admin")
        assert result["username"] == "admin"
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
        assert pp["minimum_password_length"] == 8
        assert pp["require_symbols"] is False

    def test_account_summary(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        summary = data["account_summary"]
        assert "mfa_enabled" in summary
        assert "users" in summary
        assert isinstance(summary["users"], int)

    def test_collect_has_groups(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        assert "groups" in data
        assert isinstance(data["groups"], list)

    def test_collect_has_roles(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        assert "roles" in data
        assert isinstance(data["roles"], list)

    def test_collect_has_policies(self, iam_setup):
        collector = IAMCollector(iam_setup)
        _, data = collector.collect()
        assert "customer_managed_policies" in data
        assert isinstance(data["customer_managed_policies"], list)


class TestIAMCollectorGroupsRolesPolicies:
    """Test extended IAM collection for groups,
    roles, and customer-managed policies."""

    @pytest.fixture
    def iam_extended(self, mock_session):
        client = mock_session.client("iam")

        # Create group
        client.create_group(
            GroupName="developers"
        )

        # Create role
        client.create_role(
            RoleName="LambdaExec",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": (
                                    "lambda.amazonaws.com"
                                )
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            Tags=[
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        )

        # Create customer-managed policy
        client.create_policy(
            PolicyName="CustomReadOnly",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        return mock_session

    def test_group_collected(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        names = [
            g["group_name"] for g in data["groups"]
        ]
        assert "developers" in names

    def test_group_has_arn(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        grp = next(
            g
            for g in data["groups"]
            if g["group_name"] == "developers"
        )
        assert "arn" in grp
        assert "developers" in grp["arn"]

    def test_role_collected(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        names = [
            r["role_name"] for r in data["roles"]
        ]
        assert "LambdaExec" in names

    def test_role_has_tags(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        role = next(
            r
            for r in data["roles"]
            if r["role_name"] == "LambdaExec"
        )
        assert role["tags"].get("Environment") == "prod"

    def test_policy_collected(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        names = [
            p["policy_name"]
            for p in data["customer_managed_policies"]
        ]
        assert "CustomReadOnly" in names

    def test_policy_has_arn(self, iam_extended):
        collector = IAMCollector(iam_extended)
        _, data = collector.collect()
        pol = next(
            p
            for p in data["customer_managed_policies"]
            if p["policy_name"] == "CustomReadOnly"
        )
        assert "arn" in pol
        assert "CustomReadOnly" in pol["arn"]
