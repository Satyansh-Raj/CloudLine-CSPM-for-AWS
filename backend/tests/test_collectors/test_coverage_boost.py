"""Extra tests to cover error-handling branches
and edge-case code paths across all collectors."""

import json
from unittest.mock import MagicMock

from app.collectors.ec2 import EC2Collector
from app.collectors.iam import IAMCollector
from app.collectors.kms import KMSCollector
from app.collectors.lambda_collector import (
    LambdaCollector,
)
from app.collectors.logging_collector import (
    LoggingCollector,
)
from app.collectors.orchestrator import (
    CollectionOrchestrator,
)
from app.collectors.rds import RDSCollector
from app.collectors.s3 import S3Collector
from app.collectors.vpc import VPCCollector

# --- IAM: access_analyzer with actual analyzers ---


class TestIAMAccessAnalyzer:
    def test_access_analyzer_with_analyzer(self):
        """Cover lines 199-207: analyzer list
        comprehension."""
        session = MagicMock()
        client = MagicMock()
        client.list_analyzers.return_value = {
            "analyzers": [
                {
                    "name": "test-analyzer",
                    "arn": (
                        "arn:aws:access-analyzer"
                        ":us-east-1:123:a/test"
                    ),
                    "status": "ACTIVE",
                }
            ]
        }
        session.client.return_value = client
        collector = IAMCollector(session)
        result = collector._get_access_analyzer()
        assert len(result["analyzers"]) == 1
        assert (
            result["analyzers"][0]["name"]
            == "test-analyzer"
        )
        assert (
            result["analyzers"][0]["status"]
            == "ACTIVE"
        )


# --- IAM: password_last_used path (lines 176-180)
# Moto doesn't set PasswordLastUsed on users,
# so we mock it.


class TestIAMLastActivity:
    def test_user_with_password_last_used(
        self, mock_session
    ):
        """Cover lines 176-180: pwd_last_used
        branch."""
        from datetime import datetime, timezone

        iam = mock_session.client("iam")
        iam.create_user(UserName="active-user")

        collector = IAMCollector(mock_session)
        # Patch the user dict to include
        # PasswordLastUsed
        original = collector._build_user_dict

        def patched(client, user):
            user["PasswordLastUsed"] = datetime(
                2026, 1, 1, tzinfo=timezone.utc
            )
            return original(client, user)

        collector._build_user_dict = patched
        _, data = collector.collect()
        user = next(
            u
            for u in data["users"]
            if u["name"] == "active-user"
        )
        assert (
            user["last_activity_days_ago"] is not None
        )
        assert user["last_activity_days_ago"] >= 0


# --- S3: bucket with logging enabled (lines 187-192)


class TestS3Logging:
    def test_bucket_with_logging_enabled(self):
        """Cover lines 187-194: logging enabled
        path."""
        session = MagicMock()
        client = MagicMock()
        client.get_bucket_logging.return_value = {
            "LoggingEnabled": {
                "TargetBucket": "log-bucket",
                "TargetPrefix": "logs/",
            }
        }
        session.client.return_value = client
        collector = S3Collector(session)
        result = collector._get_logging(
            client, "source-bucket"
        )
        assert result["enabled"] is True
        assert (
            result["target_bucket"] == "log-bucket"
        )

    def test_versioning_exception(self):
        """Cover lines 162-163: versioning
        exception."""
        session = MagicMock()
        client = MagicMock()
        client.get_bucket_versioning.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = S3Collector(session)
        result = collector._get_versioning(
            client, "bucket"
        )
        assert result is False

    def test_mfa_delete_exception(self):
        """Cover lines 175-176: mfa_delete
        exception."""
        session = MagicMock()
        client = MagicMock()
        client.get_bucket_versioning.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = S3Collector(session)
        result = collector._get_mfa_delete(
            client, "bucket"
        )
        assert result is False


# --- EC2: instance with IAM profile (line 99) ---


class TestEC2IAMProfile:
    def test_instance_with_iam_profile(
        self, mock_session
    ):
        """Cover line 99: iam_role from instance
        profile."""
        ec2 = mock_session.client("ec2")
        iam = mock_session.client("iam")

        # Create role + instance profile
        iam.create_role(
            RoleName="EC2Role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "ec2.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        iam.create_instance_profile(
            InstanceProfileName="EC2Profile"
        )
        iam.add_role_to_instance_profile(
            InstanceProfileName="EC2Profile",
            RoleName="EC2Role",
        )

        # Launch instance with profile
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            IamInstanceProfile={
                "Name": "EC2Profile"
            },
        )
        iid = instances["Instances"][0][
            "InstanceId"
        ]

        collector = EC2Collector(mock_session)
        result = collector.collect_resource(iid)
        assert result["iam_role"] is not None
        assert "role_arn" in result["iam_role"]


# --- Logging: Config recorders (lines 120-136)


class TestLoggingConfigRecorder:
    def test_config_recorder(self, mock_session):
        """Cover lines 120-136: config recorder
        collection."""
        config = mock_session.client("config")
        config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": (
                    "arn:aws:iam::123456789012:"
                    "role/config-role"
                ),
                "recordingGroup": {
                    "allSupported": True,
                },
            }
        )
        # Need a delivery channel too
        s3 = mock_session.client("s3")
        s3.create_bucket(Bucket="config-bucket")
        config.put_delivery_channel(
            DeliveryChannel={
                "name": "default",
                "s3BucketName": "config-bucket",
            }
        )
        config.start_configuration_recorder(
            ConfigurationRecorderName="default"
        )

        collector = LoggingCollector(mock_session)
        recorders = (
            collector._get_config_recorders()
        )
        assert len(recorders) > 0
        rec = recorders[0]
        assert rec["name"] == "default"
        assert rec["all_supported"] is True


# --- VPC: _get_flow_logs with filter (line 70) ---


class TestVPCFlowLogFilter:
    def test_flow_logs_with_resource_filter(
        self, mock_session
    ):
        """Cover line 70: flow_logs with
        resource_ids filter."""
        ec2 = mock_session.client("ec2")
        vpc = ec2.create_vpc(
            CidrBlock="10.0.0.0/16"
        )
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="test-logs",
            DeliverLogsPermissionArn=(
                "arn:aws:iam::123456789012:"
                "role/flow"
            ),
        )
        collector = VPCCollector(mock_session)
        ec2_client = mock_session.client("ec2")
        result = collector._get_flow_logs(
            ec2_client, [vpc_id]
        )
        assert len(result) > 0
        assert result[0]["resource_id"] == vpc_id


# --- VPC: _get_nacls with filter (line 110) ---


class TestVPCNaclFilter:
    def test_nacls_with_filter(
        self, mock_session
    ):
        """Cover line 110: nacl with nacl_ids."""
        ec2 = mock_session.client("ec2")
        vpc = ec2.create_vpc(
            CidrBlock="10.0.0.0/16"
        )
        vpc_id = vpc["Vpc"]["VpcId"]
        # Get default NACL for this VPC
        nacls = ec2.describe_network_acls(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id],
                }
            ]
        )
        nacl_id = nacls["NetworkAcls"][0][
            "NetworkAclId"
        ]
        collector = VPCCollector(mock_session)
        ec2_client = mock_session.client("ec2")
        result = collector._get_nacls(
            ec2_client, [nacl_id]
        )
        assert len(result) == 1
        assert result[0]["nacl_id"] == nacl_id


# --- Orchestrator: collector failure (lines 79-80)


class TestOrchestratorFailure:
    def test_collect_full_handles_collector_error(
        self, mock_session
    ):
        """Cover lines 79-80: exception in
        collector.collect()."""
        orch = CollectionOrchestrator(
            session=mock_session,
            account_id="123456789012",
            region="us-east-1",
        )
        # Sabotage one collector
        bad = MagicMock()
        bad.collect.side_effect = RuntimeError(
            "boom"
        )
        orch.collectors[0] = bad
        # Should still succeed with partial data
        result = orch.collect_full()
        assert "account_id" in result
        assert "collection_timestamp" in result


# --- KMS: backup plans + protected resources ---


class TestKMSBackup:
    def test_backup_plans_and_protected(
        self, mock_session
    ):
        """Cover lines 173-187, 201-202: backup
        plan collection."""
        # Backup plans are hard to mock with moto,
        # but collect_full calls them and the empty
        # path is covered. We test that the methods
        # return empty lists cleanly.
        collector = KMSCollector(mock_session)
        plans = collector._get_backup_plans()
        assert plans == []
        resources = (
            collector._get_protected_resources()
        )
        assert resources == []


# --- S3: error branch on list_buckets ---


class TestS3ErrorBranch:
    def test_s3_collect_error_branch(self):
        """Cover lines 25-26: exception on
        list_buckets."""
        session = MagicMock()
        client = MagicMock()
        client.list_buckets.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = S3Collector(session)
        key, data = collector.collect()
        assert key == "s3"
        assert data["buckets"] == []


# --- EC2: error branches ---


class TestEC2ErrorBranches:
    def test_describe_instances_error(self):
        """Cover lines 64-65."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = EC2Collector(session)
        result = collector._get_instances(client)
        assert result == []

    def test_describe_sgs_error(self):
        """Cover lines 152-153."""
        session = MagicMock()
        client = MagicMock()
        client.describe_security_groups.side_effect = Exception("denied")
        session.client.return_value = client
        collector = EC2Collector(session)
        result = collector._get_security_groups(
            client
        )
        assert result == []

    def test_describe_volumes_error(self):
        """Cover lines 234-235."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = EC2Collector(session)
        result = collector._get_ebs_volumes(client)
        assert result == []


# --- VPC: error branches ---


class TestVPCErrorBranches:
    def test_describe_vpcs_error(self):
        """Cover lines 55-56."""
        session = MagicMock()
        client = MagicMock()
        client.describe_vpcs.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = VPCCollector(session)
        result = collector._get_vpcs(client)
        assert result == []

    def test_describe_flow_logs_error(self):
        """Cover lines 95-96."""
        session = MagicMock()
        client = MagicMock()
        client.describe_flow_logs.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = VPCCollector(session)
        result = collector._get_flow_logs(client)
        assert result == []

    def test_describe_nacls_error(self):
        """Cover lines 148-149."""
        session = MagicMock()
        client = MagicMock()
        client.describe_network_acls.side_effect = Exception("denied")
        session.client.return_value = client
        collector = VPCCollector(session)
        result = collector._get_nacls(client)
        assert result == []


# --- IAM: account_summary error branch ---


class TestIAMErrorBranches:
    def test_account_summary_error(self):
        """Cover lines 54-55."""
        session = MagicMock()
        client = MagicMock()
        client.get_account_summary.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = IAMCollector(session)
        result = collector._get_account_summary(
            client
        )
        assert result["mfa_enabled"] is False
        assert result["users"] == 0


# --- RDS: error branch ---


class TestRDSErrorBranch:
    def test_describe_db_instances_error(self):
        """Cover lines 55-56."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = RDSCollector(session)
        result = collector._get_db_instances(client)
        assert result == []


# --- Lambda: error branch ---


class TestLambdaErrorBranch:
    def test_list_functions_error(self):
        """Cover lines 48-49."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = LambdaCollector(session)
        result = collector._get_functions(client)
        assert result == []


# --- Logging: error branches ---


class TestLoggingErrorBranches:
    def test_cloudtrail_error(self):
        """Cover lines 92-93."""
        session = MagicMock()
        client = MagicMock()
        client.describe_trails.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = LoggingCollector(session)
        result = (
            collector._get_cloudtrail_trails()
        )
        assert result == []

    def test_cloudwatch_error(self):
        """Cover lines 168-169."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = LoggingCollector(session)
        result = (
            collector._get_cloudwatch_alarms()
        )
        assert result == []

    def test_guardduty_error(self):
        """Cover lines 199-200."""
        session = MagicMock()
        client = MagicMock()
        client.list_detectors.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = LoggingCollector(session)
        result = (
            collector._get_guardduty_detectors()
        )
        assert result == []

    def test_config_recorder_error(self):
        """Cover lines 135-136."""
        session = MagicMock()
        client = MagicMock()
        client.describe_configuration_recorders.side_effect = Exception(
            "denied"
        )
        session.client.return_value = client
        collector = LoggingCollector(session)
        result = (
            collector._get_config_recorders()
        )
        assert result == []


# --- KMS: error branches ---


class TestKMSErrorBranches:
    def test_list_keys_error(self):
        """Cover lines 118-119."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_kms_keys()
        assert result == []

    def test_secrets_error(self):
        """Cover lines 158-159."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = Exception(
            "denied"
        )
        client.get_paginator.return_value = pag
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_secrets()
        assert result == []

    def test_collect_resource_rotation_error(
        self,
    ):
        """Cover lines 55-56: rotation status
        error in collect_resource."""
        session = MagicMock()
        client = MagicMock()
        client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "key-123",
                "Arn": "arn:aws:kms:us-east-1:123:key/key-123",
                "KeyState": "Enabled",
            }
        }
        client.get_key_rotation_status.side_effect = Exception(
            "denied"
        )
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector.collect_resource(
            "key-123"
        )
        assert result["key_id"] == "key-123"
        assert (
            result["key_rotation_enabled"] is False
        )

    def test_describe_key_inner_error(self):
        """Cover lines 116-117: describe_key fails
        inside _get_kms_keys loop."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"Keys": [{"KeyId": "key-bad"}]}
        ]
        client.get_paginator.return_value = pag
        client.describe_key.side_effect = Exception(
            "denied"
        )
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_kms_keys()
        assert result == []

    def test_aws_managed_key_skipped(self):
        """Cover line 89: AWS-managed key skip."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"Keys": [{"KeyId": "aws-key-1"}]}
        ]
        client.get_paginator.return_value = pag
        client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "aws-key-1",
                "Arn": "arn:...",
                "KeyState": "Enabled",
                "KeyManager": "AWS",
            }
        }
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_kms_keys()
        assert result == []

    def test_rotation_error_in_list_keys(self):
        """Cover lines 101-102: rotation error
        inside _get_kms_keys."""
        session = MagicMock()
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"Keys": [{"KeyId": "cust-key-1"}]}
        ]
        client.get_paginator.return_value = pag
        client.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": "cust-key-1",
                "Arn": "arn:...",
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
            }
        }
        client.get_key_rotation_status.side_effect = Exception(
            "denied"
        )
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_kms_keys()
        assert len(result) == 1
        assert (
            result[0]["key_rotation_enabled"]
            is False
        )

    def test_backup_plans_with_data(self):
        """Cover lines 173-187: backup plans
        with actual data."""
        session = MagicMock()
        client = MagicMock()
        client.list_backup_plans.return_value = {
            "BackupPlansList": [
                {
                    "BackupPlanId": "plan-1",
                    "BackupPlanName": "daily",
                    "BackupPlanArn": "arn:...",
                }
            ]
        }
        session.client.return_value = client
        collector = KMSCollector(session)
        result = collector._get_backup_plans()
        assert len(result) == 1
        assert result[0]["plan_id"] == "plan-1"
        assert result[0]["plan_name"] == "daily"

    def test_protected_resources_with_data(self):
        """Cover lines 201-202: protected
        resources with actual data."""
        session = MagicMock()
        client = MagicMock()
        client.list_protected_resources.return_value = {
            "Results": [
                {
                    "ResourceArn": "arn:aws:rds:...",
                    "ResourceType": "RDS",
                }
            ]
        }
        session.client.return_value = client
        collector = KMSCollector(session)
        result = (
            collector._get_protected_resources()
        )
        assert len(result) == 1
        assert result[0]["resource_type"] == "RDS"


# --- EC2: STS error (lines 81-82) ---


class TestEC2STSError:
    def test_build_instance_sts_error(
        self, mock_session
    ):
        """Cover lines 81-82: STS call fails."""
        ec2 = mock_session.client("ec2")
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
        )
        inst = instances["Instances"][0]

        collector = EC2Collector(mock_session)
        # Patch session.client to raise on STS
        orig_client = mock_session.client

        def sts_fail(service, **kw):
            if service == "sts":
                raise Exception("no sts")
            return orig_client(service, **kw)

        mock_session.client = sts_fail
        result = collector._build_instance(
            ec2, inst
        )
        assert result["instance_id"] == inst[
            "InstanceId"
        ]
        # ARN should have empty account
        assert ":instance/" in result["arn"]


# --- CloudTrail: get_trail_status error (68-69)


class TestCloudTrailStatusError:
    def test_trail_status_error(self):
        """Cover lines 68-69: get_trail_status
        exception."""
        session = MagicMock()
        client = MagicMock()
        client.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "broken-trail",
                    "TrailARN": "arn:...",
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": True,
                    "S3BucketName": "logs",
                }
            ]
        }
        client.get_trail_status.side_effect = (
            Exception("denied")
        )
        session.client.return_value = client
        collector = LoggingCollector(session)
        result = (
            collector._get_cloudtrail_trails()
        )
        assert len(result) == 1
        assert result[0]["name"] == "broken-trail"
        # is_logging defaults to False on error
        assert result[0]["is_logging"] is False


# --- IAM: access key last_used (lines 142-148)


class TestIAMAccessKeyLastUsed:
    def test_access_key_last_used_computed(self):
        """Cover lines 142-148: last_used_days
        computation."""
        from datetime import datetime, timezone

        session = MagicMock()
        client = MagicMock()

        client.list_mfa_devices.return_value = {
            "MFADevices": []
        }
        client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIA123",
                    "Status": "Active",
                    "CreateDate": datetime(
                        2026, 1, 1,
                        tzinfo=timezone.utc,
                    ),
                }
            ]
        }
        client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "LastUsedDate": datetime(
                    2026, 2, 1,
                    tzinfo=timezone.utc,
                ),
                "ServiceName": "s3",
                "Region": "us-east-1",
            }
        }
        client.list_attached_user_policies.return_value = {
            "AttachedPolicies": []
        }

        session.client.return_value = client
        collector = IAMCollector(session)
        user = {
            "UserName": "testuser",
            "Arn": "arn:aws:iam::123:user/testuser",
        }
        result = collector._build_user_dict(
            client, user
        )
        assert (
            result["access_keys"][0][
                "last_used_days_ago"
            ]
            is not None
        )
        assert (
            result["access_keys"][0][
                "last_used_days_ago"
            ]
            >= 0
        )

    def test_access_key_last_used_error(self):
        """Cover lines 147-148: last_used
        exception."""
        from datetime import datetime, timezone

        session = MagicMock()
        client = MagicMock()

        client.list_mfa_devices.return_value = {
            "MFADevices": []
        }
        client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIA123",
                    "Status": "Active",
                    "CreateDate": datetime(
                        2026, 1, 1,
                        tzinfo=timezone.utc,
                    ),
                }
            ]
        }
        client.get_access_key_last_used.side_effect = Exception(
            "denied"
        )
        client.list_attached_user_policies.return_value = {
            "AttachedPolicies": []
        }

        session.client.return_value = client
        collector = IAMCollector(session)
        user = {
            "UserName": "testuser",
            "Arn": "arn:aws:iam::123:user/testuser",
        }
        result = collector._build_user_dict(
            client, user
        )
        assert (
            result["access_keys"][0][
                "last_used_days_ago"
            ]
            is None
        )
