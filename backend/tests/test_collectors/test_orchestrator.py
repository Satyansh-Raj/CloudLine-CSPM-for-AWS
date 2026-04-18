"""Tests for the Collection Orchestrator."""

import json

import pytest

from app.collectors.orchestrator import (
    COLLECTOR_MAP,
    CollectionOrchestrator,
)


@pytest.fixture
def full_setup(mock_session):
    """Set up resources across all services."""
    # IAM
    iam = mock_session.client("iam")
    iam.create_user(UserName="testuser")

    # S3
    s3 = mock_session.client("s3")
    s3.create_bucket(Bucket="test-bucket")

    # EC2
    ec2 = mock_session.client("ec2")
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )

    # Lambda
    lam = mock_session.client("lambda")
    iam_client = mock_session.client("iam")
    role = iam_client.create_role(
        RoleName="lambda-role",
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
    )
    lam.create_function(
        FunctionName="test-fn",
        Runtime="python3.11",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"fake"},
    )

    return mock_session


class TestOrchestrator:
    def test_collect_full_returns_all_keys(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_full()

        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"
        assert result["collection_mode"] == "full"
        assert "collection_timestamp" in result

        # All service keys present (original 8)
        assert "iam" in result
        assert "s3" in result
        assert "ec2" in result
        assert "vpc" in result
        assert "rds" in result
        assert "lambda_functions" in result
        assert "cloudtrail" in result
        assert "kms" in result
        assert "secrets_manager" in result
        assert "backup" in result
        # New 5 collectors (Batch 3-7)
        assert "elb" in result
        assert "cdn" in result
        assert "dynamodb" in result
        assert "apigateway" in result
        assert "ecs" in result

    def test_collect_full_iam_data(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_full()
        names = [
            u["username"]
            for u in result["iam"]["users"]
        ]
        assert "testuser" in names

    def test_collect_full_s3_data(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_full()
        names = [
            b["name"]
            for b in result["s3"]["buckets"]
        ]
        assert "test-bucket" in names

    def test_collect_full_ec2_data(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_full()
        assert len(result["ec2"]["instances"]) > 0

    def test_collect_targeted_iam(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_targeted(
            "iam", "testuser"
        )
        assert result["username"] == "testuser"

    def test_collect_targeted_s3(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_targeted(
            "s3", "test-bucket"
        )
        assert result["name"] == "test-bucket"

    def test_collect_targeted_unknown_service(
        self, full_setup
    ):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_targeted(
            "unknown", "res-123"
        )
        assert result == {}

    def test_collector_map_complete(self):
        expected = {
            "iam",
            "s3",
            "ec2",
            "vpc",
            "rds",
            "lambda",
            "logging",
            "kms",
            "elb",
            "cdn",
            "dynamodb",
            "apigateway",
            "containers",
            "macie",
        }
        assert set(COLLECTOR_MAP.keys()) == expected

    def test_collector_map_has_14_entries(self):
        """14 collectors: 1 global + 13 regional."""
        assert len(COLLECTOR_MAP) == 14

    def test_timestamp_format(self, full_setup):
        orch = CollectionOrchestrator(
            session=full_setup,
            account_id="123456789012",
            region="us-east-1",
        )
        result = orch.collect_full()
        ts = result["collection_timestamp"]
        # Should be ISO format
        assert "T" in ts
