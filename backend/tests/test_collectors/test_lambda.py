"""Tests for Lambda collector using moto."""

import json

import pytest

from app.collectors.lambda_collector import (
    LambdaCollector,
)


@pytest.fixture
def lambda_setup(mock_session):
    """Set up Lambda resources for testing."""
    client = mock_session.client("lambda")
    iam = mock_session.client("iam")

    # Create IAM role for Lambda
    role = iam.create_role(
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
    role_arn = role["Role"]["Arn"]

    # Create Lambda function
    client.create_function(
        FunctionName="data-processor",
        Runtime="python3.11",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": b"fake-code"},
        TracingConfig={"Mode": "Active"},
    )

    return mock_session


class TestLambdaCollector:
    def test_collect_returns_key(
        self, lambda_setup
    ):
        collector = LambdaCollector(lambda_setup)
        key, data = collector.collect()
        assert key == "lambda_functions"

    def test_collect_finds_function(
        self, lambda_setup
    ):
        collector = LambdaCollector(lambda_setup)
        _, data = collector.collect()
        names = [
            f["function_name"]
            for f in data["functions"]
        ]
        assert "data-processor" in names

    def test_function_properties(
        self, lambda_setup
    ):
        collector = LambdaCollector(lambda_setup)
        _, data = collector.collect()
        fn = next(
            f
            for f in data["functions"]
            if f["function_name"]
            == "data-processor"
        )
        assert fn["runtime"] == "python3.11"
        assert "lambda-role" in fn["role"]

    def test_tracing_config(self, lambda_setup):
        collector = LambdaCollector(lambda_setup)
        _, data = collector.collect()
        fn = next(
            f
            for f in data["functions"]
            if f["function_name"]
            == "data-processor"
        )
        assert fn["tracing_config"] == "Active"

    def test_vpc_config_empty(self, lambda_setup):
        collector = LambdaCollector(lambda_setup)
        _, data = collector.collect()
        fn = data["functions"][0]
        assert fn["vpc_config"]["subnet_ids"] == []
        assert (
            fn["vpc_config"][
                "security_group_ids"
            ]
            == []
        )

    def test_collect_resource(self, lambda_setup):
        collector = LambdaCollector(lambda_setup)
        result = collector.collect_resource(
            "data-processor"
        )
        assert (
            result["function_name"]
            == "data-processor"
        )

    def test_collect_resource_not_found(
        self, lambda_setup
    ):
        collector = LambdaCollector(lambda_setup)
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}

    def test_no_functions(self, mock_session):
        collector = LambdaCollector(mock_session)
        _, data = collector.collect()
        assert data["functions"] == []
