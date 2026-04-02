"""Tests for DynamoDB collector using moto."""

import pytest

from app.collectors.dynamodb import (
    DynamoDBCollector,
)


@pytest.fixture
def dynamodb_setup(mock_session):
    """Set up DynamoDB tables for testing."""
    client = mock_session.client("dynamodb")
    client.create_table(
        TableName="users",
        KeySchema=[
            {
                "AttributeName": "user_id",
                "KeyType": "HASH",
            }
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "user_id",
                "AttributeType": "S",
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return mock_session


class TestDynamoDBCollector:
    def test_collect_returns_dynamodb_key(
        self, dynamodb_setup
    ):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        key, _ = collector.collect()
        assert key == "dynamodb"

    def test_collect_has_tables(
        self, dynamodb_setup
    ):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        _, data = collector.collect()
        assert "tables" in data
        assert len(data["tables"]) >= 1

    def test_table_name(self, dynamodb_setup):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        _, data = collector.collect()
        names = [
            t["table_name"]
            for t in data["tables"]
        ]
        assert "users" in names

    def test_table_has_arn(self, dynamodb_setup):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        _, data = collector.collect()
        tbl = next(
            t
            for t in data["tables"]
            if t["table_name"] == "users"
        )
        assert "table_arn" in tbl
        assert tbl["table_arn"] != ""

    def test_collect_resource(
        self, dynamodb_setup
    ):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        result = collector.collect_resource(
            "users"
        )
        assert result["table_name"] == "users"

    def test_collect_resource_not_found(
        self, dynamodb_setup
    ):
        collector = DynamoDBCollector(
            dynamodb_setup
        )
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}
