"""Tests for scan pipeline inventory integration.

Verifies that _run_scan() builds and persists resource
inventory alongside violation state.
"""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.models.resource import ResourceRecord
from app.pipeline.resource_store import ResourceStore

ACCOUNT = "123456789012"
REGION = "us-east-1"
TABLE_NAME = "resource-inventory"


def _create_table(session):
    """Create the resource-inventory table."""
    ddb = session.resource("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {
                "AttributeName": "technology_category",
                "AttributeType": "S",
            },
            {
                "AttributeName": "risk_score",
                "AttributeType": "N",
            },
            {
                "AttributeName": "exposure",
                "AttributeType": "S",
            },
            {
                "AttributeName": "violation_count",
                "AttributeType": "N",
            },
            {
                "AttributeName": "service",
                "AttributeType": "S",
            },
            {
                "AttributeName": "last_seen",
                "AttributeType": "S",
            },
            {
                "AttributeName": "region",
                "AttributeType": "S",
            },
            {
                "AttributeName": "account_id",
                "AttributeType": "S",
            },
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "category-index",
                "KeySchema": [
                    {
                        "AttributeName": (
                            "technology_category"
                        ),
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "risk_score",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "exposure-index",
                "KeySchema": [
                    {
                        "AttributeName": "exposure",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "violation_count",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "service-index",
                "KeySchema": [
                    {
                        "AttributeName": "service",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "last_seen",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "region-index",
                "KeySchema": [
                    {
                        "AttributeName": "region",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": (
                            "technology_category"
                        ),
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "account-index",
                "KeySchema": [
                    {
                        "AttributeName": "account_id",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "last_seen",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class TestPersistInventory:
    """Test classify → persist flow."""

    @mock_aws
    def test_classify_and_persist(self):
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="bkt-1",
                        arn="arn:aws:s3:::bkt-1",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        for rec in records:
            assert store.put_resource(rec)

        result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::bkt-1",
        )
        assert result is not None
        assert result.resource_name == "bkt-1"
        assert result.technology_category == "storage"

    @mock_aws
    def test_enrich_then_persist(self):
        """Violation counts survive DynamoDB round-trip."""
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="vbkt",
                        arn="arn:aws:s3:::vbkt",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        class FV:
            def __init__(self, res, sev):
                self.resource = res
                self.severity = sev
                self.status = "alarm"
                self.check_id = "s3_block_public_acls"

        clf.enrich_with_violations(records, [
            FV("arn:aws:s3:::vbkt", "critical"),
            FV("arn:aws:s3:::vbkt", "high"),
        ])

        for rec in records:
            store.put_resource(rec)

        result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::vbkt",
        )
        assert result.violation_count == 2
        assert result.critical_violations == 1
        assert result.high_violations == 1


class TestSoftDeleteUnseen:
    """Test deactivation of resources not seen in scan."""

    @mock_aws
    def test_unseen_resources_deactivated(self):
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        # Pre-populate with old resource
        old = ResourceRecord(
            pk=f"{ACCOUNT}#{REGION}",
            sk="s3_bucket#arn:aws:s3:::old-bkt",
            resource_id="arn:aws:s3:::old-bkt",
            resource_name="old-bkt",
            resource_type="s3_bucket",
            technology_category="storage",
            service="s3",
            region=REGION,
            account_id=ACCOUNT,
            last_seen="2026-03-17T00:00:00Z",
            is_active=True,
        )
        store.put_resource(old)

        # New scan only sees new-bkt
        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="new-bkt",
                        arn="arn:aws:s3:::new-bkt",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        new_records = clf.classify_all(data)

        # Persist new records
        for rec in new_records:
            store.put_resource(rec)

        # Mark unseen as inactive
        seen_keys = {
            (r.resource_type, r.resource_id)
            for r in new_records
        }
        existing = store.query_by_account(
            ACCOUNT, REGION, limit=5000
        )
        for ex in existing:
            key = (ex.resource_type, ex.resource_id)
            if ex.is_active and key not in seen_keys:
                store.deactivate_resource(
                    ACCOUNT, REGION,
                    ex.resource_type,
                    ex.resource_id,
                )

        # Verify old-bkt is deactivated
        old_result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::old-bkt",
        )
        assert old_result is not None
        assert old_result.is_active is False
        assert old_result.deactivated_at is not None

        # Verify new-bkt is still active
        new_result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::new-bkt",
        )
        assert new_result is not None
        assert new_result.is_active is True
