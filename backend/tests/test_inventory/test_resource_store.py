"""Tests for ResourceStore DynamoDB CRUD operations."""

from decimal import Decimal
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from app.models.resource import ResourceRecord
from app.pipeline.resource_store import (
    ResourceStore,
    _item_to_resource,
    _resource_to_item,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
TABLE_NAME = "resource-inventory"


def _create_table(session):
    """Create the resource-inventory table with GSIs."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=TABLE_NAME,
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
                "Projection": {
                    "ProjectionType": "ALL"
                },
            },
            {
                "IndexName": "exposure-index",
                "KeySchema": [
                    {
                        "AttributeName": "exposure",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": (
                            "violation_count"
                        ),
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
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
                "Projection": {
                    "ProjectionType": "ALL"
                },
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
                "Projection": {
                    "ProjectionType": "ALL"
                },
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
                "Projection": {
                    "ProjectionType": "ALL"
                },
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_resource(
    resource_type="s3_bucket",
    resource_id="arn:aws:s3:::prod-data",
    resource_name="prod-data",
    technology_category="storage",
    service="s3",
    exposure="private",
    risk_score=0,
    violation_count=0,
    is_active=True,
    last_seen="2026-03-18T10:00:00Z",
):
    """Build a ResourceRecord for testing."""
    return ResourceRecord(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{resource_type}#{resource_id}",
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        technology_category=technology_category,
        service=service,
        region=REGION,
        account_id=ACCOUNT,
        exposure=exposure,
        risk_score=risk_score,
        violation_count=violation_count,
        is_active=is_active,
        last_seen=last_seen,
    )


@pytest.fixture
def store(aws_credentials):
    """Create ResourceStore with moto DynamoDB."""
    with mock_aws():
        session = boto3.Session(
            region_name=REGION
        )
        _create_table(session)
        yield ResourceStore(session, TABLE_NAME)


# --------------------------------------------------
# PUT + GET
# --------------------------------------------------


class TestPutAndGetResource:
    """Test put_resource and get_resource."""

    def test_roundtrip(self, store):
        """Write and read back a resource."""
        res = _make_resource()
        assert store.put_resource(res) is True

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result is not None
        assert result.resource_id == (
            "arn:aws:s3:::prod-data"
        )
        assert result.resource_name == "prod-data"
        assert result.technology_category == "storage"
        assert result.service == "s3"
        assert result.is_active is True

    def test_get_nonexistent_returns_none(
        self, store
    ):
        """Missing resource returns None."""
        result = store.get_resource(
            ACCOUNT, REGION, "ec2_instance", "arn:fake"
        )
        assert result is None

    def test_put_overwrites_existing(self, store):
        """Second put overwrites the first."""
        r1 = _make_resource(exposure="private")
        r2 = _make_resource(exposure="internet")
        store.put_resource(r1)
        store.put_resource(r2)

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result.exposure == "internet"

    def test_put_with_none_fields(self, store):
        """None fields are stripped before write."""
        res = _make_resource()
        res.created_at = None
        res.managed_by = None
        assert store.put_resource(res) is True

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result is not None
        assert result.created_at is None
        assert result.managed_by is None

    def test_roundtrip_preserves_lists(self, store):
        """List fields survive serialization."""
        res = _make_resource(
            resource_id="arn:aws:s3:::bucket-pii",
            resource_name="bucket-pii",
        )
        res.data_types = ["pii", "financial"]
        res.compliance_gaps = ["CIS 2.1.5"]
        res.connected_to = ["arn:aws:kms:::key/k1"]
        # Update sk to match resource_type#resource_id
        res.sk = (
            f"s3_bucket#{res.resource_id}"
        )
        store.put_resource(res)

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::bucket-pii",
        )
        assert result.data_types == [
            "pii",
            "financial",
        ]
        assert result.compliance_gaps == [
            "CIS 2.1.5"
        ]
        assert result.connected_to == [
            "arn:aws:kms:::key/k1"
        ]

    def test_roundtrip_preserves_tags(self, store):
        """Tags dict survives serialization."""
        res = _make_resource()
        res.tags = {"env": "prod", "team": "sec"}
        store.put_resource(res)

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result.tags == {
            "env": "prod",
            "team": "sec",
        }


# --------------------------------------------------
# QUERY BY ACCOUNT (Primary Key)
# --------------------------------------------------


class TestQueryByAccount:
    """Test query_by_account operation."""

    def test_returns_matching_records(self, store):
        """Query returns all for account+region."""
        r1 = _make_resource(
            resource_id="arn:aws:s3:::bucket-a",
            resource_name="bucket-a",
        )
        r1.sk = f"s3_bucket#{r1.resource_id}"
        r2 = _make_resource(
            resource_type="ec2_instance",
            resource_id="arn:aws:ec2:...:i/i-123",
            resource_name="web-server",
            technology_category="compute",
            service="ec2",
        )
        r2.sk = f"ec2_instance#{r2.resource_id}"
        store.put_resource(r1)
        store.put_resource(r2)

        results = store.query_by_account(
            ACCOUNT, REGION
        )
        assert len(results) == 2

    def test_empty_account_returns_empty(
        self, store
    ):
        """Unknown account returns empty list."""
        results = store.query_by_account(
            "999999999999", REGION
        )
        assert results == []

    def test_limit_respected(self, store):
        """Limit caps the result count."""
        for i in range(5):
            r = _make_resource(
                resource_id=f"arn:aws:s3:::bkt-{i}",
                resource_name=f"bkt-{i}",
            )
            r.sk = f"s3_bucket#{r.resource_id}"
            store.put_resource(r)

        results = store.query_by_account(
            ACCOUNT, REGION, limit=3
        )
        assert len(results) == 3


# --------------------------------------------------
# QUERY BY CATEGORY (GSI-1)
# --------------------------------------------------


class TestQueryByCategory:
    """Test query_by_category via category-index."""

    def test_returns_category_records(self, store):
        """Query by category returns matches."""
        r1 = _make_resource(
            technology_category="storage",
        )
        r2 = _make_resource(
            resource_type="ec2_instance",
            resource_id="arn:aws:ec2:...:i/i-1",
            resource_name="web",
            technology_category="compute",
            service="ec2",
        )
        r2.sk = f"ec2_instance#{r2.resource_id}"
        store.put_resource(r1)
        store.put_resource(r2)

        results = store.query_by_category("storage")
        assert len(results) == 1
        assert results[0].technology_category == (
            "storage"
        )

    def test_empty_category_returns_empty(
        self, store
    ):
        """Unknown category returns empty list."""
        results = store.query_by_category("backup")
        assert results == []


# --------------------------------------------------
# QUERY BY EXPOSURE (GSI-2)
# --------------------------------------------------


class TestQueryByExposure:
    """Test query_by_exposure via exposure-index."""

    def test_returns_exposure_records(self, store):
        """Query by exposure returns matches."""
        r1 = _make_resource(exposure="internet")
        r2 = _make_resource(
            resource_id="arn:aws:s3:::private-bkt",
            resource_name="private-bkt",
            exposure="private",
        )
        r2.sk = f"s3_bucket#{r2.resource_id}"
        store.put_resource(r1)
        store.put_resource(r2)

        results = store.query_by_exposure("internet")
        assert len(results) == 1
        assert results[0].exposure == "internet"

    def test_empty_exposure_returns_empty(
        self, store
    ):
        """Unknown exposure returns empty."""
        results = store.query_by_exposure(
            "cross-account"
        )
        assert results == []


# --------------------------------------------------
# QUERY BY SERVICE (GSI-3)
# --------------------------------------------------


class TestQueryByService:
    """Test query_by_service via service-index."""

    def test_returns_service_records(self, store):
        """Query by service returns matches."""
        r1 = _make_resource(service="s3")
        r2 = _make_resource(
            resource_type="ec2_instance",
            resource_id="arn:aws:ec2:...:i/i-1",
            resource_name="web",
            technology_category="compute",
            service="ec2",
        )
        r2.sk = f"ec2_instance#{r2.resource_id}"
        store.put_resource(r1)
        store.put_resource(r2)

        results = store.query_by_service("s3")
        assert len(results) == 1
        assert results[0].service == "s3"

    def test_empty_service_returns_empty(
        self, store
    ):
        """Unknown service returns empty list."""
        results = store.query_by_service("rds")
        assert results == []


# --------------------------------------------------
# UPDATE SECURITY POSTURE
# --------------------------------------------------


class TestUpdateSecurityPosture:
    """Test update_security_posture operation."""

    def test_update_violation_counts(self, store):
        """Update increments violation counts."""
        res = _make_resource()
        store.put_resource(res)

        ok = store.update_security_posture(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
            violation_count=3,
            critical_violations=1,
            high_violations=2,
            risk_score=85,
            compliance_gaps=["CIS 2.1.5"],
        )
        assert ok is True

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result.violation_count == 3
        assert result.critical_violations == 1
        assert result.high_violations == 2
        assert result.risk_score == 85
        assert result.compliance_gaps == [
            "CIS 2.1.5"
        ]

    def test_update_clears_violations(self, store):
        """Update can reset to zero violations."""
        res = _make_resource(
            violation_count=5, risk_score=90
        )
        store.put_resource(res)

        store.update_security_posture(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
            violation_count=0,
            critical_violations=0,
            high_violations=0,
            risk_score=0,
            compliance_gaps=[],
        )

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result.violation_count == 0
        assert result.risk_score == 0
        assert result.compliance_gaps == []


# --------------------------------------------------
# DEACTIVATE (Soft Delete)
# --------------------------------------------------


class TestDeactivateResource:
    """Test deactivate_resource (soft-delete)."""

    def test_deactivate_sets_inactive(self, store):
        """Deactivate sets is_active=False."""
        res = _make_resource()
        store.put_resource(res)

        ok = store.deactivate_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert ok is True

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result.is_active is False
        assert result.deactivated_at is not None
        assert result.deactivated_at.endswith("Z")


# --------------------------------------------------
# DELETE (Hard Delete)
# --------------------------------------------------


class TestDeleteResource:
    """Test delete_resource operation."""

    def test_delete_removes_record(self, store):
        """Delete removes the record."""
        res = _make_resource()
        store.put_resource(res)

        ok = store.delete_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert ok is True

        result = store.get_resource(
            ACCOUNT,
            REGION,
            "s3_bucket",
            "arn:aws:s3:::prod-data",
        )
        assert result is None

    def test_delete_nonexistent_succeeds(
        self, store
    ):
        """Deleting missing record returns True."""
        ok = store.delete_resource(
            ACCOUNT, REGION, "nope", "arn:fake"
        )
        assert ok is True


# --------------------------------------------------
# COUNT BY CATEGORY
# --------------------------------------------------


class TestCountByCategory:
    """Test count_by_category operation."""

    def test_counts_storage_resources(self, store):
        """Count storage resources."""
        for i in range(3):
            r = _make_resource(
                resource_id=f"arn:aws:s3:::bkt-{i}",
                resource_name=f"bkt-{i}",
                technology_category="storage",
            )
            r.sk = f"s3_bucket#{r.resource_id}"
            store.put_resource(r)

        r = _make_resource(
            resource_type="ec2_instance",
            resource_id="arn:aws:ec2:...:i/i-1",
            resource_name="web",
            technology_category="compute",
            service="ec2",
        )
        r.sk = f"ec2_instance#{r.resource_id}"
        store.put_resource(r)

        assert (
            store.count_by_category("storage") == 3
        )
        assert (
            store.count_by_category("compute") == 1
        )

    def test_count_empty_returns_zero(self, store):
        """Empty category returns 0."""
        assert (
            store.count_by_category("backup") == 0
        )


# --------------------------------------------------
# CONVERSION HELPERS
# --------------------------------------------------


class TestResourceToItem:
    """Test _resource_to_item helper."""

    def test_strips_none_values(self):
        """None fields are removed from item."""
        res = _make_resource()
        res.created_at = None
        res.managed_by = None
        item = _resource_to_item(res)
        assert "created_at" not in item
        assert "managed_by" not in item

    def test_preserves_all_fields(self):
        """Non-None fields are all present."""
        res = _make_resource()
        res.created_at = "2026-01-01T00:00:00Z"
        item = _resource_to_item(res)
        assert item["pk"] == f"{ACCOUNT}#{REGION}"
        assert item["resource_id"] == (
            "arn:aws:s3:::prod-data"
        )
        assert item["is_active"] is True
        assert item["created_at"] == (
            "2026-01-01T00:00:00Z"
        )

    def test_preserves_lists(self):
        """List fields are preserved."""
        res = _make_resource()
        res.data_types = ["pii"]
        item = _resource_to_item(res)
        assert item["data_types"] == ["pii"]

    def test_empty_lists_preserved(self):
        """Empty lists are NOT stripped."""
        res = _make_resource()
        item = _resource_to_item(res)
        assert item["data_types"] == []


class TestItemToResource:
    """Test _item_to_resource helper."""

    def test_converts_decimals(self):
        """DynamoDB Decimal values are converted."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "s3_bucket#arn:aws:s3:::bkt",
            "resource_id": "arn:aws:s3:::bkt",
            "resource_name": "bkt",
            "resource_type": "s3_bucket",
            "technology_category": "storage",
            "service": "s3",
            "region": REGION,
            "account_id": ACCOUNT,
            "last_seen": "2026-03-18T10:00:00Z",
            "risk_score": Decimal("85"),
            "violation_count": Decimal("3"),
            "critical_violations": Decimal("1"),
            "high_violations": Decimal("2"),
        }
        r = _item_to_resource(item)
        assert r.risk_score == 85
        assert isinstance(r.risk_score, int)
        assert r.violation_count == 3
        assert r.critical_violations == 1
        assert r.high_violations == 2

    def test_handles_missing_optional_fields(self):
        """Minimal item converts successfully."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "s3_bucket#arn",
            "resource_id": "arn",
            "resource_name": "x",
            "resource_type": "s3_bucket",
            "technology_category": "storage",
            "service": "s3",
            "region": REGION,
            "account_id": ACCOUNT,
            "last_seen": "2026-03-18T10:00:00Z",
        }
        r = _item_to_resource(item)
        assert r.exposure == "unknown"
        assert r.risk_score == 0
        assert r.is_active is True
        assert r.managed_by is None

    def test_boolean_roundtrip(self):
        """Boolean is_active survives DynamoDB."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "s3_bucket#arn",
            "resource_id": "arn",
            "resource_name": "x",
            "resource_type": "s3_bucket",
            "technology_category": "storage",
            "service": "s3",
            "region": REGION,
            "account_id": ACCOUNT,
            "last_seen": "2026-03-18T10:00:00Z",
            "is_active": False,
        }
        r = _item_to_resource(item)
        assert r.is_active is False


# --------------------------------------------------
# ENDPOINT URL
# --------------------------------------------------


class TestEndpointUrl:
    """Test endpoint_url kwarg branch."""

    def test_with_endpoint_url(self, aws_credentials):
        """endpoint_url is passed to DynamoDB."""
        with mock_aws():
            session = boto3.Session(
                region_name=REGION
            )
            _create_table(session)
            store = ResourceStore(
                session,
                TABLE_NAME,
                endpoint_url=(
                    "http://localhost:9730"
                ),
            )
            assert store.table_name == TABLE_NAME


# --------------------------------------------------
# ERROR BRANCHES
# --------------------------------------------------


class TestErrorBranches:
    """Test all except branches return safely."""

    def _broken_store(self):
        """Build a ResourceStore with broken table."""
        store = ResourceStore.__new__(ResourceStore)
        store.table_name = TABLE_NAME
        store.table = MagicMock()
        store.table.get_item.side_effect = (
            Exception("DynamoDB down")
        )
        store.table.put_item.side_effect = (
            Exception("DynamoDB down")
        )
        store.table.update_item.side_effect = (
            Exception("DynamoDB down")
        )
        store.table.delete_item.side_effect = (
            Exception("DynamoDB down")
        )
        store.table.query.side_effect = (
            Exception("DynamoDB down")
        )
        return store

    def test_get_resource_error(self):
        """get_resource returns None on error."""
        s = self._broken_store()
        result = s.get_resource(
            ACCOUNT, REGION, "s3_bucket", "arn"
        )
        assert result is None

    def test_put_resource_error(self):
        """put_resource returns False on error."""
        s = self._broken_store()
        res = _make_resource()
        assert s.put_resource(res) is False

    def test_update_security_posture_error(self):
        """update returns False on error."""
        s = self._broken_store()
        result = s.update_security_posture(
            ACCOUNT, REGION, "s3_bucket", "arn",
            violation_count=0,
            critical_violations=0,
            high_violations=0,
            risk_score=0,
            compliance_gaps=[],
        )
        assert result is False

    def test_deactivate_resource_error(self):
        """deactivate returns False on error."""
        s = self._broken_store()
        result = s.deactivate_resource(
            ACCOUNT, REGION, "s3_bucket", "arn"
        )
        assert result is False

    def test_query_by_account_error(self):
        """query_by_account returns [] on error."""
        s = self._broken_store()
        result = s.query_by_account(ACCOUNT, REGION)
        assert result == []

    def test_query_by_category_error(self):
        """query_by_category returns [] on error."""
        s = self._broken_store()
        result = s.query_by_category("storage")
        assert result == []

    def test_query_by_exposure_error(self):
        """query_by_exposure returns [] on error."""
        s = self._broken_store()
        result = s.query_by_exposure("internet")
        assert result == []

    def test_query_by_service_error(self):
        """query_by_service returns [] on error."""
        s = self._broken_store()
        result = s.query_by_service("s3")
        assert result == []

    def test_delete_resource_error(self):
        """delete_resource returns False on error."""
        s = self._broken_store()
        result = s.delete_resource(
            ACCOUNT, REGION, "s3_bucket", "arn"
        )
        assert result is False

    def test_count_by_category_error(self):
        """count_by_category returns 0 on error."""
        s = self._broken_store()
        result = s.count_by_category("storage")
        assert result == 0
