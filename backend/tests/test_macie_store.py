"""Tests for MacieFindingStore DynamoDB CRUD and
GET /api/v1/macie/findings router.

Uses moto for the store layer and TestClient + mock
for the router layer.
"""

from unittest.mock import MagicMock

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app.models.macie import MacieData, MacieFinding

ACCOUNT = "123456789012"
REGION = "ap-south-1"
TABLE_NAME = "macie-findings"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_finding(**kwargs) -> MacieFinding:
    defaults = {
        "finding_id": "find-001",
        "type": "SensitiveData:S3Object/Personal",
        "bucket_name": "my-bucket",
        "severity": "High",
        "category": "CLASSIFICATION",
        "count": 3,
        "first_observed_at": "2026-04-01T00:00:00Z",
        "last_observed_at": "2026-04-02T00:00:00Z",
        "region": REGION,
        "account_id": ACCOUNT,
    }
    defaults.update(kwargs)
    return MacieFinding(**defaults)


def _make_macie_data(findings) -> MacieData:
    by_bucket: dict[str, list[str]] = {}
    for f in findings:
        by_bucket.setdefault(
            f.bucket_name, []
        ).append(f.finding_id)
    return MacieData(
        enabled=True,
        findings=findings,
        by_bucket=by_bucket,
        summary={"total": len(findings)},
    )


def _create_table(session):
    """Create macie-findings table with GSIs."""
    ddb = session.resource("dynamodb")
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
                "AttributeName": "bucket_name",
                "AttributeType": "S",
            },
            {
                "AttributeName": "severity",
                "AttributeType": "S",
            },
            {
                "AttributeName": "first_observed_at",
                "AttributeType": "S",
            },
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "bucket-index",
                "KeySchema": [
                    {
                        "AttributeName": "bucket_name",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "first_observed_at",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "severity-index",
                "KeySchema": [
                    {
                        "AttributeName": "severity",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "first_observed_at",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# MacieFindingStore tests
# ---------------------------------------------------------------------------
class TestMacieFindingStore:
    """Unit tests for MacieFindingStore DynamoDB layer."""

    @mock_aws
    def test_put_and_list_by_account(self):
        """put_findings stores items; list_findings returns them."""
        from app.pipeline.macie_store import MacieFindingStore

        session = boto3.Session(region_name="us-east-1")
        _create_table(session)
        store = MacieFindingStore(
            session=session,
            table_name=TABLE_NAME,
        )
        f1 = _make_finding(finding_id="find-001")
        f2 = _make_finding(
            finding_id="find-002",
            bucket_name="other-bucket",
            severity="Medium",
        )
        data = _make_macie_data([f1, f2])
        store.put_findings(data, ACCOUNT, REGION)

        results = store.list_findings(
            account_id=ACCOUNT, limit=100
        )
        assert len(results) == 2

    @mock_aws
    def test_list_filter_by_bucket(self):
        """list_findings(bucket_name=...) filters by bucket."""
        from app.pipeline.macie_store import MacieFindingStore

        session = boto3.Session(region_name="us-east-1")
        _create_table(session)
        store = MacieFindingStore(
            session=session,
            table_name=TABLE_NAME,
        )
        f1 = _make_finding(
            finding_id="find-001",
            bucket_name="bucket-a",
        )
        f2 = _make_finding(
            finding_id="find-002",
            bucket_name="bucket-b",
        )
        data = _make_macie_data([f1, f2])
        store.put_findings(data, ACCOUNT, REGION)

        results = store.list_findings(
            bucket_name="bucket-a", limit=100
        )
        assert len(results) == 1
        assert results[0]["bucket_name"] == "bucket-a"

    @mock_aws
    def test_list_filter_by_severity(self):
        """list_findings(severity=...) filters by severity."""
        from app.pipeline.macie_store import MacieFindingStore

        session = boto3.Session(region_name="us-east-1")
        _create_table(session)
        store = MacieFindingStore(
            session=session,
            table_name=TABLE_NAME,
        )
        f_high = _make_finding(
            finding_id="find-001",
            severity="High",
        )
        f_low = _make_finding(
            finding_id="find-002",
            severity="Low",
        )
        data = _make_macie_data([f_high, f_low])
        store.put_findings(data, ACCOUNT, REGION)

        results = store.list_findings(
            severity="High", limit=100
        )
        assert len(results) == 1
        assert results[0]["severity"] == "High"

    @mock_aws
    def test_list_respects_limit(self):
        """list_findings(limit=1) returns at most 1 item."""
        from app.pipeline.macie_store import MacieFindingStore

        session = boto3.Session(region_name="us-east-1")
        _create_table(session)
        store = MacieFindingStore(
            session=session,
            table_name=TABLE_NAME,
        )
        findings = [
            _make_finding(
                finding_id=f"find-{i:03d}",
                bucket_name=f"bucket-{i}",
            )
            for i in range(3)
        ]
        data = _make_macie_data(findings)
        store.put_findings(data, ACCOUNT, REGION)

        results = store.list_findings(
            account_id=ACCOUNT, limit=1
        )
        assert len(results) == 1

    @mock_aws
    def test_put_findings_empty_does_not_crash(self):
        """put_findings with empty findings list is a no-op."""
        from app.pipeline.macie_store import MacieFindingStore

        session = boto3.Session(region_name="us-east-1")
        _create_table(session)
        store = MacieFindingStore(
            session=session,
            table_name=TABLE_NAME,
        )
        data = _make_macie_data([])
        store.put_findings(data, ACCOUNT, REGION)

        results = store.list_findings(
            account_id=ACCOUNT, limit=100
        )
        assert results == []


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------
class TestMacieFindingsRouter:
    """Tests for GET /api/v1/macie/findings."""

    def _make_mock_store(self, findings=None):
        store = MagicMock()
        store.list_findings.return_value = (
            findings if findings is not None else []
        )
        return store

    def test_list_findings_returns_200(self):
        """GET /macie/findings returns 200 with results."""
        from app.dependencies import get_macie_store
        from app.main import app

        mock_store = self._make_mock_store(
            findings=[
                {
                    "finding_id": "find-001",
                    "bucket_name": "my-bucket",
                    "severity": "High",
                    "category": "CLASSIFICATION",
                    "type": "SensitiveData:S3Object/Personal",
                    "count": 3,
                    "first_observed_at": "2026-04-01T00:00:00Z",
                    "account_id": ACCOUNT,
                    "region": REGION,
                }
            ]
        )
        app.dependency_overrides[
            get_macie_store
        ] = lambda: mock_store

        client = TestClient(app)
        resp = client.get("/api/v1/macie/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["finding_id"] == "find-001"

        app.dependency_overrides.pop(
            get_macie_store, None
        )

    def test_list_findings_empty(self):
        """GET /macie/findings returns [] when no findings."""
        from app.dependencies import get_macie_store
        from app.main import app

        mock_store = self._make_mock_store(findings=[])
        app.dependency_overrides[
            get_macie_store
        ] = lambda: mock_store

        client = TestClient(app)
        resp = client.get("/api/v1/macie/findings")
        assert resp.status_code == 200
        assert resp.json() == []

        app.dependency_overrides.pop(
            get_macie_store, None
        )

    def test_list_findings_passes_bucket_filter(self):
        """Query param bucket_name is forwarded to store."""
        from app.dependencies import get_macie_store
        from app.main import app

        mock_store = self._make_mock_store()
        app.dependency_overrides[
            get_macie_store
        ] = lambda: mock_store

        client = TestClient(app)
        resp = client.get(
            "/api/v1/macie/findings",
            params={"bucket_name": "my-bucket"},
        )
        assert resp.status_code == 200
        mock_store.list_findings.assert_called_once()
        call_kwargs = mock_store.list_findings.call_args.kwargs
        assert call_kwargs.get("bucket_name") == "my-bucket"

        app.dependency_overrides.pop(
            get_macie_store, None
        )

    def test_list_findings_passes_severity_filter(self):
        """Query param severity is forwarded to store."""
        from app.dependencies import get_macie_store
        from app.main import app

        mock_store = self._make_mock_store()
        app.dependency_overrides[
            get_macie_store
        ] = lambda: mock_store

        client = TestClient(app)
        resp = client.get(
            "/api/v1/macie/findings",
            params={"severity": "High"},
        )
        assert resp.status_code == 200
        call_kwargs = mock_store.list_findings.call_args.kwargs
        assert call_kwargs.get("severity") == "High"

        app.dependency_overrides.pop(
            get_macie_store, None
        )
