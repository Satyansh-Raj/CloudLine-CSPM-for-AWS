"""Tests for inventory REST API endpoints."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.dependencies import (
    get_boto3_session,
    get_resource_store,
    get_settings,
)
from app.config import Settings
from app.main import app
from app.routers.inventory import reset_region_cache
from app.models.resource import ResourceRecord

ACCOUNT = "832843292195"
REGION = "ap-south-1"


def _make_resource(
    resource_type="s3_bucket",
    resource_id="arn:aws:s3:::test-bucket",
    resource_name="test-bucket",
    technology_category="storage",
    service="s3",
    exposure="private",
    tags=None,
    violation_count=0,
    risk_score=0,
    is_active=True,
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
        tags=tags or {},
        violation_count=violation_count,
        risk_score=risk_score,
        is_active=is_active,
        last_seen="2026-03-18T00:00:00Z",
    )


RESOURCES = [
    _make_resource(),
    _make_resource(
        resource_type="ec2_instance",
        resource_id=(
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-abc"
        ),
        resource_name="i-abc",
        technology_category="compute",
        service="ec2",
        exposure="internet",
        tags={"Environment": "prod"},
        violation_count=3,
        risk_score=85,
    ),
    _make_resource(
        resource_type="rds_instance",
        resource_id=(
            "arn:aws:rds:ap-south-1:832843292195"
            ":db:mydb"
        ),
        resource_name="mydb",
        technology_category="database",
        service="rds",
        exposure="private",
    ),
    _make_resource(
        resource_type="lambda_function",
        resource_id=(
            "arn:aws:lambda:ap-south-1:832843292195"
            ":function:api-fn"
        ),
        resource_name="api-fn",
        technology_category="serverless",
        service="lambda",
        exposure="internet",
        violation_count=1,
    ),
]


def _mock_store(resources=None):
    """Create a mock ResourceStore."""
    store = MagicMock()
    all_res = (
        resources if resources is not None else []
    )
    store.query_by_account.return_value = all_res
    store.summary_by_account.return_value = [
        {
            "technology_category": r.technology_category,
            "exposure": r.exposure,
            "service": r.service,
            "is_active": r.is_active,
        }
        for r in all_res
    ]
    store.query_by_category.return_value = [
        r for r in all_res
        if r.technology_category == "storage"
    ]
    store.query_by_exposure.return_value = [
        r for r in all_res
        if r.exposure == "internet"
    ]
    store.query_by_service.return_value = [
        r for r in all_res
        if r.service == "s3"
    ]
    store.get_resource.return_value = (
        all_res[0] if all_res else None
    )
    return store


# ── GET /api/v1/inventory ──────────────────────────


class TestListInventory:
    """GET /api/v1/inventory."""

    def setup_method(self):
        self._mock = _mock_store(RESOURCES)
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get("/api/v1/inventory")
        assert resp.status_code == 200

    def test_returns_list(self):
        client = TestClient(app)
        resp = client.get("/api/v1/inventory")
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 4

    def test_resource_fields(self):
        client = TestClient(app)
        resp = client.get("/api/v1/inventory")
        item = resp.json()[0]
        assert "resource_id" in item
        assert "resource_name" in item
        assert "resource_type" in item
        assert "technology_category" in item
        assert "service" in item
        assert "exposure" in item
        assert "tags" in item
        assert "violation_count" in item
        assert "risk_score" in item

    def test_filter_by_category(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?category=storage"
        )
        assert resp.status_code == 200
        self._mock.query_by_category.assert_called_once()

    def test_filter_by_exposure(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?exposure=internet"
        )
        assert resp.status_code == 200
        self._mock.query_by_exposure.assert_called_once()

    def test_filter_by_service(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?service=s3"
        )
        assert resp.status_code == 200
        self._mock.query_by_service.assert_called_once()

    def test_search_filters_by_name(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?search=abc"
        )
        assert resp.status_code == 200
        data = resp.json()
        # Only i-abc and vpc-abc etc. should match
        for item in data:
            assert "abc" in item["resource_name"].lower() or \
                   "abc" in item["resource_id"].lower()

    def test_limit_param(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?limit=2"
        )
        assert resp.status_code == 200

    def test_empty_result(self):
        self._mock = _mock_store([])
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock
        client = TestClient(app)
        resp = client.get("/api/v1/inventory")
        assert resp.json() == []


# ── GET /api/v1/inventory/summary ──────────────────


class TestInventorySummary:
    """GET /api/v1/inventory/summary."""

    def setup_method(self):
        self._mock = _mock_store(RESOURCES)
        # Mock session whose EC2 raises so
        # _discover_regions falls back to config.
        self._session = MagicMock()
        ec2 = MagicMock()
        ec2.describe_regions.side_effect = Exception(
            "mock"
        )
        self._session.client.return_value = ec2
        self._settings = Settings(
            aws_regions=[REGION],
            aws_account_id=ACCOUNT,
        )
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock
        app.dependency_overrides[
            get_boto3_session
        ] = lambda: self._session
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )
        app.dependency_overrides.pop(
            get_boto3_session, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )
        reset_region_cache()

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        assert resp.status_code == 200

    def test_total_count(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        data = resp.json()
        assert data["total"] == 4

    def test_by_category(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        cats = resp.json()["by_category"]
        assert cats["storage"] == 1
        assert cats["compute"] == 1

    def test_by_exposure(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        exp = resp.json()["by_exposure"]
        assert exp["internet"] == 2
        assert exp["private"] == 2

    def test_by_service(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        svcs = resp.json()["by_service"]
        assert svcs["s3"] == 1
        assert svcs["ec2"] == 1

    def test_empty_inventory(self):
        self._mock = _mock_store([])
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
        )
        data = resp.json()
        assert data["total"] == 0


# ── GET /api/v1/inventory/detail ───────────────────


class TestInventoryDetail:
    """GET /api/v1/inventory/detail."""

    def setup_method(self):
        self._mock = _mock_store(RESOURCES)
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/detail"
            "?resource_type=s3_bucket"
            "&resource_id=arn:aws:s3:::test-bucket"
        )
        assert resp.status_code == 200

    def test_returns_resource(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/detail"
            "?resource_type=s3_bucket"
            "&resource_id=arn:aws:s3:::test-bucket"
        )
        data = resp.json()
        assert data["resource_name"] == "test-bucket"

    def test_not_found(self):
        self._mock.get_resource.return_value = None
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/detail"
            "?resource_type=s3_bucket"
            "&resource_id=arn:aws:s3:::nonexistent"
        )
        assert resp.status_code == 404

    def test_missing_params(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/detail"
        )
        assert resp.status_code == 422


# ── Region filtering ─────────────────────────────


class TestRegionFiltering:
    """Region param must filter GSI query results."""

    def setup_method(self):
        # Resources from two different regions
        self._res = [
            _make_resource(
                resource_id="arn:aws:s3:::ap-bkt",
                resource_name="ap-bkt",
            ),
            ResourceRecord(
                pk=f"{ACCOUNT}#us-east-1",
                sk="s3_bucket#arn:aws:s3:::us-bkt",
                resource_id="arn:aws:s3:::us-bkt",
                resource_name="us-bkt",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region="us-east-1",
                account_id=ACCOUNT,
                last_seen="2026-03-18T00:00:00Z",
            ),
        ]
        self._mock = MagicMock()
        # GSI returns all regardless of region
        self._mock.query_by_category.return_value = (
            self._res
        )
        self._mock.query_by_exposure.return_value = (
            self._res
        )
        self._mock.query_by_service.return_value = (
            self._res
        )
        self._mock.query_by_account.return_value = (
            self._res
        )
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )

    def test_category_with_region_filters(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory"
            "?category=storage&region=ap-south-1"
        )
        data = resp.json()
        regions = {r["region"] for r in data}
        assert regions == {"ap-south-1"}

    def test_exposure_with_region_filters(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory"
            "?exposure=private&region=us-east-1"
        )
        data = resp.json()
        regions = {r["region"] for r in data}
        assert regions == {"us-east-1"}

    def test_service_with_region_filters(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory"
            "?service=s3&region=ap-south-1"
        )
        data = resp.json()
        regions = {r["region"] for r in data}
        assert regions == {"ap-south-1"}

    def test_no_region_returns_all(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory?category=storage"
        )
        data = resp.json()
        assert len(data) == 2
