"""Tests for GET /v1/inventory/regions endpoint
and region-filter parameter on existing endpoints.
"""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.config import Settings
from app.dependencies import (
    get_boto3_session,
    get_resource_store,
    get_settings,
)
from app.main import app
from app.models.resource import ResourceRecord
from app.routers.inventory import reset_region_cache

ACCOUNT = "832843292195"
REGION_PRIMARY = "ap-south-1"
REGION_SECONDARY = "eu-west-1"


def _make_resource(
    region=REGION_PRIMARY,
    resource_type="s3_bucket",
    resource_id="arn:aws:s3:::test-bucket",
    resource_name="test-bucket",
):
    return ResourceRecord(
        pk=f"{ACCOUNT}#{region}",
        sk=f"{resource_type}#{resource_id}",
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        technology_category="storage",
        service="s3",
        region=region,
        account_id=ACCOUNT,
        exposure="private",
        tags={},
        violation_count=0,
        risk_score=0,
        is_active=True,
        last_seen="2026-03-18T00:00:00Z",
    )


def _mock_store(resources=None):
    store = MagicMock()
    all_res = resources if resources is not None else []
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
    store.query_by_category.return_value = all_res
    store.query_by_exposure.return_value = all_res
    store.query_by_service.return_value = all_res
    return store


# ── GET /api/v1/inventory/regions ─────────────────


def _mock_boto3_session():
    """Return a mock session whose EC2 client raises
    so _discover_regions falls back to config."""
    session = MagicMock()
    ec2 = MagicMock()
    ec2.describe_regions.side_effect = Exception(
        "mocked — use config fallback"
    )
    session.client.return_value = ec2
    return session


class TestListRegions:
    """GET /api/v1/inventory/regions."""

    def setup_method(self):
        reset_region_cache()
        self._settings = Settings(
            aws_regions=[
                REGION_PRIMARY,
                REGION_SECONDARY,
            ],
            aws_account_id=ACCOUNT,
        )
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings
        app.dependency_overrides[
            get_boto3_session
        ] = _mock_boto3_session

    def teardown_method(self):
        reset_region_cache()
        app.dependency_overrides.pop(
            get_settings, None
        )
        app.dependency_overrides.pop(
            get_boto3_session, None
        )

    def test_list_regions_returns_configured(self):
        """Endpoint returns the configured regions list."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/regions"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "regions" in data
        assert "default" in data
        assert data["regions"] == [
            REGION_PRIMARY,
            REGION_SECONDARY,
        ]

    def test_list_regions_default_is_first(self):
        """default field equals first configured region."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/regions"
        )
        data = resp.json()
        assert data["default"] == REGION_PRIMARY

    def test_list_regions_single_region(self):
        """Works correctly when only one region is
        configured."""
        self._settings = Settings(
            aws_regions=["us-east-1"],
            aws_account_id=ACCOUNT,
        )
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings

        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/regions"
        )
        data = resp.json()
        assert data["regions"] == ["us-east-1"]
        assert data["default"] == "us-east-1"

    def test_list_regions_many_regions(self):
        """Works correctly with many regions."""
        many = [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "ap-south-1",
        ]
        self._settings = Settings(
            aws_regions=many,
            aws_account_id=ACCOUNT,
        )
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings

        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/regions"
        )
        data = resp.json()
        assert len(data["regions"]) == 4
        assert data["default"] == "us-east-1"

    def test_dynamic_discovery_overrides_config(self):
        """When EC2 describe_regions succeeds, its
        result is returned instead of config."""
        reset_region_cache()
        discovered = [
            "ap-south-1",
            "eu-west-1",
            "us-east-1",
        ]
        mock_session = MagicMock()
        ec2 = MagicMock()
        ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": r}
                for r in discovered
            ],
        }
        mock_session.client.return_value = ec2
        app.dependency_overrides[
            get_boto3_session
        ] = lambda: mock_session

        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/regions"
        )
        data = resp.json()
        assert data["regions"] == discovered
        # default still comes from settings
        assert data["default"] == REGION_PRIMARY


# ── GET /api/v1/inventory?region= ─────────────────


class TestInventoryWithRegionFilter:
    """GET /api/v1/inventory with region param."""

    def setup_method(self):
        self._store = _mock_store(
            [_make_resource(region=REGION_PRIMARY)]
        )
        self._settings = Settings(
            aws_regions=[
                REGION_PRIMARY,
                REGION_SECONDARY,
            ],
            aws_account_id=ACCOUNT,
        )
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._store
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_inventory_with_region_filter(self):
        """region param is accepted without error."""
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/inventory?region={REGION_SECONDARY}"
        )
        assert resp.status_code == 200

    def test_inventory_region_param_calls_store(self):
        """Providing region passes it to query_by_account."""
        client = TestClient(app)
        client.get(
            f"/api/v1/inventory?region={REGION_SECONDARY}"
        )
        self._store.query_by_account.assert_called_once_with(
            ACCOUNT,
            REGION_SECONDARY,
            limit=200,
        )

    def test_inventory_no_region_uses_default(self):
        """Omitting region falls back to settings.aws_region."""
        client = TestClient(app)
        client.get("/api/v1/inventory")
        self._store.query_by_account.assert_called_once_with(
            ACCOUNT,
            REGION_PRIMARY,
            limit=200,
        )

    def test_inventory_empty_region_uses_default(self):
        """Passing region= (empty string) falls back to
        settings.aws_region."""
        client = TestClient(app)
        client.get("/api/v1/inventory?region=")
        self._store.query_by_account.assert_called_once_with(
            ACCOUNT,
            REGION_PRIMARY,
            limit=200,
        )

    def test_inventory_returns_list_with_region(self):
        """Response is still a valid list when region
        is provided."""
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/inventory?region={REGION_PRIMARY}"
        )
        assert isinstance(resp.json(), list)


# ── GET /api/v1/inventory/summary?region= ─────────


class TestInventorySummaryWithRegion:
    """GET /api/v1/inventory/summary with region param."""

    def setup_method(self):
        reset_region_cache()
        self._store = _mock_store(
            [
                _make_resource(
                    region=REGION_PRIMARY
                )
            ]
        )
        self._settings = Settings(
            aws_regions=[
                REGION_PRIMARY,
                REGION_SECONDARY,
            ],
            aws_account_id=ACCOUNT,
        )
        # Mock session whose EC2 raises so
        # _discover_regions falls back to config.
        self._session = MagicMock()
        ec2 = MagicMock()
        ec2.describe_regions.side_effect = Exception(
            "mock"
        )
        self._session.client.return_value = ec2
        app.dependency_overrides[
            get_resource_store
        ] = lambda: self._store
        app.dependency_overrides[
            get_settings
        ] = lambda: self._settings
        app.dependency_overrides[
            get_boto3_session
        ] = lambda: self._session

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_resource_store, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )
        app.dependency_overrides.pop(
            get_boto3_session, None
        )
        reset_region_cache()

    def test_inventory_summary_with_region(self):
        """region param is accepted without error."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
            f"?region={REGION_SECONDARY}"
        )
        assert resp.status_code == 200

    def test_summary_region_param_calls_store(self):
        """Providing region passes it to
        summary_by_account with regions list."""
        client = TestClient(app)
        client.get(
            "/api/v1/inventory/summary"
            f"?region={REGION_SECONDARY}"
        )
        self._store.summary_by_account.assert_called_once_with(
            ACCOUNT,
            regions=[REGION_SECONDARY],
        )

    def test_summary_no_region_uses_all(self):
        """Omitting region queries all configured
        regions."""
        client = TestClient(app)
        client.get("/api/v1/inventory/summary")
        self._store.summary_by_account.assert_called_once_with(
            ACCOUNT,
            regions=[
                REGION_PRIMARY,
                REGION_SECONDARY,
            ],
        )

    def test_summary_returns_valid_structure(self):
        """Response always has the expected shape."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/inventory/summary"
            f"?region={REGION_PRIMARY}"
        )
        data = resp.json()
        assert "total" in data
        assert "by_category" in data
        assert "by_exposure" in data
        assert "by_service" in data
