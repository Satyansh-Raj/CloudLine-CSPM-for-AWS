"""Tests for ComplianceMapper — compliance-data mapping.

Covers:
- Model validation (ComplianceRequirement,
  DataComplianceResult)
- ComplianceMapper init (default path, custom path,
  missing file)
- reload() picks up config changes
- Single data-type mapping (pii, financial, health,
  credentials, logs, unknown)
- Multi-type mapping (union of frameworks, deduplication)
- Compliance gap string formatting
- ResourceClassifier.enrich_with_data_classification()
- _resource_to_dict() exposes the three new fields
- GET /inventory/data-classification endpoint
- GET /inventory/data-summary endpoint
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.inventory.compliance_mapper import (
    ComplianceMapper,
    ComplianceRequirement,
    DataComplianceResult,
)
from app.inventory.data_classifier import (
    DataClassification,
)
from app.models.resource import ResourceRecord

# ── Helpers ────────────────────────────────────────


ACCOUNT = "123456789012"
REGION = "us-east-1"


def _classification(
    data_types: list[str],
    sensitivity: str = "unknown",
) -> DataClassification:
    """Build a DataClassification for testing."""
    return DataClassification(
        sensitivity=sensitivity,
        data_types=data_types,
        confidence="high",
        source="tag",
    )


def _make_record(
    resource_type: str = "s3_bucket",
    resource_id: str = "arn:aws:s3:::test-bkt",
    resource_name: str = "test-bkt",
    data_sensitivity: str = "unknown",
    data_types: list[str] | None = None,
    compliance_gaps: list[str] | None = None,
) -> ResourceRecord:
    """Build a ResourceRecord for testing."""
    return ResourceRecord(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{resource_type}#{resource_id}",
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        technology_category="storage",
        service="s3",
        region=REGION,
        account_id=ACCOUNT,
        data_sensitivity=data_sensitivity,
        data_types=data_types or [],
        compliance_gaps=compliance_gaps or [],
        last_seen="2026-03-18T00:00:00Z",
    )


def _make_mapper(
    extra: dict | None = None,
) -> ComplianceMapper:
    """Return a ComplianceMapper using the real config."""
    return ComplianceMapper()


# ── ComplianceRequirement model ────────────────────


class TestComplianceRequirementModel:
    """Unit tests for the ComplianceRequirement model."""

    def test_create_with_all_fields(self):
        req = ComplianceRequirement(
            framework="PCI DSS",
            controls=["3.4", "3.5"],
            requirements=["Must be encrypted"],
        )
        assert req.framework == "PCI DSS"
        assert req.controls == ["3.4", "3.5"]
        assert req.requirements == ["Must be encrypted"]

    def test_create_with_empty_controls(self):
        req = ComplianceRequirement(
            framework="SOC 2",
            controls=[],
            requirements=["Audit access"],
        )
        assert req.controls == []
        assert req.framework == "SOC 2"


# ── DataComplianceResult model ─────────────────────


class TestDataComplianceResultModel:
    """Unit tests for the DataComplianceResult model."""

    def test_full_result(self):
        result = DataComplianceResult(
            data_types=["pii"],
            sensitivity="critical",
            frameworks=["NIST 800-53", "SOC 2"],
            compliance_requirements=[
                ComplianceRequirement(
                    framework="NIST 800-53",
                    controls=["SI-12"],
                    requirements=["Encrypt at rest"],
                )
            ],
            compliance_gaps=["NIST 800-53 SI-12"],
        )
        assert result.sensitivity == "critical"
        assert "NIST 800-53" in result.frameworks
        assert len(result.compliance_requirements) == 1
        assert "NIST 800-53 SI-12" in result.compliance_gaps

    def test_empty_unknown_result(self):
        result = DataComplianceResult(
            data_types=[],
            sensitivity="unknown",
            frameworks=[],
            compliance_requirements=[],
            compliance_gaps=[],
        )
        assert result.data_types == []
        assert result.frameworks == []
        assert result.compliance_gaps == []


# ── ComplianceMapper init ──────────────────────────


class TestComplianceMapperInit:
    """Tests for ComplianceMapper.__init__."""

    def test_loads_default_config_path(self):
        """Default path resolves and loads without error."""
        mapper = ComplianceMapper()
        # If it loaded, map() should work, not raise
        result = mapper.map(
            _classification(["pii"], "critical")
        )
        assert isinstance(result, DataComplianceResult)

    def test_loads_custom_config_path(self):
        """Custom path is accepted and loaded."""
        config = {
            "version": "1.0",
            "framework_names": {
                "test_fw": "Test Framework"
            },
            "mappings": {
                "pii": {
                    "frameworks": ["Test Framework"],
                    "controls": {
                        "test_fw": ["T-1"]
                    },
                    "requirements": [
                        "Test requirement"
                    ],
                }
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as f:
            json.dump(config, f)
            tmp_path = f.name
        try:
            mapper = ComplianceMapper(
                config_path=tmp_path
            )
            result = mapper.map(
                _classification(["pii"], "critical")
            )
            assert "Test Framework" in result.frameworks
        finally:
            os.unlink(tmp_path)

    def test_raises_for_missing_file(self):
        """FileNotFoundError raised for bad path."""
        with pytest.raises(FileNotFoundError):
            ComplianceMapper(
                config_path="/nonexistent/path.json"
            )


# ── ComplianceMapper reload ────────────────────────


class TestComplianceMapperReload:
    """Tests for ComplianceMapper.reload()."""

    def test_reload_rerereads_json(self):
        """reload() re-reads without raising."""
        mapper = ComplianceMapper()
        # Should not raise — idempotent reload
        mapper.reload()
        result = mapper.map(
            _classification(["pii"], "critical")
        )
        assert isinstance(result, DataComplianceResult)

    def test_reload_picks_up_changes(self):
        """After reload(), updated JSON is reflected."""
        config_v1 = {
            "version": "1.0",
            "framework_names": {
                "fw_a": "Framework A"
            },
            "mappings": {
                "pii": {
                    "frameworks": ["Framework A"],
                    "controls": {"fw_a": ["A-1"]},
                    "requirements": ["Req A"],
                }
            },
        }
        config_v2 = {
            "version": "1.0",
            "framework_names": {
                "fw_b": "Framework B"
            },
            "mappings": {
                "pii": {
                    "frameworks": ["Framework B"],
                    "controls": {"fw_b": ["B-99"]},
                    "requirements": ["Req B"],
                }
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as f:
            json.dump(config_v1, f)
            tmp_path = f.name
        try:
            mapper = ComplianceMapper(
                config_path=tmp_path
            )
            result1 = mapper.map(
                _classification(["pii"], "critical")
            )
            assert "Framework A" in result1.frameworks

            # Overwrite config with v2
            with open(tmp_path, "w") as f:
                json.dump(config_v2, f)

            mapper.reload()
            result2 = mapper.map(
                _classification(["pii"], "critical")
            )
            assert "Framework B" in result2.frameworks
            assert "Framework A" not in result2.frameworks
        finally:
            os.unlink(tmp_path)


# ── Single data-type mapping ───────────────────────


class TestMapSingleDataType:
    """Tests mapping one data type at a time."""

    def setup_method(self):
        self.mapper = ComplianceMapper()

    def test_pii_frameworks(self):
        result = self.mapper.map(
            _classification(["pii"], "critical")
        )
        assert "NIST 800-53" in result.frameworks
        assert "SOC 2" in result.frameworks
        # Controls must include the pii nist controls
        nist_req = next(
            r for r in result.compliance_requirements
            if r.framework == "NIST 800-53"
        )
        assert "SI-12" in nist_req.controls
        assert "MP-6" in nist_req.controls
        assert "AC-3" in nist_req.controls

    def test_financial_frameworks(self):
        result = self.mapper.map(
            _classification(["financial"], "high")
        )
        assert "PCI DSS v4.0" in result.frameworks
        assert "SOC 2" in result.frameworks
        pci_req = next(
            r for r in result.compliance_requirements
            if r.framework == "PCI DSS v4.0"
        )
        assert "3.4" in pci_req.controls
        assert "3.5" in pci_req.controls

    def test_health_frameworks(self):
        result = self.mapper.map(
            _classification(["health"], "critical")
        )
        assert "HIPAA" in result.frameworks
        assert "NIST 800-53" in result.frameworks
        hipaa_req = next(
            r for r in result.compliance_requirements
            if r.framework == "HIPAA"
        )
        assert "164.312(a)(1)" in hipaa_req.controls

    def test_credentials_frameworks(self):
        result = self.mapper.map(
            _classification(["credentials"], "high")
        )
        assert (
            "CIS AWS Foundations Benchmark v1.5.0"
            in result.frameworks
        )
        assert "NIST 800-53" in result.frameworks
        assert "SOC 2" in result.frameworks
        cis_req = next(
            r for r in result.compliance_requirements
            if r.framework
            == "CIS AWS Foundations Benchmark v1.5.0"
        )
        assert "1.12" in cis_req.controls
        assert "1.14" in cis_req.controls

    def test_logs_frameworks(self):
        result = self.mapper.map(
            _classification(["logs"], "low")
        )
        assert (
            "CIS AWS Foundations Benchmark v1.5.0"
            in result.frameworks
        )
        assert "SOC 2" in result.frameworks

    def test_unknown_type_returns_empty(self):
        result = self.mapper.map(
            _classification(["totally_unknown"])
        )
        assert result.data_types == ["totally_unknown"]
        assert result.frameworks == []
        assert result.compliance_requirements == []
        assert result.compliance_gaps == []


# ── Multi-type mapping ─────────────────────────────


class TestMapMultipleDataTypes:
    """Tests mapping multiple data types at once."""

    def setup_method(self):
        self.mapper = ComplianceMapper()

    def test_pii_and_financial_union(self):
        result = self.mapper.map(
            _classification(
                ["pii", "financial"], "critical"
            )
        )
        # Both framework sets must be present
        assert "NIST 800-53" in result.frameworks
        assert "SOC 2" in result.frameworks
        assert "PCI DSS v4.0" in result.frameworks

    def test_pii_and_health_nist_deduplicated(self):
        """NIST 800-53 appears only once despite two types
        referencing it."""
        result = self.mapper.map(
            _classification(
                ["pii", "health"], "critical"
            )
        )
        nist_count = result.frameworks.count(
            "NIST 800-53"
        )
        assert nist_count == 1

    def test_all_types_all_frameworks_present(self):
        result = self.mapper.map(
            _classification(
                [
                    "pii",
                    "financial",
                    "health",
                    "credentials",
                    "logs",
                ],
                "critical",
            )
        )
        for fw in [
            "NIST 800-53",
            "SOC 2",
            "PCI DSS v4.0",
            "HIPAA",
            "CIS AWS Foundations Benchmark v1.5.0",
        ]:
            assert fw in result.frameworks, (
                f"{fw} missing from frameworks"
            )

    def test_empty_data_types_returns_empty_result(self):
        result = self.mapper.map(
            _classification([], "unknown")
        )
        assert result.data_types == []
        assert result.frameworks == []
        assert result.compliance_requirements == []
        assert result.compliance_gaps == []


# ── Compliance gap string format ───────────────────


class TestComplianceGapsFormat:
    """Tests the "FRAMEWORK CONTROL" gap strings."""

    def setup_method(self):
        self.mapper = ComplianceMapper()

    def test_pii_gaps_exact(self):
        result = self.mapper.map(
            _classification(["pii"], "critical")
        )
        expected = {
            "NIST 800-53 SI-12",
            "NIST 800-53 MP-6",
            "NIST 800-53 AC-3",
            "SOC 2 CC6.1",
            "SOC 2 CC6.5",
        }
        assert expected.issubset(
            set(result.compliance_gaps)
        )

    def test_financial_gaps_exact(self):
        result = self.mapper.map(
            _classification(["financial"], "high")
        )
        expected = {
            "PCI DSS v4.0 3.4",
            "PCI DSS v4.0 3.5",
            "PCI DSS v4.0 4.1",
            "PCI DSS v4.0 10.1",
            "SOC 2 CC6.1",
        }
        assert expected.issubset(
            set(result.compliance_gaps)
        )

    def test_multi_type_gaps_combined_deduplicated(self):
        """SOC 2 CC6.1 appears in both pii and financial
        but must only appear once in gaps."""
        result = self.mapper.map(
            _classification(
                ["pii", "financial"], "critical"
            )
        )
        soc2_cc61_count = result.compliance_gaps.count(
            "SOC 2 CC6.1"
        )
        assert soc2_cc61_count == 1

    def test_no_types_no_gaps(self):
        result = self.mapper.map(
            _classification([], "unknown")
        )
        assert result.compliance_gaps == []


# ── enrich_with_data_classification ───────────────


class TestEnrichWithDataClassification:
    """Tests for ResourceClassifier.enrich_with_data_classification."""

    def _make_classifier(self):
        from app.inventory.classifier import (
            ResourceClassifier,
        )
        return ResourceClassifier(ACCOUNT, REGION)

    def test_s3_pii_enriches_record(self):
        """S3 bucket with PII gets critical sensitivity
        and populated gaps."""
        clf = self._make_classifier()
        record = _make_record(
            resource_type="s3_bucket",
            resource_name="customer-data",
        )
        dc_mock = MagicMock()
        dc_mock.classify_resource.return_value = (
            DataClassification(
                sensitivity="critical",
                data_types=["pii"],
                confidence="high",
                source="tag",
            )
        )
        mapper = ComplianceMapper()
        clf.enrich_with_data_classification(
            [record], dc_mock, mapper
        )
        assert record.data_sensitivity == "critical"
        assert "pii" in record.data_types
        assert len(record.compliance_gaps) > 0

    def test_rds_financial_enriches_record(self):
        """RDS with financial tags gets high sensitivity."""
        clf = self._make_classifier()
        record = _make_record(
            resource_type="rds_instance",
            resource_name="billing-db",
        )
        dc_mock = MagicMock()
        dc_mock.classify_resource.return_value = (
            DataClassification(
                sensitivity="high",
                data_types=["financial"],
                confidence="high",
                source="tag",
            )
        )
        mapper = ComplianceMapper()
        clf.enrich_with_data_classification(
            [record], dc_mock, mapper
        )
        assert record.data_sensitivity == "high"
        assert "financial" in record.data_types
        assert (
            "PCI DSS v4.0 3.4" in record.compliance_gaps
        )

    def test_unknown_classification_stays_unknown(self):
        """Resource with no signals stays unknown."""
        clf = self._make_classifier()
        record = _make_record()
        dc_mock = MagicMock()
        dc_mock.classify_resource.return_value = (
            DataClassification(
                sensitivity="unknown",
                data_types=[],
                confidence="low",
                source="heuristic",
            )
        )
        mapper = ComplianceMapper()
        clf.enrich_with_data_classification(
            [record], dc_mock, mapper
        )
        assert record.data_sensitivity == "unknown"
        assert record.data_types == []
        assert record.compliance_gaps == []

    def test_multiple_records_all_enriched(self):
        """All records in the list are enriched."""
        clf = self._make_classifier()
        records = [
            _make_record(resource_id=f"arn:aws:s3:::bkt-{i}")
            for i in range(3)
        ]
        dc_mock = MagicMock()
        dc_mock.classify_resource.return_value = (
            DataClassification(
                sensitivity="critical",
                data_types=["pii"],
                confidence="high",
                source="tag",
            )
        )
        mapper = ComplianceMapper()
        clf.enrich_with_data_classification(
            records, dc_mock, mapper
        )
        for rec in records:
            assert rec.data_sensitivity == "critical"
            assert "pii" in rec.data_types

    def test_exception_in_classifier_is_skipped(self):
        """An exception for one resource does not crash
        the whole enrichment pass."""
        clf = self._make_classifier()
        records = [
            _make_record(
                resource_id="arn:aws:s3:::bkt-good"
            ),
            _make_record(
                resource_id="arn:aws:s3:::bkt-bad"
            ),
        ]
        dc_mock = MagicMock()
        # First call raises, second returns valid result
        dc_mock.classify_resource.side_effect = [
            Exception("boto3 failure"),
            DataClassification(
                sensitivity="high",
                data_types=["financial"],
                confidence="medium",
                source="heuristic",
            ),
        ]
        mapper = ComplianceMapper()
        # Must not raise
        clf.enrich_with_data_classification(
            records, dc_mock, mapper
        )
        # First record is untouched (still unknown)
        assert records[0].data_sensitivity == "unknown"
        # Second record is enriched
        assert records[1].data_sensitivity == "high"


# ── _resource_to_dict fields ───────────────────────


class TestResourceToDictFields:
    """Tests that _resource_to_dict exposes the 3 new
    data-classification fields."""

    def _to_dict(self, record: ResourceRecord) -> dict:
        from app.routers.inventory import _resource_to_dict
        return _resource_to_dict(record)

    def test_includes_data_fields(self):
        record = _make_record(
            data_sensitivity="critical",
            data_types=["pii"],
            compliance_gaps=["NIST 800-53 SI-12"],
        )
        d = self._to_dict(record)
        assert "data_sensitivity" in d
        assert "data_types" in d
        assert "compliance_gaps" in d

    def test_values_are_correct(self):
        record = _make_record(
            data_sensitivity="high",
            data_types=["financial"],
            compliance_gaps=["PCI DSS 3.4"],
        )
        d = self._to_dict(record)
        assert d["data_sensitivity"] == "high"
        assert d["data_types"] == ["financial"]
        assert d["compliance_gaps"] == ["PCI DSS 3.4"]


# ── GET /inventory/data-classification endpoint ────


class TestDataClassificationEndpoint:
    """Integration tests for the data-classification
    endpoint using FastAPI TestClient."""

    def _make_client(self, resource=None):
        from app.dependencies import get_resource_store
        from app.main import app

        store_mock = MagicMock()
        store_mock.get_resource.return_value = resource
        app.dependency_overrides[
            get_resource_store
        ] = lambda: store_mock
        client = TestClient(app)
        return client, store_mock

    def teardown_method(self):
        from app.dependencies import get_resource_store
        from app.main import app
        app.dependency_overrides.pop(
            get_resource_store, None
        )

    def test_returns_classification_for_known_resource(
        self,
    ):
        record = _make_record(
            data_sensitivity="critical",
            data_types=["pii"],
            compliance_gaps=["NIST 800-53 SI-12"],
        )
        client, _ = self._make_client(resource=record)
        resp = client.get(
            "/api/v1/inventory/data-classification"
            "?resource_type=s3_bucket"
            "&resource_id=arn:aws:s3:::test-bkt"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["sensitivity"] == "critical"
        assert "pii" in body["data_types"]
        assert "NIST 800-53 SI-12" in body[
            "compliance_gaps"
        ]

    def test_returns_404_for_unknown_resource(self):
        client, _ = self._make_client(resource=None)
        resp = client.get(
            "/api/v1/inventory/data-classification"
            "?resource_type=s3_bucket"
            "&resource_id=arn:aws:s3:::no-such-bkt"
        )
        assert resp.status_code == 404


# ── GET /inventory/data-summary endpoint ──────────


class TestDataSummaryEndpoint:
    """Integration tests for the data-summary endpoint."""

    def _make_client(self, resources: list):
        from app.dependencies import (
            get_resource_store,
            get_settings,
        )
        from app.main import app
        from app.config import Settings

        store_mock = MagicMock()
        store_mock.query_by_account.return_value = (
            resources
        )
        settings = Settings(
            aws_region=REGION,
            aws_account_id=ACCOUNT,
            api_key="test",
            app_env="testing",
        )
        app.dependency_overrides[
            get_resource_store
        ] = lambda: store_mock
        app.dependency_overrides[
            get_settings
        ] = lambda: settings
        return TestClient(app)

    def teardown_method(self):
        from app.dependencies import (
            get_resource_store,
            get_settings,
        )
        from app.main import app
        app.dependency_overrides.pop(
            get_resource_store, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_returns_correct_counts(self):
        resources = [
            _make_record(
                resource_id="arn:aws:s3:::bkt-1",
                data_sensitivity="critical",
                data_types=["pii"],
            ),
            _make_record(
                resource_id="arn:aws:s3:::bkt-2",
                data_sensitivity="critical",
                data_types=["pii", "financial"],
            ),
            _make_record(
                resource_id="arn:aws:s3:::bkt-3",
                data_sensitivity="high",
                data_types=["financial"],
            ),
        ]
        client = self._make_client(resources)
        resp = client.get(
            "/api/v1/inventory/data-summary"
        )
        assert resp.status_code == 200
        body = resp.json()
        # by_type: pii seen in 2 resources, financial in 2
        assert body["by_type"]["pii"] == 2
        assert body["by_type"]["financial"] == 2
        # by_sensitivity
        assert body["by_sensitivity"]["critical"] == 2
        assert body["by_sensitivity"]["high"] == 1
        # by_framework: PCI DSS v4.0 appears for 2 financial
        # resources, NIST 800-53 for 2 pii resources
        assert (
            body["by_framework"]["PCI DSS v4.0"] >= 2
        )
        assert (
            body["by_framework"]["NIST 800-53"] >= 2
        )

    def test_empty_inventory_returns_zeros(self):
        client = self._make_client([])
        resp = client.get(
            "/api/v1/inventory/data-summary"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["by_type"] == {}
        assert body["by_sensitivity"] == {}
        assert body["by_framework"] == {}
