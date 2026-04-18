"""Tests for MacieCollector — Batch 3B TDD.

Uses unittest.mock to simulate the macie2 boto3 client
since moto does not fully support Macie 2 operations.
"""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from app.collectors.macie import MacieCollector
from app.models.macie import MacieData, MacieFinding


# ── Helpers ────────────────────────────────────────


def _client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": code}},
        "Operation",
    )


def _raw_finding(
    finding_id: str = "f1",
    bucket_name: str = "my-bucket",
    severity: str = "High",
    category: str = "CLASSIFICATION",
    finding_type: str = (
        "SensitiveData:S3Object/Personal"
    ),
    count: int = 3,
    region: str = "ap-south-1",
    account_id: str = "832843292195",
) -> dict:
    return {
        "id": finding_id,
        "type": finding_type,
        "severity": {"description": severity},
        "category": category,
        "count": count,
        "createdAt": "2026-04-08T00:00:00Z",
        "updatedAt": "2026-04-08T01:00:00Z",
        "region": region,
        "accountId": account_id,
        "resourcesAffected": {
            "s3Bucket": {"name": bucket_name}
        },
    }


def _make_session(macie2_client: MagicMock):
    """Return a mock boto3 session wired to the
    given macie2 client."""
    session = MagicMock()
    session.client.return_value = macie2_client
    return session


# ── Fixtures ───────────────────────────────────────


@pytest.fixture
def disabled_client():
    """macie2 client where Macie is not enabled."""
    client = MagicMock()
    client.get_macie_session.return_value = {
        "status": "PAUSED"
    }
    return client


@pytest.fixture
def access_denied_client():
    """macie2 client that raises AccessDeniedException."""
    client = MagicMock()
    client.get_macie_session.side_effect = (
        _client_error("AccessDeniedException")
    )
    return client


@pytest.fixture
def enabled_no_findings_client():
    """macie2 client where Macie is enabled but
    has no findings."""
    client = MagicMock()
    client.get_macie_session.return_value = {
        "status": "ENABLED"
    }
    client.list_findings.return_value = {
        "findingIds": []
    }
    return client


@pytest.fixture
def single_finding_client():
    """macie2 client with one finding."""
    client = MagicMock()
    client.get_macie_session.return_value = {
        "status": "ENABLED"
    }
    client.list_findings.return_value = {
        "findingIds": ["f1"]
    }
    client.get_findings.return_value = {
        "findings": [_raw_finding("f1")]
    }
    return client


@pytest.fixture
def multi_bucket_client():
    """macie2 client with findings across two buckets."""
    client = MagicMock()
    client.get_macie_session.return_value = {
        "status": "ENABLED"
    }
    client.list_findings.return_value = {
        "findingIds": ["f1", "f2"]
    }
    client.get_findings.return_value = {
        "findings": [
            _raw_finding(
                "f1",
                bucket_name="bucket-a",
                severity="High",
            ),
            _raw_finding(
                "f2",
                bucket_name="bucket-b",
                severity="Medium",
            ),
        ]
    }
    return client


# ── collect() — disabled / inaccessible ───────────


class TestMacieCollectorDisabled:
    def test_collect_returns_macie_key(
        self, disabled_client
    ):
        collector = MacieCollector(
            _make_session(disabled_client)
        )
        key, _ = collector.collect()
        assert key == "macie"

    def test_collect_returns_dict(
        self, disabled_client
    ):
        collector = MacieCollector(
            _make_session(disabled_client)
        )
        _, data = collector.collect()
        assert isinstance(data, dict)

    def test_macie_paused_returns_disabled(
        self, disabled_client
    ):
        collector = MacieCollector(
            _make_session(disabled_client)
        )
        _, data = collector.collect()
        assert data["enabled"] is False

    def test_macie_paused_returns_empty_findings(
        self, disabled_client
    ):
        collector = MacieCollector(
            _make_session(disabled_client)
        )
        _, data = collector.collect()
        assert data["findings"] == []

    def test_access_denied_returns_disabled(
        self, access_denied_client
    ):
        collector = MacieCollector(
            _make_session(access_denied_client)
        )
        _, data = collector.collect()
        assert data["enabled"] is False

    def test_access_denied_empty_findings(
        self, access_denied_client
    ):
        collector = MacieCollector(
            _make_session(access_denied_client)
        )
        _, data = collector.collect()
        assert data["findings"] == []


# ── collect() — enabled, no findings ──────────────


class TestMacieCollectorEnabledNoFindings:
    def test_enabled_flag_true(
        self, enabled_no_findings_client
    ):
        collector = MacieCollector(
            _make_session(enabled_no_findings_client)
        )
        _, data = collector.collect()
        assert data["enabled"] is True

    def test_no_findings_returned(
        self, enabled_no_findings_client
    ):
        collector = MacieCollector(
            _make_session(enabled_no_findings_client)
        )
        _, data = collector.collect()
        assert data["findings"] == []

    def test_empty_by_bucket(
        self, enabled_no_findings_client
    ):
        collector = MacieCollector(
            _make_session(enabled_no_findings_client)
        )
        _, data = collector.collect()
        assert data["by_bucket"] == {}


# ── collect() — findings parsing ──────────────────


class TestMacieCollectorFindings:
    def test_finding_id_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert data["findings"][0]["finding_id"] == "f1"

    def test_bucket_name_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert (
            data["findings"][0]["bucket_name"]
            == "my-bucket"
        )

    def test_severity_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert data["findings"][0]["severity"] == "High"

    def test_category_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert (
            data["findings"][0]["category"]
            == "CLASSIFICATION"
        )

    def test_count_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert data["findings"][0]["count"] == 3

    def test_timestamps_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        f = data["findings"][0]
        assert f["first_observed_at"] == (
            "2026-04-08T00:00:00Z"
        )
        assert f["last_observed_at"] == (
            "2026-04-08T01:00:00Z"
        )

    def test_region_and_account_parsed(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        f = data["findings"][0]
        assert f["region"] == "ap-south-1"
        assert f["account_id"] == "832843292195"


# ── by_bucket index ────────────────────────────────


class TestMacieBucketIndex:
    def test_by_bucket_single_finding(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert "my-bucket" in data["by_bucket"]
        assert data["by_bucket"]["my-bucket"] == ["f1"]

    def test_by_bucket_multiple_buckets(
        self, multi_bucket_client
    ):
        collector = MacieCollector(
            _make_session(multi_bucket_client)
        )
        _, data = collector.collect()
        assert "bucket-a" in data["by_bucket"]
        assert "bucket-b" in data["by_bucket"]
        assert data["by_bucket"]["bucket-a"] == ["f1"]
        assert data["by_bucket"]["bucket-b"] == ["f2"]


# ── summary stats ──────────────────────────────────


class TestMacieSummary:
    def test_summary_total(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        assert data["summary"]["total"] == 1

    def test_summary_by_severity(
        self, multi_bucket_client
    ):
        collector = MacieCollector(
            _make_session(multi_bucket_client)
        )
        _, data = collector.collect()
        sv = data["summary"]["by_severity"]
        assert sv.get("High") == 1
        assert sv.get("Medium") == 1

    def test_summary_by_category(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        _, data = collector.collect()
        cat = data["summary"]["by_category"]
        assert cat.get("CLASSIFICATION") == 1


# ── pagination ─────────────────────────────────────


class TestMaciePagination:
    def test_paginated_findings_collected(self):
        """list_findings with two pages returns all IDs."""
        client = MagicMock()
        client.get_macie_session.return_value = {
            "status": "ENABLED"
        }
        client.list_findings.side_effect = [
            {
                "findingIds": ["f1", "f2"],
                "nextToken": "page2",
            },
            {
                "findingIds": ["f3"],
            },
        ]
        client.get_findings.return_value = {
            "findings": [
                _raw_finding("f1"),
                _raw_finding("f2", bucket_name="b2"),
                _raw_finding("f3", bucket_name="b3"),
            ]
        }
        collector = MacieCollector(
            _make_session(client)
        )
        _, data = collector.collect()
        ids = [
            f["finding_id"] for f in data["findings"]
        ]
        assert "f1" in ids
        assert "f2" in ids
        assert "f3" in ids

    def test_paginated_list_findings_called_twice(
        self,
    ):
        """list_findings is called for each page."""
        client = MagicMock()
        client.get_macie_session.return_value = {
            "status": "ENABLED"
        }
        client.list_findings.side_effect = [
            {
                "findingIds": ["f1"],
                "nextToken": "tok",
            },
            {"findingIds": ["f2"]},
        ]
        client.get_findings.return_value = {
            "findings": [
                _raw_finding("f1"),
                _raw_finding("f2", bucket_name="b2"),
            ]
        }
        collector = MacieCollector(
            _make_session(client)
        )
        collector.collect()
        assert client.list_findings.call_count == 2


# ── batching (>25 findings) ────────────────────────


class TestMacieBatching:
    def test_large_finding_list_batched(self):
        """get_findings is called in batches of 25."""
        # 30 finding IDs → 2 batch calls
        ids = [f"f{i}" for i in range(30)]
        client = MagicMock()
        client.get_macie_session.return_value = {
            "status": "ENABLED"
        }
        client.list_findings.return_value = {
            "findingIds": ids
        }
        # Return one finding per batch call
        client.get_findings.side_effect = [
            {
                "findings": [
                    _raw_finding(fid)
                    for fid in ids[:25]
                ]
            },
            {
                "findings": [
                    _raw_finding(fid)
                    for fid in ids[25:]
                ]
            },
        ]
        collector = MacieCollector(
            _make_session(client)
        )
        _, data = collector.collect()
        assert client.get_findings.call_count == 2
        assert len(data["findings"]) == 30


# ── collect_resource() ─────────────────────────────


class TestMacieCollectResource:
    def test_collect_resource_returns_dict(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        result = collector.collect_resource(
            "my-bucket"
        )
        assert isinstance(result, dict)

    def test_collect_resource_known_bucket(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        result = collector.collect_resource(
            "my-bucket"
        )
        assert result["bucket_name"] == "my-bucket"
        assert len(result["findings"]) == 1
        assert (
            result["findings"][0]["finding_id"] == "f1"
        )

    def test_collect_resource_unknown_bucket(
        self, single_finding_client
    ):
        collector = MacieCollector(
            _make_session(single_finding_client)
        )
        result = collector.collect_resource(
            "nonexistent-bucket"
        )
        assert result["findings"] == []

    def test_collect_resource_macie_disabled(
        self, disabled_client
    ):
        collector = MacieCollector(
            _make_session(disabled_client)
        )
        result = collector.collect_resource(
            "any-bucket"
        )
        assert result["findings"] == []


# ── Detection types extraction ─────────────────────


def _raw_finding_with_detections(
    detection_type_list: list[str],
    finding_id: str = "f-med",
    bucket_name: str = "phi-bucket",
) -> dict:
    """Raw Macie finding with classificationDetails."""
    raw = _raw_finding(
        finding_id=finding_id,
        bucket_name=bucket_name,
        finding_type="SensitiveData:S3Object/Personal",
    )
    raw["classificationDetails"] = {
        "result": {
            "sensitiveData": [
                {
                    "category": "PERSONAL_INFORMATION",
                    "detections": [
                        {"type": dt, "count": 1}
                        for dt in detection_type_list
                    ],
                    "totalCount": len(
                        detection_type_list
                    ),
                }
            ]
        }
    }
    return raw


class TestParseDetectionTypes:
    """_parse_finding extracts classificationDetails
    detection types into MacieFinding.detection_types."""

    def test_medical_record_number_extracted(self):
        raw = _raw_finding_with_detections(
            ["MEDICAL_RECORD_NUMBER"]
        )
        finding = MacieCollector._parse_finding(raw)
        assert finding is not None
        assert "MEDICAL_RECORD_NUMBER" in (
            finding.detection_types
        )

    def test_nhs_number_extracted(self):
        raw = _raw_finding_with_detections(
            ["UK_NHS_NUMBER"]
        )
        finding = MacieCollector._parse_finding(raw)
        assert finding is not None
        assert "UK_NHS_NUMBER" in finding.detection_types

    def test_multiple_detection_types_all_extracted(
        self,
    ):
        raw = _raw_finding_with_detections(
            [
                "MEDICAL_RECORD_NUMBER",
                "US_SOCIAL_SECURITY_NUMBER",
                "UK_NHS_NUMBER",
            ]
        )
        finding = MacieCollector._parse_finding(raw)
        assert finding is not None
        assert len(finding.detection_types) == 3
        assert "MEDICAL_RECORD_NUMBER" in (
            finding.detection_types
        )
        assert "US_SOCIAL_SECURITY_NUMBER" in (
            finding.detection_types
        )

    def test_no_classification_details_gives_empty(
        self,
    ):
        """Finding with no classificationDetails →
        detection_types stays []."""
        raw = _raw_finding("f-plain")
        finding = MacieCollector._parse_finding(raw)
        assert finding is not None
        assert finding.detection_types == []

    def test_multiple_sensitive_data_categories(self):
        """Detections across multiple sensitiveData
        entries are all collected."""
        raw = _raw_finding(
            "f-multi", bucket_name="mixed-bucket"
        )
        raw["classificationDetails"] = {
            "result": {
                "sensitiveData": [
                    {
                        "category": (
                            "PERSONAL_INFORMATION"
                        ),
                        "detections": [
                            {
                                "type": (
                                    "MEDICAL_RECORD"
                                    "_NUMBER"
                                ),
                                "count": 2,
                            }
                        ],
                        "totalCount": 2,
                    },
                    {
                        "category": (
                            "FINANCIAL_INFORMATION"
                        ),
                        "detections": [
                            {
                                "type": (
                                    "CREDIT_CARD_NUMBER"
                                ),
                                "count": 1,
                            }
                        ],
                        "totalCount": 1,
                    },
                ]
            }
        }
        finding = MacieCollector._parse_finding(raw)
        assert finding is not None
        assert "MEDICAL_RECORD_NUMBER" in (
            finding.detection_types
        )
        assert "CREDIT_CARD_NUMBER" in (
            finding.detection_types
        )
