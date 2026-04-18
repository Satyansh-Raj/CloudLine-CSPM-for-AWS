"""Tests for MacieFinding, MacieData Pydantic models
and their integration with UnifiedAWSInput.

TDD Batch 3A — RED phase.
"""

import pytest

from app.models.macie import MacieData, MacieFinding
from app.models.aws_input import UnifiedAWSInput


# ── MacieFinding ───────────────────────────────────


class TestMacieFinding:
    """Unit tests for the MacieFinding model."""

    def test_required_fields_accepted(self):
        f = MacieFinding(
            finding_id="abc123",
            type="SensitiveData:S3Object/Personal",
            bucket_name="my-bucket",
            severity="High",
            category="CLASSIFICATION",
            count=5,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        assert f.finding_id == "abc123"
        assert f.bucket_name == "my-bucket"
        assert f.severity == "High"
        assert f.count == 5

    def test_optional_fields_have_defaults(self):
        f = MacieFinding(
            finding_id="abc123",
            type="SensitiveData:S3Object/Financial",
            bucket_name="my-bucket",
            severity="Medium",
            category="CLASSIFICATION",
            count=1,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        assert f.last_observed_at is None
        assert f.region == ""
        assert f.account_id == ""

    def test_optional_fields_accepted(self):
        f = MacieFinding(
            finding_id="f1",
            type="SensitiveData:S3Object/Credentials",
            bucket_name="creds-bucket",
            severity="High",
            category="CLASSIFICATION",
            count=2,
            first_observed_at="2026-04-08T00:00:00Z",
            last_observed_at="2026-04-08T01:00:00Z",
            region="ap-south-1",
            account_id="832843292195",
        )
        assert f.last_observed_at == "2026-04-08T01:00:00Z"
        assert f.region == "ap-south-1"
        assert f.account_id == "832843292195"

    def test_model_dump_round_trip(self):
        f = MacieFinding(
            finding_id="round",
            type="SensitiveData:S3Object/Personal",
            bucket_name="b",
            severity="Low",
            category="CLASSIFICATION",
            count=0,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        d = f.model_dump()
        assert d["finding_id"] == "round"
        assert d["bucket_name"] == "b"
        assert "last_observed_at" in d

    def test_extra_fields_accepted(self):
        """MacieFinding uses extra='allow'."""
        f = MacieFinding(
            finding_id="x",
            type="SensitiveData:S3Object/Personal",
            bucket_name="b",
            severity="High",
            category="CLASSIFICATION",
            count=1,
            first_observed_at="2026-04-08T00:00:00Z",
            new_field_from_aws="some_value",
        )
        assert f.model_extra.get(
            "new_field_from_aws"
        ) == "some_value"

    def test_detection_types_defaults_empty(self):
        """detection_types defaults to empty list."""
        f = MacieFinding(
            finding_id="d1",
            type="SensitiveData:S3Object/Personal",
            bucket_name="b",
            severity="High",
            category="CLASSIFICATION",
            count=1,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        assert f.detection_types == []

    def test_detection_types_accepts_values(self):
        """detection_types stores specific managed
        identifier names."""
        f = MacieFinding(
            finding_id="d2",
            type="SensitiveData:S3Object/Personal",
            bucket_name="phi-bucket",
            severity="High",
            category="CLASSIFICATION",
            count=4,
            first_observed_at="2026-04-08T00:00:00Z",
            detection_types=[
                "MEDICAL_RECORD_NUMBER",
                "UK_NHS_NUMBER",
            ],
        )
        assert "MEDICAL_RECORD_NUMBER" in (
            f.detection_types
        )
        assert "UK_NHS_NUMBER" in f.detection_types

    def test_detection_types_in_model_dump(self):
        """detection_types appears in model_dump()."""
        f = MacieFinding(
            finding_id="d3",
            type="SensitiveData:S3Object/Personal",
            bucket_name="b",
            severity="High",
            category="CLASSIFICATION",
            count=1,
            first_observed_at="2026-04-08T00:00:00Z",
            detection_types=["US_SOCIAL_SECURITY_NUMBER"],
        )
        d = f.model_dump()
        assert "detection_types" in d
        assert d["detection_types"] == [
            "US_SOCIAL_SECURITY_NUMBER"
        ]


# ── MacieData ──────────────────────────────────────


class TestMacieData:
    """Unit tests for the MacieData container model."""

    def test_defaults_to_disabled_empty(self):
        m = MacieData()
        assert m.enabled is False
        assert m.findings == []
        assert m.by_bucket == {}
        assert m.summary == {}

    def test_accepts_findings_list(self):
        finding = MacieFinding(
            finding_id="f1",
            type="SensitiveData:S3Object/Financial",
            bucket_name="finance-bucket",
            severity="High",
            category="CLASSIFICATION",
            count=3,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        m = MacieData(
            enabled=True,
            findings=[finding],
            by_bucket={"finance-bucket": ["f1"]},
            summary={"total": 1, "by_severity": {"High": 1}},
        )
        assert m.enabled is True
        assert len(m.findings) == 1
        assert m.findings[0].finding_id == "f1"
        assert m.by_bucket == {"finance-bucket": ["f1"]}
        assert m.summary["total"] == 1

    def test_model_dump_round_trip(self):
        m = MacieData(
            enabled=True,
            findings=[
                MacieFinding(
                    finding_id="f2",
                    type="SensitiveData:S3Object/Personal",
                    bucket_name="pii-bucket",
                    severity="High",
                    category="CLASSIFICATION",
                    count=10,
                    first_observed_at=(
                        "2026-04-08T00:00:00Z"
                    ),
                )
            ],
            by_bucket={"pii-bucket": ["f2"]},
            summary={"total": 1},
        )
        d = m.model_dump()
        assert d["enabled"] is True
        assert len(d["findings"]) == 1
        assert d["findings"][0]["bucket_name"] == (
            "pii-bucket"
        )

    def test_extra_fields_accepted(self):
        m = MacieData(custom_field="test")
        assert m.model_extra.get("custom_field") == "test"

    def test_multiple_findings_different_buckets(self):
        f1 = MacieFinding(
            finding_id="fa",
            type="SensitiveData:S3Object/Personal",
            bucket_name="bucket-a",
            severity="High",
            category="CLASSIFICATION",
            count=1,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        f2 = MacieFinding(
            finding_id="fb",
            type="SensitiveData:S3Object/Credentials",
            bucket_name="bucket-b",
            severity="High",
            category="CLASSIFICATION",
            count=2,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        m = MacieData(
            enabled=True,
            findings=[f1, f2],
            by_bucket={
                "bucket-a": ["fa"],
                "bucket-b": ["fb"],
            },
        )
        assert len(m.findings) == 2
        assert "bucket-a" in m.by_bucket
        assert "bucket-b" in m.by_bucket


# ── UnifiedAWSInput integration ────────────────────


class TestUnifiedAWSInputMacieField:
    """Tests that UnifiedAWSInput accepts and exposes
    the new MacieData field."""

    def _base_input(self, **kwargs) -> UnifiedAWSInput:
        return UnifiedAWSInput(
            account_id="123456789012",
            region="ap-south-1",
            collection_timestamp="2026-04-08T00:00:00Z",
            **kwargs,
        )

    def test_macie_defaults_to_empty_maciedata(self):
        inp = self._base_input()
        assert isinstance(inp.macie, MacieData)
        assert inp.macie.enabled is False
        assert inp.macie.findings == []

    def test_macie_accepts_populated_maciedata(self):
        finding = MacieFinding(
            finding_id="f1",
            type="SensitiveData:S3Object/Personal",
            bucket_name="pii-bucket",
            severity="High",
            category="CLASSIFICATION",
            count=5,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        macie_data = MacieData(
            enabled=True,
            findings=[finding],
            by_bucket={"pii-bucket": ["f1"]},
            summary={"total": 1},
        )
        inp = self._base_input(macie=macie_data)
        assert inp.macie.enabled is True
        assert len(inp.macie.findings) == 1

    def test_model_dump_includes_macie(self):
        inp = self._base_input()
        d = inp.model_dump()
        assert "macie" in d
        assert d["macie"]["enabled"] is False
        assert d["macie"]["findings"] == []

    def test_model_dump_with_findings_round_trips(self):
        finding = MacieFinding(
            finding_id="rt1",
            type="SensitiveData:S3Object/Financial",
            bucket_name="fin",
            severity="Medium",
            category="CLASSIFICATION",
            count=2,
            first_observed_at="2026-04-08T00:00:00Z",
        )
        inp = self._base_input(
            macie=MacieData(
                enabled=True,
                findings=[finding],
                by_bucket={"fin": ["rt1"]},
            )
        )
        d = inp.model_dump()
        assert d["macie"]["enabled"] is True
        assert (
            d["macie"]["findings"][0]["finding_id"]
            == "rt1"
        )

    def test_existing_fields_unaffected(self):
        """Adding macie field must not break anything."""
        inp = self._base_input()
        assert inp.account_id == "123456789012"
        assert inp.region == "ap-south-1"
        # iam, s3, ec2 etc. still present
        assert hasattr(inp, "iam")
        assert hasattr(inp, "s3")
        assert hasattr(inp, "ec2")
