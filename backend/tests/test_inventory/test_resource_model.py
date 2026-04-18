"""Tests for ResourceRecord Pydantic model."""

import pytest
from pydantic import ValidationError

from app.models.resource import ResourceRecord

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _make_resource(**overrides):
    """Build a ResourceRecord with sensible defaults."""
    defaults = {
        "pk": f"{ACCOUNT}#{REGION}",
        "sk": "s3_bucket#arn:aws:s3:::prod-data",
        "resource_id": "arn:aws:s3:::prod-data",
        "resource_name": "prod-data",
        "resource_type": "s3_bucket",
        "technology_category": "storage",
        "service": "s3",
        "region": REGION,
        "account_id": ACCOUNT,
        "last_seen": "2026-03-18T10:00:00Z",
    }
    defaults.update(overrides)
    return ResourceRecord(**defaults)


class TestRequiredFields:
    """Required fields must be present."""

    def test_valid_minimal_resource(self):
        """All required fields present succeeds."""
        r = _make_resource()
        assert r.resource_id == (
            "arn:aws:s3:::prod-data"
        )
        assert r.resource_type == "s3_bucket"
        assert r.technology_category == "storage"
        assert r.service == "s3"

    def test_missing_pk_raises(self):
        """Missing pk raises ValidationError."""
        with pytest.raises(ValidationError):
            ResourceRecord(
                sk="s3_bucket#arn",
                resource_id="arn",
                resource_name="x",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region=REGION,
                account_id=ACCOUNT,
                last_seen="2026-03-18T10:00:00Z",
            )

    def test_missing_sk_raises(self):
        """Missing sk raises ValidationError."""
        with pytest.raises(ValidationError):
            ResourceRecord(
                pk=f"{ACCOUNT}#{REGION}",
                resource_id="arn",
                resource_name="x",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region=REGION,
                account_id=ACCOUNT,
                last_seen="2026-03-18T10:00:00Z",
            )

    def test_missing_resource_id_raises(self):
        """Missing resource_id raises."""
        with pytest.raises(ValidationError):
            ResourceRecord(
                pk=f"{ACCOUNT}#{REGION}",
                sk="s3_bucket#arn",
                resource_name="x",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region=REGION,
                account_id=ACCOUNT,
                last_seen="2026-03-18T10:00:00Z",
            )

    def test_missing_resource_name_raises(self):
        """Missing resource_name raises."""
        with pytest.raises(ValidationError):
            ResourceRecord(
                pk=f"{ACCOUNT}#{REGION}",
                sk="s3_bucket#arn",
                resource_id="arn",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region=REGION,
                account_id=ACCOUNT,
                last_seen="2026-03-18T10:00:00Z",
            )

    def test_missing_last_seen_raises(self):
        """Missing last_seen raises."""
        with pytest.raises(ValidationError):
            ResourceRecord(
                pk=f"{ACCOUNT}#{REGION}",
                sk="s3_bucket#arn",
                resource_id="arn",
                resource_name="x",
                resource_type="s3_bucket",
                technology_category="storage",
                service="s3",
                region=REGION,
                account_id=ACCOUNT,
            )


class TestDefaultValues:
    """Optional fields have correct defaults."""

    def test_exposure_defaults_unknown(self):
        """Exposure defaults to 'unknown'."""
        r = _make_resource()
        assert r.exposure == "unknown"

    def test_data_sensitivity_defaults_unknown(self):
        """Data sensitivity defaults to 'unknown'."""
        r = _make_resource()
        assert r.data_sensitivity == "unknown"

    def test_environment_defaults_unknown(self):
        """Environment defaults to 'unknown'."""
        r = _make_resource()
        assert r.environment == "unknown"

    def test_data_types_defaults_empty(self):
        """Data types defaults to empty list."""
        r = _make_resource()
        assert r.data_types == []

    def test_compliance_gaps_defaults_empty(self):
        """Compliance gaps defaults to empty list."""
        r = _make_resource()
        assert r.compliance_gaps == []

    def test_connected_to_defaults_empty(self):
        """Connected_to defaults to empty list."""
        r = _make_resource()
        assert r.connected_to == []

    def test_tags_defaults_empty(self):
        """Tags defaults to empty dict."""
        r = _make_resource()
        assert r.tags == {}

    def test_is_active_defaults_true(self):
        """is_active defaults to True."""
        r = _make_resource()
        assert r.is_active is True

    def test_numeric_defaults_zero(self):
        """Numeric fields default to 0."""
        r = _make_resource()
        assert r.violation_count == 0
        assert r.critical_violations == 0
        assert r.high_violations == 0
        assert r.risk_score == 0

    def test_optional_fields_default_none(self):
        """Optional str fields default to None."""
        r = _make_resource()
        assert r.created_at is None
        assert r.deactivated_at is None
        assert r.managed_by is None
        assert r.belongs_to is None

    def test_owner_defaults_empty(self):
        """Owner defaults to empty string."""
        r = _make_resource()
        assert r.owner == ""


class TestFieldOverrides:
    """Fields can be overridden at construction."""

    def test_set_exposure(self):
        """Exposure can be set."""
        r = _make_resource(exposure="internet")
        assert r.exposure == "internet"

    def test_set_data_sensitivity(self):
        """Data sensitivity can be set."""
        r = _make_resource(data_sensitivity="critical")
        assert r.data_sensitivity == "critical"

    def test_set_data_types(self):
        """Data types list can be set."""
        r = _make_resource(
            data_types=["pii", "financial"]
        )
        assert r.data_types == ["pii", "financial"]

    def test_set_tags(self):
        """Tags dict can be set."""
        r = _make_resource(
            tags={"env": "prod", "team": "sec"}
        )
        assert r.tags == {
            "env": "prod",
            "team": "sec",
        }

    def test_set_security_posture(self):
        """Security posture fields can be set."""
        r = _make_resource(
            violation_count=5,
            critical_violations=2,
            high_violations=3,
            risk_score=85,
            compliance_gaps=["CIS 1.5", "NIST IA-2"],
        )
        assert r.violation_count == 5
        assert r.critical_violations == 2
        assert r.high_violations == 3
        assert r.risk_score == 85
        assert r.compliance_gaps == [
            "CIS 1.5",
            "NIST IA-2",
        ]

    def test_set_relationships(self):
        """Relationship fields can be set."""
        r = _make_resource(
            connected_to=["arn:aws:kms:::key/abc"],
            managed_by="arn:aws:iam::123:role/admin",
            belongs_to="arn:aws:ec2::123:vpc/vpc-1",
        )
        assert r.connected_to == [
            "arn:aws:kms:::key/abc"
        ]
        assert r.managed_by == (
            "arn:aws:iam::123:role/admin"
        )
        assert r.belongs_to == (
            "arn:aws:ec2::123:vpc/vpc-1"
        )

    def test_set_is_active_false(self):
        """is_active can be set to False."""
        r = _make_resource(is_active=False)
        assert r.is_active is False


class TestModelDump:
    """model_dump() produces correct dict."""

    def test_dump_includes_all_fields(self):
        """Dump includes required and optional."""
        r = _make_resource()
        d = r.model_dump()
        assert d["pk"] == f"{ACCOUNT}#{REGION}"
        assert d["resource_id"] == (
            "arn:aws:s3:::prod-data"
        )
        assert d["exposure"] == "unknown"
        assert d["data_types"] == []
        assert d["is_active"] is True

    def test_dump_none_fields_present(self):
        """model_dump includes None fields."""
        r = _make_resource()
        d = r.model_dump()
        assert "created_at" in d
        assert d["created_at"] is None

    def test_list_default_isolation(self):
        """Each instance has independent lists."""
        r1 = _make_resource()
        r2 = _make_resource()
        r1.data_types.append("pii")
        assert r2.data_types == []

    def test_dict_default_isolation(self):
        """Each instance has independent dicts."""
        r1 = _make_resource()
        r2 = _make_resource()
        r1.tags["env"] = "prod"
        assert r2.tags == {}
