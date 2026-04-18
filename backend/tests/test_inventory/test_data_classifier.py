"""Tests for the DataClassifier data type detection engine.

Covers S3 object key sampling, Macie findings ingestion,
RDS/DynamoDB schema metadata extraction, tag-based
classification, and the resource-type dispatcher.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from app.inventory.data_classifier import (
    DataClassification,
    DataClassifier,
)
from app.models.macie import MacieData, MacieFinding

# ── Helpers ────────────────────────────────────────


def _make_client_error(code: str) -> Exception:
    """Build a ClientError for the given error code."""
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "denied"}},
        "operation",
    )


def _make_session(clients: dict):
    """Build a mock boto3 Session.

    Args:
        clients: Maps service name → mock client.
    """
    session = MagicMock()
    session.client.side_effect = (
        lambda svc, **kw: clients[svc]
    )
    return session


def _s3_list_response(keys: list[str]) -> dict:
    """Build a ListObjectsV2 response from a key list."""
    return {
        "Contents": [{"Key": k} for k in keys],
        "IsTruncated": False,
    }


# ── DataClassification model ───────────────────────


class TestDataClassificationModel:
    """Unit tests for the DataClassification model."""

    def test_required_fields(self):
        dc = DataClassification(
            sensitivity="critical",
            data_types=["pii"],
            confidence="high",
            source="tag",
        )
        assert dc.sensitivity == "critical"
        assert dc.data_types == ["pii"]
        assert dc.confidence == "high"
        assert dc.source == "tag"

    def test_unknown_defaults(self):
        dc = DataClassification(
            sensitivity="unknown",
            data_types=[],
            confidence="low",
            source="heuristic",
        )
        assert dc.data_types == []

    def test_multiple_data_types(self):
        dc = DataClassification(
            sensitivity="critical",
            data_types=["pii", "financial"],
            confidence="medium",
            source="heuristic",
        )
        assert "pii" in dc.data_types
        assert "financial" in dc.data_types


# ── S3 Classification ──────────────────────────────


class TestS3Classification:
    """Tests for classify_s3_bucket()."""

    def test_pii_object_keys(self):
        """Bucket with PII-signaling keys → pii, critical."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "customer_data.csv",
                    "users.json",
                    "personal/profiles.parquet",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "my-bucket", {}
        )
        assert "pii" in result.data_types
        assert result.sensitivity == "critical"
        assert result.source == "heuristic"

    def test_financial_object_keys(self):
        """Bucket with financial keys → financial, high."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "invoices/2026-01.pdf",
                    "payment_records.csv",
                    "billing_summary.json",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "finance-bucket", {}
        )
        assert "financial" in result.data_types
        assert result.sensitivity == "high"

    def test_health_object_keys(self):
        """Bucket with health/medical keys → health, critical."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "patient_records/2026/data.json",
                    "hipaa/audit.log",
                    "medical_history.csv",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "health-bucket", {}
        )
        assert "health" in result.data_types
        assert result.sensitivity == "critical"

    def test_credential_object_keys(self):
        """Bucket with credential/secret keys → credentials."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    ".env",
                    "secrets.json",
                    "api_token.txt",
                    "password_list.csv",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "secret-bucket", {}
        )
        assert "credentials" in result.data_types
        assert result.sensitivity == "high"

    def test_log_object_keys(self):
        """Bucket with log/audit keys → logs, low."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "access_logs/2026-03-18.gz",
                    "audit_trail.json",
                    "cloudwatch_events.log",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "logs-bucket", {}
        )
        assert "logs" in result.data_types
        assert result.sensitivity == "low"

    def test_mixed_content_pii_and_logs(self):
        """Mixed PII + logs → highest sensitivity wins."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "user_profiles.csv",
                    "access_logs/app.log",
                    "customer_export.json",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "mixed-bucket", {}
        )
        assert "pii" in result.data_types
        assert "logs" in result.data_types
        # pii → critical beats logs → low
        assert result.sensitivity == "critical"

    def test_empty_bucket_no_objects(self):
        """Empty bucket → unknown, low confidence."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = {
            "IsTruncated": False
        }
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "empty-bucket", {}
        )
        assert result.sensitivity == "unknown"
        assert result.data_types == []
        assert result.confidence == "low"

    def test_tag_based_classification_overrides(self):
        """data-classification tag overrides heuristics."""
        s3 = MagicMock()
        # Keys suggest logs, but tag says pii
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                ["access_logs/app.log"]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "tagged-bucket",
            {"data-classification": "pii"},
        )
        assert "pii" in result.data_types
        assert result.sensitivity == "critical"
        assert result.confidence == "high"
        assert result.source == "tag"

    def test_compliance_tag_hipaa(self):
        """compliance=hipaa tag maps to health data."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response([])
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "hipaa-bucket",
            {"compliance": "hipaa"},
        )
        assert "health" in result.data_types
        assert result.confidence == "high"
        assert result.source == "tag"

    def test_list_objects_access_denied(self):
        """AccessDenied on ListObjectsV2 → graceful fallback."""
        s3 = MagicMock()
        s3.list_objects_v2.side_effect = (
            _make_client_error("AccessDenied")
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        # Must not raise
        result = clf.classify_s3_bucket(
            "restricted-bucket", {}
        )
        assert result.sensitivity == "unknown"
        assert result.data_types == []

    def test_limit_100_passed_to_list_objects(self):
        """MaxKeys=100 must be passed to ListObjectsV2."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response([])
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        clf.classify_s3_bucket("my-bucket", {})
        call_kwargs = (
            s3.list_objects_v2.call_args[1]
        )
        assert call_kwargs.get("MaxKeys") == 100

    def test_unicode_special_chars_in_keys(self):
        """Unicode/emoji object keys must not crash."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "données_clients/résumé.csv",
                    "用户数据/个人信息.json",
                    "emoji_🔑_key.txt",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        # Must not raise
        result = clf.classify_s3_bucket(
            "unicode-bucket", {}
        )
        assert isinstance(result, DataClassification)


# ── Macie Classification ───────────────────────────


class TestMacieClassification:
    """Tests for classify_from_macie()."""

    def test_macie_pii_findings(self):
        """Macie PII findings → pii data type, high conf."""
        macie = MagicMock()
        macie.list_findings.return_value = {
            "findingIds": ["f-001", "f-002"]
        }
        macie.get_findings.return_value = {
            "findings": [
                {
                    "id": "f-001",
                    "type": (
                        "SensitiveData:S3Object/Personal"
                    ),
                    "resourcesAffected": {
                        "s3Bucket": {
                            "name": "my-bucket"
                        }
                    },
                },
                {
                    "id": "f-002",
                    "type": (
                        "SensitiveData:S3Object/Personal"
                    ),
                    "resourcesAffected": {
                        "s3Bucket": {
                            "name": "my-bucket"
                        }
                    },
                },
            ]
        }
        session = _make_session(
            {"macie2": macie}
        )
        clf = DataClassifier(session)
        result = clf.classify_from_macie("my-bucket")
        assert result is not None
        assert "pii" in result.data_types
        assert result.confidence == "high"
        assert result.source == "macie"

    def test_macie_no_findings(self):
        """Macie enabled but no findings → None."""
        macie = MagicMock()
        macie.list_findings.return_value = {
            "findingIds": []
        }
        session = _make_session(
            {"macie2": macie}
        )
        clf = DataClassifier(session)
        result = clf.classify_from_macie("clean-bucket")
        assert result is None

    def test_macie_not_enabled(self):
        """Macie AccessDenied → None (graceful fallback)."""
        macie = MagicMock()
        macie.list_findings.side_effect = (
            _make_client_error("AccessDeniedException")
        )
        session = _make_session(
            {"macie2": macie}
        )
        clf = DataClassifier(session)
        # Must not raise
        result = clf.classify_from_macie("my-bucket")
        assert result is None

    def test_macie_multiple_types(self):
        """Macie returns both PII and financial findings."""
        macie = MagicMock()
        macie.list_findings.return_value = {
            "findingIds": ["f-pii", "f-fin"]
        }
        macie.get_findings.return_value = {
            "findings": [
                {
                    "id": "f-pii",
                    "type": (
                        "SensitiveData:S3Object/Personal"
                    ),
                    "resourcesAffected": {
                        "s3Bucket": {
                            "name": "mixed-bucket"
                        }
                    },
                },
                {
                    "id": "f-fin",
                    "type": (
                        "SensitiveData:S3Object/Financial"
                    ),
                    "resourcesAffected": {
                        "s3Bucket": {
                            "name": "mixed-bucket"
                        }
                    },
                },
            ]
        }
        session = _make_session(
            {"macie2": macie}
        )
        clf = DataClassifier(session)
        result = clf.classify_from_macie("mixed-bucket")
        assert result is not None
        assert "pii" in result.data_types
        assert "financial" in result.data_types
        assert result.sensitivity == "critical"


# ── RDS Classification ─────────────────────────────


class TestRDSClassification:
    """Tests for classify_rds_instance()."""

    def test_customer_in_name(self):
        """RDS with 'customer' in ID → pii signal."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "customer-db", "mysql", {}
        )
        assert "pii" in result.data_types
        assert result.sensitivity == "critical"
        assert result.source == "heuristic"

    def test_financial_tags(self):
        """RDS with compliance=pci tag → financial data."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "payments-db",
            "postgres",
            {"compliance": "pci"},
        )
        assert "financial" in result.data_types
        assert result.sensitivity == "high"
        assert result.confidence == "high"
        assert result.source == "tag"

    def test_no_signals_unknown(self):
        """RDS with no signals → unknown classification."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "app-db", "aurora", {}
        )
        assert result.sensitivity == "unknown"
        assert result.data_types == []
        assert result.confidence == "low"

    def test_health_related_tags(self):
        """RDS with compliance=hipaa tag → health data."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "ehr-database",
            "mysql",
            {"compliance": "hipaa"},
        )
        assert "health" in result.data_types
        assert result.sensitivity == "critical"
        assert result.source == "tag"

    def test_user_in_name(self):
        """RDS with 'user' in name → pii heuristic."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "user-profiles-db", "mysql", {}
        )
        assert "pii" in result.data_types


# ── DynamoDB Classification ────────────────────────


class TestDynamoDBClassification:
    """Tests for classify_dynamodb_table()."""

    def test_pii_field_names_from_scan(self):
        """DynamoDB with email/ssn fields → pii, critical."""
        ddb = MagicMock()
        ddb.scan.return_value = {
            "Items": [
                {
                    "user_id": {"S": "u-001"},
                    "email": {
                        "S": "alice@example.com"
                    },
                    "ssn": {"S": "123-45-6789"},
                    "phone_number": {
                        "S": "555-0100"
                    },
                }
            ]
        }
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        result = clf.classify_dynamodb_table(
            "users-table", {}
        )
        assert "pii" in result.data_types
        assert result.sensitivity == "critical"
        assert result.source == "schema"
        assert result.confidence == "medium"

    def test_financial_field_names_from_scan(self):
        """DynamoDB with account_balance field → financial."""
        ddb = MagicMock()
        ddb.scan.return_value = {
            "Items": [
                {
                    "id": {"S": "txn-001"},
                    "account_balance": {
                        "N": "1000.00"
                    },
                    "transaction_id": {
                        "S": "t-abc"
                    },
                }
            ]
        }
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        result = clf.classify_dynamodb_table(
            "transactions", {}
        )
        assert "financial" in result.data_types
        assert result.sensitivity == "high"

    def test_empty_table_classify_by_name(self):
        """Empty DynamoDB table → classify by table name."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": []}
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        # Table name has pii signal
        result = clf.classify_dynamodb_table(
            "user-data-table", {}
        )
        assert "pii" in result.data_types

    def test_scan_access_denied_fallback(self):
        """Scan AccessDenied → graceful fallback by name."""
        ddb = MagicMock()
        ddb.scan.side_effect = (
            _make_client_error("AccessDenied")
        )
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        # Must not raise; falls back to name-based
        result = clf.classify_dynamodb_table(
            "audit-log-table", {}
        )
        assert isinstance(result, DataClassification)

    def test_scan_limit_1_passed(self):
        """Scan must be called with Limit=1."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": []}
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        clf.classify_dynamodb_table(
            "some-table", {}
        )
        ddb.scan.assert_called_once_with(
            TableName="some-table", Limit=1
        )

    def test_tag_overrides_schema(self):
        """Tag-based classification overrides schema."""
        ddb = MagicMock()
        # Fields suggest logs, but tag says financial
        ddb.scan.return_value = {
            "Items": [
                {
                    "event_id": {"S": "e-001"},
                    "audit_log": {"S": "action"},
                }
            ]
        }
        session = _make_session(
            {"dynamodb": ddb}
        )
        clf = DataClassifier(session)
        result = clf.classify_dynamodb_table(
            "billing-events",
            {"compliance": "pci"},
        )
        assert "financial" in result.data_types
        assert result.source == "tag"
        assert result.confidence == "high"


# ── classify_resource Dispatcher ──────────────────


class TestClassifyResourceDispatcher:
    """Tests for classify_resource() dispatcher."""

    def test_dispatches_s3(self):
        """classify_resource routes S3 to classify_s3_bucket."""
        session = MagicMock()
        clf = DataClassifier(session)
        clf.classify_s3_bucket = MagicMock(
            return_value=DataClassification(
                sensitivity="low",
                data_types=["logs"],
                confidence="medium",
                source="heuristic",
            )
        )
        result = clf.classify_resource(
            "s3_bucket",
            "arn:aws:s3:::my-bucket",
            "my-bucket",
            {},
        )
        clf.classify_s3_bucket.assert_called_once_with(
            "my-bucket", {}, None
        )
        assert result.sensitivity == "low"

    def test_dispatches_rds(self):
        """classify_resource routes RDS to classify_rds."""
        session = MagicMock()
        clf = DataClassifier(session)
        clf.classify_rds_instance = MagicMock(
            return_value=DataClassification(
                sensitivity="high",
                data_types=["financial"],
                confidence="high",
                source="tag",
            )
        )
        result = clf.classify_resource(
            "rds_instance",
            "arn:aws:rds:us-east-1:123:db:mydb",
            "mydb",
            {"compliance": "pci"},
        )
        clf.classify_rds_instance.assert_called_once()
        assert result.sensitivity == "high"

    def test_dispatches_dynamodb(self):
        """classify_resource routes DynamoDB table."""
        session = MagicMock()
        clf = DataClassifier(session)
        clf.classify_dynamodb_table = MagicMock(
            return_value=DataClassification(
                sensitivity="critical",
                data_types=["pii"],
                confidence="medium",
                source="schema",
            )
        )
        result = clf.classify_resource(
            "dynamodb_table",
            "arn:aws:dynamodb:us-east-1:123:table/u",
            "users",
            {},
        )
        clf.classify_dynamodb_table.assert_called_once_with(
            "users", {}
        )
        assert "pii" in result.data_types

    def test_unknown_resource_type_returns_unknown(self):
        """Unknown resource_type → unknown classification."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_resource(
            "kms_key",
            "arn:aws:kms:us-east-1:123:key/k-1",
            "k-1",
            {},
        )
        assert result.sensitivity == "unknown"
        assert result.data_types == []
        assert result.confidence == "low"

    def test_tag_takes_precedence_over_heuristic(self):
        """Tag classification wins regardless of heuristics."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                ["logs/access.log"]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        # Tag says PII, heuristics say logs
        result = clf.classify_resource(
            "s3_bucket",
            "arn:aws:s3:::data-bucket",
            "data-bucket",
            {"data-classification": "pii"},
        )
        assert result.source == "tag"
        assert "pii" in result.data_types
        assert result.sensitivity == "critical"


# ── Edge Cases ─────────────────────────────────────


class TestEdgeCases:
    """Edge cases and resilience tests."""

    def test_all_boto3_calls_fail(self):
        """All AWS calls fail → unknown, no crash."""
        s3 = MagicMock()
        s3.list_objects_v2.side_effect = (
            _make_client_error("InternalError")
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "broken-bucket", {}
        )
        assert result.sensitivity == "unknown"
        assert result.data_types == []

    def test_large_key_list_uses_max_keys_100(self):
        """Even with many keys only MaxKeys=100 is requested."""
        s3 = MagicMock()
        many_keys = [
            f"file_{i}.csv" for i in range(500)
        ]
        s3.list_objects_v2.return_value = (
            _s3_list_response(many_keys[:100])
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        clf.classify_s3_bucket("big-bucket", {})
        call_kwargs = (
            s3.list_objects_v2.call_args[1]
        )
        assert call_kwargs.get("MaxKeys") == 100

    def test_empty_bucket_name_no_crash(self):
        """Empty string bucket name → unknown, no crash."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response([])
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket("", {})
        assert isinstance(result, DataClassification)

    def test_sensitivity_priority_order(self):
        """PII + health both present → critical (not high)."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                [
                    "patient_records.csv",
                    "user_profiles.json",
                    "invoice_data.csv",
                ]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "combo-bucket", {}
        )
        # pii OR health → critical (highest wins)
        assert result.sensitivity == "critical"
        assert len(result.data_types) >= 2

    def test_confidence_tag_is_high(self):
        """Tag-sourced results always get confidence high."""
        session = MagicMock()
        clf = DataClassifier(session)
        result = clf.classify_rds_instance(
            "mydb",
            "mysql",
            {"data-classification": "confidential"},
        )
        assert result.confidence == "high"
        assert result.source == "tag"

    def test_confidence_heuristic_is_medium(self):
        """Name/key heuristics → confidence medium."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                ["customer_export.csv"]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "export-bucket", {}
        )
        assert result.confidence == "medium"

    def test_macie_generic_exception(self):
        """Non-ClientError in Macie → None, no crash."""
        macie = MagicMock()
        macie.list_findings.side_effect = (
            RuntimeError("unexpected failure")
        )
        session = _make_session(
            {"macie2": macie}
        )
        clf = DataClassifier(session)
        result = clf.classify_from_macie("my-bucket")
        assert result is None


# ── Batch 3C: Macie priority (pre-collected data) ──
# Tests for classify_s3_bucket(macie_data=...) and
# threading macie_data through classify_resource().


def _make_macie_data(
    bucket_name: str,
    finding_id: str = "f1",
    finding_type: str = (
        "SensitiveData:S3Object/Personal"
    ),
    severity: str = "High",
) -> MacieData:
    """Build a populated MacieData for tests."""
    finding = MacieFinding(
        finding_id=finding_id,
        type=finding_type,
        bucket_name=bucket_name,
        severity=severity,
        category="CLASSIFICATION",
        count=1,
        first_observed_at="2026-04-09T00:00:00Z",
        region="ap-south-1",
        account_id="832843292195",
    )
    return MacieData(
        enabled=True,
        findings=[finding],
        by_bucket={bucket_name: [finding_id]},
        summary={"total": 1},
    )


class TestClassifyS3WithMacieData:
    """Tests for classify_s3_bucket(macie_data=...)
    — Batch 3C: Macie beats tags beats heuristics."""

    def test_macie_data_pii_beats_tags(self):
        """Macie finding wins over matching tag."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data(
            "my-bucket", finding_type=(
                "SensitiveData:S3Object/Personal"
            )
        )
        # Even with a logs tag, Macie wins
        result = clf.classify_s3_bucket(
            "my-bucket",
            {"data-classification": "logs"},
            macie_data=macie,
        )
        assert result.source == "macie"
        assert "pii" in result.data_types
        assert result.confidence == "high"

    def test_macie_data_financial_type(self):
        """Financial Macie finding → financial data type."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data(
            "fin-bucket",
            finding_type=(
                "SensitiveData:S3Object/Financial"
            ),
        )
        result = clf.classify_s3_bucket(
            "fin-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        assert "financial" in result.data_types
        assert result.sensitivity == "high"

    def test_macie_data_credentials_type(self):
        """Credentials Macie finding → credentials type."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data(
            "creds-bucket",
            finding_type=(
                "SensitiveData:S3Object/Credentials"
            ),
        )
        result = clf.classify_s3_bucket(
            "creds-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        assert "credentials" in result.data_types

    def test_macie_data_beats_heuristic_keys(self):
        """Macie wins over object-key heuristics."""
        s3 = MagicMock()
        # Keys suggest logs
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                ["audit_log/access.log"]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        # But Macie says PII
        macie = _make_macie_data("log-bucket")
        result = clf.classify_s3_bucket(
            "log-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        # S3 key listing should not be called
        s3.list_objects_v2.assert_not_called()

    def test_macie_disabled_falls_back_to_tags(self):
        """macie_data.enabled=False → tag fallback."""
        session = MagicMock()
        clf = DataClassifier(session)
        disabled = MacieData(enabled=False)
        result = clf.classify_s3_bucket(
            "tagged-bucket",
            {"data-classification": "financial"},
            macie_data=disabled,
        )
        assert result.source == "tag"
        assert "financial" in result.data_types

    def test_macie_no_findings_for_bucket_falls_to_tags(
        self,
    ):
        """Macie enabled but bucket not in by_bucket
        → tag fallback."""
        session = MagicMock()
        clf = DataClassifier(session)
        # Macie has findings, but for a different bucket
        macie = _make_macie_data("other-bucket")
        result = clf.classify_s3_bucket(
            "tagged-bucket",
            {"data-classification": "health"},
            macie_data=macie,
        )
        # Falls through to tag
        assert result.source == "tag"
        assert "health" in result.data_types

    def test_macie_none_preserves_existing_behavior(
        self,
    ):
        """macie_data=None (default) → existing tag/
        heuristic flow unchanged."""
        s3 = MagicMock()
        s3.list_objects_v2.return_value = (
            _s3_list_response(
                ["customer_data.csv"]
            )
        )
        session = _make_session({"s3": s3})
        clf = DataClassifier(session)
        result = clf.classify_s3_bucket(
            "heuristic-bucket", {}
        )
        assert result.source == "heuristic"
        assert "pii" in result.data_types

    def test_macie_sensitivity_is_correct(self):
        """Macie PII finding → critical sensitivity."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data("bucket")
        result = clf.classify_s3_bucket(
            "bucket", {}, macie_data=macie
        )
        assert result.sensitivity == "critical"


class TestClassifyResourceMacieThreading:
    """Tests that classify_resource threads macie_data
    through to classify_s3_bucket."""

    def test_classify_resource_passes_macie_data(self):
        """classify_resource passes macie_data kwarg
        to classify_s3_bucket for S3 resources."""
        session = MagicMock()
        clf = DataClassifier(session)
        clf.classify_s3_bucket = MagicMock(
            return_value=DataClassification(
                sensitivity="critical",
                data_types=["pii"],
                confidence="high",
                source="macie",
            )
        )
        macie = _make_macie_data("my-bucket")
        clf.classify_resource(
            "s3_bucket",
            "arn:aws:s3:::my-bucket",
            "my-bucket",
            {},
            macie_data=macie,
        )
        clf.classify_s3_bucket.assert_called_once_with(
            "my-bucket", {}, macie
        )

    def test_classify_resource_no_macie_data_s3(self):
        """classify_resource with no macie_data passes
        None to classify_s3_bucket (backward compat)."""
        session = MagicMock()
        clf = DataClassifier(session)
        clf.classify_s3_bucket = MagicMock(
            return_value=DataClassification(
                sensitivity="unknown",
                data_types=[],
                confidence="low",
                source="heuristic",
            )
        )
        clf.classify_resource(
            "s3_bucket",
            "arn:aws:s3:::my-bucket",
            "my-bucket",
            {},
        )
        clf.classify_s3_bucket.assert_called_once_with(
            "my-bucket", {}, None
        )

    def test_classify_resource_non_s3_ignores_macie(
        self,
    ):
        """Non-S3 resource types ignore macie_data."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data("my-bucket")
        # RDS should not error on macie_data
        result = clf.classify_resource(
            "rds_instance",
            "arn:aws:rds::123:db:mydb",
            "mydb",
            {},
            macie_data=macie,
        )
        assert isinstance(result, DataClassification)


# ── Detection-type-level health classification ─────


def _make_macie_data_with_detections(
    bucket_name: str,
    detection_types: list[str],
    finding_id: str = "f-det",
    finding_type: str = (
        "SensitiveData:S3Object/Personal"
    ),
) -> MacieData:
    """MacieData with specific detection_types set."""
    finding = MacieFinding(
        finding_id=finding_id,
        type=finding_type,
        bucket_name=bucket_name,
        severity="High",
        category="CLASSIFICATION",
        count=1,
        first_observed_at="2026-04-09T00:00:00Z",
        detection_types=detection_types,
    )
    return MacieData(
        enabled=True,
        findings=[finding],
        by_bucket={bucket_name: [finding_id]},
        summary={"total": 1},
    )


class TestMacieDetectionTypeLevelClassification:
    """When MacieFinding.detection_types contains
    medical identifiers, classify_s3_bucket should
    return data_type='health' not 'pii'."""

    def test_medical_record_number_gives_health(self):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "phi-bucket",
            ["MEDICAL_RECORD_NUMBER"],
        )
        result = clf.classify_s3_bucket(
            "phi-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        assert "health" in result.data_types
        assert result.sensitivity == "critical"

    def test_nhs_number_gives_health(self):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "nhs-bucket",
            ["UK_NHS_NUMBER"],
        )
        result = clf.classify_s3_bucket(
            "nhs-bucket", {}, macie_data=macie
        )
        assert "health" in result.data_types

    def test_health_insurance_claim_gives_health(self):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "ins-bucket",
            ["HEALTH_INSURANCE_CLAIM_NUMBER"],
        )
        result = clf.classify_s3_bucket(
            "ins-bucket", {}, macie_data=macie
        )
        assert "health" in result.data_types

    def test_medicare_beneficiary_gives_health(self):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "medicare-bucket",
            ["MEDICARE_BENEFICIARY_NUMBER"],
        )
        result = clf.classify_s3_bucket(
            "medicare-bucket", {}, macie_data=macie
        )
        assert "health" in result.data_types

    def test_mixed_pii_and_medical_includes_both(self):
        """Finding with SSN + medical record → both
        pii and health detected."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "mixed-bucket",
            [
                "US_SOCIAL_SECURITY_NUMBER",
                "MEDICAL_RECORD_NUMBER",
            ],
        )
        result = clf.classify_s3_bucket(
            "mixed-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        assert "health" in result.data_types
        assert result.sensitivity == "critical"

    def test_personal_finding_no_detection_types_stays_pii(
        self,
    ):
        """Backward compat: Personal type with no
        detection_types still gives pii."""
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data(
            "old-bucket",
            finding_type=(
                "SensitiveData:S3Object/Personal"
            ),
        )
        result = clf.classify_s3_bucket(
            "old-bucket", {}, macie_data=macie
        )
        assert result.source == "macie"
        assert "pii" in result.data_types

    def test_ssn_detection_type_gives_pii(self):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "ssn-bucket",
            ["US_SOCIAL_SECURITY_NUMBER"],
        )
        result = clf.classify_s3_bucket(
            "ssn-bucket", {}, macie_data=macie
        )
        assert "pii" in result.data_types

    def test_credit_card_detection_gives_financial(
        self,
    ):
        session = MagicMock()
        clf = DataClassifier(session)
        macie = _make_macie_data_with_detections(
            "cc-bucket",
            ["CREDIT_CARD_NUMBER"],
            finding_type=(
                "SensitiveData:S3Object/Financial"
            ),
        )
        result = clf.classify_s3_bucket(
            "cc-bucket", {}, macie_data=macie
        )
        assert "financial" in result.data_types
