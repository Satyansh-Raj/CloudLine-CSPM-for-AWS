"""Tests for compliance enrichment in the evaluator.

Verifies that violations get compliance mappings
attached post-OPA via the dynamic registry.
"""

import json

import pytest

from app.compliance.mappings import (
    ComplianceMappingRegistry,
)
from app.engine.evaluator import PolicyEvaluator
from app.engine.result_parser import ResultParser
from app.models.violation import (
    ComplianceMapping,
    Violation,
)


# ── ResultParser graceful fallback ────────────────


class TestParserGracefulFallback:
    """Parser must handle missing compliance field."""

    def test_parse_without_compliance(self):
        parser = ResultParser()
        raw = {
            "check_id": "iam_root_mfa",
            "status": "alarm",
            "severity": "critical",
            "reason": "Root MFA not enabled",
            "resource": "arn:aws:iam::123:root",
            "domain": "identity",
            "remediation_id": "REM_01",
            # NO compliance field
        }
        v = parser.parse(raw)
        assert v is not None
        assert v.check_id == "iam_root_mfa"
        assert isinstance(
            v.compliance, ComplianceMapping
        )
        # Should have empty defaults
        assert v.compliance.cis_aws == []

    def test_parse_with_compliance_still_works(self):
        parser = ResultParser()
        raw = {
            "check_id": "iam_root_mfa",
            "status": "alarm",
            "severity": "critical",
            "reason": "Root MFA not enabled",
            "resource": "arn:aws:iam::123:root",
            "domain": "identity",
            "compliance": {
                "cis_aws": ["1.5"],
                "nist_800_53": ["IA-2(1)"],
            },
            "remediation_id": "REM_01",
        }
        v = parser.parse(raw)
        assert v.compliance.cis_aws == ["1.5"]


# ── Enrichment function ──────────────────────────


class TestEnrichCompliance:
    """Test enrich_compliance() utility."""

    @pytest.fixture()
    def registry(self, tmp_path):
        cfg = tmp_path / "mappings.json"
        data = {
            "version": "1.0.0",
            "frameworks": ["cis_aws", "nist_800_53"],
            "mappings": {
                "iam_root_mfa": {
                    "cis_aws": ["1.5"],
                    "nist_800_53": ["IA-2(1)"],
                    "pci_dss": ["8.3.1"],
                    "hipaa": [],
                    "soc2": [],
                    "owasp": [],
                },
                "s3_block_public_acls": {
                    "cis_aws": ["2.1.5"],
                    "nist_800_53": ["AC-3"],
                    "pci_dss": ["1.3.1"],
                    "hipaa": [],
                    "soc2": [],
                    "owasp": [],
                },
            },
        }
        with open(str(cfg), "w") as f:
            json.dump(data, f)
        return ComplianceMappingRegistry(str(cfg))

    def test_enriches_known_check_ids(
        self, registry
    ):
        from app.compliance.mappings import (
            enrich_compliance,
        )

        violations = [
            Violation(
                check_id="iam_root_mfa",
                status="alarm",
                severity="critical",
                reason="test",
                resource="arn:test",
                domain="identity",
            ),
        ]
        enriched = enrich_compliance(
            violations, registry
        )
        assert enriched[0].compliance.cis_aws == [
            "1.5"
        ]
        assert enriched[0].compliance.pci_dss == [
            "8.3.1"
        ]

    def test_unknown_check_id_gets_empty(
        self, registry
    ):
        from app.compliance.mappings import (
            enrich_compliance,
        )

        violations = [
            Violation(
                check_id="unknown_99",
                status="alarm",
                severity="low",
                reason="test",
                resource="arn:test",
                domain="unknown",
            ),
        ]
        enriched = enrich_compliance(
            violations, registry
        )
        assert enriched[0].compliance.cis_aws == []

    def test_preserves_existing_compliance(
        self, registry
    ):
        """If violation already has compliance from
        Rego (backward compat), it gets overwritten
        by the registry."""
        from app.compliance.mappings import (
            enrich_compliance,
        )

        violations = [
            Violation(
                check_id="iam_root_mfa",
                status="alarm",
                severity="critical",
                reason="test",
                resource="arn:test",
                domain="identity",
                compliance=ComplianceMapping(
                    cis_aws=["old_value"],
                ),
            ),
        ]
        enriched = enrich_compliance(
            violations, registry
        )
        # Registry value takes precedence
        assert enriched[0].compliance.cis_aws == [
            "1.5"
        ]

    def test_enriches_multiple_violations(
        self, registry
    ):
        from app.compliance.mappings import (
            enrich_compliance,
        )

        violations = [
            Violation(
                check_id="iam_root_mfa",
                status="alarm",
                severity="critical",
                reason="test1",
                resource="arn:1",
                domain="identity",
            ),
            Violation(
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                reason="test2",
                resource="arn:2",
                domain="data_protection",
            ),
        ]
        enriched = enrich_compliance(
            violations, registry
        )
        assert enriched[0].compliance.cis_aws == [
            "1.5"
        ]
        assert enriched[1].compliance.cis_aws == [
            "2.1.5"
        ]
