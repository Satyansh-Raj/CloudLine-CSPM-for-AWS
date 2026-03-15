"""Tests for policy evaluator."""

from unittest.mock import MagicMock

from app.engine.evaluator import PolicyEvaluator
from app.engine.opa_cli import OPACLIClient
from app.models.violation import Violation


class TestPolicyEvaluator:
    def setup_method(self):
        self.mock_opa = MagicMock(spec=OPACLIClient)
        self.evaluator = PolicyEvaluator(
            opa_client=self.mock_opa
        )

    def test_evaluate_all_violations(self):
        """Test evaluate_all returns violations."""
        self.mock_opa.evaluate_all.return_value = {
            "iam": {
                "violations": [{
                    "check_id": "iam_01",
                    "status": "alarm",
                    "severity": "critical",
                    "reason": "Root MFA off",
                    "resource": "arn:root",
                    "domain": "identity",
                    "compliance": {},
                    "remediation_id": "REM_01",
                }],
                "compliant": [],
            }
        }
        results = self.evaluator.evaluate_all({})
        assert len(results) == 1
        assert results[0].check_id == "iam_01"
        assert results[0].status == "alarm"

    def test_evaluate_all_mixed(self):
        """Test with both violations and compliant."""
        self.mock_opa.evaluate_all.return_value = {
            "iam": {
                "violations": [{
                    "check_id": "iam_01",
                    "status": "alarm",
                    "severity": "critical",
                    "reason": "bad",
                    "resource": "arn:1",
                    "domain": "identity",
                    "compliance": {},
                }],
                "compliant": [{
                    "check_id": "iam_02",
                    "status": "ok",
                    "severity": "high",
                    "reason": "good",
                    "resource": "arn:2",
                    "domain": "identity",
                    "compliance": {},
                }],
            }
        }
        results = self.evaluator.evaluate_all({})
        assert len(results) == 2
        statuses = {r.status for r in results}
        assert statuses == {"alarm", "ok"}

    def test_evaluate_all_empty(self):
        """Test evaluate_all with empty results."""
        self.mock_opa.evaluate_all.return_value = {}
        results = self.evaluator.evaluate_all({})
        assert results == []

    def test_evaluate_all_skips_invalid(self):
        """Test that invalid results are skipped."""
        self.mock_opa.evaluate_all.return_value = {
            "iam": {
                "violations": [
                    {"status": "alarm"},
                ],
                "compliant": [],
            }
        }
        results = self.evaluator.evaluate_all({})
        assert len(results) == 0

    def test_evaluate_check(self):
        """Test single check evaluation."""
        self.mock_opa.evaluate.return_value = [{
            "check_id": "s3_01",
            "status": "alarm",
            "severity": "critical",
            "reason": "S3 public",
            "resource": "arn:s3",
            "domain": "data_protection",
            "compliance": {},
        }]
        results = self.evaluator.evaluate_check(
            {}, "data_protection.s3"
        )
        assert len(results) == 1
        assert results[0].check_id == "s3_01"

    def test_evaluate_check_empty(self):
        """Test single check with no results."""
        self.mock_opa.evaluate.return_value = []
        results = self.evaluator.evaluate_check(
            {}, "identity.iam"
        )
        assert results == []


class TestComplianceScore:
    def setup_method(self):
        self.mock_opa = MagicMock(spec=OPACLIClient)
        self.evaluator = PolicyEvaluator(
            opa_client=self.mock_opa
        )

    def test_score_all_passed(self):
        """Test 100% compliance score."""
        violations = [
            Violation(
                check_id="C01",
                status="ok",
                severity="critical",
                domain="identity",
            ),
            Violation(
                check_id="C02",
                status="ok",
                severity="high",
                domain="network",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.total_checks == 2
        assert score.passed == 2
        assert score.failed == 0
        assert score.score_percent == 100.0

    def test_score_mixed(self):
        """Test partial compliance score."""
        violations = [
            Violation(
                check_id="C01",
                status="alarm",
                severity="critical",
                domain="identity",
            ),
            Violation(
                check_id="C02",
                status="ok",
                severity="high",
                domain="identity",
            ),
            Violation(
                check_id="C03",
                status="ok",
                severity="medium",
                domain="network",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.total_checks == 3
        assert score.passed == 2
        assert score.failed == 1
        assert score.score_percent == 66.7

    def test_score_all_failed(self):
        """Test 0% compliance score."""
        violations = [
            Violation(
                check_id="C01",
                status="alarm",
                severity="critical",
                domain="identity",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.score_percent == 0.0
        assert score.failed == 1

    def test_score_empty(self):
        """Test empty input."""
        score = self.evaluator.compute_compliance_score(
            []
        )
        assert score.total_checks == 0
        assert score.score_percent == 0.0

    def test_score_by_domain(self):
        """Test domain breakdown."""
        violations = [
            Violation(
                check_id="C01",
                status="alarm",
                severity="high",
                domain="identity",
            ),
            Violation(
                check_id="C02",
                status="ok",
                severity="high",
                domain="identity",
            ),
            Violation(
                check_id="C03",
                status="alarm",
                severity="medium",
                domain="network",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.by_domain["identity"] == {
            "passed": 1,
            "failed": 1,
        }
        assert score.by_domain["network"] == {
            "passed": 0,
            "failed": 1,
        }

    def test_score_by_severity(self):
        """Test severity breakdown."""
        violations = [
            Violation(
                check_id="C01",
                status="alarm",
                severity="critical",
                domain="identity",
            ),
            Violation(
                check_id="C02",
                status="alarm",
                severity="high",
                domain="network",
            ),
            Violation(
                check_id="C03",
                status="alarm",
                severity="critical",
                domain="data_protection",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.by_severity["critical"] == 2
        assert score.by_severity["high"] == 1

    def test_score_with_errors_and_skips(self):
        """Test errors and skips are counted."""
        violations = [
            Violation(
                check_id="C01",
                status="ok",
                domain="identity",
            ),
            Violation(
                check_id="C02",
                status="error",
                domain="identity",
            ),
            Violation(
                check_id="C03",
                status="skip",
                domain="network",
            ),
        ]
        score = self.evaluator.compute_compliance_score(
            violations
        )
        assert score.errors == 1
        assert score.skipped == 1
        assert score.total_checks == 1
