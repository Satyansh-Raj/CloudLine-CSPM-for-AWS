"""Cross-feature integration tests — F9 Batch 22.

Validates the full lifecycle of a vulnerable resource
across all major CloudLine subsystems:

    PolicyEvaluator  (OPA mock)
  → ComplianceMappingRegistry  (real JSON config)
  → ResourceClassifier.enrich_with_violations
  → StateManager  (moto DynamoDB)
  → StateManager.update_status  (alarm → ok)
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.compliance.mappings import (
    ComplianceMappingRegistry,
    enrich_compliance,
    get_registry,
)
from app.engine.evaluator import PolicyEvaluator
from app.inventory.classifier import ResourceClassifier
from app.models.resource import ResourceRecord
from app.models.violation import (
    ComplianceMapping,
    Violation,
)
from app.pipeline.models import ViolationState
from app.pipeline.state_manager import StateManager

# ── constants ────────────────────────────────────

ACCOUNT = "832843292195"
REGION = "ap-south-1"
TABLE_NAME = "violation-state"
CONFIG_PATH = str(
    Path(__file__).resolve().parents[2]
    / "config"
    / "check_compliance_mapping.json"
)

# ── DynamoDB table helper ────────────────────────

def _create_violation_table(session):
    """Create the violation-state DynamoDB table."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {
                "AttributeName": "pk",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "sk",
                "KeyType": "RANGE",
            },
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "pk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "sk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "status",
                "AttributeType": "S",
            },
            {
                "AttributeName": "risk_score",
                "AttributeType": "N",
            },
            {
                "AttributeName": "domain",
                "AttributeType": "S",
            },
            {
                "AttributeName": "last_evaluated",
                "AttributeType": "S",
            },
            {
                "AttributeName": "check_id",
                "AttributeType": "S",
            },
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-index",
                "KeySchema": [
                    {
                        "AttributeName": "status",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "risk_score",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
            },
            {
                "IndexName": "domain-index",
                "KeySchema": [
                    {
                        "AttributeName": "domain",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": (
                            "last_evaluated"
                        ),
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
            },
            {
                "IndexName": "check-index",
                "KeySchema": [
                    {
                        "AttributeName": "check_id",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "status",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

# ── OPA mock payloads ───────────────────────────

def _s3_violations_payload():
    """Simulate OPA returning S3 violations."""
    return {
        "data_protection.s3": {
            "violations": [
                {
                    "check_id": "s3_block_public_acls",
                    "status": "alarm",
                    "severity": "high",
                    "reason": (
                        "S3 bucket my-app-data does"
                        " not block public ACLs"
                    ),
                    "resource": (
                        "arn:aws:s3:::my-app-data"
                    ),
                    "domain": "data_protection",
                    "compliance": {},
                    "remediation_id": (
                        "s3_block_public_acls"
                    ),
                },
                {
                    "check_id": "s3_versioning_enabled",
                    "status": "alarm",
                    "severity": "medium",
                    "reason": (
                        "S3 bucket my-app-data does"
                        " not have versioning"
                    ),
                    "resource": (
                        "arn:aws:s3:::my-app-data"
                    ),
                    "domain": "data_protection",
                    "compliance": {},
                    "remediation_id": (
                        "s3_versioning_enabled"
                    ),
                },
            ],
            "compliant": [],
        },
        "network.ec2": {
            "violations": [
                {
                    "check_id": "ec2_no_open_ssh",
                    "status": "alarm",
                    "severity": "critical",
                    "reason": (
                        "Security group sg-abc123"
                        " allows SSH from 0.0.0.0/0"
                    ),
                    "resource": (
                        "arn:aws:ec2:ap-south-1:"
                        f"{ACCOUNT}:security-group"
                        "/sg-abc123"
                    ),
                    "domain": "network",
                    "compliance": {},
                    "remediation_id": (
                        "ec2_no_open_ssh"
                    ),
                },
            ],
            "compliant": [],
        },
    }

# ── resource factory ─────────────────────────────

def _make_resource(
    resource_id,
    name,
    resource_type,
    service,
    tags=None,
):
    """Build a ResourceRecord for testing."""
    return ResourceRecord(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{resource_type}#{resource_id}",
        resource_id=resource_id,
        resource_name=name,
        resource_type=resource_type,
        technology_category="storage",
        service=service,
        region=REGION,
        account_id=ACCOUNT,
        last_seen=datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        tags=tags or {},
    )

# ── ViolationState factory ───────────────────────

def _violation_to_state(v: Violation):
    """Convert an evaluator Violation to a
    ViolationState for DynamoDB persistence."""
    now = (
        datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{v.check_id}#{v.resource}",
        check_id=v.check_id,
        status=v.status,
        severity=v.severity,
        domain=v.domain,
        resource_arn=v.resource,
        reason=v.reason,
        compliance=v.compliance.model_dump(),
        remediation_id=v.remediation_id,
        first_detected=now,
        last_evaluated=now,
    )

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test class: Full Vulnerable Resource Lifecycle
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestVulnerableResourceLifecycle:
    """End-to-end: OPA → Compliance → DynamoDB →
    SecurityGraph → Resolution."""

    @pytest.fixture(autouse=True)
    def setup(self, aws_credentials):
        """Set up moto DynamoDB and mock OPA."""
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_violation_table(session)
            self.state_mgr = StateManager(
                session, TABLE_NAME
            )
            self.session = session
            yield

    # ── Phase 1: PolicyEvaluator + Compliance ────

    def test_evaluator_returns_violations_with_compliance(
        self,
    ):
        """PolicyEvaluator parses OPA output and
        enriches with compliance mappings."""
        opa = MagicMock()
        opa.evaluate_all.return_value = (
            _s3_violations_payload()
        )

        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})

        assert len(results) == 3

        # All violations should be alarm status
        alarm = [
            r for r in results if r.status == "alarm"
        ]
        assert len(alarm) == 3

        # Verify check_ids
        ids = {r.check_id for r in results}
        assert "s3_block_public_acls" in ids
        assert "s3_versioning_enabled" in ids
        assert "ec2_no_open_ssh" in ids

    def test_compliance_enrichment_attaches_frameworks(
        self,
    ):
        """enrich_compliance populates CIS/NIST/PCI
        from the JSON config."""
        opa = MagicMock()
        opa.evaluate_all.return_value = (
            _s3_violations_payload()
        )

        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})

        # Find the s3_block_public_acls violation
        s3_pub = next(
            r
            for r in results
            if r.check_id == "s3_block_public_acls"
        )

        # Should have CIS and NIST controls
        assert len(s3_pub.compliance.cis_aws) > 0
        assert len(s3_pub.compliance.nist_800_53) > 0

    def test_compliance_registry_loads_all_mappings(
        self,
    ):
        """Registry loads every check_id from JSON."""
        registry = ComplianceMappingRegistry(
            CONFIG_PATH
        )
        mapping = registry.get("s3_block_public_acls")
        assert mapping is not None
        assert "2.1.5" in mapping.cis_aws
        assert "AC-3" in mapping.nist_800_53

    def test_compliance_enrichment_idempotent(self):
        """Enriching twice gives the same result."""
        violations = [
            Violation(
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                resource="arn:aws:s3:::bucket",
                domain="data_protection",
            )
        ]
        enrich_compliance(violations)
        first = violations[0].compliance.cis_aws[:]

        enrich_compliance(violations)
        second = violations[0].compliance.cis_aws[:]

        assert first == second

    # ── Phase 2: DynamoDB State Persistence ──────

    def test_violation_persists_to_dynamodb(self):
        """Violations written via StateManager are
        readable with correct fields."""
        opa = MagicMock()
        opa.evaluate_all.return_value = (
            _s3_violations_payload()
        )

        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})

        # Persist all alarm violations
        for v in results:
            if v.status == "alarm":
                state = _violation_to_state(v)
                ok = self.state_mgr.put_state(state)
                assert ok is True

        # Read back the critical one
        rec = self.state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            (
                f"arn:aws:ec2:ap-south-1:{ACCOUNT}"
                ":security-group/sg-abc123"
            ),
        )
        assert rec is not None
        assert rec.status == "alarm"
        assert rec.severity == "critical"
        assert rec.domain == "network"
        assert rec.resolved_at is None

    def test_compliance_tags_survive_roundtrip(self):
        """Compliance dict survives DynamoDB
        serialization/deserialization."""
        violations = [
            Violation(
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                resource="arn:aws:s3:::bucket",
                domain="data_protection",
            )
        ]
        enrich_compliance(violations)
        state = _violation_to_state(violations[0])
        self.state_mgr.put_state(state)

        rec = self.state_mgr.get_state(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            "arn:aws:s3:::bucket",
        )
        assert rec is not None
        assert "cis_aws" in rec.compliance
        assert "2.1.5" in rec.compliance["cis_aws"]

    # ── Phase 3: ResourceClassifier Enrichment ───

    def test_resource_classifier_computes_risk_score(
        self,
    ):
        """enrich_with_violations sets violation_count
        and risk_score from severity weights."""
        resources = [
            _make_resource(
                "arn:aws:s3:::my-app-data",
                "my-app-data",
                "s3_bucket",
                "s3",
            ),
        ]

        violations = [
            Violation(
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                resource="arn:aws:s3:::my-app-data",
                domain="data_protection",
            ),
            Violation(
                check_id="s3_versioning_enabled",
                status="alarm",
                severity="medium",
                resource="arn:aws:s3:::my-app-data",
                domain="data_protection",
            ),
        ]

        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )

        r = resources[0]
        assert r.violation_count == 2
        assert r.high_violations == 1
        # high=15, medium=8 → risk_score=23
        assert r.risk_score == 23

    def test_risk_score_caps_at_100(self):
        """Multiple critical violations cap at 100."""
        resources = [
            _make_resource(
                "arn:aws:ec2:ap-south-1:123:i/i-1",
                "web-server",
                "ec2_instance",
                "ec2",
            ),
        ]

        violations = [
            Violation(
                check_id=f"check_{i}",
                status="alarm",
                severity="critical",
                resource=(
                    "arn:aws:ec2:ap-south-1:123"
                    ":i/i-1"
                ),
                domain="network",
            )
            for i in range(6)
        ]  # 6 × 25 = 150 → capped 100

        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )

        assert resources[0].risk_score == 100
        assert resources[0].critical_violations == 6

    def test_ok_violations_ignored_in_enrichment(self):
        """Only alarm-status violations are counted."""
        resources = [
            _make_resource(
                "arn:aws:s3:::clean-bucket",
                "clean-bucket",
                "s3_bucket",
                "s3",
            ),
        ]

        violations = [
            Violation(
                check_id="s3_versioning_enabled",
                status="ok",
                severity="medium",
                resource="arn:aws:s3:::clean-bucket",
                domain="data_protection",
            ),
        ]

        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )

        assert resources[0].violation_count == 0
        assert resources[0].risk_score == 0

    def test_violations_in_different_regions(self):
        """Violations in us-east-1 and ap-south-1
        are stored under separate partition keys."""
        for region in ("us-east-1", "ap-south-1"):
            state = ViolationState(
                pk=f"{ACCOUNT}#{region}",
                sk=(
                    "s3_block_public_acls"
                    "#arn:aws:s3:::bkt"
                ),
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                domain="data_protection",
                resource_arn="arn:aws:s3:::bkt",
                last_evaluated=(
                    "2026-03-20T10:00:00Z"
                ),
                first_detected=(
                    "2026-03-20T10:00:00Z"
                ),
            )
            self.state_mgr.put_state(state)

        r1 = self.state_mgr.get_state(
            ACCOUNT,
            "us-east-1",
            "s3_block_public_acls",
            "arn:aws:s3:::bkt",
        )
        r2 = self.state_mgr.get_state(
            ACCOUNT,
            "ap-south-1",
            "s3_block_public_acls",
            "arn:aws:s3:::bkt",
        )
        assert r1 is not None
        assert r2 is not None
        assert r1.pk != r2.pk

    def test_multiple_frameworks_enriched(self):
        """Check IDs that map to multiple frameworks
        get all controls attached."""
        violations = [
            Violation(
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                resource="arn:aws:s3:::fw-bucket",
                domain="data_protection",
            ),
        ]
        enrich_compliance(violations)

        c = violations[0].compliance
        # s3_block_public_acls maps to CIS + NIST +
        # PCI
        assert len(c.cis_aws) >= 1
        assert len(c.nist_800_53) >= 1
        assert len(c.pci_dss) >= 1

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test class: State Regression Tracking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestStateRegressionTracking:
    """Verify alarm → ok → alarm (regression) is
    tracked correctly."""

    @pytest.fixture(autouse=True)
    def setup(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_violation_table(session)
            self.state_mgr = StateManager(
                session, TABLE_NAME
            )
            yield

    def test_alarm_ok_alarm_cycle(self):
        """Transitioning alarm→ok→alarm preserves
        previous_status at each step."""
        arn = "arn:aws:ec2:us-east-1:123:sg/sg-reg"
        state = ViolationState(
            pk=f"{ACCOUNT}#us-east-1",
            sk=f"ec2_no_open_ssh#{arn}",
            check_id="ec2_no_open_ssh",
            status="alarm",
            severity="critical",
            domain="network",
            resource_arn=arn,
            last_evaluated="2026-03-20T10:00:00Z",
            first_detected="2026-03-20T10:00:00Z",
        )
        self.state_mgr.put_state(state)

        # alarm → ok
        self.state_mgr.update_status(
            ACCOUNT,
            "us-east-1",
            "ec2_no_open_ssh",
            arn,
            new_status="ok",
            reason="Fixed",
        )
        rec = self.state_mgr.get_state(
            ACCOUNT,
            "us-east-1",
            "ec2_no_open_ssh",
            arn,
        )
        assert rec.status == "ok"
        assert rec.previous_status == "alarm"
        assert rec.resolved_at is not None

        # ok → alarm (regression)
        self.state_mgr.update_status(
            ACCOUNT,
            "us-east-1",
            "ec2_no_open_ssh",
            arn,
            new_status="alarm",
            reason="Reconfigured insecurely",
        )
        rec = self.state_mgr.get_state(
            ACCOUNT,
            "us-east-1",
            "ec2_no_open_ssh",
            arn,
        )
        assert rec.status == "alarm"
        assert rec.previous_status == "ok"

    def test_multiple_violations_independent(self):
        """Each violation state is updated
        independently."""
        arns = [
            "arn:aws:s3:::bucket-a",
            "arn:aws:s3:::bucket-b",
        ]
        for arn in arns:
            state = ViolationState(
                pk=f"{ACCOUNT}#{REGION}",
                sk=f"s3_block_public_acls#{arn}",
                check_id="s3_block_public_acls",
                status="alarm",
                severity="high",
                domain="data_protection",
                resource_arn=arn,
                last_evaluated=(
                    "2026-03-20T10:00:00Z"
                ),
                first_detected=(
                    "2026-03-20T10:00:00Z"
                ),
            )
            self.state_mgr.put_state(state)

        # Resolve only bucket-a
        self.state_mgr.update_status(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            arns[0],
            new_status="ok",
            reason="Fixed",
        )

        a = self.state_mgr.get_state(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            arns[0],
        )
        b = self.state_mgr.get_state(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            arns[1],
        )
        assert a.status == "ok"
        assert b.status == "alarm"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test class: Edge Cases
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCrossFeatureEdgeCases:
    """Boundary conditions across feature
    boundaries."""

    @pytest.fixture(autouse=True)
    def setup(self, aws_credentials):
        with mock_aws():
            session = boto3.Session(
                region_name="us-east-1"
            )
            _create_violation_table(session)
            self.state_mgr = StateManager(
                session, TABLE_NAME
            )
            yield

    def test_evaluator_handles_empty_opa_response(
        self,
    ):
        """Empty OPA response → empty results list."""
        opa = MagicMock()
        opa.evaluate_all.return_value = {}

        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})
        assert results == []

    def test_classifier_no_mutations_on_no_alarms(
        self,
    ):
        """When all violations are ok, resources
        stay at zero counts."""
        resources = [
            _make_resource(
                "arn:aws:s3:::ok-bucket",
                "ok-bucket",
                "s3_bucket",
                "s3",
            ),
        ]
        violations = [
            Violation(
                check_id="s3_block_public_acls",
                status="ok",
                severity="high",
                resource="arn:aws:s3:::ok-bucket",
                domain="data_protection",
            ),
        ]
        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )
        assert resources[0].violation_count == 0
        assert resources[0].risk_score == 0

    def test_unknown_check_id_compliance_graceful(
        self,
    ):
        """Unknown check_id doesn't crash compliance
        enrichment."""
        violations = [
            Violation(
                check_id="nonexistent_check_xyz",
                status="alarm",
                severity="low",
                resource="arn:aws:s3:::bkt",
                domain="misc",
            ),
        ]
        enrich_compliance(violations)
        # Should still have empty compliance
        c = violations[0].compliance
        assert isinstance(c.cis_aws, list)

    def test_evaluator_mixed_alarm_and_ok(self):
        """Evaluator returns both alarm and ok status
        results from OPA."""
        opa = MagicMock()
        opa.evaluate_all.return_value = {
            "data_protection.s3": {
                "violations": [
                    {
                        "check_id": (
                            "s3_block_public_acls"
                        ),
                        "status": "alarm",
                        "severity": "high",
                        "reason": "No block",
                        "resource": (
                            "arn:aws:s3:::bkt"
                        ),
                        "domain": "data_protection",
                        "compliance": {},
                        "remediation_id": (
                            "s3_block_public_acls"
                        ),
                    },
                ],
                "compliant": [
                    {
                        "check_id": (
                            "s3_versioning_enabled"
                        ),
                        "status": "ok",
                        "severity": "medium",
                        "reason": "Enabled",
                        "resource": (
                            "arn:aws:s3:::bkt"
                        ),
                        "domain": "data_protection",
                        "compliance": {},
                        "remediation_id": (
                            "s3_versioning_enabled"
                        ),
                    },
                ],
            }
        }
        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})
        assert len(results) == 2
        statuses = {r.status for r in results}
        assert "alarm" in statuses
        assert "ok" in statuses

    def test_risk_score_medium_only(self):
        """Medium-only violations compute correct
        risk score."""
        resources = [
            _make_resource(
                "arn:aws:s3:::med-bkt",
                "med-bkt",
                "s3_bucket",
                "s3",
            ),
        ]
        violations = [
            Violation(
                check_id=f"med_{i}",
                status="alarm",
                severity="medium",
                resource="arn:aws:s3:::med-bkt",
                domain="data_protection",
            )
            for i in range(3)
        ]
        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )
        # 3 × 8 = 24
        assert resources[0].risk_score == 24
        assert resources[0].violation_count == 3

    def test_state_manager_put_and_update_roundtrip(
        self,
    ):
        """Full DynamoDB put → update → get cycle."""
        arn = "arn:aws:s3:::roundtrip-bkt"
        state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk=f"s3_block_public_acls#{arn}",
            check_id="s3_block_public_acls",
            status="alarm",
            severity="high",
            domain="data_protection",
            resource_arn=arn,
            last_evaluated="2026-03-20T10:00:00Z",
            first_detected="2026-03-20T10:00:00Z",
        )
        self.state_mgr.put_state(state)

        self.state_mgr.update_status(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            arn,
            new_status="ok",
            reason="Blocked",
            risk_score=0,
        )

        rec = self.state_mgr.get_state(
            ACCOUNT,
            REGION,
            "s3_block_public_acls",
            arn,
        )
        assert rec.status == "ok"
        assert rec.risk_score == 0
        assert rec.resolved_at is not None
        assert rec.previous_status == "alarm"

    def test_compliance_all_six_frameworks(self):
        """Registry returns all 6 framework fields
        for each mapping."""
        registry = ComplianceMappingRegistry(
            CONFIG_PATH
        )
        mapping = registry.get("s3_block_public_acls")
        # All framework fields should exist
        assert hasattr(mapping, "cis_aws")
        assert hasattr(mapping, "nist_800_53")
        assert hasattr(mapping, "pci_dss")
        assert hasattr(mapping, "hipaa")
        assert hasattr(mapping, "soc2")
        assert hasattr(mapping, "owasp")

    def test_evaluator_compliance_not_lost_on_parse(
        self,
    ):
        """Even if OPA returns compliance data in
        the raw result, the post-enrichment from
        JSON config takes precedence."""
        opa = MagicMock()
        opa.evaluate_all.return_value = {
            "data_protection.s3": {
                "violations": [
                    {
                        "check_id": (
                            "s3_block_public_acls"
                        ),
                        "status": "alarm",
                        "severity": "high",
                        "reason": "No block",
                        "resource": (
                            "arn:aws:s3:::bkt"
                        ),
                        "domain": "data_protection",
                        "compliance": {
                            "cis_aws": ["old_1.1"],
                        },
                        "remediation_id": (
                            "s3_block_public_acls"
                        ),
                    },
                ],
                "compliant": [],
            }
        }
        evaluator = PolicyEvaluator(opa)
        results = evaluator.evaluate_all({})
        v = results[0]
        # JSON config enrichment should override
        # the Rego-embedded "old_1.1"
        assert "2.1.5" in v.compliance.cis_aws

    def test_resource_record_defaults(self):
        """ResourceRecord defaults are correct for
        new resources."""
        r = _make_resource(
            "arn:aws:s3:::defaults",
            "defaults",
            "s3_bucket",
            "s3",
        )
        assert r.violation_count == 0
        assert r.risk_score == 0
        assert r.critical_violations == 0
        assert r.high_violations == 0
        assert r.is_active is True
        assert r.exposure == "unknown"

    def test_violation_state_defaults(self):
        """ViolationState defaults are correct."""
        state = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="check#arn",
            check_id="check",
        )
        assert state.status == "ok"
        assert state.previous_status == ""
        assert state.risk_score == 0
        assert state.resolved_at is None
        assert state.ticket_id is None

    def test_classifier_low_severity_weight(self):
        """Low-severity violations add 3 to risk."""
        resources = [
            _make_resource(
                "arn:aws:s3:::low-bkt",
                "low-bkt",
                "s3_bucket",
                "s3",
            ),
        ]
        violations = [
            Violation(
                check_id="low_check",
                status="alarm",
                severity="low",
                resource="arn:aws:s3:::low-bkt",
                domain="data_protection",
            ),
        ]
        classifier = ResourceClassifier(
            ACCOUNT, REGION
        )
        classifier.enrich_with_violations(
            resources, violations
        )
        assert resources[0].risk_score == 3
        assert resources[0].violation_count == 1
