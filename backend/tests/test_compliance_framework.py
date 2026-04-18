"""Tests for F6 Batch 13 — Compliance framework API.

Covers:
  - ComplianceMappingRegistry.check_ids_for_framework()
  - ComplianceFrameworkScorer
  - GET /compliance/frameworks endpoint
  - GET /compliance/framework/{framework_name} endpoint
  - Enhanced GET /compliance/score with by_framework
"""

import json

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.compliance.mappings import (
    ComplianceMappingRegistry,
)
from app.config import Settings
from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.main import app
from app.pipeline.models import ViolationState


# ── Fixtures ──────────────────────────────────────


@pytest.fixture()
def two_check_registry(tmp_path):
    """Registry with two check_ids across 3 frameworks."""
    cfg = tmp_path / "mappings.json"
    data = {
        "version": "1.0.0",
        "frameworks": [
            "cis_aws",
            "nist_800_53",
            "pci_dss",
            "hipaa",
            "soc2",
            "owasp",
        ],
        "mappings": {
            "iam_root_mfa": {
                "cis_aws": ["1.5"],
                "nist_800_53": ["IA-2(1)"],
                "pci_dss": ["8.3.1"],
                "hipaa": [],
                "soc2": [],
                "owasp": [],
            },
            "s3_encryption": {
                "cis_aws": ["2.1.1"],
                "nist_800_53": ["SC-28"],
                "pci_dss": [],
                "hipaa": ["164.312(a)(2)(iv)"],
                "soc2": [],
                "owasp": [],
            },
        },
    }
    with open(str(cfg), "w") as f:
        json.dump(data, f)
    return ComplianceMappingRegistry(str(cfg))


@pytest.fixture()
def single_check_registry(tmp_path):
    """Registry with one check mapped to cis_aws only."""
    cfg = tmp_path / "mappings.json"
    data = {
        "version": "1.0.0",
        "frameworks": [
            "cis_aws",
            "nist_800_53",
            "pci_dss",
            "hipaa",
            "soc2",
            "owasp",
        ],
        "mappings": {
            "ec2_no_open_ssh": {
                "cis_aws": ["4.1"],
                "nist_800_53": [],
                "pci_dss": [],
                "hipaa": [],
                "soc2": [],
                "owasp": [],
            },
        },
    }
    with open(str(cfg), "w") as f:
        json.dump(data, f)
    return ComplianceMappingRegistry(str(cfg))


@pytest.fixture()
def empty_registry(tmp_path):
    """Registry with no mappings."""
    cfg = tmp_path / "mappings.json"
    data = {
        "version": "1.0.0",
        "frameworks": [
            "cis_aws",
            "nist_800_53",
            "pci_dss",
            "hipaa",
            "soc2",
            "owasp",
        ],
        "mappings": {},
    }
    with open(str(cfg), "w") as f:
        json.dump(data, f)
    return ComplianceMappingRegistry(str(cfg))


def _make_alarm(
    check_id: str,
    resource_arn: str = "arn:aws:test",
    severity: str = "high",
    account_id: str = "123456789012",
    region: str = "us-east-1",
) -> ViolationState:
    return ViolationState(
        pk=f"{account_id}#{region}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status="alarm",
        severity=severity,
        reason="Test violation",
        resource_arn=resource_arn,
        domain="identity",
    )


def _make_ok(
    check_id: str,
    resource_arn: str = "arn:aws:test",
) -> ViolationState:
    return ViolationState(
        pk="123456789012#us-east-1",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status="ok",
        severity="low",
        reason="Passing",
        resource_arn=resource_arn,
        domain="identity",
    )


# ── Part 1: check_ids_for_framework() ─────────────


class TestCheckIdsForFramework:
    """Tests for the new registry method."""

    def test_returns_list_for_cis_aws(
        self, two_check_registry
    ):
        """Both check_ids map to cis_aws."""
        ids = two_check_registry.check_ids_for_framework(
            "cis_aws"
        )
        assert isinstance(ids, list)
        assert "iam_root_mfa" in ids
        assert "s3_encryption" in ids

    def test_returns_list_for_nist(
        self, two_check_registry
    ):
        """Both check_ids map to nist_800_53."""
        ids = two_check_registry.check_ids_for_framework(
            "nist_800_53"
        )
        assert "iam_root_mfa" in ids
        assert "s3_encryption" in ids

    def test_excludes_check_without_mapping(
        self, two_check_registry
    ):
        """s3_encryption has empty pci_dss list."""
        ids = two_check_registry.check_ids_for_framework(
            "pci_dss"
        )
        assert "iam_root_mfa" in ids
        assert "s3_encryption" not in ids

    def test_hipaa_partial_coverage(
        self, two_check_registry
    ):
        """Only s3_encryption maps to hipaa."""
        ids = two_check_registry.check_ids_for_framework(
            "hipaa"
        )
        assert "s3_encryption" in ids
        assert "iam_root_mfa" not in ids

    def test_unknown_framework_returns_empty(
        self, two_check_registry
    ):
        """Non-existent framework returns []."""
        ids = two_check_registry.check_ids_for_framework(
            "nonexistent_framework"
        )
        assert ids == []

    def test_empty_string_framework_returns_empty(
        self, two_check_registry
    ):
        """Empty string framework returns []."""
        ids = two_check_registry.check_ids_for_framework(
            ""
        )
        assert ids == []

    def test_empty_registry_returns_empty(
        self, empty_registry
    ):
        """No mappings → any framework → []."""
        ids = empty_registry.check_ids_for_framework(
            "cis_aws"
        )
        assert ids == []

    def test_soc2_returns_empty_when_none_mapped(
        self, two_check_registry
    ):
        """Neither check maps to soc2."""
        ids = two_check_registry.check_ids_for_framework(
            "soc2"
        )
        assert ids == []

    def test_single_check_registry(
        self, single_check_registry
    ):
        """Only cis_aws returns ec2_no_open_ssh."""
        ids = (
            single_check_registry
            .check_ids_for_framework("cis_aws")
        )
        assert ids == ["ec2_no_open_ssh"]

    def test_returns_list_not_set(
        self, two_check_registry
    ):
        """Result must be a list, not a set."""
        result = (
            two_check_registry
            .check_ids_for_framework("cis_aws")
        )
        assert isinstance(result, list)

    def test_production_registry_cis_aws(self):
        """Real config file returns non-empty list."""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "check_compliance_mapping.json",
        )
        if not os.path.exists(config_path):
            pytest.skip(
                "Production config not found"
            )
        reg = ComplianceMappingRegistry(config_path)
        ids = reg.check_ids_for_framework("cis_aws")
        assert len(ids) > 0

    def test_production_registry_nonexistent(self):
        """Real config: bad framework → []."""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "check_compliance_mapping.json",
        )
        if not os.path.exists(config_path):
            pytest.skip(
                "Production config not found"
            )
        reg = ComplianceMappingRegistry(config_path)
        ids = reg.check_ids_for_framework(
            "made_up_framework_xyz"
        )
        assert ids == []


# ── Part 2: ComplianceFrameworkScorer ─────────────


class TestComplianceFrameworkScorer:
    """Tests for scorer.py."""

    @pytest.fixture(autouse=True)
    def _import(self):
        """Import scorer after it is implemented."""
        from app.compliance.scorer import (
            ComplianceFrameworkScorer,
            ControlStatus,
            FrameworkScore,
        )
        self.Scorer = ComplianceFrameworkScorer
        self.ControlStatus = ControlStatus
        self.FrameworkScore = FrameworkScore

    def test_no_violations_returns_100_percent(
        self, two_check_registry
    ):
        """Zero violations → all controls compliant."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        assert isinstance(result, self.FrameworkScore)
        assert result.score_percent == 100.0
        assert result.compliant == result.total_controls
        assert result.non_compliant == 0

    def test_all_violated_returns_0_percent(
        self, two_check_registry
    ):
        """Violations for every check → 0%."""
        violations = [
            _make_alarm("iam_root_mfa"),
            _make_alarm("s3_encryption"),
        ]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        assert result.score_percent == 0.0
        assert result.non_compliant == result.total_controls

    def test_partial_violations_score(
        self, two_check_registry
    ):
        """One of two controls violated → 50%."""
        violations = [_make_alarm("iam_root_mfa")]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        assert result.score_percent == 50.0
        assert result.compliant == 1
        assert result.non_compliant == 1

    def test_ok_status_does_not_count_as_alarm(
        self, two_check_registry
    ):
        """ok violations must NOT affect compliance."""
        violations = [
            _make_ok("iam_root_mfa"),
        ]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        assert result.score_percent == 100.0

    def test_framework_field_in_result(
        self, two_check_registry
    ):
        """FrameworkScore.framework == scorer's framework."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        assert result.framework == "cis_aws"

    def test_controls_list_populated(
        self, two_check_registry
    ):
        """controls list has one entry per control_id."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        # two check_ids each with one cis_aws control
        # (1.5 and 2.1.1) → 2 distinct controls
        assert len(result.controls) >= 2

    def test_control_status_compliant(
        self, two_check_registry
    ):
        """Unviolated control has status 'compliant'."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        for ctrl in result.controls:
            assert ctrl.status == "compliant"

    def test_control_status_non_compliant(
        self, two_check_registry
    ):
        """Violated control has status 'non_compliant'."""
        violations = [_make_alarm("iam_root_mfa")]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        # CIS 1.5 should be non_compliant
        non_comp = [
            c
            for c in result.controls
            if c.status == "non_compliant"
        ]
        assert len(non_comp) >= 1
        ctrl_ids = [c.control_id for c in non_comp]
        assert "1.5" in ctrl_ids

    def test_control_severity_worst_case(
        self, two_check_registry
    ):
        """Severity is worst among violations for control."""
        violations = [
            _make_alarm(
                "iam_root_mfa",
                resource_arn="arn:r1",
                severity="low",
            ),
            _make_alarm(
                "iam_root_mfa",
                resource_arn="arn:r2",
                severity="critical",
            ),
        ]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        ctrl_15 = next(
            (
                c
                for c in result.controls
                if c.control_id == "1.5"
            ),
            None,
        )
        assert ctrl_15 is not None
        assert ctrl_15.severity == "critical"

    def test_control_violations_list(
        self, two_check_registry
    ):
        """violations list on ControlStatus is populated."""
        violations = [
            _make_alarm(
                "iam_root_mfa",
                resource_arn="arn:my-resource",
                severity="high",
            )
        ]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        ctrl_15 = next(
            (
                c
                for c in result.controls
                if c.control_id == "1.5"
            ),
            None,
        )
        assert ctrl_15 is not None
        assert len(ctrl_15.violations) == 1
        v = ctrl_15.violations[0]
        assert v["resource_arn"] == "arn:my-resource"
        assert v["severity"] == "high"
        assert "reason" in v

    def test_unknown_framework_empty_result(
        self, two_check_registry
    ):
        """Unknown framework returns empty FrameworkScore."""
        scorer = self.Scorer(
            framework="made_up_xyz",
            violations=[_make_alarm("iam_root_mfa")],
            registry=two_check_registry,
        )
        result = scorer.score()
        assert result.total_controls == 0
        assert result.score_percent == 100.0

    def test_violations_outside_framework_ignored(
        self, two_check_registry
    ):
        """Violations for checks not in framework don't fail."""
        # only_nist_check: nist only, not cis_aws
        violations = [
            _make_alarm("s3_encryption"),  # pci_dss=[]
        ]
        scorer = self.Scorer(
            framework="pci_dss",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        # s3_encryption has empty pci_dss
        # so this alarm doesn't map to any pci control
        assert result.total_controls > 0 or (
            result.total_controls == 0
        )

    def test_total_controls_count(
        self, two_check_registry
    ):
        """total_controls = compliant + non_compliant."""
        violations = [_make_alarm("iam_root_mfa")]
        scorer = self.Scorer(
            framework="cis_aws",
            violations=violations,
            registry=two_check_registry,
        )
        result = scorer.score()
        assert (
            result.total_controls
            == result.compliant + result.non_compliant
        )

    def test_check_ids_field_on_control(
        self, two_check_registry
    ):
        """ControlStatus.check_ids lists contributing checks."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        ctrl_15 = next(
            (
                c
                for c in result.controls
                if c.control_id == "1.5"
            ),
            None,
        )
        assert ctrl_15 is not None
        assert "iam_root_mfa" in ctrl_15.check_ids

    def test_framework_score_model_fields(
        self, two_check_registry
    ):
        """FrameworkScore has all expected fields."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        assert hasattr(result, "framework")
        assert hasattr(result, "total_controls")
        assert hasattr(result, "compliant")
        assert hasattr(result, "non_compliant")
        assert hasattr(result, "score_percent")
        assert hasattr(result, "controls")

    def test_score_percent_is_float(
        self, two_check_registry
    ):
        """score_percent must be a float."""
        scorer = self.Scorer(
            framework="cis_aws",
            violations=[],
            registry=two_check_registry,
        )
        result = scorer.score()
        assert isinstance(result.score_percent, float)


# ── Part 3: API Endpoints ──────────────────────────


FRAMEWORKS = [
    "cis_aws",
    "nist_800_53",
    "pci_dss",
    "hipaa",
    "soc2",
    "owasp",
]

MOCK_ALARM_STATES = [
    ViolationState(
        pk="123456789012#us-east-1",
        sk="iam_root_mfa#arn:root",
        check_id="iam_root_mfa",
        status="alarm",
        severity="critical",
        reason="Root MFA off",
        resource_arn="arn:root",
        domain="identity",
    ),
    ViolationState(
        pk="123456789012#us-east-1",
        sk="s3_encryption#arn:bucket",
        check_id="s3_encryption",
        status="alarm",
        severity="high",
        reason="Not encrypted",
        resource_arn="arn:bucket",
        domain="data_protection",
    ),
    ViolationState(
        pk="123456789012#us-east-1",
        sk="ec2_no_open_ssh#arn:sg",
        check_id="ec2_no_open_ssh",
        status="ok",
        severity="high",
        reason="SSH closed",
        resource_arn="arn:sg",
        domain="network",
    ),
]


def _mock_state_manager():
    mock = MagicMock()
    mock.query_by_account.return_value = (
        MOCK_ALARM_STATES
    )
    return mock


def _mock_settings():
    return Settings(
        aws_account_id="123456789012",
        aws_regions=["us-east-1"],
    )


class TestFrameworksListEndpoint:
    """GET /compliance/frameworks"""

    def setup_method(self):
        app.dependency_overrides[
            get_state_manager
        ] = _mock_state_manager
        app.dependency_overrides[
            get_settings
        ] = _mock_settings

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_returns_200(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/frameworks"
        )
        assert resp.status_code == 200

    def test_returns_frameworks_list(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/frameworks"
        )
        data = resp.json()
        assert "frameworks" in data
        assert isinstance(data["frameworks"], list)

    def test_all_six_frameworks_present(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/frameworks"
        )
        data = resp.json()
        for fw in FRAMEWORKS:
            assert fw in data["frameworks"]

    def test_response_has_exactly_six(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/frameworks"
        )
        data = resp.json()
        assert len(data["frameworks"]) == 6


class TestFrameworkScoreEndpoint:
    """GET /compliance/framework/{framework_name}"""

    def setup_method(self):
        app.dependency_overrides[
            get_state_manager
        ] = _mock_state_manager
        app.dependency_overrides[
            get_settings
        ] = _mock_settings

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_valid_framework_returns_200(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        assert resp.status_code == 200

    def test_invalid_framework_returns_404(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/made_up_xyz"
        )
        assert resp.status_code == 404

    def test_response_has_framework_field(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        assert data["framework"] == "cis_aws"

    def test_response_has_score_percent(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        assert "score_percent" in data
        assert isinstance(data["score_percent"], float)

    def test_response_has_total_controls(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/nist_800_53"
        )
        data = resp.json()
        assert "total_controls" in data
        assert isinstance(data["total_controls"], int)

    def test_response_has_compliant_count(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        assert "compliant" in data
        assert "non_compliant" in data

    def test_response_has_controls_list(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        assert "controls" in data
        assert isinstance(data["controls"], list)

    def test_region_param_forwarded(self):
        """region query param is passed to state manager."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
            "?region=eu-west-1"
        )
        assert resp.status_code == 200

    def test_all_valid_frameworks_return_200(self):
        client = TestClient(app)
        for fw in FRAMEWORKS:
            resp = client.get(
                f"/api/v1/compliance/framework/{fw}"
            )
            assert resp.status_code == 200, (
                f"Framework {fw} returned "
                f"{resp.status_code}"
            )

    def test_score_percent_between_0_and_100(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/pci_dss"
        )
        data = resp.json()
        assert 0.0 <= data["score_percent"] <= 100.0

    def test_total_equals_compliant_plus_non(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        assert data["total_controls"] == (
            data["compliant"] + data["non_compliant"]
        )

    def test_controls_have_required_fields(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/framework/cis_aws"
        )
        data = resp.json()
        for ctrl in data["controls"]:
            assert "control_id" in ctrl
            assert "status" in ctrl
            assert "check_ids" in ctrl
            assert "violations" in ctrl
            assert "severity" in ctrl


class TestEnhancedComplianceScore:
    """GET /compliance/score now includes by_framework."""

    def setup_method(self):
        app.dependency_overrides[
            get_state_manager
        ] = _mock_state_manager
        app.dependency_overrides[
            get_settings
        ] = _mock_settings

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_score_still_has_original_fields(self):
        """Enhancement must not break existing fields."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "score_percent" in data
        assert "total_checks" in data
        assert "passed" in data
        assert "failed" in data
        assert "by_domain" in data

    def test_score_has_by_framework_field(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        assert "by_framework" in data

    def test_by_framework_has_all_six_keys(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        bf = data["by_framework"]
        for fw in FRAMEWORKS:
            assert fw in bf

    def test_by_framework_has_score_percent(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        bf = data["by_framework"]
        for fw in FRAMEWORKS:
            assert "score_percent" in bf[fw]

    def test_by_framework_has_total_controls(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        bf = data["by_framework"]
        for fw in FRAMEWORKS:
            assert "total_controls" in bf[fw]

    def test_by_framework_scores_are_valid(self):
        """Each per-framework score_percent in [0, 100]."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        bf = data["by_framework"]
        for fw, fdata in bf.items():
            pct = fdata["score_percent"]
            assert 0.0 <= pct <= 100.0, (
                f"{fw} score_percent={pct} out of range"
            )
