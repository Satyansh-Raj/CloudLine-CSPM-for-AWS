"""Tests for enhanced violations endpoint.

Verifies that the violations response includes the
new fields: resolved_at, first_detected,
previous_status, compliance, and remediation_id.

Also verifies that ?status=ok correctly returns
only resolved violations with resolved_at set.
"""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.dependencies import get_settings, get_state_manager
from app.main import app
from app.config import Settings
from app.pipeline.models import ViolationState

ACCOUNT = "832843292195"
REGION = "ap-south-1"


def _make_alarm_state(
    check_id="ec2_no_open_ssh",
    resource_arn=(
        "arn:aws:ec2:ap-south-1:832843292195:sg/sg-1"
    ),
    severity="critical",
    domain="network",
    risk_score=80,
    previous_status="ok",
    first_detected="2026-03-01T10:00:00Z",
    last_evaluated="2026-03-10T12:00:00Z",
    compliance=None,
    remediation_id="ec2_no_open_ssh",
) -> ViolationState:
    """Build an alarm ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status="alarm",
        previous_status=previous_status,
        severity=severity,
        domain=domain,
        risk_score=risk_score,
        resource_arn=resource_arn,
        reason="Port 22 open to 0.0.0.0/0",
        compliance=compliance or {
            "cis_aws": ["4.1"],
            "nist_800_53": ["SC-7"],
        },
        remediation_id=remediation_id,
        first_detected=first_detected,
        last_evaluated=last_evaluated,
        resolved_at=None,
    )


def _make_resolved_state(
    check_id="iam_root_mfa",
    resource_arn="arn:aws:iam::832843292195:root",
    severity="critical",
    domain="identity",
    risk_score=0,
    previous_status="alarm",
    first_detected="2026-02-01T08:00:00Z",
    last_evaluated="2026-03-15T09:00:00Z",
    resolved_at="2026-03-15T09:00:00Z",
    compliance=None,
    remediation_id="iam_root_mfa",
) -> ViolationState:
    """Build an ok (resolved) ViolationState."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status="ok",
        previous_status=previous_status,
        severity=severity,
        domain=domain,
        risk_score=risk_score,
        resource_arn=resource_arn,
        reason="MFA enabled",
        compliance=compliance or {
            "cis_aws": ["1.5"],
            "hipaa": ["164.312"],
        },
        remediation_id=remediation_id,
        first_detected=first_detected,
        last_evaluated=last_evaluated,
        resolved_at=resolved_at,
    )


def _mock_mgr(states=None):
    """Return a mock StateManager."""
    mgr = MagicMock()
    mgr.query_by_account.return_value = (
        states if states is not None else []
    )
    return mgr


class TestViolationsEnhancedFields:
    """Enhanced field presence in violations response."""

    def setup_method(self):
        self._mgr = _mock_mgr(
            states=[_make_alarm_state()]
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: Settings(
            aws_region=REGION,
            aws_account_id=ACCOUNT,
        )

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_response_includes_resolved_at(self):
        """resolved_at field present in every item."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert "resolved_at" in items[0]

    def test_response_includes_first_detected(self):
        """first_detected field present in every item."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "first_detected" in items[0]
        assert (
            items[0]["first_detected"]
            == "2026-03-01T10:00:00Z"
        )

    def test_response_includes_previous_status(self):
        """previous_status field present in every item."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "previous_status" in items[0]
        assert items[0]["previous_status"] == "ok"

    def test_response_includes_compliance(self):
        """compliance dict present in every item."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "compliance" in items[0]
        assert isinstance(items[0]["compliance"], dict)

    def test_response_includes_remediation_id(self):
        """remediation_id field present in every item."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "remediation_id" in items[0]
        assert (
            items[0]["remediation_id"]
            == "ec2_no_open_ssh"
        )


class TestViolationsStatusOkFilter:
    """?status=ok returns only resolved violations."""

    def setup_method(self):
        alarm = _make_alarm_state()
        resolved = _make_resolved_state()
        self._mgr = _mock_mgr(
            states=[alarm, resolved]
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: Settings(
            aws_region=REGION,
            aws_account_id=ACCOUNT,
        )

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_status_ok_returns_only_resolved(self):
        """?status=ok filters to ok items only."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=ok"
        )
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["status"] == "ok"

    def test_resolved_item_has_resolved_at(self):
        """Resolved item carries its resolved_at ts."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=ok"
        )
        items = resp.json()
        assert items[0]["resolved_at"] == (
            "2026-03-15T09:00:00Z"
        )

    def test_resolved_item_has_previous_status(self):
        """Resolved item shows previous_status=alarm."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=ok"
        )
        items = resp.json()
        assert items[0]["previous_status"] == "alarm"

    def test_resolved_item_has_first_detected(self):
        """Resolved item carries first_detected ts."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=ok"
        )
        items = resp.json()
        assert items[0]["first_detected"] == (
            "2026-02-01T08:00:00Z"
        )

    def test_alarm_item_resolved_at_is_none(self):
        """Active alarm violation has resolved_at=None."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=alarm"
        )
        items = resp.json()
        assert len(items) == 1
        assert items[0]["resolved_at"] is None


class TestViolationsStatusHistoryFields:
    """Verify status_history and regression_count in response."""

    def setup_method(self):
        history = [
            {
                "status": "alarm",
                "timestamp": "2026-03-01T10:00:00Z",
            },
            {
                "status": "ok",
                "timestamp": "2026-03-05T12:00:00Z",
            },
        ]
        state = _make_alarm_state()
        state.status_history = history
        state.regression_count = 1
        self._mgr = _mock_mgr(states=[state])
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: Settings(
            aws_region=REGION,
            aws_account_id=ACCOUNT,
        )

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_settings, None
        )

    def test_response_includes_status_history(self):
        """status_history list present in response."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "status_history" in items[0]
        assert len(items[0]["status_history"]) == 2
        assert (
            items[0]["status_history"][0]["status"]
            == "alarm"
        )

    def test_response_includes_regression_count(self):
        """regression_count present in response."""
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        items = resp.json()
        assert "regression_count" in items[0]
        assert items[0]["regression_count"] == 1
