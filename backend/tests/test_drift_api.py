"""Tests for drift alerts REST API endpoint."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.dependencies import get_state_manager
from app.main import app
from app.pipeline.models import ViolationState

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _make_state(
    check_id="ec2_no_open_ssh",
    status="alarm",
    previous_status="ok",
    severity="critical",
    risk_score=92,
    domain="network",
    resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
    reason="Port 22 open to 0.0.0.0/0",
    last_evaluated="2026-02-28T12:00:00Z",
):
    """Build a ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        previous_status=previous_status,
        severity=severity,
        risk_score=risk_score,
        domain=domain,
        resource_arn=resource_arn,
        reason=reason,
        first_detected="2026-02-28T10:00:00Z",
        last_evaluated=last_evaluated,
    )


ALARM_STATES = [
    _make_state(
        check_id="ec2_no_open_ssh",
        status="alarm",
        previous_status="ok",
        severity="critical",
        last_evaluated="2026-02-28T12:00:00Z",
    ),
    _make_state(
        check_id="s3_block_public_acls",
        status="alarm",
        previous_status="ok",
        severity="high",
        domain="data_protection",
        resource_arn="arn:aws:s3:::public-bucket",
        reason="S3 bucket publicly accessible",
        last_evaluated="2026-02-28T11:30:00Z",
    ),
]

OK_STATES = [
    _make_state(
        check_id="ec2_imdsv2",
        status="ok",
        previous_status="alarm",
        severity="medium",
        resource_arn="arn:aws:ec2:us-east-1:123:i/i-1",
        reason="EC2 instance now compliant",
        last_evaluated="2026-02-28T11:00:00Z",
    ),
]


def _mock_state_manager(
    alarm_states=None, ok_states=None
):
    """Create a mock StateManager."""
    mgr = MagicMock()
    mgr.query_by_status.side_effect = (
        lambda status, limit=100: (
            (alarm_states or [])
            if status == "alarm"
            else (ok_states or [])
        )
    )
    mgr.query_by_check.return_value = (
        (alarm_states or []) + (ok_states or [])
    )
    return mgr


class TestDriftAlertsEndpoint:
    """GET /api/v1/drift/alerts."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_returns_200(self):
        """Endpoint returns 200."""
        client = TestClient(app)
        resp = client.get("/api/v1/drift/alerts")
        assert resp.status_code == 200

    def test_returns_all_alerts(self):
        """All alarm + ok states returned."""
        client = TestClient(app)
        resp = client.get("/api/v1/drift/alerts")
        data = resp.json()
        assert len(data["alerts"]) == 3

    def test_response_format(self):
        """Each alert has expected fields."""
        client = TestClient(app)
        resp = client.get("/api/v1/drift/alerts")
        alert = resp.json()["alerts"][0]

        assert "type" in alert
        assert "check_id" in alert
        assert "resource" in alert
        assert "severity" in alert
        assert "risk_score" in alert
        assert "timestamp" in alert
        assert "reason" in alert
        assert "domain" in alert
        assert "previous_status" in alert
        assert "current_status" in alert


class TestDriftFilterByType:
    """Filter by ?type= parameter."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_filter_new_violation(self):
        """?type=new_violation returns only alarms."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?type=new_violation"
        )
        data = resp.json()
        assert len(data["alerts"]) == 2
        for a in data["alerts"]:
            assert a["type"] == "new_violation"

    def test_filter_resolution(self):
        """?type=resolution returns only resolved."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?type=resolution"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["type"] == "resolution"


class TestDriftFilterBySince:
    """Filter by ?since= timestamp."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_since_filters_old_alerts(self):
        """Only alerts after timestamp returned."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?since=2026-02-28T11:45:00Z"
        )
        data = resp.json()
        # Only ec2_no_open_ssh at 12:00:00Z passes
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["check_id"]
            == "ec2_no_open_ssh"
        )

    def test_since_returns_all_when_old(self):
        """Ancient since returns everything."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?since=2020-01-01T00:00:00Z"
        )
        data = resp.json()
        assert len(data["alerts"]) == 3


class TestDriftFilterBySeverity:
    """Filter by ?severity= parameter."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_filter_critical(self):
        """?severity=critical returns only critical."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?severity=critical"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["severity"] == "critical"
        )

    def test_filter_high(self):
        """?severity=high returns only high."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?severity=high"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["severity"] == "high"


class TestDriftFilterByCheckId:
    """Filter by ?check_id= parameter."""

    def setup_method(self):
        mgr = MagicMock()
        # When check_id filter used with no type,
        # query_by_check is called
        mgr.query_by_check.return_value = [
            ALARM_STATES[0]
        ]
        mgr.query_by_status.return_value = []
        self._mock = mgr
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_filter_by_check_id(self):
        """?check_id= queries by check."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?check_id=ec2_no_open_ssh"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["check_id"]
            == "ec2_no_open_ssh"
        )


class TestDriftEmptyResults:
    """No alerts available."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=[], ok_states=[]
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_empty_returns_empty_list(self):
        """No violations returns empty alerts list."""
        client = TestClient(app)
        resp = client.get("/api/v1/drift/alerts")
        data = resp.json()
        assert data["alerts"] == []


class TestDriftLimit:
    """Limit parameter."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_limit_truncates(self):
        """?limit=1 returns at most 1 alert."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?limit=1"
        )
        data = resp.json()
        assert len(data["alerts"]) <= 1

    def test_limit_validation_min(self):
        """?limit=0 returns 422 validation error."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?limit=0"
        )
        assert resp.status_code == 422


class TestStateToAlert:
    """_state_to_alert conversion logic."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=[
                _make_state(
                    status="alarm",
                    previous_status="",
                ),
            ],
            ok_states=[],
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_alarm_without_previous_is_new(self):
        """alarm with no previous = new_violation."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?type=new_violation"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["type"]
            == "new_violation"
        )


class TestDriftCombinedFilters:
    """Multiple filters applied together."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=ALARM_STATES,
            ok_states=OK_STATES,
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_type_and_severity(self):
        """?type=new_violation&severity=critical."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?type=new_violation&severity=critical"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["severity"] == "critical"
        )
        assert (
            data["alerts"][0]["type"]
            == "new_violation"
        )

    def test_since_and_type(self):
        """?since=...&type=new_violation."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?since=2026-02-28T11:45:00Z"
            "&type=new_violation"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["check_id"]
            == "ec2_no_open_ssh"
        )

    def test_check_id_and_type(self):
        """?check_id=...&type=new_violation filters."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts"
            "?type=new_violation"
            "&check_id=ec2_no_open_ssh"
        )
        data = resp.json()
        for a in data["alerts"]:
            assert (
                a["check_id"]
                == "ec2_no_open_ssh"
            )


class TestStateToAlertOkNoPrevious:
    """ok status with no previous_status."""

    def setup_method(self):
        self._mock = _mock_state_manager(
            alarm_states=[],
            ok_states=[
                _make_state(
                    status="ok",
                    previous_status="",
                    check_id="ec2_imdsv2",
                ),
            ],
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_ok_without_previous_is_no_change(
        self,
    ):
        """ok with no previous = no_change."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/drift/alerts?type=no_change"
        )
        data = resp.json()
        assert len(data["alerts"]) == 1
        assert (
            data["alerts"][0]["type"]
            == "no_change"
        )
