"""Tests for API endpoints and app setup."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from moto import mock_aws

from app.dependencies import (
    get_evaluator,
    get_state_manager,
)
from app.engine.evaluator import PolicyEvaluator
from app.main import app
from app.models.violation import Violation
from app.pipeline.models import ViolationState
from app.pipeline.state_manager import StateManager


class TestHealthEndpoint:
    def test_health(self):
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestScanEndpoint:
    @mock_aws
    def test_scan_returns_202(self):
        client = TestClient(app)
        resp = client.post("/api/v1/scans")
        assert resp.status_code == 202
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "queued"

    @mock_aws
    def test_scan_get_result_running(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/scans/nonexistent-id"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"


MOCK_STATES = [
    ViolationState(
        pk="832843292195#us-east-1",
        sk="iam_01#arn:root",
        check_id="iam_01",
        status="alarm",
        severity="critical",
        reason="Root MFA off",
        resource_arn="arn:root",
        domain="identity",
    ),
    ViolationState(
        pk="832843292195#us-east-1",
        sk="ec2_05#arn:sg",
        check_id="ec2_05",
        status="alarm",
        severity="high",
        reason="SSH open",
        resource_arn="arn:sg",
        domain="network",
    ),
    ViolationState(
        pk="832843292195#us-east-1",
        sk="iam_02#arn:policy",
        check_id="iam_02",
        status="ok",
        severity="medium",
        reason="Password policy OK",
        resource_arn="arn:policy",
        domain="identity",
    ),
]


def _mock_state_manager():
    """Create a mock state manager."""
    mock = MagicMock(spec=StateManager)
    mock.query_by_account.return_value = (
        MOCK_STATES
    )
    mock.query_by_status.return_value = [
        s
        for s in MOCK_STATES
        if s.status == "alarm"
    ]
    mock.query_by_domain.side_effect = (
        lambda domain, **kw: [
            s
            for s in MOCK_STATES
            if s.domain == domain
        ]
    )
    mock.query_by_check.side_effect = (
        lambda check_id, **kw: [
            s
            for s in MOCK_STATES
            if s.check_id == check_id
        ]
    )
    return mock


class TestViolationsEndpoint:
    def setup_method(self):
        self._mock = _mock_state_manager()
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_list_violations(self):
        client = TestClient(app)
        resp = client.get("/api/v1/violations")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3

    def test_filter_by_severity(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?severity=critical"
        )
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "critical"

    def test_filter_by_domain(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?domain=network"
        )
        data = resp.json()
        assert len(data) == 1
        assert data[0]["domain"] == "network"

    def test_filter_by_status(self):
        self._mock.query_by_status.return_value = [
            s
            for s in MOCK_STATES
            if s.status == "ok"
        ]
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?status=ok"
        )
        data = resp.json()
        assert len(data) == 1
        assert data[0]["status"] == "ok"

    def test_filter_by_check_id(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations"
            "?check_id=ec2_05"
        )
        data = resp.json()
        assert len(data) == 1
        assert data[0]["check_id"] == "ec2_05"

    def test_filter_no_match(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/violations?severity=low"
        )
        data = resp.json()
        assert len(data) == 0


class TestComplianceEndpoint:
    def setup_method(self):
        self._mock = _mock_state_manager()
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )

    def test_compliance_score(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_checks" in data
        assert "passed" in data
        assert "failed" in data
        assert "score_percent" in data
        # Check-level scoring: 287 total checks,
        # 2 distinct check_ids with violations
        assert data["total_checks"] == 287
        assert data["failed"] == 2
        assert data["passed"] == 285

    def test_compliance_by_domain(self):
        client = TestClient(app)
        resp = client.get(
            "/api/v1/compliance/score"
        )
        data = resp.json()
        assert "by_domain" in data
        assert "identity" in data["by_domain"]
