"""Tests for the executive summary endpoint.

Covers GET /api/v1/summary/executive:
- total_active, total_resolved, resolution_rate
- by_domain breakdown with all known domains
- by_severity counts
- trend (resolved_last_24h, new_last_24h)
- edge cases: empty, all alarm, all resolved
- optional region/account_id query params

Also covers state-transition integration scenarios
verifying that update_status sets resolved_at and
preserves previous_status correctly.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app.config import Settings
from app.dependencies import get_settings, get_state_manager
from app.main import app
from app.pipeline.models import ViolationState
from app.pipeline.state_manager import StateManager

ACCOUNT = "832843292195"
REGION = "ap-south-1"
TABLE_NAME = "violation-state"

# ----- helpers -----------------------------------------------


def _ts(hours_ago: float = 0) -> str:
    """Return ISO 8601 UTC timestamp offset by hours."""
    dt = datetime.now(UTC) - timedelta(hours=hours_ago)
    return dt.isoformat().replace("+00:00", "Z")


def _make_state(
    check_id: str = "ec2_no_open_ssh",
    resource_arn: str = (
        "arn:aws:ec2:ap-south-1:832843292195:sg/sg-1"
    ),
    status: str = "alarm",
    severity: str = "critical",
    domain: str = "network",
    risk_score: int = 80,
    previous_status: str = "ok",
    resolved_at: str | None = None,
    first_detected: str | None = None,
    last_evaluated: str | None = None,
) -> ViolationState:
    """Build a ViolationState for testing."""
    now = _ts(0)
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        previous_status=previous_status,
        severity=severity,
        domain=domain,
        risk_score=risk_score,
        resource_arn=resource_arn,
        reason="test reason",
        compliance={"cis_aws": ["1.1"]},
        remediation_id=check_id,
        first_detected=first_detected or now,
        last_evaluated=last_evaluated or now,
        resolved_at=resolved_at,
    )


def _make_resolved(
    check_id: str = "iam_root_mfa",
    resource_arn: str = (
        "arn:aws:iam::832843292195:root"
    ),
    severity: str = "critical",
    domain: str = "identity",
    resolved_hours_ago: float = 2.0,
    first_detected_hours_ago: float = 48.0,
) -> ViolationState:
    """Shorthand for a resolved (ok) state."""
    return _make_state(
        check_id=check_id,
        resource_arn=resource_arn,
        status="ok",
        severity=severity,
        domain=domain,
        previous_status="alarm",
        resolved_at=_ts(resolved_hours_ago),
        first_detected=_ts(first_detected_hours_ago),
    )


def _mock_mgr(states=None):
    """Return a MagicMock StateManager."""
    mgr = MagicMock()
    mgr.query_by_account.return_value = (
        states if states is not None else []
    )
    return mgr


def _override(mgr, region=REGION, account=ACCOUNT):
    """Set up FastAPI dependency overrides."""
    app.dependency_overrides[
        get_state_manager
    ] = lambda: mgr
    app.dependency_overrides[
        get_settings
    ] = lambda: Settings(
        aws_region=region,
        aws_account_id=account,
    )


def _clear():
    """Remove dependency overrides."""
    app.dependency_overrides.pop(
        get_state_manager, None
    )
    app.dependency_overrides.pop(get_settings, None)


# ----- DynamoDB table helper for integration tests -----------


def _create_table(session):
    """Create the violation-state table with GSIs."""
    ddb = session.resource("dynamodb")
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
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
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "domain-index",
                "KeySchema": [
                    {
                        "AttributeName": "domain",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "last_evaluated",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
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
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def state_mgr(aws_credentials):
    """StateManager backed by moto DynamoDB."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        yield StateManager(session, TABLE_NAME)


# ============================================================
# Executive Summary endpoint tests
# ============================================================


class TestExecutiveSummaryBasic:
    """GET /api/v1/summary/executive — basic contract."""

    def setup_method(self):
        alarm = _make_state(
            check_id="ec2_no_open_ssh",
            severity="critical",
            domain="network",
        )
        resolved = _make_resolved(
            check_id="iam_root_mfa",
            domain="identity",
            severity="critical",
        )
        _override(_mock_mgr(states=[alarm, resolved]))

    def teardown_method(self):
        _clear()

    def test_returns_200(self):
        """Endpoint exists and responds 200."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/summary/executive"
        )
        assert resp.status_code == 200

    def test_has_total_active(self):
        """Response includes total_active key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "total_active" in data

    def test_has_total_resolved(self):
        """Response includes total_resolved key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "total_resolved" in data

    def test_has_resolution_rate(self):
        """Response includes resolution_rate key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "resolution_rate" in data

    def test_has_by_domain(self):
        """Response includes by_domain dict."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "by_domain" in data
        assert isinstance(data["by_domain"], dict)

    def test_has_by_severity(self):
        """Response includes by_severity dict."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "by_severity" in data

    def test_has_trend(self):
        """Response includes trend dict."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "trend" in data


class TestExecutiveSummaryCounts:
    """Verify counts from mixed alarm/ok states."""

    def setup_method(self):
        states = [
            # 3 alarms
            _make_state(
                check_id="chk_a",
                resource_arn="arn:a",
                status="alarm",
                severity="critical",
                domain="network",
            ),
            _make_state(
                check_id="chk_b",
                resource_arn="arn:b",
                status="alarm",
                severity="high",
                domain="compute",
            ),
            _make_state(
                check_id="chk_c",
                resource_arn="arn:c",
                status="alarm",
                severity="medium",
                domain="identity",
            ),
            # 2 resolved
            _make_resolved(
                check_id="chk_d",
                resource_arn="arn:d",
                severity="low",
                domain="data_protection",
            ),
            _make_resolved(
                check_id="chk_e",
                resource_arn="arn:e",
                severity="high",
                domain="network",
            ),
        ]
        _override(_mock_mgr(states=states))

    def teardown_method(self):
        _clear()

    def test_total_active_count(self):
        """total_active equals number of alarm states."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["total_active"] == 3

    def test_total_resolved_count(self):
        """total_resolved equals number of ok states."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["total_resolved"] == 2

    def test_resolution_rate_calculation(self):
        """resolution_rate = resolved / total * 100."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        # 2 / (3 + 2) * 100 = 40.0
        assert abs(data["resolution_rate"] - 40.0) < 0.1

    def test_by_severity_critical(self):
        """by_severity.critical counts alarm criticals."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["by_severity"]["critical"] == 1

    def test_by_severity_high(self):
        """by_severity.high counts alarm highs."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["by_severity"]["high"] == 1

    def test_by_severity_medium(self):
        """by_severity.medium counts alarm mediums."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["by_severity"]["medium"] == 1

    def test_by_severity_low(self):
        """by_severity.low counts alarm lows (zero here)."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["by_severity"]["low"] == 0


class TestExecutiveSummaryDomain:
    """by_domain breakdown correctness."""

    KNOWN_DOMAINS = [
        "identity",
        "compute",
        "data_protection",
        "network",
        "logging_monitoring",
        "detection",
        "cross_resource",
    ]

    def setup_method(self):
        states = [
            _make_state(
                check_id="c1",
                resource_arn="arn:1",
                status="alarm",
                domain="identity",
                severity="high",
            ),
            _make_state(
                check_id="c2",
                resource_arn="arn:2",
                status="alarm",
                domain="identity",
                severity="medium",
            ),
            _make_resolved(
                check_id="c3",
                resource_arn="arn:3",
                domain="identity",
                severity="critical",
            ),
            _make_state(
                check_id="c4",
                resource_arn="arn:4",
                status="alarm",
                domain="network",
                severity="low",
            ),
        ]
        _override(_mock_mgr(states=states))

    def teardown_method(self):
        _clear()

    def test_by_domain_contains_all_domains(self):
        """All 7 known domains are in by_domain."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            assert d in data["by_domain"], (
                f"Domain '{d}' missing from by_domain"
            )

    def test_by_domain_entry_has_active(self):
        """Each domain entry has 'active' key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            assert "active" in data["by_domain"][d]

    def test_by_domain_entry_has_resolved(self):
        """Each domain entry has 'resolved' key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            assert "resolved" in data["by_domain"][d]

    def test_by_domain_entry_has_total_checks(self):
        """Each domain entry has 'total_checks' key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            assert "total_checks" in data["by_domain"][d]

    def test_by_domain_entry_has_score_percent(self):
        """Each domain entry has 'score_percent' key."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            assert (
                "score_percent" in data["by_domain"][d]
            )

    def test_identity_domain_active_count(self):
        """identity.active == 2 (2 alarm items)."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["by_domain"]["identity"]["active"] == 2

    def test_identity_domain_resolved_count(self):
        """identity.resolved == 1 (1 ok item)."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert (
            data["by_domain"]["identity"]["resolved"] == 1
        )

    def test_total_checks_from_constant(self):
        """identity.total_checks == 37 (from constant)."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert (
            data["by_domain"]["identity"]["total_checks"]
            == 37
        )

    def test_score_percent_between_0_and_100(self):
        """score_percent is in [0, 100] for all domains."""
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        for d in self.KNOWN_DOMAINS:
            score = data["by_domain"][d]["score_percent"]
            assert 0 <= score <= 100, (
                f"{d}.score_percent={score} out of range"
            )


class TestExecutiveSummaryEdgeCases:
    """Edge cases: empty, all alarm, all resolved."""

    def teardown_method(self):
        _clear()

    def test_empty_state_total_active_zero(self):
        """No violations → total_active = 0."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["total_active"] == 0

    def test_empty_state_total_resolved_zero(self):
        """No violations → total_resolved = 0."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["total_resolved"] == 0

    def test_empty_state_resolution_rate_zero(self):
        """No violations → resolution_rate = 0."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["resolution_rate"] == 0.0

    def test_all_alarm_resolution_rate_zero(self):
        """All alarm → resolution_rate = 0."""
        states = [
            _make_state(
                check_id="c1",
                resource_arn="arn:1",
                status="alarm",
            ),
            _make_state(
                check_id="c2",
                resource_arn="arn:2",
                status="alarm",
            ),
        ]
        _override(_mock_mgr(states=states))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["resolution_rate"] == 0.0

    def test_all_resolved_resolution_rate_100(self):
        """All ok → resolution_rate = 100."""
        states = [
            _make_resolved(
                check_id="c1", resource_arn="arn:1"
            ),
            _make_resolved(
                check_id="c2", resource_arn="arn:2"
            ),
        ]
        _override(_mock_mgr(states=states))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert abs(
            data["resolution_rate"] - 100.0
        ) < 0.1

    def test_empty_by_severity_all_zeros(self):
        """No violations → all severity counts = 0."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        sev = data["by_severity"]
        assert sev["critical"] == 0
        assert sev["high"] == 0
        assert sev["medium"] == 0
        assert sev["low"] == 0


class TestExecutiveSummaryTrend:
    """Trend: recent 24 h resolved/new counts."""

    def teardown_method(self):
        _clear()

    def test_trend_has_resolved_last_24h(self):
        """trend dict has resolved_last_24h key."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "resolved_last_24h" in data["trend"]

    def test_trend_has_new_last_24h(self):
        """trend dict has new_last_24h key."""
        _override(_mock_mgr(states=[]))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert "new_last_24h" in data["trend"]

    def test_trend_resolved_last_24h_recent(self):
        """Violation resolved 2h ago counts in 24h."""
        states = [
            _make_resolved(
                check_id="c1",
                resource_arn="arn:1",
                resolved_hours_ago=2.0,
            ),
            _make_resolved(
                check_id="c2",
                resource_arn="arn:2",
                resolved_hours_ago=30.0,  # outside 24h
            ),
        ]
        _override(_mock_mgr(states=states))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["trend"]["resolved_last_24h"] == 1

    def test_trend_new_last_24h_recent(self):
        """Violation first_detected 6h ago counts in 24h."""
        states = [
            _make_state(
                check_id="c1",
                resource_arn="arn:1",
                status="alarm",
                first_detected=_ts(6),
            ),
            _make_state(
                check_id="c2",
                resource_arn="arn:2",
                status="alarm",
                first_detected=_ts(30),  # outside 24h
            ),
        ]
        _override(_mock_mgr(states=states))
        client = TestClient(app)
        data = client.get(
            "/api/v1/summary/executive"
        ).json()
        assert data["trend"]["new_last_24h"] == 1


class TestExecutiveSummaryQueryParams:
    """Optional region and account_id query params."""

    def setup_method(self):
        _override(_mock_mgr(states=[]))

    def teardown_method(self):
        _clear()

    def test_region_param_accepted(self):
        """?region= query param is accepted (200)."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/summary/executive"
            "?region=us-east-1"
        )
        assert resp.status_code == 200

    def test_account_id_param_accepted(self):
        """?account_id= query param is accepted (200)."""
        client = TestClient(app)
        resp = client.get(
            "/api/v1/summary/executive"
            "?account_id=123456789012"
        )
        assert resp.status_code == 200


# ============================================================
# State-transition integration tests (moto DynamoDB)
# ============================================================


class TestStateTransitionIntegration:
    """Integration: update_status sets resolved_at etc."""

    def test_update_status_sets_resolved_at(
        self, state_mgr
    ):
        """update_status(ok) sets resolved_at field."""
        state = _make_state(
            check_id="iam_root_mfa",
            resource_arn=(
                "arn:aws:iam::832843292195:root"
            ),
            status="alarm",
        )
        state_mgr.put_state(state)
        state_mgr.update_status(
            account_id=ACCOUNT,
            region=REGION,
            check_id="iam_root_mfa",
            resource_arn=(
                "arn:aws:iam::832843292195:root"
            ),
            new_status="ok",
            reason="MFA now enabled",
        )
        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "iam_root_mfa",
            "arn:aws:iam::832843292195:root",
        )
        assert result is not None
        assert result.resolved_at is not None
        assert "Z" in result.resolved_at

    def test_update_status_preserves_previous_status(
        self, state_mgr
    ):
        """previous_status captures alarm before ok."""
        state = _make_state(
            check_id="s3_block_public",
            resource_arn="arn:aws:s3:::my-bucket",
            status="alarm",
        )
        state_mgr.put_state(state)
        state_mgr.update_status(
            account_id=ACCOUNT,
            region=REGION,
            check_id="s3_block_public",
            resource_arn="arn:aws:s3:::my-bucket",
            new_status="ok",
            reason="Public access blocked",
        )
        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "s3_block_public",
            "arn:aws:s3:::my-bucket",
        )
        assert result is not None
        assert result.previous_status == "alarm"

    def test_alarm_to_ok_appears_in_status_ok_filter(
        self, state_mgr
    ):
        """Resolved violation appears when status=ok."""
        state = _make_state(
            check_id="vpc_flow_logs",
            resource_arn="arn:aws:ec2:ap-south-1::vpc/1",
            status="alarm",
        )
        state_mgr.put_state(state)
        state_mgr.update_status(
            account_id=ACCOUNT,
            region=REGION,
            check_id="vpc_flow_logs",
            resource_arn=(
                "arn:aws:ec2:ap-south-1::vpc/1"
            ),
            new_status="ok",
            reason="Flow logs enabled",
        )
        all_states = state_mgr.query_by_account(
            ACCOUNT, REGION, limit=100
        )
        ok_states = [
            s for s in all_states if s.status == "ok"
        ]
        assert len(ok_states) == 1
        assert ok_states[0].check_id == "vpc_flow_logs"

    def test_auto_resolve_reason_preserved(
        self, state_mgr
    ):
        """Auto-resolve reason is stored correctly."""
        state = _make_state(
            check_id="ec2_no_open_ssh",
            resource_arn=(
                "arn:aws:ec2:ap-south-1:832843292195:sg/1"
            ),
            status="alarm",
        )
        state_mgr.put_state(state)
        reason = (
            "Resource no longer exists in AWS "
            "(auto-resolved)"
        )
        state_mgr.update_status(
            account_id=ACCOUNT,
            region=REGION,
            check_id="ec2_no_open_ssh",
            resource_arn=(
                "arn:aws:ec2:ap-south-1:832843292195:sg/1"
            ),
            new_status="ok",
            reason=reason,
        )
        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:ap-south-1:832843292195:sg/1",
        )
        assert result is not None
        assert "auto-resolved" in result.reason

    def test_resolved_retains_severity_and_domain(
        self, state_mgr
    ):
        """Severity and domain survive status transition."""
        state = _make_state(
            check_id="kms_rotation",
            resource_arn="arn:aws:kms:ap-south-1::key/1",
            status="alarm",
            severity="high",
            domain="data_protection",
        )
        state_mgr.put_state(state)
        state_mgr.update_status(
            account_id=ACCOUNT,
            region=REGION,
            check_id="kms_rotation",
            resource_arn=(
                "arn:aws:kms:ap-south-1::key/1"
            ),
            new_status="ok",
            reason="Rotation enabled",
        )
        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "kms_rotation",
            "arn:aws:kms:ap-south-1::key/1",
        )
        assert result is not None
        assert result.severity == "high"
        assert result.domain == "data_protection"
