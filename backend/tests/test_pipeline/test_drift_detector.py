"""Tests for DriftDetector state comparison logic."""

from app.pipeline.drift_detector import (
    DriftDetector,
    _build_reason,
    _classify_transition,
    _parse_severity,
)
from app.pipeline.models import (
    AlertSeverity,
    DriftType,
    ViolationState,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
ARN = "arn:aws:ec2:us-east-1:123:sg/sg-1"


def _make_prev_state(
    status="ok",
    check_id="ec2_no_open_ssh",
    resource_arn=ARN,
    resolved_at=None,
    regression_count=0,
):
    """Build a previous ViolationState."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        severity="critical",
        domain="network",
        resource_arn=resource_arn,
        risk_score=92,
        reason="Previous reason",
        first_detected="2026-02-27T10:00:00Z",
        last_evaluated="2026-02-27T11:00:00Z",
        resolved_at=resolved_at,
        regression_count=regression_count,
    )


class TestClassifyTransition:
    """Test _classify_transition helper."""

    def test_ok_to_alarm(self):
        """ok -> alarm = NEW_VIOLATION."""
        assert _classify_transition(
            "ok", "alarm"
        ) == DriftType.NEW_VIOLATION

    def test_alarm_to_ok(self):
        """alarm -> ok = RESOLUTION."""
        assert _classify_transition(
            "alarm", "ok"
        ) == DriftType.RESOLUTION

    def test_alarm_to_alarm(self):
        """alarm -> alarm = NO_CHANGE."""
        assert _classify_transition(
            "alarm", "alarm"
        ) == DriftType.NO_CHANGE

    def test_ok_to_ok(self):
        """ok -> ok = NO_CHANGE."""
        assert _classify_transition(
            "ok", "ok"
        ) == DriftType.NO_CHANGE

    def test_error_to_alarm(self):
        """error -> alarm = NEW_VIOLATION."""
        assert _classify_transition(
            "error", "alarm"
        ) == DriftType.NEW_VIOLATION

    def test_ok_to_error(self):
        """ok -> error = NO_CHANGE (not a drift)."""
        assert _classify_transition(
            "ok", "error"
        ) == DriftType.NO_CHANGE

    def test_alarm_to_error(self):
        """alarm -> error = NO_CHANGE."""
        assert _classify_transition(
            "alarm", "error"
        ) == DriftType.NO_CHANGE


class TestParseSeverity:
    """Test _parse_severity helper."""

    def test_valid_severities(self):
        """All valid severities parse correctly."""
        assert (
            _parse_severity("critical")
            == AlertSeverity.CRITICAL
        )
        assert (
            _parse_severity("high")
            == AlertSeverity.HIGH
        )
        assert (
            _parse_severity("medium")
            == AlertSeverity.MEDIUM
        )
        assert (
            _parse_severity("low")
            == AlertSeverity.LOW
        )

    def test_case_insensitive(self):
        """Severity parsing is case-insensitive."""
        assert (
            _parse_severity("CRITICAL")
            == AlertSeverity.CRITICAL
        )
        assert (
            _parse_severity("High")
            == AlertSeverity.HIGH
        )

    def test_invalid_defaults_medium(self):
        """Unknown severity defaults to MEDIUM."""
        assert (
            _parse_severity("unknown")
            == AlertSeverity.MEDIUM
        )
        assert (
            _parse_severity("")
            == AlertSeverity.MEDIUM
        )

    def test_none_defaults_medium(self):
        """None input defaults to MEDIUM."""
        assert (
            _parse_severity(None)
            == AlertSeverity.MEDIUM
        )


class TestBuildReason:
    """Test _build_reason helper."""

    def test_new_violation_with_reason(self):
        """NEW_VIOLATION includes drift prefix."""
        result = _build_reason(
            DriftType.NEW_VIOLATION,
            "ok",
            "alarm",
            "Port 22 open",
        )
        assert result == (
            "DRIFT: ok -> alarm. Port 22 open"
        )

    def test_resolution_with_reason(self):
        """RESOLUTION includes resolved prefix."""
        result = _build_reason(
            DriftType.RESOLUTION,
            "alarm",
            "ok",
            "Fixed",
        )
        assert result == (
            "RESOLVED: alarm -> ok. Fixed"
        )

    def test_no_change_with_reason(self):
        """NO_CHANGE uses status prefix."""
        result = _build_reason(
            DriftType.NO_CHANGE,
            "alarm",
            "alarm",
            "Still open",
        )
        assert result == (
            "Status: alarm. Still open"
        )

    def test_without_reason(self):
        """Empty reason returns just prefix."""
        result = _build_reason(
            DriftType.NEW_VIOLATION,
            "ok",
            "alarm",
            "",
        )
        assert result == "DRIFT: ok -> alarm"


class TestDriftDetectorDetect:
    """Test DriftDetector.detect method."""

    def setup_method(self):
        self.detector = DriftDetector()

    def test_first_seen_alarm(self):
        """No previous state + alarm = FIRST_SEEN."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            severity="critical",
            risk_score=92,
            trigger_event=(
                "AuthorizeSecurityGroupIngress"
            ),
            account_id=ACCOUNT,
            region=REGION,
        )
        assert (
            alert.drift_type
            == DriftType.FIRST_SEEN
        )
        assert alert.current_status == "alarm"
        assert alert.previous_status == ""
        assert alert.check_id == "ec2_no_open_ssh"
        assert alert.resource_arn == ARN
        assert alert.risk_score == 92
        assert (
            alert.severity == AlertSeverity.CRITICAL
        )

    def test_first_seen_ok(self):
        """No previous state + ok = FIRST_SEEN."""
        alert = self.detector.detect(
            previous=None,
            current_status="ok",
            check_id="s3_block_public_acls",
            resource_arn="arn:aws:s3:::bucket",
        )
        assert (
            alert.drift_type
            == DriftType.FIRST_SEEN
        )
        assert alert.current_status == "ok"

    def test_first_seen_default_reason(self):
        """First seen with no reason uses default."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
        )
        assert "First evaluation" in alert.reason

    def test_first_seen_custom_reason(self):
        """First seen with custom reason keeps it."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            reason="Port 22 open to world",
        )
        assert alert.reason == (
            "Port 22 open to world"
        )

    def test_ok_to_alarm_drift(self):
        """ok -> alarm = NEW_VIOLATION."""
        prev = _make_prev_state(status="ok")
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            severity="critical",
            risk_score=92,
            reason="SSH open",
            trigger_event=(
                "AuthorizeSecurityGroupIngress"
            ),
            account_id=ACCOUNT,
            region=REGION,
        )
        assert (
            alert.drift_type
            == DriftType.NEW_VIOLATION
        )
        assert alert.previous_status == "ok"
        assert alert.current_status == "alarm"
        assert "DRIFT" in alert.reason

    def test_alarm_to_ok_resolution(self):
        """alarm -> ok = RESOLUTION."""
        prev = _make_prev_state(status="alarm")
        alert = self.detector.detect(
            previous=prev,
            current_status="ok",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            reason="Fixed by admin",
        )
        assert (
            alert.drift_type
            == DriftType.RESOLUTION
        )
        assert alert.previous_status == "alarm"
        assert alert.current_status == "ok"
        assert "RESOLVED" in alert.reason

    def test_no_change_alarm(self):
        """alarm -> alarm = NO_CHANGE."""
        prev = _make_prev_state(status="alarm")
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
        )
        assert (
            alert.drift_type == DriftType.NO_CHANGE
        )

    def test_no_change_ok(self):
        """ok -> ok = NO_CHANGE."""
        prev = _make_prev_state(status="ok")
        alert = self.detector.detect(
            previous=prev,
            current_status="ok",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
        )
        assert (
            alert.drift_type == DriftType.NO_CHANGE
        )

    def test_regression_increments(self):
        """alarm→ok→alarm increments regression."""
        prev = _make_prev_state(
            status="ok",
            resolved_at="2026-02-27T11:30:00Z",
            regression_count=1,
        )
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        assert (
            alert.drift_type
            == DriftType.NEW_VIOLATION
        )

    def test_no_regression_without_resolved_at(self):
        """First alarm doesn't increment regression."""
        prev = _make_prev_state(
            status="ok",
            resolved_at=None,
            regression_count=0,
        )
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        assert (
            alert.drift_type
            == DriftType.NEW_VIOLATION
        )

    def test_timestamp_is_set(self):
        """Alert timestamp is populated."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
        )
        assert alert.timestamp.endswith("Z")
        assert len(alert.timestamp) > 10

    def test_severity_default(self):
        """Empty severity defaults to MEDIUM."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
        )
        assert (
            alert.severity == AlertSeverity.MEDIUM
        )


class TestBuildUpdatedState:
    """Test DriftDetector.build_updated_state."""

    def setup_method(self):
        self.detector = DriftDetector()

    def test_first_seen_builds_new_state(self):
        """First seen creates fresh ViolationState."""
        alert = self.detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            severity="critical",
            risk_score=92,
            reason="SSH open",
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=None,
            alert=alert,
            domain="network",
        )
        assert state.pk == f"{ACCOUNT}#{REGION}"
        assert state.sk == f"ec2_no_open_ssh#{ARN}"
        assert state.status == "alarm"
        assert state.previous_status == ""
        assert state.severity == "critical"
        assert state.domain == "network"
        assert state.first_detected != ""
        assert state.last_evaluated != ""
        assert state.resolved_at is None
        assert state.regression_count == 0

    def test_first_seen_ok_sets_resolved(self):
        """First seen ok sets resolved_at."""
        alert = self.detector.detect(
            previous=None,
            current_status="ok",
            check_id="s3_block_public_acls",
            resource_arn="arn:aws:s3:::bucket",
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=None, alert=alert
        )
        assert state.resolved_at is not None

    def test_drift_preserves_first_detected(self):
        """State update keeps original first_detected."""
        prev = _make_prev_state(status="ok")
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=prev, alert=alert
        )
        assert state.first_detected == (
            "2026-02-27T10:00:00Z"
        )
        assert state.last_evaluated != (
            "2026-02-27T11:00:00Z"
        )

    def test_resolution_sets_resolved_at(self):
        """alarm→ok sets resolved_at."""
        prev = _make_prev_state(status="alarm")
        alert = self.detector.detect(
            previous=prev,
            current_status="ok",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=prev, alert=alert
        )
        assert state.resolved_at is not None
        assert state.status == "ok"
        assert state.previous_status == "alarm"

    def test_new_violation_clears_resolved(self):
        """ok→alarm clears resolved_at."""
        prev = _make_prev_state(
            status="ok",
            resolved_at="2026-02-27T11:30:00Z",
        )
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=prev, alert=alert
        )
        assert state.resolved_at is None
        assert state.status == "alarm"

    def test_regression_incremented(self):
        """Regression count increments on re-alarm."""
        prev = _make_prev_state(
            status="ok",
            resolved_at="2026-02-27T11:30:00Z",
            regression_count=2,
        )
        alert = self.detector.detect(
            previous=prev,
            current_status="alarm",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=prev, alert=alert
        )
        assert state.regression_count == 3

    def test_inherits_previous_domain(self):
        """Domain falls back to previous value."""
        prev = _make_prev_state(status="alarm")
        alert = self.detector.detect(
            previous=prev,
            current_status="ok",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        state = self.detector.build_updated_state(
            previous=prev, alert=alert
        )
        assert state.domain == "network"

    def test_compliance_override(self):
        """Explicit compliance overrides previous."""
        prev = _make_prev_state(status="alarm")
        alert = self.detector.detect(
            previous=prev,
            current_status="ok",
            check_id="ec2_no_open_ssh",
            resource_arn=ARN,
            account_id=ACCOUNT,
            region=REGION,
        )
        new_comp = {"cis_aws": ["5.2"]}
        state = self.detector.build_updated_state(
            previous=prev,
            alert=alert,
            compliance=new_comp,
        )
        assert state.compliance == new_comp
