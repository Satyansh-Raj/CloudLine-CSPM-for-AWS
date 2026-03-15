"""End-to-end integration tests for the real-time
detection pipeline.

Tests the full flow: CloudTrail event → parse → map →
collect → evaluate → drift detect → state persist →
alert generate. Uses mocked AWS services (collectors,
OPA) but real pipeline orchestration logic.
"""

from unittest.mock import MagicMock

from app.models.violation import (
    ComplianceMapping,
    Violation,
)
from app.pipeline.alert_generator import (
    AlertGenerator,
)
from app.pipeline.drift_detector import DriftDetector
from app.pipeline.event_handler import EventHandler
from app.pipeline.event_mapper import (
    EVENT_POLICY_MAP,
    get_event_mapping,
)
from app.pipeline.event_parser import (
    parse_cloudtrail_event,
)
from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
    ViolationState,
)
from app.pipeline.ws_manager import (
    format_drift_event,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"


# ---- Helpers ----

def _raw_event(
    event_name="CreateBucket",
    event_source="s3.amazonaws.com",
    resource_id="my-bucket",
    resource_arn="",
    account_id=ACCOUNT,
    region=REGION,
):
    """Build an EventBridge-wrapped CloudTrail event."""
    return {
        "detail": {
            "eventName": event_name,
            "eventSource": event_source,
            "eventTime": "2026-03-01T12:00:00Z",
            "awsRegion": region,
            "userIdentity": {
                "type": "IAMUser",
                "arn": (
                    "arn:aws:iam::123:user/admin"
                ),
                "accountId": account_id,
            },
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "bucketName": resource_id,
                "groupId": resource_id,
                "userName": resource_id,
                "roleName": resource_id,
                "instanceId": resource_id,
                "name": resource_id,
                "dBInstanceIdentifier": (
                    resource_id
                ),
                "functionName": resource_id,
                "detectorId": resource_id,
            },
            "responseElements": (
                {"arn": resource_arn}
                if resource_arn
                else {}
            ),
        },
    }


def _violation(
    check_id="s3_01",
    status="alarm",
    severity="high",
    reason="S3 bucket publicly accessible",
    domain="data_protection",
):
    """Build a Violation."""
    return Violation(
        check_id=check_id,
        status=status,
        severity=severity,
        reason=reason,
        resource="test-resource",
        domain=domain,
        compliance=ComplianceMapping(
            cis_aws=["2.1.1"],
        ),
        remediation_id=f"REM_{check_id}",
    )


def _make_handler(
    eval_return=None,
    state_return=None,
):
    """Build EventHandler with mock dependencies.

    Args:
        eval_return: What evaluator.evaluate_check
            returns (or a list for side_effect).
        state_return: What state_manager.get_state
            returns.
    """
    evaluator = MagicMock()
    if isinstance(eval_return, list) and eval_return:
        if isinstance(eval_return[0], list):
            evaluator.evaluate_check.side_effect = (
                eval_return
            )
        else:
            evaluator.evaluate_check.return_value = (
                eval_return
            )
    else:
        evaluator.evaluate_check.return_value = (
            eval_return or []
        )

    state_mgr = MagicMock()
    state_mgr.get_state.return_value = state_return
    state_mgr.put_state.return_value = True

    handler = EventHandler(
        session=MagicMock(),
        evaluator=evaluator,
        state_manager=state_mgr,
        account_id=ACCOUNT,
        region=REGION,
    )
    handler.orchestrator = MagicMock()
    handler.orchestrator.collect_targeted.return_value = {}

    return handler, evaluator, state_mgr


# ---- Test Classes ----


class TestFullPipelineFlow:
    """End-to-end: event → parse → map → collect →
    evaluate → drift → persist."""

    def test_s3_create_bucket_full_flow(self):
        """S3 CreateBucket event through full pipe."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(status="alarm"),
            ],
        )

        raw = _raw_event(
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            resource_id="test-bucket",
        )
        alerts = handler.process_event(raw)

        # Parse + map succeeded
        handler.orchestrator.collect_targeted.assert_called_once_with(
            "s3", "test-bucket"
        )
        # Evaluate called for mapped policy
        evaluator.evaluate_check.assert_called_once()
        # Drift detected, state persisted
        assert len(alerts) == 1
        assert (
            alerts[0].drift_type
            == DriftType.FIRST_SEEN
        )
        assert alerts[0].current_status == "alarm"
        state_mgr.put_state.assert_called_once()

    def test_ec2_security_group_full_flow(self):
        """EC2 AuthorizeSecurityGroupIngress → 2
        policies evaluated."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                [_violation(
                    check_id="ec2_05",
                    status="alarm",
                    severity="critical",
                    reason="Port 22 open",
                    domain="network",
                )],
                [_violation(
                    check_id="capital_one_01",
                    status="ok",
                    domain="network",
                )],
            ],
        )

        raw = _raw_event(
            event_name=(
                "AuthorizeSecurityGroupIngress"
            ),
            event_source="ec2.amazonaws.com",
            resource_id="sg-abc123",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 2
        assert (
            evaluator.evaluate_check.call_count == 2
        )
        assert (
            state_mgr.put_state.call_count == 2
        )

        statuses = {
            a.current_status for a in alerts
        }
        assert statuses == {"alarm", "ok"}

    def test_iam_create_user_full_flow(self):
        """IAM CreateUser evaluates identity.iam."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="iam_09",
                    status="alarm",
                    severity="high",
                    reason="MFA not enabled",
                    domain="identity_access",
                ),
            ],
        )

        raw = _raw_event(
            event_name="CreateUser",
            event_source="iam.amazonaws.com",
            resource_id="new-user",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].check_id == "iam_09"

    def test_rds_create_db_full_flow(self):
        """RDS CreateDBInstance full pipeline."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="rds_01",
                    status="alarm",
                    severity="high",
                    reason="RDS not encrypted",
                    domain="data_protection",
                ),
            ],
        )

        raw = _raw_event(
            event_name="CreateDBInstance",
            event_source="rds.amazonaws.com",
            resource_id="my-db",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].check_id
            == "rds_01"
        )
        handler.orchestrator.collect_targeted.assert_called_once_with(
            "rds", "my-db"
        )

    def test_cloudtrail_stop_logging_full_flow(self):
        """StopLogging is a critical security event."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="cloudtrail_01",
                    status="alarm",
                    severity="critical",
                    reason="CloudTrail logging stopped",
                    domain="logging_monitoring",
                ),
            ],
        )

        raw = _raw_event(
            event_name="StopLogging",
            event_source=(
                "cloudtrail.amazonaws.com"
            ),
            resource_id="main-trail",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].severity
            == AlertSeverity.CRITICAL
        )
        handler.orchestrator.collect_targeted.assert_called_once_with(
            "logging", "main-trail"
        )


class TestStateTransitionCycle:
    """ok → alarm → ok full cycle with state."""

    def test_ok_to_alarm_to_ok_cycle(self):
        """Full lifecycle: first_seen → violation →
        resolution."""
        evaluator = MagicMock()
        state_mgr = MagicMock()
        state_mgr.put_state.return_value = True
        detector = DriftDetector()

        handler = EventHandler(
            session=MagicMock(),
            evaluator=evaluator,
            state_manager=state_mgr,
            account_id=ACCOUNT,
            region=REGION,
        )
        handler.orchestrator = MagicMock()
        handler.orchestrator.collect_targeted.return_value = {}

        raw = _raw_event(
            event_name="CreateBucket",
            resource_id="cycle-bucket",
        )

        # Phase 1: First seen (no prior state) → alarm
        state_mgr.get_state.return_value = None
        evaluator.evaluate_check.return_value = [
            _violation(status="alarm"),
        ]
        alerts_1 = handler.process_event(raw)
        assert (
            alerts_1[0].drift_type
            == DriftType.FIRST_SEEN
        )
        assert alerts_1[0].current_status == "alarm"

        # Capture what was persisted
        saved_1 = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved_1.status == "alarm"

        # Phase 2: Still alarm (no change)
        state_mgr.get_state.return_value = saved_1
        evaluator.evaluate_check.return_value = [
            _violation(status="alarm"),
        ]
        alerts_2 = handler.process_event(raw)
        assert (
            alerts_2[0].drift_type
            == DriftType.NO_CHANGE
        )

        # Phase 3: Resolve (alarm → ok)
        state_mgr.get_state.return_value = saved_1
        evaluator.evaluate_check.return_value = [
            _violation(status="ok"),
        ]
        alerts_3 = handler.process_event(raw)
        assert (
            alerts_3[0].drift_type
            == DriftType.RESOLUTION
        )
        assert alerts_3[0].current_status == "ok"
        assert (
            alerts_3[0].previous_status == "alarm"
        )

        saved_3 = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved_3.status == "ok"
        assert saved_3.previous_status == "alarm"
        assert saved_3.resolved_at is not None

    def test_regression_count_increments(self):
        """ok→alarm→ok→alarm increments regression."""
        detector = DriftDetector()

        # Phase 1: First alarm
        alert_1 = detector.detect(
            previous=None,
            current_status="alarm",
            check_id="ec2_05",
            resource_arn="arn:aws:ec2:...:sg/sg-1",
            severity="critical",
            trigger_event=(
                "AuthorizeSecurityGroupIngress"
            ),
            account_id=ACCOUNT,
            region=REGION,
        )
        state_1 = detector.build_updated_state(
            previous=None,
            alert=alert_1,
            domain="network",
        )
        assert state_1.regression_count == 0

        # Phase 2: Resolution
        alert_2 = detector.detect(
            previous=state_1,
            current_status="ok",
            check_id="ec2_05",
            resource_arn="arn:aws:ec2:...:sg/sg-1",
            severity="critical",
            trigger_event=(
                "RevokeSecurityGroupIngress"
            ),
            account_id=ACCOUNT,
            region=REGION,
        )
        state_2 = detector.build_updated_state(
            previous=state_1,
            alert=alert_2,
            domain="network",
        )
        assert state_2.resolved_at is not None
        assert state_2.regression_count == 0

        # Phase 3: Regression (alarm again)
        alert_3 = detector.detect(
            previous=state_2,
            current_status="alarm",
            check_id="ec2_05",
            resource_arn="arn:aws:ec2:...:sg/sg-1",
            severity="critical",
            trigger_event=(
                "AuthorizeSecurityGroupIngress"
            ),
            account_id=ACCOUNT,
            region=REGION,
        )
        state_3 = detector.build_updated_state(
            previous=state_2,
            alert=alert_3,
            domain="network",
        )
        assert state_3.regression_count == 1
        assert state_3.resolved_at is None


class TestEventMappingCoverage:
    """Verify all tracked events map correctly."""

    def test_all_events_have_valid_mapping(self):
        """Every EVENT_POLICY_MAP entry returns a
        valid EventMapping."""
        for event_name in EVENT_POLICY_MAP:
            mapping = get_event_mapping(event_name)
            assert mapping is not None, (
                f"No mapping for {event_name}"
            )
            assert mapping.collector, (
                f"No collector for {event_name}"
            )
            assert len(mapping.policies) > 0, (
                f"No policies for {event_name}"
            )

    def test_all_events_parseable(self):
        """Every tracked event can be parsed from a
        well-formed CloudTrail payload."""
        for event_name in EVENT_POLICY_MAP:
            source = f"{event_name.lower()}.amazonaws.com"
            raw = _raw_event(
                event_name=event_name,
                event_source=source,
                resource_id="test-resource",
            )
            parsed = parse_cloudtrail_event(raw)
            assert parsed is not None, (
                f"Failed to parse {event_name}"
            )
            assert (
                parsed.event_name == event_name
            )

    def test_40_event_types_tracked(self):
        """EVENT_POLICY_MAP has 40 event types."""
        assert len(EVENT_POLICY_MAP) == 40


class TestAlertToWebSocket:
    """DriftAlert → WebSocket message format."""

    def test_violation_alert_to_ws_message(self):
        """NEW_VIOLATION alert formats correctly for
        WebSocket broadcast."""
        alert = DriftAlert(
            drift_type=DriftType.NEW_VIOLATION,
            check_id="ec2_05",
            resource_arn=(
                "arn:aws:ec2:us-east-1:123:sg/sg-1"
            ),
            previous_status="ok",
            current_status="alarm",
            severity=AlertSeverity.CRITICAL,
            risk_score=92,
            trigger_event=(
                "AuthorizeSecurityGroupIngress"
            ),
            timestamp="2026-03-01T12:00:00Z",
            reason="Port 22 open to 0.0.0.0/0",
            account_id=ACCOUNT,
            region=REGION,
        )

        msg = format_drift_event(alert)

        assert msg["type"] == "violation_new"
        assert (
            msg["data"]["check_id"]
            == "ec2_05"
        )
        assert msg["data"]["severity"] == "critical"
        assert msg["data"]["risk_score"] == 92

    def test_resolution_alert_to_ws_message(self):
        """RESOLUTION alert formats as
        violation_resolved."""
        alert = DriftAlert(
            drift_type=DriftType.RESOLUTION,
            check_id="s3_01",
            resource_arn="arn:aws:s3:::my-bucket",
            previous_status="alarm",
            current_status="ok",
            severity=AlertSeverity.HIGH,
            trigger_event=(
                "PutBucketPublicAccessBlock"
            ),
            timestamp="2026-03-01T12:30:00Z",
            reason="S3 bucket no longer public",
            account_id=ACCOUNT,
            region=REGION,
        )

        msg = format_drift_event(alert)

        assert msg["type"] == "violation_resolved"
        assert (
            msg["data"]["current_status"] == "ok"
        )


class TestAlertGeneratorIntegration:
    """AlertGenerator with pipeline alerts."""

    def test_pipeline_alert_publishable(self):
        """Alert from EventHandler can be published."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(status="alarm"),
            ],
        )

        raw = _raw_event()
        alerts = handler.process_event(raw)

        # Verify alert has all fields needed by
        # AlertGenerator
        alert = alerts[0]
        assert alert.check_id
        assert alert.drift_type in (
            DriftType.FIRST_SEEN,
            DriftType.NEW_VIOLATION,
            DriftType.RESOLUTION,
            DriftType.NO_CHANGE,
        )
        assert alert.severity in AlertSeverity
        assert alert.timestamp

    def test_non_alertable_types_filtered(self):
        """FIRST_SEEN and NO_CHANGE don't publish."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=""
        )

        first_seen = DriftAlert(
            drift_type=DriftType.FIRST_SEEN,
            check_id="s3_01",
        )
        no_change = DriftAlert(
            drift_type=DriftType.NO_CHANGE,
            check_id="s3_01",
        )

        assert gen.publish(first_seen) is False
        assert gen.publish(no_change) is False


class TestMultiServiceEvents:
    """Different AWS service events through pipeline."""

    def test_lambda_function_creation(self):
        """Lambda CreateFunction20150331."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="serverless_01",
                    status="alarm",
                    severity="medium",
                    reason="Lambda not in VPC",
                    domain="serverless",
                ),
            ],
        )

        raw = _raw_event(
            event_name="CreateFunction20150331",
            event_source="lambda.amazonaws.com",
            resource_id="my-function",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].check_id
            == "serverless_01"
        )
        handler.orchestrator.collect_targeted.assert_called_once_with(
            "lambda", "my-function"
        )

    def test_guardduty_delete_detector(self):
        """GuardDuty DeleteDetector."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="awssec_01",
                    status="alarm",
                    severity="critical",
                    reason="GuardDuty disabled",
                    domain="logging_monitoring",
                ),
            ],
        )

        raw = _raw_event(
            event_name="DeleteDetector",
            event_source="guardduty.amazonaws.com",
            resource_id="detector-123",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].check_id
            == "awssec_01"
        )

    def test_ebs_create_volume(self):
        """EBS CreateVolume."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    check_id="storage_01",
                    status="alarm",
                    severity="medium",
                    reason="EBS volume unencrypted",
                    domain="data_protection",
                ),
            ],
        )

        raw = _raw_event(
            event_name="CreateVolume",
            event_source="ec2.amazonaws.com",
            resource_id="vol-abc",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert (
            alerts[0].check_id
            == "storage_01"
        )


class TestUntracked:
    """Untracked events and malformed payloads."""

    def test_untracked_event_returns_empty(self):
        """Events not in EVENT_POLICY_MAP produce
        no alerts."""
        handler, _, _ = _make_handler()
        raw = _raw_event(
            event_name="DescribeBuckets",
            event_source="s3.amazonaws.com",
        )
        alerts = handler.process_event(raw)
        assert alerts == []

    def test_malformed_event_returns_empty(self):
        """Missing required fields returns empty."""
        handler, _, _ = _make_handler()
        alerts = handler.process_event({})
        assert alerts == []

    def test_missing_event_source(self):
        """Event with no eventSource returns empty."""
        handler, _, _ = _make_handler()
        raw = {
            "detail": {
                "eventName": "CreateBucket",
                "eventTime": "2026-03-01T12:00:00Z",
            }
        }
        alerts = handler.process_event(raw)
        assert alerts == []


class TestRiskScoreE2E:
    """Risk scoring flows through the full pipeline."""

    def test_alarm_gets_risk_score(self):
        """Alarm violation produces non-zero risk."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    status="alarm",
                    severity="critical",
                ),
            ],
        )

        raw = _raw_event(
            event_name="CreateBucket",
            resource_id="risky-bucket",
        )
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].risk_score > 0

        saved = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved.risk_score > 0
        assert saved.risk_score == (
            alerts[0].risk_score
        )

    def test_risk_score_with_resource_tags(self):
        """Resource tags affect data sensitivity."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    status="alarm",
                    severity="high",
                ),
            ],
        )
        handler.orchestrator.collect_targeted.return_value = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "pii",
                }
            ]
        }

        raw = _raw_event(
            event_name="CreateBucket",
            resource_id="pii-bucket",
        )
        alerts = handler.process_event(raw)

        # PII tag should boost the score
        assert alerts[0].risk_score > 30

    def test_empty_violations_zero_risk(self):
        """No violations → zero risk score."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[],
        )

        raw = _raw_event()
        alerts = handler.process_event(raw)

        assert len(alerts) == 1
        assert alerts[0].risk_score == 0

class TestStatePersistenceFields:
    """Verify all expected fields on persisted state."""

    def test_first_seen_state_has_all_fields(self):
        """State from first evaluation has required
        DynamoDB fields."""
        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(
                    status="alarm",
                    severity="high",
                    reason="S3 public",
                    domain="data_protection",
                ),
            ],
        )

        raw = _raw_event(resource_id="test-bucket")
        handler.process_event(raw)

        saved = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved.pk == f"{ACCOUNT}#{REGION}"
        assert saved.check_id
        assert saved.status == "alarm"
        assert saved.severity == "high"
        assert saved.domain == "data_protection"
        assert saved.resource_arn
        assert saved.reason
        assert saved.first_detected
        assert saved.last_evaluated

    def test_drift_state_preserves_previous(self):
        """State after drift has correct
        previous_status."""
        prev = ViolationState(
            pk=f"{ACCOUNT}#{REGION}",
            sk="s3_01#test-bucket",
            check_id="s3_01",
            status="ok",
            severity="high",
            domain="data_protection",
            resource_arn="test-bucket",
            first_detected="2026-03-01T10:00:00Z",
            last_evaluated="2026-03-01T11:00:00Z",
        )

        handler, evaluator, state_mgr = _make_handler(
            eval_return=[
                _violation(status="alarm"),
            ],
            state_return=prev,
        )

        raw = _raw_event(resource_id="test-bucket")
        handler.process_event(raw)

        saved = (
            state_mgr.put_state.call_args.args[0]
        )
        assert saved.status == "alarm"
        assert saved.previous_status == "ok"
        assert saved.first_detected == (
            "2026-03-01T10:00:00Z"
        )
