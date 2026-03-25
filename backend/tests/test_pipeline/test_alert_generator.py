"""Tests for AlertGenerator SNS publishing."""

import json
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from app.pipeline.alert_generator import (  # noqa: I001
    _ALERTABLE_TYPES,
    AlertGenerator,
)
from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
)

TOPIC_ARN = (
    "arn:aws:sns:us-east-1:123456789012:alerts"
)
ACCOUNT = "123456789012"
REGION = "us-east-1"


def _make_alert(
    drift_type=DriftType.NEW_VIOLATION,
    check_id="ec2_no_open_ssh",
    resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
    previous_status="ok",
    current_status="alarm",
    severity=AlertSeverity.CRITICAL,
    risk_score=92,
    trigger_event="AuthorizeSecurityGroupIngress",
    reason="Port 22 open to 0.0.0.0/0",
    account_id=ACCOUNT,
    region=REGION,
):
    """Build a DriftAlert for testing."""
    return DriftAlert(
        drift_type=drift_type,
        check_id=check_id,
        resource_arn=resource_arn,
        previous_status=previous_status,
        current_status=current_status,
        severity=severity,
        risk_score=risk_score,
        trigger_event=trigger_event,
        timestamp="2026-02-28T12:00:00Z",
        reason=reason,
        account_id=account_id,
        region=region,
    )


class TestPublishHappyPath:
    """SNS publish with moto."""

    @mock_aws
    def test_new_violation_published(self):
        """new_violation alert published to SNS."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")
        arn = topic["TopicArn"]

        gen = AlertGenerator(
            session=session, topic_arn=arn
        )
        alert = _make_alert(
            drift_type=DriftType.NEW_VIOLATION
        )
        result = gen.publish(alert)

        assert result is True

    @mock_aws
    def test_resolution_published(self):
        """resolution alert published to SNS."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")
        arn = topic["TopicArn"]

        gen = AlertGenerator(
            session=session, topic_arn=arn
        )
        alert = _make_alert(
            drift_type=DriftType.RESOLUTION,
            previous_status="alarm",
            current_status="ok",
        )
        result = gen.publish(alert)

        assert result is True


class TestNoTopicArn:
    """Graceful fallback when no topic configured."""

    def test_no_topic_returns_false(self):
        """Empty topic ARN returns False."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=""
        )
        alert = _make_alert()
        result = gen.publish(alert)
        assert result is False

    def test_no_topic_does_not_call_sns(self):
        """No SNS client call when no topic."""
        session = MagicMock()
        gen = AlertGenerator(
            session=session, topic_arn=""
        )
        gen.publish(_make_alert())
        session.client.assert_not_called()


class TestNonAlertableTypes:
    """Skipping NO_CHANGE and FIRST_SEEN."""

    def test_no_change_skipped(self):
        """NO_CHANGE drift type not published."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            drift_type=DriftType.NO_CHANGE
        )
        result = gen.publish(alert)
        assert result is False

    def test_first_seen_skipped(self):
        """FIRST_SEEN drift type not published."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            drift_type=DriftType.FIRST_SEEN,
            previous_status="",
        )
        result = gen.publish(alert)
        assert result is False

    def test_alertable_types_correct(self):
        """Only NEW_VIOLATION and RESOLUTION alertable."""
        assert _ALERTABLE_TYPES == {
            DriftType.NEW_VIOLATION,
            DriftType.RESOLUTION,
        }


class TestSNSError:
    """Error handling on publish failure."""

    def test_publish_error_returns_false(self):
        """SNS exception returns False."""
        session = MagicMock()
        client = MagicMock()
        client.publish.side_effect = Exception(
            "SNS down"
        )
        session.client.return_value = client

        gen = AlertGenerator(
            session=session, topic_arn=TOPIC_ARN
        )
        result = gen.publish(_make_alert())
        assert result is False


class TestFormatMessage:
    """Message payload format."""

    def test_message_contains_all_fields(self):
        """Plain-text message has all key fields."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert()
        msg = gen._format_message(alert)

        assert isinstance(msg, str)
        assert "ec2_no_open_ssh" in msg
        assert "arn:aws:ec2" in msg
        assert "ok" in msg
        assert "alarm" in msg
        assert "CRITICAL" in msg
        assert "92" in msg
        assert (
            "AuthorizeSecurityGroupIngress" in msg
        )
        assert "Port 22" in msg
        assert ACCOUNT in msg
        assert REGION in msg

    def test_message_is_plain_text(self):
        """Message is a plain-text string."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert()
        msg = gen._format_message(alert)
        assert isinstance(msg, str)
        assert "WHAT HAPPENED" in msg
        assert "ENVIRONMENT" in msg


class TestFormatSubject:
    """Subject line format."""

    def test_violation_subject(self):
        """NEW_VIOLATION → [ALERT] prefix."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            drift_type=DriftType.NEW_VIOLATION,
            severity=AlertSeverity.CRITICAL,
        )
        subject = gen._format_subject(alert)
        assert subject.startswith("[ALERT]")
        assert "ec2_no_open_ssh" in subject
        assert "CRITICAL" in subject

    def test_resolution_subject(self):
        """RESOLUTION → [RESOLVED] prefix."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            drift_type=DriftType.RESOLUTION,
        )
        subject = gen._format_subject(alert)
        assert subject.startswith("[RESOLVED]")

    def test_subject_max_100_chars(self):
        """Subject truncated to 100 characters."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            check_id="check_" + "x" * 120,
        )
        subject = gen._format_subject(alert)
        assert len(subject) <= 100


class TestAttributes:
    """SNS MessageAttributes for filtering."""

    def test_attributes_contain_drift_type(self):
        """drift_type attribute set."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert()
        attrs = gen._attributes(alert)

        assert (
            attrs["drift_type"]["StringValue"]
            == "new_violation"
        )
        assert (
            attrs["drift_type"]["DataType"] == "String"
        )

    def test_attributes_contain_severity(self):
        """severity attribute set."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert(
            severity=AlertSeverity.HIGH
        )
        attrs = gen._attributes(alert)
        assert (
            attrs["severity"]["StringValue"] == "high"
        )

    def test_attributes_contain_check_id(self):
        """check_id attribute set."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        alert = _make_alert()
        attrs = gen._attributes(alert)
        assert (
            attrs["check_id"]["StringValue"]
            == "ec2_no_open_ssh"
        )


class TestPublishBatch:
    """Batch publish multiple alerts."""

    @mock_aws
    def test_batch_publishes_alertable_only(self):
        """Only new_violation/resolution counted."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")
        arn = topic["TopicArn"]

        gen = AlertGenerator(
            session=session, topic_arn=arn
        )
        alerts = [
            _make_alert(
                drift_type=DriftType.NEW_VIOLATION
            ),
            _make_alert(
                drift_type=DriftType.NO_CHANGE
            ),
            _make_alert(
                drift_type=DriftType.RESOLUTION,
                previous_status="alarm",
                current_status="ok",
            ),
            _make_alert(
                drift_type=DriftType.FIRST_SEEN,
                previous_status="",
            ),
        ]
        count = gen.publish_batch(alerts)

        assert count == 2

    def test_batch_empty_list(self):
        """Empty batch returns 0."""
        gen = AlertGenerator(
            session=MagicMock(), topic_arn=TOPIC_ARN
        )
        assert gen.publish_batch([]) == 0

    @mock_aws
    def test_batch_all_published(self):
        """All alertable alerts counted."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")
        arn = topic["TopicArn"]

        gen = AlertGenerator(
            session=session, topic_arn=arn
        )
        alerts = [
            _make_alert(
                drift_type=DriftType.NEW_VIOLATION,
                check_id=f"check_{i}",
            )
            for i in range(3)
        ]
        count = gen.publish_batch(alerts)
        assert count == 3


class TestLazyClient:
    """Lazy SNS client initialization."""

    def test_client_created_on_first_access(self):
        """Client not created until first publish."""
        session = MagicMock()
        gen = AlertGenerator(
            session=session, topic_arn=TOPIC_ARN
        )
        session.client.assert_not_called()

        _ = gen.client
        session.client.assert_called_once_with("sns")

    def test_client_reused(self):
        """Same client instance returned."""
        session = MagicMock()
        gen = AlertGenerator(
            session=session, topic_arn=TOPIC_ARN
        )
        c1 = gen.client
        c2 = gen.client
        assert c1 is c2
        session.client.assert_called_once()

    def test_endpoint_url_passed(self):
        """Custom endpoint_url forwarded to client."""
        session = MagicMock()
        gen = AlertGenerator(
            session=session,
            topic_arn=TOPIC_ARN,
            endpoint_url="http://localhost:4566",
        )
        _ = gen.client
        session.client.assert_called_once_with(
            "sns",
            endpoint_url="http://localhost:4566",
        )


class TestSNSPublishPayload:
    """Verify the actual SNS publish call args."""

    @mock_aws
    def test_publish_call_args(self):
        """SNS publish called with correct params."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")
        arn = topic["TopicArn"]

        gen = AlertGenerator(
            session=session, topic_arn=arn
        )
        alert = _make_alert()

        # Replace client to inspect calls
        mock_client = MagicMock()
        gen._client = mock_client

        gen.publish(alert)

        mock_client.publish.assert_called_once()
        call_kwargs = (
            mock_client.publish.call_args.kwargs
        )
        assert call_kwargs["TopicArn"] == arn
        assert "[ALERT]" in call_kwargs["Subject"]

        msg = call_kwargs["Message"]
        assert isinstance(msg, str)
        assert alert.check_id in msg

        attrs = call_kwargs["MessageAttributes"]
        assert "drift_type" in attrs
        assert "severity" in attrs
        assert "check_id" in attrs
