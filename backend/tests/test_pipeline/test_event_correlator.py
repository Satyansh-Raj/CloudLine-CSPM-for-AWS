"""Tests for EventCorrelator time-window grouping."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from app.pipeline.event_correlator import (
    TTL_HOURS,
    EventCorrelator,
)
from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
TABLE = "event-correlation"


def _make_alert(
    drift_type=DriftType.NEW_VIOLATION,
    check_id="ec2_05",
    resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
    trigger_event="AuthorizeSecurityGroupIngress",
    severity=AlertSeverity.CRITICAL,
    account_id=ACCOUNT,
    region=REGION,
    timestamp="2026-02-28T12:00:00Z",
):
    """Build a DriftAlert for testing."""
    return DriftAlert(
        drift_type=drift_type,
        check_id=check_id,
        resource_arn=resource_arn,
        previous_status="ok",
        current_status="alarm",
        severity=severity,
        risk_score=92,
        trigger_event=trigger_event,
        timestamp=timestamp,
        reason="Test reason",
        account_id=account_id,
        region=region,
    )


def _create_table(session):
    """Create the event-correlation DynamoDB table."""
    dynamo = session.client("dynamodb")
    dynamo.create_table(
        TableName=TABLE,
        AttributeDefinitions=[
            {
                "AttributeName": "pk",
                "AttributeType": "S",
            },
            {
                "AttributeName": "sk",
                "AttributeType": "S",
            },
        ],
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
        BillingMode="PAY_PER_REQUEST",
    )


class TestCorrelateNewGroup:
    """First event in a group creates new window."""

    @mock_aws
    def test_first_event_returns_true(self):
        """First event should trigger alert."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        result = correlator.correlate(alert)

        assert result is True

    @mock_aws
    def test_new_window_record_created(self):
        """DynamoDB record written for new window."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        correlator.correlate(alert)

        # Scan to find the record
        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        items = resp["Items"]

        assert len(items) == 1
        item = items[0]
        assert item["event_count"] == 1
        assert item["alert_sent"] is True
        assert len(item["events"]) == 1
        assert (
            item["events"][0]["check_id"]
            == "ec2_05"
        )

    @mock_aws
    def test_ttl_set_to_24h(self):
        """TTL is 24 hours from creation."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        now = datetime.now(UTC)
        alert = _make_alert()
        correlator.correlate(alert)

        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        item = resp["Items"][0]

        expected_ttl = int(
            (
                now + timedelta(hours=TTL_HOURS)
            ).timestamp()
        )
        # Allow 5 seconds tolerance
        assert abs(int(item["ttl"]) - expected_ttl) < 5


class TestCorrelateExistingWindow:
    """Events within the same window are grouped."""

    @mock_aws
    def test_second_event_deduped(self):
        """Second event in same group returns False."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert1 = _make_alert()
        alert2 = _make_alert(
            resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-2",
        )

        result1 = correlator.correlate(alert1)
        result2 = correlator.correlate(alert2)

        assert result1 is True
        assert result2 is False

    @mock_aws
    def test_event_appended_to_window(self):
        """Second event increments count and appends."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert1 = _make_alert()
        alert2 = _make_alert(
            resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-2",
        )

        correlator.correlate(alert1)
        correlator.correlate(alert2)

        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        item = resp["Items"][0]

        assert item["event_count"] == 2
        assert len(item["events"]) == 2

    @mock_aws
    def test_three_events_in_window(self):
        """Multiple events accumulated correctly."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )

        for i in range(3):
            alert = _make_alert(
                resource_arn=f"arn:aws:ec2:us-east-1:123:sg/sg-{i}",
            )
            correlator.correlate(alert)

        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        item = resp["Items"][0]

        assert item["event_count"] == 3
        assert len(item["events"]) == 3


class TestCorrelateDistinctGroups:
    """Different groups create separate windows."""

    @mock_aws
    def test_different_check_ids_separate(self):
        """Different check_ids = different groups."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert1 = _make_alert(
            check_id="ec2_05"
        )
        alert2 = _make_alert(
            check_id="s3_01"
        )

        r1 = correlator.correlate(alert1)
        r2 = correlator.correlate(alert2)

        assert r1 is True
        assert r2 is True

        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        assert len(resp["Items"]) == 2

    @mock_aws
    def test_different_accounts_separate(self):
        """Different accounts = different groups."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert1 = _make_alert(
            account_id="111111111111"
        )
        alert2 = _make_alert(
            account_id="222222222222"
        )

        r1 = correlator.correlate(alert1)
        r2 = correlator.correlate(alert2)

        assert r1 is True
        assert r2 is True

    @mock_aws
    def test_different_regions_separate(self):
        """Different regions = different groups."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert1 = _make_alert(region="us-east-1")
        alert2 = _make_alert(region="eu-west-1")

        r1 = correlator.correlate(alert1)
        r2 = correlator.correlate(alert2)

        assert r1 is True
        assert r2 is True


class TestGroupKey:
    """_group_key formatting."""

    def test_group_key_format(self):
        """Key is account#region#check_id."""
        correlator = EventCorrelator(
            session=MagicMock(), table_name=TABLE
        )
        alert = _make_alert(
            account_id="111111111111",
            region="eu-west-1",
            check_id="s3_01",
        )
        key = correlator._group_key(alert)
        assert key == (
            "111111111111"
            "#eu-west-1"
            "#s3_01"
        )


class TestEventSummary:
    """_event_summary payload."""

    def test_summary_fields(self):
        """Summary contains expected fields."""
        correlator = EventCorrelator(
            session=MagicMock(), table_name=TABLE
        )
        alert = _make_alert()
        summary = correlator._event_summary(alert)

        assert (
            summary["check_id"]
            == "ec2_05"
        )
        assert summary["resource_arn"].endswith(
            "sg/sg-1"
        )
        assert summary["drift_type"] == "new_violation"
        assert summary["severity"] == "critical"
        assert (
            summary["trigger_event"]
            == "AuthorizeSecurityGroupIngress"
        )
        assert summary["timestamp"].endswith("Z")


class TestGetGroup:
    """get_group direct lookup."""

    @mock_aws
    def test_get_existing_group(self):
        """Returns item when it exists."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        correlator.correlate(alert)

        # Find the record's sk
        table = session.resource("dynamodb").Table(
            TABLE
        )
        resp = table.scan()
        item = resp["Items"][0]

        result = correlator.get_group(
            item["pk"], item["sk"]
        )
        assert result is not None
        assert result["event_count"] == 1

    @mock_aws
    def test_get_nonexistent_group(self):
        """Returns None when not found."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        result = correlator.get_group(
            "nonexistent", "2026-01-01T00:00:00"
        )
        assert result is None

    def test_get_group_error_returns_none(self):
        """DynamoDB error returns None."""
        session = MagicMock()
        table = MagicMock()
        table.get_item.side_effect = Exception(
            "DynamoDB down"
        )
        resource = MagicMock()
        resource.Table.return_value = table
        session.resource.return_value = resource

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        result = correlator.get_group("key", "sk")
        assert result is None


class TestConfigurableWindow:
    """Window size configuration."""

    def test_default_window_5_minutes(self):
        """Default window is 5 minutes."""
        correlator = EventCorrelator(
            session=MagicMock(), table_name=TABLE
        )
        assert correlator.window_minutes == 5

    def test_custom_window(self):
        """Custom window size accepted."""
        correlator = EventCorrelator(
            session=MagicMock(),
            table_name=TABLE,
            window_minutes=10,
        )
        assert correlator.window_minutes == 10


class TestErrorHandling:
    """Error branches in correlator."""

    def test_query_error_creates_new_window(self):
        """Query failure falls through to new window."""
        session = MagicMock()
        table = MagicMock()
        table.query.side_effect = Exception(
            "Query failed"
        )
        table.put_item.return_value = {}
        resource = MagicMock()
        resource.Table.return_value = table
        session.resource.return_value = resource

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        result = correlator.correlate(alert)

        # Query fails → no existing window found →
        # creates new window → returns True
        assert result is True
        table.put_item.assert_called_once()

    def test_create_window_error_returns_true(self):
        """Create failure still returns True
        (correlate returns True for first-in-group)."""
        session = MagicMock()
        table = MagicMock()
        table.query.return_value = {"Items": []}
        table.put_item.side_effect = Exception(
            "Write failed"
        )
        resource = MagicMock()
        resource.Table.return_value = table
        session.resource.return_value = resource

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        result = correlator.correlate(alert)

        # Even though persistence failed, this is a
        # new group so alert should still fire
        assert result is True

    def test_append_error_still_checks_dedup(self):
        """Append failure doesn't prevent dedup check."""
        session = MagicMock()
        table = MagicMock()
        existing = {
            "pk": "123#us-east-1#ec2_05",
            "sk": "2026-02-28T12:00:00",
            "alert_sent": True,
            "events": [],
            "event_count": 1,
        }
        table.query.return_value = {
            "Items": [existing]
        }
        table.update_item.side_effect = Exception(
            "Update failed"
        )
        resource = MagicMock()
        resource.Table.return_value = table
        session.resource.return_value = resource

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        result = correlator.correlate(alert)

        # Existing window has alert_sent=True → dedup
        assert result is False

    def test_mark_alerted_error_still_returns_true(
        self,
    ):
        """mark_alerted failure still allows alert."""
        session = MagicMock()
        table = MagicMock()
        existing = {
            "pk": "123#us-east-1#ec2_05",
            "sk": "2026-02-28T12:00:00",
            "alert_sent": False,
            "events": [],
            "event_count": 1,
        }
        table.query.return_value = {
            "Items": [existing]
        }
        # First update_item = append (succeeds)
        # Second update_item = mark_alerted (fails)
        table.update_item.side_effect = [
            {},
            Exception("Mark failed"),
        ]
        resource = MagicMock()
        resource.Table.return_value = table
        session.resource.return_value = resource

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        alert = _make_alert()
        result = correlator.correlate(alert)

        # alert_sent was False, so alert should fire
        assert result is True


class TestMarkAlerted:
    """_mark_alerted success path."""

    @mock_aws
    def test_mark_alerted_success(self):
        """mark_alerted sets alert_sent to True."""
        session = boto3.Session(
            region_name="us-east-1"
        )
        _create_table(session)

        table = session.resource("dynamodb").Table(
            TABLE
        )
        # Manually insert a window with
        # alert_sent=False
        window = {
            "pk": f"{ACCOUNT}#us-east-1#ec2_05",
            "sk": "2026-02-28T12:00:00",
            "events": [],
            "event_count": 1,
            "alert_sent": False,
            "ttl": 9999999999,
        }
        table.put_item(Item=window)

        correlator = EventCorrelator(
            session=session, table_name=TABLE
        )
        result = correlator._mark_alerted(window)
        assert result is True

        # Verify flag is now True in DB
        item = table.get_item(
            Key={
                "pk": window["pk"],
                "sk": window["sk"],
            },
        )["Item"]
        assert item["alert_sent"] is True


class TestEndpointUrl:
    """Custom endpoint_url for DynamoDB Local."""

    def test_endpoint_url_passed(self):
        """endpoint_url forwarded to resource."""
        session = MagicMock()
        EventCorrelator(
            session=session,
            table_name=TABLE,
            endpoint_url="http://localhost:9730",
        )
        session.resource.assert_called_once_with(
            "dynamodb",
            endpoint_url="http://localhost:9730",
        )

    def test_no_endpoint_url(self):
        """No endpoint_url when not specified."""
        session = MagicMock()
        EventCorrelator(
            session=session, table_name=TABLE
        )
        session.resource.assert_called_once_with(
            "dynamodb",
        )
