"""Tests for StateManager DynamoDB CRUD operations."""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.pipeline.models import ViolationState
from app.pipeline.state_manager import (
    StateManager,
    _item_to_state,
    _state_to_item,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
TABLE_NAME = "violation-state"


def _create_table(session):
    """Create the violation-state table with GSIs."""
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


def _make_state(
    check_id="ec2_no_open_ssh",
    resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
    status="alarm",
    severity="critical",
    domain="network",
    risk_score=92,
    reason="Open SSH to 0.0.0.0/0",
):
    """Build a ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        severity=severity,
        domain=domain,
        resource_arn=resource_arn,
        risk_score=risk_score,
        reason=reason,
        first_detected="2026-02-27T10:00:00Z",
        last_evaluated="2026-02-27T12:00:00Z",
    )


@pytest.fixture
def state_mgr(aws_credentials):
    """Create StateManager with moto DynamoDB."""
    with mock_aws():
        session = boto3.Session(
            region_name=REGION
        )
        _create_table(session)
        yield StateManager(session, TABLE_NAME)


class TestPutAndGetState:
    """Test put_state and get_state operations."""

    def test_put_and_get_roundtrip(self, state_mgr):
        """Write and read back a state record."""
        state = _make_state()
        assert state_mgr.put_state(state) is True

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result is not None
        assert result.check_id == "ec2_no_open_ssh"
        assert result.status == "alarm"
        assert result.severity == "critical"
        assert result.risk_score == 92
        assert result.domain == "network"

    def test_get_nonexistent_returns_none(
        self, state_mgr
    ):
        """Missing record returns None."""
        result = state_mgr.get_state(
            ACCOUNT, REGION, "NOPE", "arn:fake"
        )
        assert result is None

    def test_put_overwrites_existing(
        self, state_mgr
    ):
        """Second put overwrites the first."""
        state1 = _make_state(status="ok")
        state2 = _make_state(status="alarm")
        state_mgr.put_state(state1)
        state_mgr.put_state(state2)

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result.status == "alarm"

    def test_put_state_with_none_fields(
        self, state_mgr
    ):
        """None fields are stripped before write."""
        state = _make_state()
        state.resolved_at = None
        state.ttl = None
        assert state_mgr.put_state(state) is True

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result is not None
        assert result.resolved_at is None


class TestUpdateStatus:
    """Test update_status operation."""

    def test_update_changes_status(
        self, state_mgr
    ):
        """Update status field in place."""
        state = _make_state(status="alarm")
        state_mgr.put_state(state)

        ok = state_mgr.update_status(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
            "ok",
            reason="Fixed",
            risk_score=0,
        )
        assert ok is True

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result.status == "ok"
        assert result.reason == "Fixed"
        assert result.risk_score == 0
        assert result.resolved_at is not None

    def test_update_sets_last_evaluated(
        self, state_mgr
    ):
        """Update refreshes last_evaluated."""
        state = _make_state()
        state_mgr.put_state(state)

        state_mgr.update_status(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
            "alarm",
        )

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result.last_evaluated != ""
        assert result.last_evaluated.endswith("Z")


class TestQueryByAccount:
    """Test query_by_account operation."""

    def test_returns_matching_records(
        self, state_mgr
    ):
        """Query returns all records for account."""
        s1 = _make_state(check_id="iam_root_mfa")
        s2 = _make_state(check_id="iam_pwd_min_length")
        state_mgr.put_state(s1)
        state_mgr.put_state(s2)

        results = state_mgr.query_by_account(
            ACCOUNT, REGION
        )
        assert len(results) == 2
        check_ids = {r.check_id for r in results}
        assert check_ids == {
            "iam_root_mfa",
            "iam_pwd_min_length",
        }

    def test_empty_account_returns_empty(
        self, state_mgr
    ):
        """Unknown account returns empty list."""
        results = state_mgr.query_by_account(
            "999999999999", REGION
        )
        assert results == []

    def test_limit_respected(self, state_mgr):
        """Limit caps the result count."""
        for i in range(5):
            state_mgr.put_state(
                _make_state(check_id=f"test_{i:02d}")
            )

        results = state_mgr.query_by_account(
            ACCOUNT, REGION, limit=3
        )
        assert len(results) == 3


class TestQueryByStatus:
    """Test query_by_status via GSI-1."""

    def test_returns_alarm_records(
        self, state_mgr
    ):
        """Query alarm status returns matches."""
        s1 = _make_state(
            check_id="iam_root_mfa", status="alarm"
        )
        s2 = _make_state(
            check_id="iam_pwd_min_length", status="ok"
        )
        state_mgr.put_state(s1)
        state_mgr.put_state(s2)

        alarms = state_mgr.query_by_status("alarm")
        assert len(alarms) == 1
        assert alarms[0].check_id == "iam_root_mfa"

    def test_returns_ok_records(self, state_mgr):
        """Query ok status returns matches."""
        s1 = _make_state(
            check_id="iam_root_mfa", status="ok"
        )
        state_mgr.put_state(s1)

        results = state_mgr.query_by_status("ok")
        assert len(results) == 1

    def test_empty_status_returns_empty(
        self, state_mgr
    ):
        """Unknown status returns empty list."""
        results = state_mgr.query_by_status(
            "nonexistent"
        )
        assert results == []


class TestQueryByDomain:
    """Test query_by_domain via GSI-2."""

    def test_returns_domain_records(
        self, state_mgr
    ):
        """Query by domain returns matches."""
        s1 = _make_state(
            check_id="ec2_no_open_ssh", domain="network"
        )
        s2 = _make_state(
            check_id="s3_block_public_acls",
            domain="data_protection",
        )
        state_mgr.put_state(s1)
        state_mgr.put_state(s2)

        results = state_mgr.query_by_domain(
            "network"
        )
        assert len(results) == 1
        assert results[0].domain == "network"

    def test_empty_domain_returns_empty(
        self, state_mgr
    ):
        """Unknown domain returns empty list."""
        results = state_mgr.query_by_domain(
            "nonexistent"
        )
        assert results == []


class TestQueryByCheck:
    """Test query_by_check via GSI-3."""

    def test_returns_check_records(
        self, state_mgr
    ):
        """Query by check_id returns matches."""
        s1 = _make_state(
            check_id="ec2_no_open_ssh",
            resource_arn="arn:aws:ec2:...:sg/sg-1",
        )
        s2 = _make_state(
            check_id="ec2_no_open_ssh",
            resource_arn="arn:aws:ec2:...:sg/sg-2",
        )
        s3 = _make_state(check_id="s3_block_public_acls")
        state_mgr.put_state(s1)
        state_mgr.put_state(s2)
        state_mgr.put_state(s3)

        results = state_mgr.query_by_check(
            "ec2_no_open_ssh"
        )
        assert len(results) == 2
        for r in results:
            assert r.check_id == "ec2_no_open_ssh"

    def test_empty_check_returns_empty(
        self, state_mgr
    ):
        """Unknown check returns empty list."""
        results = state_mgr.query_by_check(
            "unknown_99"
        )
        assert results == []


class TestDeleteState:
    """Test delete_state operation."""

    def test_delete_removes_record(
        self, state_mgr
    ):
        """Delete removes the record."""
        state = _make_state()
        state_mgr.put_state(state)

        ok = state_mgr.delete_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert ok is True

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result is None

    def test_delete_nonexistent_succeeds(
        self, state_mgr
    ):
        """Deleting missing record still returns True."""
        ok = state_mgr.delete_state(
            ACCOUNT, REGION, "NOPE", "arn:fake"
        )
        assert ok is True


class TestCountByStatus:
    """Test count_by_status operation."""

    def test_counts_alarm_records(
        self, state_mgr
    ):
        """Count alarm violations."""
        for i in range(3):
            state_mgr.put_state(
                _make_state(
                    check_id=f"test_{i:02d}",
                    status="alarm",
                )
            )
        state_mgr.put_state(
            _make_state(
                check_id="unknown_99",
                status="ok",
            )
        )

        assert (
            state_mgr.count_by_status("alarm") == 3
        )
        assert (
            state_mgr.count_by_status("ok") == 1
        )

    def test_count_empty_returns_zero(
        self, state_mgr
    ):
        """Empty table returns 0."""
        assert (
            state_mgr.count_by_status("alarm") == 0
        )


class TestStateToItem:
    """Test _state_to_item helper."""

    def test_strips_none_values(self):
        """None fields are removed from item."""
        state = _make_state()
        state.resolved_at = None
        state.ttl = None
        item = _state_to_item(state)
        assert "resolved_at" not in item
        assert "ttl" not in item

    def test_preserves_all_fields(self):
        """Non-None fields are all present."""
        state = _make_state()
        state.resolved_at = "2026-02-27T13:00:00Z"
        item = _state_to_item(state)
        assert item["pk"] == f"{ACCOUNT}#{REGION}"
        assert item["check_id"] == "ec2_no_open_ssh"
        assert item["status"] == "alarm"
        assert item["resolved_at"] == (
            "2026-02-27T13:00:00Z"
        )


class TestItemToState:
    """Test _item_to_state helper."""

    def test_converts_decimals(self):
        """DynamoDB Decimal values are converted."""
        from decimal import Decimal

        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "ec2_no_open_ssh#arn",
            "check_id": "ec2_no_open_ssh",
            "status": "alarm",
            "risk_score": Decimal("92"),
            "regression_count": Decimal("3"),
        }
        state = _item_to_state(item)
        assert state.risk_score == 92
        assert isinstance(state.risk_score, int)
        assert state.regression_count == 3

    def test_handles_missing_optional_fields(self):
        """Minimal item converts successfully."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "iam_root_mfa#arn",
            "check_id": "iam_root_mfa",
        }
        state = _item_to_state(item)
        assert state.status == "ok"
        assert state.risk_score == 0
        assert state.resolved_at is None

    def test_ttl_none_stays_none(self):
        """Null TTL stays None."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "iam_root_mfa#arn",
            "check_id": "iam_root_mfa",
            "ttl": None,
        }
        state = _item_to_state(item)
        assert state.ttl is None


class TestEndpointUrl:
    """Test endpoint_url kwarg branch."""

    def test_with_endpoint_url(self, aws_credentials):
        """endpoint_url is passed to DynamoDB."""
        with mock_aws():
            session = boto3.Session(
                region_name=REGION
            )
            _create_table(session)
            mgr = StateManager(
                session,
                TABLE_NAME,
                endpoint_url=(
                    "http://localhost:9730"
                ),
            )
            assert mgr.table_name == TABLE_NAME


class TestErrorBranches:
    """Test all except branches return safely."""

    def _broken_mgr(self):
        """Build a StateManager with a broken table."""
        mgr = StateManager.__new__(StateManager)
        mgr.table_name = TABLE_NAME
        mgr.table = MagicMock()
        mgr.table.get_item.side_effect = (
            Exception("DynamoDB down")
        )
        mgr.table.put_item.side_effect = (
            Exception("DynamoDB down")
        )
        mgr.table.update_item.side_effect = (
            Exception("DynamoDB down")
        )
        mgr.table.delete_item.side_effect = (
            Exception("DynamoDB down")
        )
        mgr.table.query.side_effect = (
            Exception("DynamoDB down")
        )
        return mgr

    def test_get_state_error(self):
        """get_state returns None on error."""
        mgr = self._broken_mgr()
        result = mgr.get_state(
            ACCOUNT, REGION, "ec2_no_open_ssh", "arn"
        )
        assert result is None

    def test_put_state_error(self):
        """put_state returns False on error."""
        mgr = self._broken_mgr()
        state = _make_state()
        assert mgr.put_state(state) is False

    def test_update_status_error(self):
        """update_status returns False on error."""
        mgr = self._broken_mgr()
        result = mgr.update_status(
            ACCOUNT, REGION, "ec2_no_open_ssh", "arn",
            "ok",
        )
        assert result is False

    def test_query_by_account_error(self):
        """query_by_account returns [] on error."""
        mgr = self._broken_mgr()
        result = mgr.query_by_account(
            ACCOUNT, REGION
        )
        assert result == []

    def test_query_by_status_error(self):
        """query_by_status returns [] on error."""
        mgr = self._broken_mgr()
        result = mgr.query_by_status("alarm")
        assert result == []

    def test_query_by_domain_error(self):
        """query_by_domain returns [] on error."""
        mgr = self._broken_mgr()
        result = mgr.query_by_domain("network")
        assert result == []

    def test_query_by_check_error(self):
        """query_by_check returns [] on error."""
        mgr = self._broken_mgr()
        result = mgr.query_by_check("ec2_no_open_ssh")
        assert result == []

    def test_delete_state_error(self):
        """delete_state returns False on error."""
        mgr = self._broken_mgr()
        result = mgr.delete_state(
            ACCOUNT, REGION, "ec2_no_open_ssh", "arn"
        )
        assert result is False

    def test_count_by_status_error(self):
        """count_by_status returns 0 on error."""
        mgr = self._broken_mgr()
        result = mgr.count_by_status("alarm")
        assert result == 0


class TestStatusHistoryRoundtrip:
    """Test status_history DynamoDB serialization."""

    def test_roundtrip_with_history(self, state_mgr):
        """status_history survives put/get cycle."""
        history = [
            {
                "status": "alarm",
                "timestamp": "2026-02-27T10:00:00Z",
            },
            {
                "status": "ok",
                "timestamp": "2026-02-27T11:00:00Z",
            },
        ]
        state = _make_state()
        state.status_history = history
        state_mgr.put_state(state)

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result is not None
        assert len(result.status_history) == 2
        assert (
            result.status_history[0]["status"]
            == "alarm"
        )
        assert (
            result.status_history[1]["status"]
            == "ok"
        )

    def test_legacy_item_missing_history(self):
        """Item without status_history defaults to []."""
        item = {
            "pk": f"{ACCOUNT}#{REGION}",
            "sk": "iam_root_mfa#arn",
            "check_id": "iam_root_mfa",
            "status": "alarm",
        }
        state = _item_to_state(item)
        assert state.status_history == []

    def test_empty_history_roundtrip(self, state_mgr):
        """Empty status_history survives roundtrip."""
        state = _make_state()
        state.status_history = []
        state_mgr.put_state(state)

        result = state_mgr.get_state(
            ACCOUNT,
            REGION,
            "ec2_no_open_ssh",
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
        )
        assert result is not None
        assert result.status_history == []
