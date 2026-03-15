"""Tests for WebSocket ConnectionManager."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
)
from app.pipeline.ws_manager import (
    ConnectionManager,
    _WS_TYPE_MAP,
    format_drift_event,
)


def _make_alert(
    drift_type=DriftType.NEW_VIOLATION,
    check_id="ec2_05",
    resource_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
    previous_status="ok",
    current_status="alarm",
    severity=AlertSeverity.CRITICAL,
    risk_score=92,
    trigger_event="AuthorizeSecurityGroupIngress",
    reason="Port 22 open to 0.0.0.0/0",
    account_id="123456789012",
    region="us-east-1",
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
        timestamp="2026-03-01T12:00:00Z",
        reason=reason,
        account_id=account_id,
        region=region,
    )


def _mock_ws():
    """Create a mock WebSocket with async methods."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.receive_text = AsyncMock()
    return ws


class TestConnect:
    """WebSocket connect behavior."""

    @pytest.mark.asyncio
    async def test_connect_accepts_websocket(self):
        """connect() calls accept on websocket."""
        mgr = ConnectionManager()
        ws = _mock_ws()
        await mgr.connect(ws)
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_adds_to_list(self):
        """connect() adds websocket to tracking."""
        mgr = ConnectionManager()
        ws = _mock_ws()
        await mgr.connect(ws)
        assert mgr.active_connections == 1

    @pytest.mark.asyncio
    async def test_multiple_connections_tracked(self):
        """Multiple connects all tracked."""
        mgr = ConnectionManager()
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        ws3 = _mock_ws()
        await mgr.connect(ws1)
        await mgr.connect(ws2)
        await mgr.connect(ws3)
        assert mgr.active_connections == 3


class TestDisconnect:
    """WebSocket disconnect behavior."""

    @pytest.mark.asyncio
    async def test_disconnect_removes(self):
        """disconnect() removes from tracking."""
        mgr = ConnectionManager()
        ws = _mock_ws()
        await mgr.connect(ws)
        mgr.disconnect(ws)
        assert mgr.active_connections == 0

    def test_disconnect_unknown_is_safe(self):
        """disconnect() with unknown ws is no-op."""
        mgr = ConnectionManager()
        ws = _mock_ws()
        mgr.disconnect(ws)  # no error
        assert mgr.active_connections == 0


class TestBroadcast:
    """Broadcast to all connections."""

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all(self):
        """broadcast() sends to every connection."""
        mgr = ConnectionManager()
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        await mgr.connect(ws1)
        await mgr.connect(ws2)

        msg = {"type": "violation_new", "data": {}}
        await mgr.broadcast(msg)

        payload = json.dumps(msg, default=str)
        ws1.send_text.assert_awaited_once_with(
            payload
        )
        ws2.send_text.assert_awaited_once_with(
            payload
        )

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead(self):
        """Dead connections removed during broadcast."""
        mgr = ConnectionManager()
        ws_good = _mock_ws()
        ws_dead = _mock_ws()
        ws_dead.send_text.side_effect = Exception(
            "closed"
        )
        await mgr.connect(ws_good)
        await mgr.connect(ws_dead)

        await mgr.broadcast({"type": "test"})

        assert mgr.active_connections == 1
        ws_good.send_text.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_broadcast_empty_list_ok(self):
        """broadcast() with no connections is no-op."""
        mgr = ConnectionManager()
        await mgr.broadcast({"type": "test"})
        assert mgr.active_connections == 0


class TestSendPersonal:
    """Send to a single connection."""

    @pytest.mark.asyncio
    async def test_sends_to_one(self):
        """send_personal() sends to target only."""
        mgr = ConnectionManager()
        ws = _mock_ws()
        await mgr.connect(ws)

        msg = {"type": "ping"}
        await mgr.send_personal(ws, msg)

        payload = json.dumps(msg, default=str)
        ws.send_text.assert_awaited_with(payload)


class TestFormatDriftEvent:
    """format_drift_event() conversion."""

    def test_new_violation_type(self):
        """NEW_VIOLATION maps to violation_new."""
        alert = _make_alert(
            drift_type=DriftType.NEW_VIOLATION
        )
        msg = format_drift_event(alert)
        assert msg["type"] == "violation_new"

    def test_resolution_type(self):
        """RESOLUTION maps to violation_resolved."""
        alert = _make_alert(
            drift_type=DriftType.RESOLUTION,
            previous_status="alarm",
            current_status="ok",
        )
        msg = format_drift_event(alert)
        assert msg["type"] == "violation_resolved"

    def test_unmapped_type_uses_value(self):
        """Unmapped DriftType uses raw enum value."""
        alert = _make_alert(
            drift_type=DriftType.FIRST_SEEN
        )
        msg = format_drift_event(alert)
        assert msg["type"] == "first_seen"

    def test_all_data_fields_present(self):
        """All expected data fields are in message."""
        alert = _make_alert()
        msg = format_drift_event(alert)

        assert "type" in msg
        assert "data" in msg
        data = msg["data"]
        assert data["check_id"] == alert.check_id
        assert (
            data["resource_arn"] == alert.resource_arn
        )
        assert (
            data["previous_status"]
            == alert.previous_status
        )
        assert (
            data["current_status"]
            == alert.current_status
        )
        assert data["severity"] == "critical"
        assert data["risk_score"] == 92
        assert (
            data["trigger_event"]
            == "AuthorizeSecurityGroupIngress"
        )
        assert data["timestamp"].endswith("Z")
        assert data["reason"] == alert.reason
        assert data["account_id"] == "123456789012"
        assert data["region"] == "us-east-1"

    def test_ws_type_map_contents(self):
        """_WS_TYPE_MAP has expected entries."""
        assert _WS_TYPE_MAP == {
            DriftType.NEW_VIOLATION: "violation_new",
            DriftType.RESOLUTION: "violation_resolved",
        }


class TestActiveConnections:
    """active_connections property."""

    def test_starts_at_zero(self):
        """New manager has 0 connections."""
        mgr = ConnectionManager()
        assert mgr.active_connections == 0

    @pytest.mark.asyncio
    async def test_reflects_count(self):
        """Property reflects actual count."""
        mgr = ConnectionManager()
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        await mgr.connect(ws1)
        assert mgr.active_connections == 1
        await mgr.connect(ws2)
        assert mgr.active_connections == 2
        mgr.disconnect(ws1)
        assert mgr.active_connections == 1
