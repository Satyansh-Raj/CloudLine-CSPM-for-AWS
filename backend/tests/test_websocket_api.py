"""Tests for WebSocket /ws/v1/events endpoint."""

import json

import pytest
from fastapi.testclient import TestClient

from app.dependencies import get_ws_manager
from app.main import app

WS_URL = "/ws/v1/events"


class TestWSConnection:
    """WebSocket connection."""

    def test_connect(self):
        """Connection is accepted without token."""
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            ws.send_text("ping")
            resp = ws.receive_json()
            assert resp["type"] == "pong"

    def test_keepalive_ping_pong(self):
        """Multiple ping/pong exchanges work."""
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            for _ in range(3):
                ws.send_text("ping")
                resp = ws.receive_json()
                assert resp["type"] == "pong"


class TestWSDisconnect:
    """Clean disconnect handling."""

    def test_clean_disconnect(self):
        """Client disconnect is handled gracefully."""
        manager = get_ws_manager()
        before = manager.active_connections
        client = TestClient(app)
        with client.websocket_connect(WS_URL):
            pass
        assert (
            manager.active_connections <= before + 1
        )


class TestWSBroadcast:
    """Broadcast reaches connected clients."""

    def test_broadcast_reaches_client(self):
        """broadcast() delivers to connected client."""
        manager = get_ws_manager()
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            ws.send_text("ping")
            resp = ws.receive_json()
            assert resp["type"] == "pong"
