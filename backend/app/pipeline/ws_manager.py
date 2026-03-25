"""WebSocket connection manager for real-time events.

Manages in-memory WebSocket connections and broadcasts
drift alerts to all connected dashboard clients.
"""

import json
import logging

from fastapi import WebSocket

from app.pipeline.models import DriftAlert, DriftType

logger = logging.getLogger(__name__)

# Map DriftType → WebSocket message type string
_WS_TYPE_MAP = {
    DriftType.NEW_VIOLATION: "violation_new",
    DriftType.RESOLUTION: "violation_resolved",
}


def format_drift_event(alert: DriftAlert) -> dict:
    """Convert a DriftAlert to WebSocket message.

    Args:
        alert: The DriftAlert to format.

    Returns:
        Dict with 'type' and 'data' keys matching
        the blueprint WS message format.

    Example:
        >>> from app.pipeline.models import (
        ...     DriftAlert, DriftType,
        ... )
        >>> alert = DriftAlert(
        ...     drift_type=DriftType.NEW_VIOLATION,
        ...     check_id="ec2_no_open_ssh",
        ... )
        >>> msg = format_drift_event(alert)
        >>> msg["type"]
        'violation_new'
    """
    ws_type = _WS_TYPE_MAP.get(
        alert.drift_type, alert.drift_type.value
    )
    return {
        "type": ws_type,
        "data": {
            "check_id": alert.check_id,
            "resource_arn": alert.resource_arn,
            "previous_status": alert.previous_status,
            "current_status": alert.current_status,
            "severity": alert.severity.value,
            "risk_score": alert.risk_score,
            "trigger_event": alert.trigger_event,
            "timestamp": alert.timestamp,
            "reason": alert.reason,
            "account_id": alert.account_id,
            "region": alert.region,
        },
    }


class ConnectionManager:
    """In-memory WebSocket connection manager.

    Tracks active WebSocket connections and provides
    broadcast / personal send capabilities. Gracefully
    handles dead connections during broadcast.

    Example:
        >>> manager = ConnectionManager()
        >>> manager.active_connections
        0
    """

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(
        self,
        websocket: WebSocket,
        max_connections: int = 100,
    ):
        """Accept and track a new WebSocket.

        Args:
            websocket: The incoming WebSocket.
            max_connections: Max allowed connections.
        """
        if len(self._connections) >= max_connections:
            await websocket.close(code=1013)
            logger.warning(
                "WebSocket rejected — "
                "max connections (%d) reached",
                max_connections,
            )
            return
        await websocket.accept()
        self._connections.append(websocket)
        logger.info(
            "WebSocket connected, total=%d",
            len(self._connections),
        )

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket from tracking.

        Safe to call with unknown websockets — silently
        ignored if not in the list.

        Args:
            websocket: The WebSocket to remove.
        """
        try:
            self._connections.remove(websocket)
            logger.info(
                "WebSocket disconnected, total=%d",
                len(self._connections),
            )
        except ValueError:
            pass

    async def broadcast(self, message: dict):
        """Send a message to all connected clients.

        Dead connections are removed automatically.

        Args:
            message: Dict payload to JSON-serialize
                     and send.
        """
        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_personal(
        self, websocket: WebSocket, message: dict
    ):
        """Send a message to a single client.

        Args:
            websocket: Target WebSocket connection.
            message: Dict payload to JSON-serialize.
        """
        payload = json.dumps(message, default=str)
        await websocket.send_text(payload)

    @property
    def active_connections(self) -> int:
        """Number of currently tracked connections."""
        return len(self._connections)
