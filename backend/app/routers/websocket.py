"""WebSocket endpoint for real-time events.

Provides /ws/v1/events for dashboard clients to
receive live violation, resolution, and scan
completion notifications via WebSocket.
"""

import logging

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
)

from app.config import settings
from app.dependencies import get_ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/v1/events")
async def ws_events(
    websocket: WebSocket,
):
    """WebSocket endpoint for real-time events.

    Args:
        websocket: The WebSocket connection.
    """
    manager = get_ws_manager()
    await manager.connect(
        websocket,
        max_connections=settings.ws_max_connections,
    )
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await manager.send_personal(
                    websocket, {"type": "pong"}
                )
    except WebSocketDisconnect:
        manager.disconnect(websocket)
