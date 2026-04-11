"""WebSocket endpoint for real-time events.

Provides /ws/v1/events for dashboard clients to
receive live violation, resolution, and scan
completion notifications via WebSocket.

Auth: when auth_enabled=True, a valid access token
must be supplied via ?token= query parameter before
the connection is accepted (WS upgrade headers cannot
carry cookies the same way HTTP can, so query param
is the standard approach). On failure the socket is
closed with code 1008 (policy violation).
"""

import logging

from fastapi import (
    APIRouter,
    Depends,
    Query,
    WebSocket,
    WebSocketDisconnect,
)

from app.auth.jwt_handler import (
    InvalidTokenError,
    decode_token,
)
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import (
    get_settings,
    get_user_store,
    get_ws_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

_WS_CLOSE_POLICY_VIOLATION = 1008


@router.websocket("/ws/v1/events")
async def ws_events(
    websocket: WebSocket,
    token: str | None = Query(
        None,
        description=(
            "Bearer access token (required when "
            "auth_enabled=True)"
        ),
    ),
    cfg: Settings = Depends(get_settings),
):
    """WebSocket endpoint for real-time events.

    When auth_enabled=True, validates the ?token=
    query parameter before accepting the connection.
    Closes with code 1008 on auth failure.

    Args:
        websocket: The WebSocket connection.
        token: Optional JWT access token.
        cfg: Application settings (injected).
    """
    if cfg.auth_enabled:
        if not token:
            await websocket.close(
                code=_WS_CLOSE_POLICY_VIOLATION,
                reason="Missing token",
            )
            return

        try:
            payload = decode_token(
                token, cfg.jwt_secret, "access"
            )
        except InvalidTokenError as exc:
            await websocket.close(
                code=_WS_CLOSE_POLICY_VIOLATION,
                reason=str(exc),
            )
            return

        store: UserStore = get_user_store()
        user = store.get_user_by_id(payload.sub)
        if not user or not user.is_active:
            await websocket.close(
                code=_WS_CLOSE_POLICY_VIOLATION,
                reason="User not found or inactive",
            )
            return

    manager = get_ws_manager()
    await manager.connect(
        websocket,
        max_connections=cfg.ws_max_connections,
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
