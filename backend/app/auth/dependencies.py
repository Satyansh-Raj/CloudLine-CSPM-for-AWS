"""FastAPI auth dependencies for CloudLine.

Provides get_current_user and role-enforcement
helpers used by every protected router.

Feature flag: when auth_enabled=False (default in
development), get_current_user returns a synthetic
Admin without inspecting any token. This keeps all
pre-RBAC tests green through Batches 4A–4G.

Usage in routers:
    from app.auth.dependencies import require_admin
    ...
    async def my_endpoint(
        user: User = Depends(require_admin),
    ): ...
"""

import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.auth.jwt_handler import (
    InvalidTokenError,
    decode_token,
)
from app.auth.models import User, UserRole
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import get_settings, get_user_store

logger = logging.getLogger(__name__)

_oauth2 = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login", auto_error=False
)

# Synthetic Admin returned when auth_enabled=False.
_SYNTHETIC_ADMIN = User(
    sk="system-admin",
    email="system@cloudline.local",
    full_name="System Admin",
    password_hash="",
    role=UserRole.ADMIN,
)


async def get_current_user(
    token: str | None = Depends(_oauth2),
    store: UserStore = Depends(get_user_store),
    cfg: Settings = Depends(get_settings),
) -> User:
    """Return the authenticated user.

    When auth_enabled=False → synthetic Admin (bypass).
    When auth_enabled=True  → decode JWT, fetch user.

    Raises:
        HTTPException(401) on any auth failure.
    """
    if not cfg.auth_enabled:
        return _SYNTHETIC_ADMIN

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(
            token, cfg.jwt_secret, "access"
        )
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = store.get_user_by_id(payload.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


def require_role(*allowed: UserRole):
    """Factory: return a dependency that enforces role.

    Args:
        *allowed: One or more UserRole values that are
            permitted to call the endpoint.

    Returns:
        An async FastAPI dependency function that
        returns the User on success or raises 403.

    Example:
        require_admin = require_role(UserRole.ADMIN)
    """
    allowed_set = set(allowed)

    async def _check(
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _check


# Convenience dependencies — import these in routers.
require_admin = require_role(UserRole.ADMIN)
require_admin_or_operator = require_role(
    UserRole.ADMIN, UserRole.OPERATOR
)
require_any_authenticated = require_role(
    *list(UserRole)
)
