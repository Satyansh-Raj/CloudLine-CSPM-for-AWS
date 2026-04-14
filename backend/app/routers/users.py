"""Admin-only user management API.

All endpoints require Admin role (require_admin).
Endpoints:
  POST   /users                      — create user
  GET    /users                      — list all users
  GET    /users/reset-requests       — pending resets
  GET    /users/{user_id}            — get one user
  PUT    /users/{user_id}            — update user
  DELETE /users/{user_id}            — soft-delete
  POST   /users/{user_id}/approve-reset — approve reset
"""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth.audit_log import AuditLogStore
from app.auth.dependencies import require_admin
from app.auth.models import User, UserRole
from app.auth.password import (
    hash_password,
    validate_password_complexity,
)
from app.auth.user_store import UserStore
from app.dependencies import (
    get_audit_log_store,
    get_user_store,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


class UserCreateRequest(BaseModel):
    """Body for creating a new platform user."""

    email: str
    full_name: str
    role: UserRole
    initial_password: str


class UserUpdateRequest(BaseModel):
    """Body for updating mutable user fields."""

    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserSetPasswordRequest(BaseModel):
    """Body for admin-initiated password reset."""

    new_password: str


def _user_to_dict(user: User) -> dict:
    """Serialize User — password_hash excluded."""
    return {
        "sk": user.sk,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "created_by": user.created_by,
        "last_login": user.last_login,
        "reset_requested_at": (
            user.reset_requested_at
        ),
        "reset_approved_by": user.reset_approved_by,
        "reset_allowed": user.reset_allowed,
    }


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    req: UserCreateRequest,
    admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Create a new platform user.

    Raises:
        409 if email already exists.
        400 if password is too short.
        500 on persistence failure.
    """
    if store.get_user_by_email(req.email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"User {req.email!r} already exists"
            ),
        )
    try:
        pw_hash = hash_password(req.initial_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    now = datetime.now(tz=timezone.utc).isoformat()
    user = User(
        sk=str(uuid.uuid4()),
        email=req.email,
        full_name=req.full_name,
        password_hash=pw_hash,
        role=req.role,
        is_active=True,
        created_at=now,
        created_by=admin.sk,
    )
    if not store.put_user(user):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail="Failed to create user",
        )
    return _user_to_dict(user)


@router.get("")
def list_users(
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> list[dict]:
    """Return all users (password_hash excluded)."""
    return [_user_to_dict(u) for u in store.list_users()]


# NOTE: this must be registered BEFORE /{user_id}
# so FastAPI prefers the literal segment.
@router.get("/reset-requests")
def list_reset_requests(
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> list[dict]:
    """Return users with pending reset requests."""
    return [
        _user_to_dict(u)
        for u in store.list_users()
        if u.reset_requested_at is not None
    ]


@router.get("/{user_id}")
def get_user(
    user_id: str,
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Fetch a single user by UUID.

    Raises:
        404 if user not found.
    """
    user = store.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    return _user_to_dict(user)


@router.put("/{user_id}")
def update_user(
    user_id: str,
    req: UserUpdateRequest,
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Update role, full_name, or is_active.

    Raises:
        404 if user not found.
        500 on persistence failure.
    """
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    if not store.update_user(
        user_id,
        full_name=req.full_name,
        role=req.role,
        is_active=req.is_active,
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=f"Failed to update {user_id}",
        )
    return _user_to_dict(
        store.get_user_by_id(user_id)
    )


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Soft-delete a user (is_active=False).

    Raises:
        404 if user not found.
        400 if this is the last active Admin.
        500 on persistence failure.
    """
    user = store.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Invariant: at least one active Admin must remain.
    if user.role == UserRole.ADMIN and user.is_active:
        active_admins = [
            u
            for u in store.list_users()
            if u.role == UserRole.ADMIN
            and u.is_active
        ]
        if len(active_admins) <= 1:
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "Cannot deactivate the last "
                    "active Admin"
                ),
            )

    if not store.update_user(user_id, is_active=False):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=f"Failed to deactivate {user_id}",
        )
    return {"user_id": user_id, "status": "deactivated"}


@router.get("/{user_id}/login-history")
def get_login_history(
    user_id: str,
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
    audit: AuditLogStore = Depends(
        get_audit_log_store
    ),
) -> list[dict]:
    """Return recent login events for a user.

    Args:
        user_id: Target user's UUID.

    Raises:
        404 if user not found.
    """
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    return audit.get_recent_logins(user_id)


@router.post("/{user_id}/set-password")
def set_user_password(
    user_id: str,
    req: UserSetPasswordRequest,
    _admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Admin sets a new password for any user.

    Raises:
        404 if user not found.
        400 if password fails complexity rules.
        500 on persistence failure.
    """
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    try:
        validate_password_complexity(req.new_password)
        pw_hash = hash_password(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    if not store.update_password_hash(user_id, pw_hash):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail="Failed to update password",
        )
    return {
        "user_id": user_id,
        "status": "password_updated",
    }


@router.post("/{user_id}/approve-reset")
def approve_reset(
    user_id: str,
    admin: User = Depends(require_admin),
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Admin approves a password reset request.

    Sets reset_allowed=True and records the approving
    admin's user_id.

    Raises:
        404 if user not found.
        500 on persistence failure.
    """
    if store.get_user_by_id(user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    if not store.approve_reset(user_id, admin.sk):
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail="Failed to approve reset",
        )
    return {
        "user_id": user_id,
        "status": "reset_approved",
    }
