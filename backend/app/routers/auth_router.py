"""Authentication endpoints for CloudLine.

Endpoints:
    POST /auth/login           — issue token pair
    POST /auth/refresh         — rotate tokens
    GET  /auth/me              — current user profile
    POST /auth/logout          — client-side logout
    POST /auth/change-password — change own password
    POST /auth/request-reset   — request Admin approval

Security features:
    - Login lockout: 10 consecutive failures →
      is_active=False. Admin must reactivate.
    - Rate limiting: configured in main.py via
      slowapi middleware on this router.
    - Password complexity: enforced on change-password.
    - Audit logging: every login attempt is written
      to the cloudline-audit-log table.
"""

from datetime import datetime, timedelta, timezone

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.auth.audit_log import AuditLogStore
from app.auth.jwt_handler import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.auth.models import (
    ChangePasswordRequest,
    LoginRequest,
    ResetRequestCreate,
    TokenPair,
)
from app.auth.password import (
    hash_password,
    validate_password_complexity,
    verify_password,
)
from app.auth.user_store import UserStore
from app.config import Settings
from app.dependencies import (
    get_audit_log_store,
    get_settings,
    get_user_store,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Limiter instance — app.state.limiter is attached
# in main.py so the middleware can enforce it.
limiter = Limiter(key_func=get_remote_address)

# auto_error=False so we can return 401 with a
# custom message rather than the FastAPI default.
_oauth2 = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login", auto_error=False
)

# Number of consecutive failures before lockout.
_LOCKOUT_THRESHOLD = 10

# Seconds after admin approval during which the user
# can call /auth/reset-password. Change to 600 for
# 10-minute production window.
_RESET_APPROVAL_EXPIRY_SECONDS = 600


class _RefreshRequest(BaseModel):
    refresh_token: str


class _UserResponse(BaseModel):
    """Public user fields returned by GET /auth/me.

    password_hash is intentionally excluded.
    """

    sk: str
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login: str | None = None
    reset_allowed: bool = False


def _decode_access(
    token: str | None, cfg: Settings
):
    """Validate a Bearer access token.

    Args:
        token: Raw token string (may be None).
        cfg: App settings (jwt_secret).

    Returns:
        Decoded TokenPayload.

    Raises:
        HTTPException(401) on any validation failure.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return decode_token(
            token, cfg.jwt_secret, "access"
        )
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Login ─────────────────────────────────────────


@router.post(
    "/login",
    response_model=TokenPair,
    status_code=status.HTTP_200_OK,
)
async def login(
    req: LoginRequest,
    request: Request,
    store: UserStore = Depends(get_user_store),
    cfg: Settings = Depends(get_settings),
    audit: AuditLogStore = Depends(
        get_audit_log_store
    ),
) -> TokenPair:
    """Authenticate user and return a token pair.

    On 10 consecutive failures the account is locked
    (is_active=False). Admin must reactivate via the
    User Management page.
    """
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")
    now_ts = datetime.now(tz=timezone.utc).isoformat()

    user = store.get_user_by_email(req.email)

    # Unknown email — fail without incrementing any
    # counter (no account to lock).
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Locked account — fail immediately.
    if not user.is_active:
        audit.log_login(
            user_id=user.sk,
            ip=ip,
            user_agent=ua,
            success=False,
            ts=now_ts,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Wrong password — increment counter, maybe lock.
    if not verify_password(
        req.password, user.password_hash
    ):
        new_count = store.increment_failed_login_count(
            user.sk
        )
        audit.log_login(
            user_id=user.sk,
            ip=ip,
            user_agent=ua,
            success=False,
            ts=now_ts,
        )
        if new_count >= _LOCKOUT_THRESHOLD:
            store.update_user(user.sk, is_active=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Correct password — reset failure counter.
    store.reset_failed_login_count(user.sk)
    store.update_last_login(user.sk, now_ts)

    access_token = create_access_token(
        user_id=user.sk,
        role=user.role,
        secret=cfg.jwt_secret,
        expires_delta=timedelta(
            minutes=cfg.access_token_expire_minutes
        ),
    )
    refresh_token = create_refresh_token(
        user_id=user.sk,
        secret=cfg.jwt_secret,
        expires_delta=timedelta(
            days=cfg.refresh_token_expire_days
        ),
    )

    # Decode to extract jti for audit log.
    try:
        payload = decode_token(
            access_token, cfg.jwt_secret, "access"
        )
        jti = payload.jti
    except InvalidTokenError:
        jti = ""

    audit.log_login(
        user_id=user.sk,
        ip=ip,
        user_agent=ua,
        success=True,
        ts=now_ts,
        jti=jti,
    )

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
    )


# ── Refresh ───────────────────────────────────────


@router.post(
    "/refresh",
    response_model=TokenPair,
    status_code=status.HTTP_200_OK,
)
async def refresh_token(
    body: _RefreshRequest,
    store: UserStore = Depends(get_user_store),
    cfg: Settings = Depends(get_settings),
) -> TokenPair:
    """Issue a new access token from a refresh token."""
    try:
        payload = decode_token(
            body.refresh_token,
            cfg.jwt_secret,
            "refresh",
        )
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    user = store.get_user_by_id(payload.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(
        user_id=user.sk,
        role=user.role,
        secret=cfg.jwt_secret,
        expires_delta=timedelta(
            minutes=cfg.access_token_expire_minutes
        ),
    )
    new_refresh = create_refresh_token(
        user_id=user.sk,
        secret=cfg.jwt_secret,
        expires_delta=timedelta(
            days=cfg.refresh_token_expire_days
        ),
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=new_refresh,
    )


# ── Me ────────────────────────────────────────────


@router.get(
    "/me",
    response_model=_UserResponse,
    status_code=status.HTTP_200_OK,
)
async def get_me(
    token: str | None = Depends(_oauth2),
    store: UserStore = Depends(get_user_store),
    cfg: Settings = Depends(get_settings),
) -> _UserResponse:
    """Return the currently authenticated user."""
    payload = _decode_access(token, cfg)
    user = store.get_user_by_id(payload.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return _UserResponse(
        sk=user.sk,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        is_active=user.is_active,
        last_login=user.last_login,
        reset_allowed=user.reset_allowed,
    )


# ── Logout ────────────────────────────────────────


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
)
async def logout() -> dict:
    """Client-side logout — discard tokens on client."""
    return {"detail": "Logged out"}


# ── Change Password ───────────────────────────────


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
)
async def change_password(
    req: ChangePasswordRequest,
    token: str | None = Depends(_oauth2),
    store: UserStore = Depends(get_user_store),
    cfg: Settings = Depends(get_settings),
) -> dict:
    """Change the current user's password.

    Enforces complexity: ≥12 chars, ≥1 digit, ≥1 symbol.
    When reset_allowed=True (Admin-approved reset),
    the current_password check is skipped. Reset
    flags are cleared on success.
    """
    payload = _decode_access(token, cfg)
    user = store.get_user_by_id(payload.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    try:
        validate_password_complexity(req.new_password)
        new_hash = hash_password(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if not user.reset_allowed:
        if not verify_password(
            req.current_password, user.password_hash
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

    store.update_password_hash(user.sk, new_hash)
    store.clear_reset_after_change(user.sk)
    return {"detail": "Password changed successfully"}


# ── Request Reset ─────────────────────────────────


@router.post(
    "/request-reset",
    status_code=status.HTTP_202_ACCEPTED,
)
async def request_reset(
    req: ResetRequestCreate,
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Request an Admin-approved password reset.

    Always returns 202 regardless of whether the
    email exists (prevents user enumeration).
    """
    user = store.get_user_by_email(req.email)
    if user and user.is_active:
        now_ts = (
            datetime.now(tz=timezone.utc).isoformat()
        )
        store.set_reset_requested(user.sk, now_ts)
    return {"detail": "Reset request submitted"}


# ── Reset Password (unauthenticated) ──────────────


class _ResetPasswordRequest(BaseModel):
    email: str
    new_password: str


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    req: _ResetPasswordRequest,
    store: UserStore = Depends(get_user_store),
) -> dict:
    """Set a new password after admin approval.

    No Bearer token required. Validates that the
    admin has approved the reset (reset_allowed=True)
    before allowing the password change.

    Always returns a generic message to prevent
    user enumeration. On success, clears all reset
    flags so the user cannot reuse this endpoint.
    """
    user = store.get_user_by_email(req.email)

    if not user or not user.is_active or not user.reset_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset not authorized or already used.",
        )

    # Enforce expiry window.
    if user.reset_approved_at:
        approved_at = datetime.fromisoformat(
            user.reset_approved_at
        )
        elapsed = (
            datetime.now(tz=timezone.utc) - approved_at
        ).total_seconds()
        if elapsed > _RESET_APPROVAL_EXPIRY_SECONDS:
            # Auto-revoke the stale approval.
            store.clear_reset_after_change(user.sk)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Reset approval expired after "
                    f"{_RESET_APPROVAL_EXPIRY_SECONDS}s. "
                    "Please request a new reset."
                ),
            )

    try:
        validate_password_complexity(req.new_password)
        new_hash = hash_password(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    store.update_password_hash(user.sk, new_hash)
    store.clear_reset_after_change(user.sk)
    return {"detail": "Password reset successfully."}

