"""JWT encode/decode utilities for CloudLine auth.

Access tokens carry sub, role, type="access", jti,
exp, and iat claims. Refresh tokens carry the same
except role (they are role-free by design — the
access token is what carries authorization).

Decoding always requires the caller to specify the
expected token type so that a refresh token cannot
be used in place of an access token (confused-deputy
prevention).
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.auth.models import TokenPayload, UserRole


class InvalidTokenError(Exception):
    """Raised when a JWT cannot be validated."""


def create_access_token(
    user_id: str,
    role: UserRole,
    secret: str,
    expires_delta: timedelta,
) -> str:
    """Encode a signed access token.

    Args:
        user_id: The authenticated user's UUID.
        role: UserRole assigned to this token.
        secret: HS256 signing key.
        expires_delta: Token lifetime.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "role": role.value,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(
            (now + expires_delta).timestamp()
        ),
    }
    return jwt.encode(
        payload, secret, algorithm="HS256"
    )


def create_refresh_token(
    user_id: str,
    secret: str,
    expires_delta: timedelta,
) -> str:
    """Encode a signed refresh token (no role claim).

    Args:
        user_id: The authenticated user's UUID.
        secret: HS256 signing key.
        expires_delta: Token lifetime.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(
            (now + expires_delta).timestamp()
        ),
    }
    return jwt.encode(
        payload, secret, algorithm="HS256"
    )


def decode_token(
    token: str,
    secret: str,
    expected_type: str,
) -> TokenPayload:
    """Decode and validate a JWT.

    Args:
        token: The encoded JWT string.
        secret: HS256 signing key.
        expected_type: "access" or "refresh".
            Prevents token type confusion attacks.

    Returns:
        Validated TokenPayload.

    Raises:
        InvalidTokenError: On expiry, bad signature,
            malformed token, or type mismatch.
    """
    try:
        raw = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError(
            "Token expired"
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(str(exc)) from exc

    token_type = raw.get("type", "")
    if token_type != expected_type:
        raise InvalidTokenError(
            f"Invalid token type: expected "
            f"{expected_type!r}, got {token_type!r}"
        )

    role_str: str | None = raw.get("role")
    role: UserRole | None = None
    if role_str is not None:
        role = UserRole(role_str)
    elif expected_type == "access":
        raise InvalidTokenError(
            "Access token missing role claim"
        )

    return TokenPayload(
        sub=raw["sub"],
        role=role,
        type=token_type,
        jti=raw.get("jti", ""),
        exp=raw["exp"],
        iat=raw["iat"],
    )
