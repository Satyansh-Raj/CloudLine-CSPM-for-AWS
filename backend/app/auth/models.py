"""RBAC user models for CloudLine authentication."""

from enum import Enum

from pydantic import BaseModel


class UserRole(str, Enum):
    """Three roles for CloudLine RBAC.

    ADMIN:    Full access — manages users, accounts,
              all platform actions.
    OPERATOR: Can create Jira tickets and trigger
              scans. Cannot manage accounts or users.
    VIEWER:   Read-only access to all dashboards.
    """

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class User(BaseModel):
    """A CloudLine platform user.

    DynamoDB keys:
        pk: Always "USERS" (fixed partition).
        sk: user_id (UUID, unique sort key).

    Attributes:
        pk: Partition key — always "USERS".
        sk: Sort key — UUID user identifier.
        email: User email address (unique).
        full_name: Display name.
        password_hash: bcrypt hash of password.
        role: UserRole enum value.
        is_active: Whether the account is enabled.
        created_at: ISO timestamp of creation.
        created_by: user_id of the creating admin.
        last_login: ISO timestamp of last login.
        reset_requested_at: ISO timestamp when user
            requested a password reset, or None.
        reset_approved_by: user_id of the admin who
            approved the reset, or None.
        reset_allowed: True if Admin approved the
            reset and user can set new password.
        allowed_account_ids: AWS account IDs this
            user may access. Ignored when
            all_accounts_access is True.
        all_accounts_access: When True, user sees all
            connected accounts (default for existing
            users — preserves current behavior).
    """

    pk: str = "USERS"
    sk: str  # user_id (UUID)
    email: str
    full_name: str
    password_hash: str
    role: UserRole
    is_active: bool = True
    created_at: str = ""
    created_by: str = ""
    last_login: str | None = None
    reset_requested_at: str | None = None
    reset_approved_by: str | None = None
    reset_approved_at: str | None = None
    reset_allowed: bool = False
    failed_login_count: int = 0
    allowed_account_ids: list[str] = []
    all_accounts_access: bool = True


class LoginRequest(BaseModel):
    """Credentials for the login endpoint."""

    email: str
    password: str


class TokenPair(BaseModel):
    """Access + refresh token pair returned on login."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Decoded JWT claims.

    role is None for refresh tokens (they carry no
    role claim — only the access token does).
    """

    sub: str  # user_id
    role: UserRole | None = None
    type: str  # "access" or "refresh"
    jti: str = ""  # JWT ID (UUID4)
    exp: int = 0
    iat: int = 0


class ChangePasswordRequest(BaseModel):
    """Payload for the change-password endpoint."""

    current_password: str
    new_password: str


class ResetRequestCreate(BaseModel):
    """Payload for requesting a password reset."""

    email: str
