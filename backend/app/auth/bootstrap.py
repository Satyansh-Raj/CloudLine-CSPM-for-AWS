"""Admin bootstrap — creates the first Admin user.

Called at startup when no users exist and bootstrap
credentials are configured via env vars. Idempotent:
exits immediately if any users are already present.
"""

import logging
import uuid
from datetime import datetime, timezone

from app.auth.models import User, UserRole
from app.auth.password import hash_password
from app.auth.user_store import UserStore
from app.config import Settings

logger = logging.getLogger(__name__)


def bootstrap_admin(
    user_store: UserStore,
    settings: Settings,
) -> None:
    """Create the initial Admin user if none exist.

    Reads ADMIN_BOOTSTRAP_EMAIL and
    ADMIN_BOOTSTRAP_PASSWORD from settings. If either
    is empty the function is a no-op. If any users
    already exist it is also a no-op (idempotent).

    Args:
        user_store: UserStore to write to.
        settings: Application settings.
    """
    if (
        not settings.admin_bootstrap_email
        or not settings.admin_bootstrap_password
    ):
        logger.debug(
            "bootstrap_admin: bootstrap creds not "
            "configured, skipping."
        )
        return

    # Check by email — avoids false-negative from
    # list_users() returning [] on transient error.
    existing = user_store.get_user_by_email(
        settings.admin_bootstrap_email
    )
    if existing is not None:
        logger.debug(
            "bootstrap_admin: admin user already "
            "exists, skipping.",
        )
        return
    # Also guard against any user existing (prevents
    # creating admin when list succeeds but email
    # check returned None due to GSI propagation lag).
    all_users = user_store.list_users()
    if all_users:
        logger.debug(
            "bootstrap_admin: %d user(s) already "
            "exist, skipping.",
            len(all_users),
        )
        return

    now = datetime.now(tz=timezone.utc).isoformat()
    user = User(
        sk=str(uuid.uuid4()),
        email=settings.admin_bootstrap_email,
        full_name="System Admin",
        password_hash=hash_password(
            settings.admin_bootstrap_password
        ),
        role=UserRole.ADMIN,
        is_active=True,
        created_at=now,
        created_by="bootstrap",
    )
    user_store.put_user(user)
    logger.info(
        "bootstrap_admin: Admin user created (%s).",
        settings.admin_bootstrap_email,
    )
