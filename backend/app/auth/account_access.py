"""Per-user account access control helpers."""

from fastapi import HTTPException, status

from app.auth.models import User, UserRole
from app.models.account import TargetAccount


def resolve_allowed_accounts(
    user: User,
    all_account_ids: list[str],
) -> list[str]:
    """Account IDs visible to user from all_account_ids.

    Admin and all_accounts_access users see everything.
    Others see intersection of their allowlist.
    """
    if (
        user.role == UserRole.ADMIN
        or user.all_accounts_access
    ):
        return all_account_ids
    allowed = set(user.allowed_account_ids)
    return [a for a in all_account_ids if a in allowed]


def assert_account_allowed(
    user: User,
    account_id: str,
) -> None:
    """Raise HTTP 403 if user may not access account_id.

    Admin and all_accounts_access users always pass.
    """
    if (
        user.role == UserRole.ADMIN
        or user.all_accounts_access
    ):
        return
    if account_id not in user.allowed_account_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access to account {account_id!r} denied"
            ),
        )


def filter_accounts(
    user: User,
    accounts: list[TargetAccount],
) -> list[TargetAccount]:
    """Filter TargetAccount list to those user may access.

    Admin and all_accounts_access users see all accounts.
    """
    if (
        user.role == UserRole.ADMIN
        or user.all_accounts_access
    ):
        return accounts
    allowed = set(user.allowed_account_ids)
    return [
        a for a in accounts if a.account_id in allowed
    ]
