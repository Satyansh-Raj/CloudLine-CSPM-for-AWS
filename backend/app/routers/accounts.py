"""Accounts CRUD API — manage target AWS accounts
for multi-account scanning.

Endpoints:
  POST   /accounts           — add a target account
  GET    /accounts           — list active accounts
  GET    /accounts/{id}      — get one account
  DELETE /accounts/{id}      — deactivate account
"""

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import (
    require_admin,
    require_any_authenticated,
)
from app.auth.models import User
from app.dependencies import (
    get_account_store,
    get_session_factory,
)
from app.models.account import TargetAccount
from app.pipeline.account_store import AccountStore
from app.pipeline.session_factory import (
    AWSSessionFactory,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["accounts"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class AccountCreateRequest(BaseModel):
    """Request body for creating a target account."""

    account_id: str
    account_name: str
    role_arn: str
    regions: list[str] = ["us-east-1"]


class AccountUpdateRequest(BaseModel):
    """Request body for updating a target account."""

    account_name: str | None = None
    regions: list[str] | None = None


def _account_to_dict(acc: TargetAccount) -> dict:
    """Serialize TargetAccount to API response dict."""
    return {
        "account_id": acc.account_id,
        "account_name": acc.account_name,
        "role_arn": acc.role_arn,
        "external_id": acc.external_id,
        "regions": acc.regions,
        "is_active": acc.is_active,
        "added_at": acc.added_at,
        "last_scanned": acc.last_scanned,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/accounts", status_code=201)
def create_account(
    req: AccountCreateRequest,
    store: AccountStore = Depends(get_account_store),
    session_factory: AWSSessionFactory = Depends(
        get_session_factory
    ),
    _user: User = Depends(require_admin),
) -> dict:
    """Add a target account for cross-account scanning.

    Generates a unique External ID, validates the role
    via STS AssumeRole, then persists the account.

    Returns:
        201 with the created account data, including
        the generated external_id.

    Raises:
        400 if the role cannot be assumed.
        500 if the account cannot be persisted.
    """
    external_id = str(uuid.uuid4())
    now = (
        datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    account = TargetAccount(
        pk="ACCOUNTS",
        sk=req.account_id,
        account_id=req.account_id,
        account_name=req.account_name,
        role_arn=req.role_arn,
        external_id=external_id,
        regions=req.regions,
        is_active=True,
        added_at=now,
    )
    # Validate the role is assumable before saving
    try:
        session_factory.get_session(account)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot assume role: {exc}",
        ) from exc
    ok = store.put_account(account)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail="Failed to persist account",
        )
    return _account_to_dict(account)


@router.get("/accounts")
def list_accounts(
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_any_authenticated),
) -> list[dict]:
    """Return all active target accounts."""
    accounts = store.list_active()
    return [_account_to_dict(a) for a in accounts]


@router.get("/accounts/{account_id}")
def get_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_any_authenticated),
) -> dict:
    """Return a single target account by ID.

    Raises:
        404 if the account does not exist.
    """
    account = store.get_account(account_id)
    if account is None:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found",
        )
    return _account_to_dict(account)


@router.put("/accounts/{account_id}")
def update_account(
    account_id: str,
    req: AccountUpdateRequest,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_admin),
) -> dict:
    """Update alias and/or regions for a target account.

    Raises:
        404 if the account does not exist.
        500 if the update cannot be persisted.
    """
    if store.get_account(account_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found",
        )
    ok = store.update_account(
        account_id,
        account_name=req.account_name,
        regions=req.regions,
    )
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to update {account_id}"
            ),
        )
    account = store.get_account(account_id)
    return _account_to_dict(account)


@router.delete("/accounts/{account_id}")
def deactivate_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_admin),
) -> dict:
    """Deactivate a target account (soft delete).

    Returns:
        200 with deactivated status.
    """
    ok = store.deactivate(account_id)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to deactivate {account_id}"
            ),
        )
    return {
        "account_id": account_id,
        "status": "deactivated",
    }
