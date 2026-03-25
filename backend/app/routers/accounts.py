"""Accounts CRUD API — manage target AWS accounts
for multi-account scanning.

Endpoints:
  POST   /accounts           — add a target account
  GET    /accounts           — list active accounts
  GET    /accounts/{id}      — get one account
  DELETE /accounts/{id}      — deactivate account
"""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import get_account_store
from app.models.account import TargetAccount
from app.pipeline.account_store import AccountStore

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
    external_id: str = ""
    regions: list[str] = ["us-east-1"]


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
) -> dict:
    """Add a target account for cross-account scanning.

    Returns:
        201 with the created account data.
    """
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
        external_id=req.external_id,
        regions=req.regions,
        is_active=True,
        added_at=now,
    )
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
) -> list[dict]:
    """Return all active target accounts."""
    accounts = store.list_active()
    return [_account_to_dict(a) for a in accounts]


@router.get("/accounts/{account_id}")
def get_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
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


@router.delete("/accounts/{account_id}")
def deactivate_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
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
