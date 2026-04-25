"""IAM graph endpoint — enriched user/policy/permission data."""

import logging
import time

from fastapi import APIRouter, Depends, Query

from app.auth.account_access import assert_account_allowed
from app.auth.dependencies import (
    get_current_user,
    require_any_authenticated,
)
from app.auth.models import User
from app.collectors.iam import IAMCollector
from app.dependencies import (
    get_account_store,
    get_boto3_session,
    get_session_factory,
    get_settings,
    get_state_manager,
)
from app.pipeline.account_store import AccountStore
from app.pipeline.session_factory import AWSSessionFactory
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["iam-graph"],
    dependencies=[Depends(require_any_authenticated)],
)

_CACHE_TTL = 300  # 5 minutes
# Per-account cache: {account_id: {"data": ..., "ts": float}}
_cache: dict = {"data": None, "ts": 0.0}


def invalidate_cache() -> None:
    """Clear IAM graph cache so the next request
    fetches fresh data. Called after scan completion."""
    _cache["data"] = None
    _cache["ts"] = 0.0
    # Clear per-account entries too
    for k in [k for k in _cache if k not in ("data", "ts")]:
        del _cache[k]


@router.get("/iam/graph")
def get_iam_graph(
    account_id: str | None = Query(
        None,
        description="AWS account ID override",
    ),
    session=Depends(get_boto3_session),
    session_factory: AWSSessionFactory = Depends(
        get_session_factory
    ),
    account_store: AccountStore = Depends(
        get_account_store
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
) -> dict:
    """IAM graph: users, policies, permissions,
    violations.

    Fetches live IAM data and joins with stored
    identity violations. Cached for 5 minutes per
    account (default account only when no account_id
    is given).
    """
    effective_account = (
        account_id or settings.aws_account_id
    )
    assert_account_allowed(current_user, effective_account)
    now = time.time()
    cached = _cache.get(effective_account, {})
    if (
        cached.get("data") is not None
        and now - cached.get("ts", 0.0) < _CACHE_TTL
    ):
        return cached["data"]

    # Use cross-account session when querying a target account
    is_cross_account = (
        account_id
        and account_id != settings.aws_account_id
    )
    acct_obj = None
    if is_cross_account:
        acct_obj = account_store.get_account(account_id)

    if is_cross_account and acct_obj:
        try:
            iam_session = session_factory.get_session(
                acct_obj
            )
        except Exception:
            logger.exception(
                "AssumeRole failed for %s", account_id
            )
            iam_session = session
    else:
        iam_session = session

    collector = IAMCollector(iam_session)
    try:
        users = collector.collect_graph_data()
    except Exception:
        logger.exception(
            "Failed to collect IAM graph data"
        )
        users = []

    # Fetch identity-domain violations for this account
    regions = (
        acct_obj.regions
        if acct_obj and acct_obj.regions
        else [settings.aws_region]
    )
    states = []
    for r in regions:
        states.extend(
            state_manager.query_by_account(
                effective_account, r
            )
        )
    identity = [
        s for s in states if s.domain == "identity"
    ]

    # Match violations to users by resource ARN
    user_arns = set()
    for user in users:
        user_arn = user["arn"]
        user_arns.add(user_arn)
        user["violations"] = [
            {
                "check_id": v.check_id,
                "status": v.status,
                "severity": v.severity,
                "reason": v.reason,
                "risk_score": v.risk_score,
            }
            for v in identity
            if v.resource_arn == user_arn
            and v.status == "alarm"
        ]

    # Collect account-level violations (password policy,
    # root account checks) whose ARN doesn't match any user.
    # Only include active alarms — skip resolved/ok states.
    account_violations = [
        {
            "check_id": v.check_id,
            "status": v.status,
            "severity": v.severity,
            "reason": v.reason,
            "risk_score": v.risk_score,
            "resource": v.resource_arn,
        }
        for v in identity
        if v.resource_arn not in user_arns
        and v.status == "alarm"
    ]

    result = {
        "account_id": effective_account,
        "users": users,
        "account_violations": account_violations,
    }

    _cache[effective_account] = {
        "data": result,
        "ts": now,
    }
    return result
