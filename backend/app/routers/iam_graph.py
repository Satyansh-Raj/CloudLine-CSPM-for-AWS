"""IAM graph endpoint — enriched user/policy/permission data."""

import logging
import time

from fastapi import APIRouter, Depends, Query

from app.collectors.iam import IAMCollector
from app.dependencies import (
    get_boto3_session,
    get_settings,
    get_state_manager,
)
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["iam-graph"],
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
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
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
    now = time.time()
    cached = _cache.get(effective_account, {})
    if (
        cached.get("data") is not None
        and now - cached.get("ts", 0.0) < _CACHE_TTL
    ):
        return cached["data"]

    collector = IAMCollector(session)
    try:
        users = collector.collect_graph_data()
    except Exception:
        logger.exception(
            "Failed to collect IAM graph data"
        )
        users = []

    # Fetch identity-domain violations for this account
    states = state_manager.query_by_account(
        effective_account,
        settings.aws_region,
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
