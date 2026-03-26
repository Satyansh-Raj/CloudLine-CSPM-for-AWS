"""IAM graph endpoint — enriched user/policy/permission data."""

import logging
import time

from fastapi import APIRouter, Depends

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
_cache: dict = {"data": None, "ts": 0.0}


def invalidate_cache() -> None:
    """Clear IAM graph cache so the next request
    fetches fresh data. Called after scan completion."""
    _cache["data"] = None
    _cache["ts"] = 0.0


@router.get("/iam/graph")
def get_iam_graph(
    session=Depends(get_boto3_session),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """IAM graph: users, policies, permissions,
    violations.

    Fetches live IAM data and joins with stored
    identity violations. Cached for 5 minutes.
    """
    now = time.time()
    if (
        _cache["data"] is not None
        and now - _cache["ts"] < _CACHE_TTL
    ):
        return _cache["data"]

    collector = IAMCollector(session)
    try:
        users = collector.collect_graph_data()
    except Exception:
        logger.exception(
            "Failed to collect IAM graph data"
        )
        users = []

    # Fetch identity-domain violations
    states = state_manager.query_by_account(
        settings.aws_account_id,
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
        ]

    result = {
        "account_id": settings.aws_account_id,
        "users": users,
    }

    _cache["data"] = result
    _cache["ts"] = now
    return result
