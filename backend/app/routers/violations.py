"""Violation listing endpoint — reads from DynamoDB."""

from fastapi import APIRouter, Depends, Query

from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["violations"],
)


@router.get("/violations")
def list_violations(
    severity: str | None = Query(
        None,
        description="Filter by severity",
    ),
    domain: str | None = Query(
        None,
        description="Filter by domain",
    ),
    status: str | None = Query(
        None,
        description="Filter by status",
    ),
    check_id: str | None = Query(
        None,
        description="Filter by check ID",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Max results",
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> list[dict]:
    """List violations from the last scan.

    Filter priority: check_id > domain > status >
    account (default). Only one primary filter is
    applied at the DynamoDB level. Severity is
    always applied in-memory.
    """
    states = state_manager.query_by_account(
        settings.aws_account_id,
        settings.aws_region,
        limit=limit,
    )
    if check_id:
        states = [
            s for s in states
            if s.check_id == check_id
        ]
    if domain:
        states = [
            s for s in states
            if s.domain == domain
        ]
    if status:
        states = [
            s for s in states
            if s.status == status
        ]

    results = []
    for s in states:
        if severity and s.severity != severity:
            continue
        results.append({
            "check_id": s.check_id,
            "status": s.status,
            "severity": s.severity,
            "domain": s.domain,
            "resource": s.resource_arn,
            "reason": s.reason,
            "risk_score": s.risk_score,
            "last_evaluated": s.last_evaluated,
        })

    return results
