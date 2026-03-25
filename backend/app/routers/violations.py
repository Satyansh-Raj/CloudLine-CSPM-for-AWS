"""Violation listing endpoint — reads from DynamoDB."""

import logging

from fastapi import APIRouter, Depends, Query

from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)

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
    region: str | None = Query(
        None,
        description="Filter by AWS region",
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
    effective_region = (
        region if region else settings.aws_region
    )
    states = state_manager.query_by_account(
        settings.aws_account_id,
        effective_region,
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

    # Lazy-load compliance registry for backfill
    registry = None
    try:
        from app.compliance.mappings import get_registry
        registry = get_registry()
    except Exception:
        logger.debug("Compliance registry unavailable")

    results = []
    for s in states:
        if severity and s.severity != severity:
            continue
        comp = s.compliance
        if registry and (not comp or not any(
            getattr(comp, f, None)
            for f in (
                "cis_aws", "nist_800_53",
                "pci_dss", "hipaa", "soc2",
            )
        )):
            comp = registry.get(s.check_id)
        # Parse account_id and region from pk
        # (format: {account_id}#{region})
        pk_parts = s.pk.split("#", 1)
        acct = pk_parts[0] if pk_parts else ""
        rgn = pk_parts[1] if len(pk_parts) > 1 else ""
        results.append({
            "check_id": s.check_id,
            "status": s.status,
            "severity": s.severity,
            "domain": s.domain,
            "resource": s.resource_arn,
            "reason": s.reason,
            "risk_score": s.risk_score,
            "last_evaluated": s.last_evaluated,
            "first_detected": s.first_detected,
            "resolved_at": s.resolved_at,
            "previous_status": s.previous_status,
            "compliance": comp,
            "remediation_id": s.remediation_id,
            "account_id": acct,
            "region": rgn,
            "ticket_id": s.ticket_id,
            "ticket_url": s.ticket_url,
        })

    return results
