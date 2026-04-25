"""Drift alerts REST API endpoint."""

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import require_any_authenticated
from app.config import settings
from app.dependencies import get_state_manager
from app.pipeline.models import DriftType
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["drift"],
    dependencies=[Depends(require_any_authenticated)],
)


@router.get("/drift/alerts")
def list_drift_alerts(
    since: str | None = Query(
        None,
        description=(
            "ISO timestamp — only return alerts "
            "evaluated after this time"
        ),
    ),
    type: str | None = Query(
        None,
        description=(
            "Filter by drift type: "
            "new_violation | resolution"
        ),
    ),
    severity: str | None = Query(
        None,
        description="Filter by severity level",
    ),
    check_id: str | None = Query(
        None,
        description="Filter by check ID",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Max results to return",
    ),
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
) -> dict:
    """List drift alerts from violation state.

    Returns violations that have changed status,
    optionally filtered by time, type, severity,
    and check_id.
    """
    # Determine which status to query
    if type == "new_violation":
        states = state_manager.query_by_status(
            "alarm", limit=limit
        )
    elif type == "resolution":
        states = state_manager.query_by_status(
            "ok", limit=limit
        )
    elif check_id:
        states = state_manager.query_by_check(
            check_id, limit=limit
        )
    else:
        # Get both alarm and ok states
        alarms = state_manager.query_by_status(
            "alarm", limit=limit
        )
        oks = state_manager.query_by_status(
            "ok", limit=limit
        )
        states = alarms + oks

    # Filter by account — default to root account
    # (same pattern as compliance, violations, risk, etc.)
    effective_account = (
        account_id or settings.aws_account_id
    )
    if effective_account:
        states = [
            s for s in states
            if s.pk.split("#")[0] == effective_account
        ]

    alerts = [
        _state_to_alert(s) for s in states
    ]

    # Apply filters
    if since:
        alerts = [
            a
            for a in alerts
            if a["timestamp"] >= since
        ]
    if severity:
        alerts = [
            a
            for a in alerts
            if a["severity"] == severity
        ]
    if check_id and type:
        alerts = [
            a
            for a in alerts
            if a["check_id"] == check_id
        ]

    return {"alerts": alerts[:limit]}


def _state_to_alert(state) -> dict:
    """Convert ViolationState to alert response."""
    if (
        state.previous_status
        and state.previous_status != state.status
    ):
        if state.status == "alarm":
            drift_type = (
                DriftType.NEW_VIOLATION.value
            )
        else:
            drift_type = DriftType.RESOLUTION.value
    elif state.status == "alarm":
        drift_type = (
            DriftType.NEW_VIOLATION.value
        )
    else:
        drift_type = DriftType.NO_CHANGE.value

    # Use first_detected for new violations so the
    # trends chart buckets the event on the day it was
    # *originally* found, not the last re-scan day.
    # last_evaluated is updated every scan and would
    # shift yesterday's violation into today's bucket.
    if (
        drift_type == DriftType.NEW_VIOLATION.value
        and state.first_detected
    ):
        timestamp = state.first_detected
    else:
        timestamp = state.last_evaluated

    return {
        "type": drift_type,
        "check_id": state.check_id,
        "resource": state.resource_arn,
        "severity": state.severity,
        "risk_score": state.risk_score,
        "timestamp": timestamp,
        "trigger_event": "",
        "reason": state.reason,
        "domain": state.domain,
        "previous_status": state.previous_status,
        "current_status": state.status,
    }
