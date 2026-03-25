"""Executive summary endpoint.

Provides a high-level security posture overview:
active/resolved counts, resolution rate, per-domain
breakdown, per-severity counts, and a 24-hour trend.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query

from app.dependencies import get_settings, get_state_manager
from app.pipeline.state_manager import StateManager
from app.routers.compliance import CHECKS_PER_DOMAIN

router = APIRouter(tags=["executive"])

_SEVERITIES = ("critical", "high", "medium", "low")
_24H = timedelta(hours=24)


def _parse_ts(ts: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp to aware datetime.

    Returns None when ts is absent or unparseable.
    Handles both '+00:00' and 'Z' suffixes.
    """
    if not ts:
        return None
    try:
        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )
    except ValueError:
        return None


def _build_summary(states: list) -> dict:
    """Compute the executive summary from states.

    Args:
        states: List of ViolationState objects.

    Returns:
        Dict matching the executive summary schema.
    """
    alarms = [s for s in states if s.status == "alarm"]
    resolved = [s for s in states if s.status == "ok"]

    total_active = len(alarms)
    total_resolved = len(resolved)
    total = total_active + total_resolved
    resolution_rate = (
        round(total_resolved / total * 100, 1)
        if total > 0
        else 0.0
    )

    # per-severity counts (alarm only)
    by_severity: dict[str, int] = {
        sev: 0 for sev in _SEVERITIES
    }
    for s in alarms:
        if s.severity in by_severity:
            by_severity[s.severity] += 1

    # per-domain breakdown
    by_domain: dict[str, dict] = {}
    for domain, total_checks in CHECKS_PER_DOMAIN.items():
        domain_alarms = sum(
            1 for s in alarms if s.domain == domain
        )
        domain_resolved = sum(
            1 for s in resolved if s.domain == domain
        )
        # score_percent: proportion of checks that are
        # NOT currently alarming (active violations are
        # the only signal since OPA emits failures only)
        score = max(
            0,
            round(
                (1 - domain_alarms / total_checks) * 100
            ),
        )
        by_domain[domain] = {
            "active": domain_alarms,
            "resolved": domain_resolved,
            "total_checks": total_checks,
            "score_percent": score,
        }

    # 24-hour trend
    cutoff = datetime.now(UTC) - _24H
    resolved_last_24h = sum(
        1
        for s in resolved
        if _parse_ts(s.resolved_at) is not None
        and _parse_ts(s.resolved_at) >= cutoff  # type: ignore[operator]
    )
    new_last_24h = sum(
        1
        for s in states
        if _parse_ts(s.first_detected) is not None
        and _parse_ts(s.first_detected) >= cutoff  # type: ignore[operator]
    )

    return {
        "total_active": total_active,
        "total_resolved": total_resolved,
        "resolution_rate": resolution_rate,
        "by_domain": by_domain,
        "by_severity": by_severity,
        "trend": {
            "resolved_last_24h": resolved_last_24h,
            "new_last_24h": new_last_24h,
        },
    }


@router.get("/summary/executive")
def executive_summary(
    region: str | None = Query(
        None,
        description="Filter by AWS region",
    ),
    account_id: str | None = Query(
        None,
        description="AWS account ID to query",
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """Return an executive security posture summary.

    Aggregates all violation states for the given
    account/region and computes:
    - Total active and resolved violation counts
    - Resolution rate percentage
    - Per-domain active/resolved/score breakdown
    - Per-severity active violation counts
    - 24-hour trend (new and resolved items)

    Args:
        region: AWS region (defaults to settings).
        account_id: AWS account ID (defaults to
            settings).
        state_manager: Injected StateManager.
        settings: Injected application settings.

    Returns:
        Executive summary dict.
    """
    effective_region = region or settings.aws_region
    effective_account = (
        account_id or settings.aws_account_id
    )

    states = state_manager.query_by_account(
        effective_account,
        effective_region,
        limit=5000,
    )

    return _build_summary(states)
