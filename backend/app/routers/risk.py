"""Risk scores REST API endpoints."""

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import require_any_authenticated
from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.pipeline.risk_scorer import RiskScorer
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["risk"],
    dependencies=[Depends(require_any_authenticated)],
)

_scorer = RiskScorer()

RISK_DOMAINS = [
    "identity_access",
    "data_protection",
    "network",
    "logging_monitoring",
    "serverless",
]


@router.get("/risk/scores")
def list_risk_scores(
    min_score: int = Query(
        0,
        ge=0,
        le=100,
        description="Minimum risk score filter",
    ),
    category: str | None = Query(
        None,
        description=(
            "Filter by category: "
            "critical|high|medium|low"
        ),
    ),
    domain: str | None = Query(
        None,
        description="Filter by security domain",
    ),
    limit: int = Query(
        50,
        ge=1,
        le=500,
        description="Max results to return",
    ),
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """List violations sorted by risk score.

    Queries violation-state scoped to the current
    account/region. Filters by min_score, category,
    and domain.
    """
    effective_account = (
        account_id or settings.aws_account_id
    )
    states = state_manager.query_by_account(
        effective_account,
        settings.aws_region,
        limit=limit * 2,
    )
    states = [
        s for s in states
        if s.status == "alarm"
        and (not domain or s.domain == domain)
    ]

    results = []
    for s in states:
        if s.risk_score < min_score:
            continue

        cat = _scorer.categorize(s.risk_score)
        if category and cat != category:
            continue

        results.append({
            "resource_arn": s.resource_arn,
            "check_id": s.check_id,
            "risk_score": s.risk_score,
            "category": cat,
            "severity": s.severity,
            "domain": s.domain,
            "last_evaluated": s.last_evaluated,
        })

        if len(results) >= limit:
            break

    return {"scores": results}


@router.get("/risk/summary")
def risk_summary(
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """Aggregate risk score statistics.

    Returns total scored, counts by category,
    average score by domain, and top 5 highest risk.
    Scoped to the current account/region.
    """
    effective_account = (
        account_id or settings.aws_account_id
    )
    states = state_manager.query_by_account(
        effective_account,
        settings.aws_region,
        limit=500,
    )
    states = [
        s for s in states if s.status == "alarm"
    ]

    by_category: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    by_domain: dict[str, dict] = {}
    scored = []

    for s in states:
        cat = _scorer.categorize(s.risk_score)
        by_category[cat] += 1

        if s.domain:
            if s.domain not in by_domain:
                by_domain[s.domain] = {
                    "total": 0,
                    "count": 0,
                }
            by_domain[s.domain]["total"] += (
                s.risk_score
            )
            by_domain[s.domain]["count"] += 1

        scored.append({
            "resource_arn": s.resource_arn,
            "check_id": s.check_id,
            "risk_score": s.risk_score,
            "severity": s.severity,
            "domain": s.domain,
        })

    # Compute averages
    domain_averages = {}
    for dom, data in by_domain.items():
        if data["count"] > 0:
            domain_averages[dom] = round(
                data["total"] / data["count"]
            )
        else:
            domain_averages[dom] = 0

    # Top 5 by risk score
    scored.sort(
        key=lambda x: x["risk_score"],
        reverse=True,
    )
    highest = scored[:5]

    return {
        "total_scored": len(states),
        "by_category": by_category,
        "by_domain": domain_averages,
        "highest_risk": highest,
    }
