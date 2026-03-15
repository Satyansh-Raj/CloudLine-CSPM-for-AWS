"""Compliance score endpoint — reads from DynamoDB."""

from fastapi import APIRouter, Depends

from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["compliance"],
)

# Total security checks defined in OPA policies.
# Used for check-level compliance scoring since OPA
# only produces violations (no "ok" results).
TOTAL_DEFINED_CHECKS = 287

# Per-domain check counts (must sum to
# TOTAL_DEFINED_CHECKS). Derived from the Rego
# policy modules in /policies/.
CHECKS_PER_DOMAIN: dict[str, int] = {
    "identity": 37,           # iam(20) + cognito(17)
    "compute": 40,            # ec2(20) + serverless(20)
    "data_protection": 88,    # s3(20) + kms(15)
    #   + secretsmanager(13) + db(20) + storage(20)
    "network": 54,            # vpc(20) + apigw(20) + waf(14)
    "logging_monitoring": 47,  # cloudtrail(15)
    #   + cloudwatch(20) + config(12)
    "detection": 20,          # awssec(20)
    "cross_resource": 1,      # CROSS(1)
}


@router.get("/compliance/score")
def get_compliance_score(
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> dict:
    """Compute compliance score from stored state.

    Score = passing checks / total defined checks.
    A check "fails" if any resource has a violation
    for that check_id.
    """
    states = state_manager.query_by_account(
        settings.aws_account_id,
        settings.aws_region,
        limit=5000,
    )

    alarms = [s for s in states if s.status == "alarm"]
    resolved = [s for s in states if s.status == "ok"]

    # Distinct check_ids with active violations
    failing_checks = {s.check_id for s in alarms}
    failed_count = len(failing_checks)
    passed_count = TOTAL_DEFINED_CHECKS - failed_count

    score_pct = round(
        passed_count / TOTAL_DEFINED_CHECKS * 100
    )

    by_severity: dict[str, int] = {}
    for s in alarms:
        if s.severity:
            sev = s.severity.lower()
            by_severity[sev] = (
                by_severity.get(sev, 0) + 1
            )

    # Distinct failing check_ids per domain
    domain_failing: dict[str, set] = {}
    for s in alarms:
        d = s.domain or "unknown"
        domain_failing.setdefault(d, set()).add(
            s.check_id
        )

    # Build scores for every known domain (even those
    # with zero violations) using the defined totals.
    domain_scores: dict[str, dict] = {}
    for d, total in CHECKS_PER_DOMAIN.items():
        failing = domain_failing.get(d, set())
        n_failing = len(failing)
        n_passed = total - n_failing
        pct = (
            round(n_passed / total * 100)
            if total > 0
            else 100
        )
        d_alarms = [
            s for s in alarms if s.domain == d
        ]
        domain_scores[d] = {
            "score_percent": pct,
            "total": total,
            "passed": n_passed,
            "alarm": len(d_alarms),
            "critical": sum(
                1
                for s in d_alarms
                if (s.severity or "").lower()
                == "critical"
            ),
            "high": sum(
                1
                for s in d_alarms
                if (s.severity or "").lower()
                == "high"
            ),
            "medium": sum(
                1
                for s in d_alarms
                if (s.severity or "").lower()
                == "medium"
            ),
            "low": sum(
                1
                for s in d_alarms
                if (s.severity or "").lower()
                == "low"
            ),
        }

    # Include any unmapped domains from violations
    for d in domain_failing:
        if d not in domain_scores:
            failing = domain_failing[d]
            d_alarms = [
                s for s in alarms if s.domain == d
            ]
            domain_scores[d] = {
                "score_percent": 0,
                "total": len(failing),
                "passed": 0,
                "alarm": len(d_alarms),
                "critical": sum(
                    1
                    for s in d_alarms
                    if (s.severity or "").lower()
                    == "critical"
                ),
                "high": sum(
                    1
                    for s in d_alarms
                    if (s.severity or "").lower()
                    == "high"
                ),
                "medium": sum(
                    1
                    for s in d_alarms
                    if (s.severity or "").lower()
                    == "medium"
                ),
                "low": sum(
                    1
                    for s in d_alarms
                    if (s.severity or "").lower()
                    == "low"
                ),
            }

    return {
        "score_percent": score_pct,
        "total_checks": TOTAL_DEFINED_CHECKS,
        "passed": passed_count,
        "failed": failed_count,
        "total_violations": len(alarms),
        "errors": 0,
        "skipped": 0,
        "by_domain": domain_scores,
        "by_severity": by_severity,
    }
