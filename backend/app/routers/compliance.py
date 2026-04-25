"""Compliance score endpoints — reads from DynamoDB."""

from fastapi import APIRouter, Depends, HTTPException

from app.auth.account_access import assert_account_allowed
from app.auth.dependencies import (
    get_current_user,
    require_any_authenticated,
)
from app.auth.models import User
from app.compliance.mappings import (
    ComplianceMappingRegistry,
    get_registry,
)
from app.compliance.scorer import (
    ComplianceFrameworkScorer,
    FrameworkScore,
)
from app.dependencies import (
    get_account_store,
    get_settings,
    get_state_manager,
)
from app.pipeline.account_store import AccountStore
from app.pipeline.state_manager import StateManager

router = APIRouter(
    tags=["compliance"],
    dependencies=[Depends(require_any_authenticated)],
)

# Per-domain check counts derived from Rego policy
# modules in /policies/. Add a new entry here when
# adding a new policy domain — total auto-updates.
CHECKS_PER_DOMAIN: dict[str, int] = {
    "identity": 37,           # iam(20) + cognito(17)
    "compute": 40,            # ec2(20) + serverless(20)
    "data_protection": 91,    # s3(20) + kms(15)
    #   + secretsmanager(13) + db(20) + storage(20)
    #   + macie(3)
    "network": 54,            # vpc(20) + apigw(20) + waf(14)
    "logging_monitoring": 47,  # cloudtrail(15)
    #   + cloudwatch(20) + config(12)
    "detection": 20,          # awssec(20)
    "cross_resource": 1,      # CROSS(1)
    "governance": 5,          # tagging(5)
}

# Derived — do not set manually.
TOTAL_DEFINED_CHECKS = sum(CHECKS_PER_DOMAIN.values())


def _get_registry() -> ComplianceMappingRegistry:
    """FastAPI dependency: return cached registry."""
    return get_registry()


@router.get("/compliance/frameworks")
def list_frameworks(
    registry: ComplianceMappingRegistry = Depends(
        _get_registry
    ),
) -> dict:
    """Return the list of supported compliance frameworks.

    Returns:
        Dict with 'frameworks' key containing all
        framework names loaded from the registry.
    """
    return {"frameworks": registry.frameworks()}


@router.get(
    "/compliance/framework/{framework_name}",
    response_model=FrameworkScore,
)
def get_framework_score(
    framework_name: str,
    region: str | None = None,
    account_id: str | None = None,
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    account_store: AccountStore = Depends(
        get_account_store
    ),
    settings=Depends(get_settings),
    registry: ComplianceMappingRegistry = Depends(
        _get_registry
    ),
    current_user: User = Depends(get_current_user),
) -> FrameworkScore:
    """Return per-control compliance score for a framework.

    Args:
        framework_name: One of the supported frameworks
            (cis_aws, nist_800_53, pci_dss, hipaa,
            soc2, owasp).
        region: Optional AWS region override.
        account_id: Optional AWS account ID override.

    Returns:
        FrameworkScore with total_controls, compliant,
        non_compliant, score_percent, and a per-control
        breakdown.

    Raises:
        404: When framework_name is not recognised.
    """
    if framework_name not in registry.frameworks():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Framework '{framework_name}' not found."
                " Supported: "
                + ", ".join(registry.frameworks())
            ),
        )

    eff_account = (
        account_id or settings.aws_account_id
    )
    assert_account_allowed(current_user, eff_account)

    if region:
        states = state_manager.query_by_account(
            eff_account, region, limit=5000
        )
    else:
        if (
            account_id
            and account_id != settings.aws_account_id
        ):
            acct_obj = account_store.get_account(
                account_id
            )
            regions = (
                acct_obj.regions
                if acct_obj and acct_obj.regions
                else settings.aws_regions
            )
        else:
            regions = settings.aws_regions
        states = []
        for r in regions:
            states.extend(
                state_manager.query_by_account(
                    eff_account, r, limit=5000
                )
            )

    scorer = ComplianceFrameworkScorer(
        framework=framework_name,
        violations=states,
        registry=registry,
    )
    return scorer.score()


@router.get("/compliance/score")
def get_compliance_score(
    region: str | None = None,
    account_id: str | None = None,
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    account_store: AccountStore = Depends(
        get_account_store
    ),
    settings=Depends(get_settings),
    registry: ComplianceMappingRegistry = Depends(
        _get_registry
    ),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Compute compliance score from stored state.

    Score = passing checks / total defined checks.
    A check 'fails' if any resource has a violation
    for that check_id.

    Includes a by_framework breakdown with per-framework
    scores computed via ComplianceFrameworkScorer.
    """
    eff_account = (
        account_id or settings.aws_account_id
    )
    assert_account_allowed(current_user, eff_account)

    if region:
        states = state_manager.query_by_account(
            eff_account, region, limit=5000
        )
    else:
        if (
            account_id
            and account_id != settings.aws_account_id
        ):
            acct_obj = account_store.get_account(
                account_id
            )
            regions = (
                acct_obj.regions
                if acct_obj and acct_obj.regions
                else settings.aws_regions
            )
        else:
            regions = settings.aws_regions
        states = []
        for r in regions:
            states.extend(
                state_manager.query_by_account(
                    eff_account, r, limit=5000
                )
            )

    alarms = [s for s in states if s.status == "alarm"]

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

    # ── Per-framework breakdown ────────────────────
    by_framework: dict[str, dict] = {}
    for fw in registry.frameworks():
        scorer = ComplianceFrameworkScorer(
            framework=fw,
            violations=states,
            registry=registry,
        )
        fw_score = scorer.score()
        by_framework[fw] = {
            "score_percent": fw_score.score_percent,
            "total_controls": fw_score.total_controls,
            "compliant": fw_score.compliant,
            "non_compliant": fw_score.non_compliant,
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
        "by_framework": by_framework,
    }
