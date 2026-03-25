"""Compliance framework scorer.

Aggregates ViolationState records into a per-framework
compliance score broken down by individual control IDs.

Usage::

    from app.compliance.scorer import (
        ComplianceFrameworkScorer,
    )

    scorer = ComplianceFrameworkScorer(
        framework="cis_aws",
        violations=violation_states,
        registry=registry,
    )
    result = scorer.score()  # FrameworkScore
"""

from pydantic import BaseModel, Field

from app.compliance.mappings import (
    ComplianceMappingRegistry,
)
from app.pipeline.models import ViolationState

# Severity rank: higher number = worse
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "": 0,
}

_WORST_ORDER = [
    "critical",
    "high",
    "medium",
    "low",
    "",
]


def _worst_severity(severities: list[str]) -> str:
    """Return the most severe level from a list."""
    if not severities:
        return ""
    return max(
        severities,
        key=lambda s: _SEVERITY_RANK.get(
            s.lower(), 0
        ),
    )


class ControlStatus(BaseModel):
    """Compliance status for a single control ID.

    Attributes:
        control_id: Framework-specific control identifier
            (e.g. 'CIS 1.5', 'AC-2').
        status: 'compliant' | 'non_compliant'
        check_ids: CloudLine check_ids that map to this
            control.
        violations: List of active alarm violations for
            this control [{resource_arn, severity, reason}]
        severity: Worst severity among violations. Empty
            string when compliant.
    """

    control_id: str
    status: str = "compliant"
    check_ids: list[str] = Field(
        default_factory=list
    )
    violations: list[dict] = Field(
        default_factory=list
    )
    severity: str = ""


class FrameworkScore(BaseModel):
    """Aggregated compliance score for one framework.

    Attributes:
        framework: Framework name (e.g. 'cis_aws').
        total_controls: Distinct control IDs covered.
        compliant: Number of passing controls.
        non_compliant: Number of failing controls.
        score_percent: Percentage of passing controls.
        controls: Per-control detail list.
    """

    framework: str
    total_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    score_percent: float = 100.0
    controls: list[ControlStatus] = Field(
        default_factory=list
    )


class ComplianceFrameworkScorer:
    """Scores violations against a single framework.

    Args:
        framework: Framework name to score against.
        violations: ViolationState items to analyse.
        registry: ComplianceMappingRegistry instance.
    """

    def __init__(
        self,
        framework: str,
        violations: list[ViolationState],
        registry: ComplianceMappingRegistry,
    ) -> None:
        self._framework = framework
        self._violations = violations
        self._registry = registry

    # ── Public ────────────────────────────────────

    def score(self) -> FrameworkScore:
        """Compute FrameworkScore for the framework.

        Returns:
            FrameworkScore with per-control breakdown.
            Returns 100% with zero controls when the
            framework has no mappings.
        """
        check_ids = (
            self._registry.check_ids_for_framework(
                self._framework
            )
        )
        if not check_ids:
            return FrameworkScore(
                framework=self._framework,
                total_controls=0,
                compliant=0,
                non_compliant=0,
                score_percent=100.0,
                controls=[],
            )

        # Map control_id → list[check_id]
        control_to_checks = (
            self._build_control_map(check_ids)
        )

        # Index alarm violations by check_id
        alarm_by_check = self._index_alarms()

        controls: list[ControlStatus] = []
        for ctrl_id, checks in sorted(
            control_to_checks.items()
        ):
            ctrl_violations: list[dict] = []
            severities: list[str] = []
            for cid in checks:
                for v in alarm_by_check.get(cid, []):
                    ctrl_violations.append(
                        {
                            "resource_arn": (
                                v.resource_arn
                            ),
                            "severity": v.severity,
                            "reason": v.reason,
                        }
                    )
                    severities.append(v.severity)

            worst = _worst_severity(severities)
            status = (
                "non_compliant"
                if ctrl_violations
                else "compliant"
            )
            controls.append(
                ControlStatus(
                    control_id=ctrl_id,
                    status=status,
                    check_ids=list(checks),
                    violations=ctrl_violations,
                    severity=worst,
                )
            )

        total = len(controls)
        non_comp = sum(
            1
            for c in controls
            if c.status == "non_compliant"
        )
        compliant = total - non_comp
        pct = (
            round(compliant / total * 100.0, 2)
            if total > 0
            else 100.0
        )

        return FrameworkScore(
            framework=self._framework,
            total_controls=total,
            compliant=compliant,
            non_compliant=non_comp,
            score_percent=pct,
            controls=controls,
        )

    # ── Private ───────────────────────────────────

    def _build_control_map(
        self, check_ids: list[str]
    ) -> dict[str, list[str]]:
        """Map control_id → [check_ids] for framework.

        Args:
            check_ids: check_ids that have a mapping
                for self._framework.

        Returns:
            Dict control_id → list of check_ids.
        """
        ctrl_map: dict[str, list[str]] = {}
        for cid in check_ids:
            mapping = self._registry.get(cid)
            controls = getattr(
                mapping, self._framework, []
            )
            for ctrl in controls:
                ctrl_map.setdefault(ctrl, []).append(
                    cid
                )
        return ctrl_map

    def _index_alarms(
        self,
    ) -> dict[str, list[ViolationState]]:
        """Index alarm violations by check_id.

        Only 'alarm' status items are returned;
        'ok', 'error', and 'skip' are ignored.

        Returns:
            Dict check_id → list[ViolationState].
        """
        index: dict[str, list[ViolationState]] = {}
        for v in self._violations:
            if v.status == "alarm":
                index.setdefault(
                    v.check_id, []
                ).append(v)
        return index
