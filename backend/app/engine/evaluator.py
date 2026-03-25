"""Policy evaluator — orchestrates OPA evaluation
against collected AWS data."""

import logging

from app.engine.opa_client import OPAClient
from app.engine.result_parser import ResultParser
from app.models.violation import (
    ComplianceScore,
    Violation,
)

logger = logging.getLogger(__name__)

_ENRICH_COMPLIANCE = True


class PolicyEvaluator:
    """Runs OPA policies against collected data and
    returns structured violations."""

    def __init__(self, opa_client: OPAClient):
        self.opa = opa_client
        self.parser = ResultParser()

    def evaluate_all(
        self, input_data: dict
    ) -> list[Violation]:
        """Evaluate all policies against input.

        Returns a flat list of all violations and
        compliant results.  Compliance mappings are
        enriched from the external JSON config
        (post-OPA) so Rego rules don't need to embed
        framework references.
        """
        raw = self.opa.evaluate_all(input_data)
        results = []

        for pkg_name, pkg_results in raw.items():
            for v in pkg_results.get(
                "violations", []
            ):
                parsed = self.parser.parse(v)
                if parsed:
                    results.append(parsed)

            for c in pkg_results.get(
                "compliant", []
            ):
                parsed = self.parser.parse(c)
                if parsed:
                    results.append(parsed)

        if _ENRICH_COMPLIANCE and results:
            try:
                from app.compliance.mappings import (
                    enrich_compliance,
                )

                enrich_compliance(results)
            except Exception as exc:
                logger.warning(
                    "Compliance enrichment failed, "
                    "using Rego-embedded values: %s",
                    exc,
                )

        return results

    def evaluate_check(
        self,
        input_data: dict,
        check_package: str,
    ) -> list[Violation]:
        """Evaluate a single check package.

        Args:
            input_data: Unified JSON document.
            check_package: e.g.
                "identity.iam"

        Returns:
            List of violations for this check.
        """
        query = (
            f"data.aws.{check_package}.violations"
        )
        raw = self.opa.evaluate(
            input_data, query
        )
        return [
            v
            for r in raw
            if (v := self.parser.parse(r))
        ]

    def compute_compliance_score(
        self, violations: list[Violation]
    ) -> ComplianceScore:
        """Compute compliance score from results.

        Returns aggregated compliance metrics.
        """
        alarms = [
            v
            for v in violations
            if v.status == "alarm"
        ]
        oks = [
            v
            for v in violations
            if v.status == "ok"
        ]
        errors = [
            v
            for v in violations
            if v.status == "error"
        ]
        skips = [
            v
            for v in violations
            if v.status == "skip"
        ]

        total = len(alarms) + len(oks)
        score_pct = (
            (len(oks) / total * 100)
            if total > 0
            else 0.0
        )

        # By domain
        by_domain: dict[str, dict] = {}
        for v in violations:
            d = v.domain or "unknown"
            if d not in by_domain:
                by_domain[d] = {
                    "passed": 0,
                    "failed": 0,
                }
            if v.status == "ok":
                by_domain[d]["passed"] += 1
            elif v.status == "alarm":
                by_domain[d]["failed"] += 1

        # By severity
        by_severity: dict[str, int] = {}
        for v in alarms:
            sev = v.severity or "unknown"
            by_severity[sev] = (
                by_severity.get(sev, 0) + 1
            )

        return ComplianceScore(
            total_checks=total,
            passed=len(oks),
            failed=len(alarms),
            errors=len(errors),
            skipped=len(skips),
            score_percent=round(score_pct, 1),
            by_domain=by_domain,
            by_severity=by_severity,
        )
