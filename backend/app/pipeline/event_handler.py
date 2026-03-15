"""Event handler — 7-step pipeline orchestrator.

Receives raw CloudTrail events and orchestrates:
1. Parse → 2. Map → 3. Collect → 4. Evaluate →
5. Lookup state → 6. Detect drift → 7. Persist.
"""

from __future__ import annotations

import logging

import boto3

from app.collectors.orchestrator import (
    CollectionOrchestrator,
)
from app.engine.evaluator import PolicyEvaluator
from app.models.violation import Violation
from app.pipeline.drift_detector import DriftDetector
from app.pipeline.event_mapper import get_event_mapping
from app.pipeline.event_parser import (
    parse_cloudtrail_event,
)
from app.pipeline.models import DriftAlert
from app.pipeline.risk_scorer import RiskScorer
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)


class EventHandler:
    """Orchestrates the real-time detection pipeline.

    Wires together the parser, mapper, collector,
    evaluator, drift detector, state manager into a
    single process_event() call.

    Example:
        >>> handler = EventHandler(
        ...     session=boto3.Session(),
        ...     evaluator=evaluator,
        ...     state_manager=state_mgr,
        ...     account_id="123456789012",
        ...     region="us-east-1",
        ... )
        >>> alerts = handler.process_event(raw_event)
    """

    def __init__(
        self,
        session: boto3.Session,
        evaluator: PolicyEvaluator,
        state_manager: StateManager,
        account_id: str = "",
        region: str = "us-east-1",
    ):
        self.session = session
        self.evaluator = evaluator
        self.state_manager = state_manager
        self.account_id = account_id
        self.region = region
        self.orchestrator = CollectionOrchestrator(
            session, account_id, region
        )
        self.drift_detector = DriftDetector()
        self.risk_scorer = RiskScorer()

    def process_event(
        self, raw_event: dict
    ) -> list[DriftAlert]:
        """Run the 7-step pipeline on a raw event.

        Args:
            raw_event: Raw CloudTrail/EventBridge JSON.

        Returns:
            List of DriftAlert objects (one per policy
            evaluated). Empty list if event is untracked
            or unparseable.
        """
        # Step 1: Parse CloudTrail event
        event = parse_cloudtrail_event(raw_event)
        if event is None:
            logger.warning("Failed to parse event")
            return []

        # Step 2: Map event to collector + policies
        mapping = get_event_mapping(event.event_name)
        if mapping is None:
            logger.debug(
                "Untracked event: %s",
                event.event_name,
            )
            return []

        account_id = event.account_id or self.account_id
        region = event.aws_region or self.region

        # Step 3: Collect targeted resource data
        resource_data = self._collect(
            mapping.collector, event.resource_id
        )

        # Step 4-7: Evaluate each policy and detect drift
        alerts: list[DriftAlert] = []
        for policy in mapping.policies:
            alert = self._evaluate_policy(
                policy=policy,
                resource_data=resource_data,
                account_id=account_id,
                region=region,
                resource_arn=(
                    event.resource_arn
                    or event.resource_id
                ),
                trigger_event=event.event_name,
                service=mapping.collector,
            )
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _collect(
        self, service: str, resource_id: str
    ) -> dict:
        """Step 3: Collect targeted resource data.

        Returns resource dict or empty dict on failure.
        """
        try:
            return self.orchestrator.collect_targeted(
                service, resource_id
            )
        except Exception as e:
            logger.error(
                "Collection failed for %s/%s: %s",
                service,
                resource_id,
                e,
            )
            return {}

    def _evaluate_policy(
        self,
        policy: str,
        resource_data: dict,
        account_id: str,
        region: str,
        resource_arn: str,
        trigger_event: str,
        service: str = "",
    ) -> DriftAlert | None:
        """Steps 4-7 for a single policy package.

        Returns DriftAlert or None on error.
        """
        # Step 4: Evaluate OPA policy package
        violations = self._run_evaluation(
            policy, resource_data
        )
        if violations is None:
            return None

        # Determine current status from results
        status, severity, reason, domain = (
            self._extract_status(violations, policy)
        )

        # Extract check_id from the most important
        # violation result (alarm > ok > error).
        # Falls back to package path when no results.
        check_id = self._extract_check_id(
            violations, policy
        )

        # Step 4.5: Compute contextual risk score
        alarm_results = [
            v for v in violations
            if v.status == "alarm"
        ]
        ok_results = [
            v for v in violations
            if v.status == "ok"
        ]
        scoring_violation = (
            alarm_results[0]
            if alarm_results
            else ok_results[0]
            if ok_results
            else None
        )
        risk_dims = self.risk_scorer.score(
            violation=scoring_violation,
            resource_data=resource_data,
            service=service,
        )

        # Step 5: Lookup previous state
        previous = self.state_manager.get_state(
            account_id, region, check_id, resource_arn
        )

        # Step 6: Detect drift
        alert = self.drift_detector.detect(
            previous=previous,
            current_status=status,
            check_id=check_id,
            resource_arn=resource_arn,
            severity=severity,
            risk_score=risk_dims.composite,
            reason=reason,
            domain=domain,
            trigger_event=trigger_event,
            account_id=account_id,
            region=region,
        )

        # Step 7: Persist updated state
        compliance = {}
        remediation_id = ""
        if violations:
            v = violations[0]
            compliance = v.compliance.model_dump()
            remediation_id = v.remediation_id

        new_state = self.drift_detector.build_updated_state(
            previous=previous,
            alert=alert,
            domain=domain,
            compliance=compliance,
            remediation_id=remediation_id,
        )
        self.state_manager.put_state(new_state)

        return alert

    @staticmethod
    def _extract_check_id(
        violations: list[Violation],
        fallback: str,
    ) -> str:
        """Pick the most relevant check_id from results.

        Priority: alarm > error > ok > fallback.
        """
        alarms = [
            v for v in violations
            if v.status == "alarm"
        ]
        if alarms:
            return alarms[0].check_id
        errors = [
            v for v in violations
            if v.status == "error"
        ]
        if errors:
            return errors[0].check_id
        if violations:
            return violations[0].check_id
        return fallback

    def _run_evaluation(
        self, policy: str, resource_data: dict
    ) -> list[Violation] | None:
        """Step 4: Run OPA evaluation for a policy.

        Returns list of Violation or None on error.
        """
        try:
            return self.evaluator.evaluate_check(
                resource_data, policy
            )
        except Exception as e:
            logger.error(
                "OPA evaluation failed for %s: %s",
                policy,
                e,
            )
            return None

    def _extract_status(
        self,
        violations: list[Violation],
        policy: str,
    ) -> tuple[str, str, str, str]:
        """Derive status from OPA evaluation results.

        Returns (status, severity, reason, domain).
        """
        error_results = [
            v for v in violations
            if v.status == "error"
        ]
        if error_results:
            v = error_results[0]
            return (
                "error",
                v.severity,
                v.reason,
                v.domain,
            )

        alarm_results = [
            v for v in violations
            if v.status == "alarm"
        ]
        if alarm_results:
            v = alarm_results[0]
            return (
                "alarm",
                v.severity,
                v.reason,
                v.domain,
            )

        ok_results = [
            v for v in violations
            if v.status == "ok"
        ]
        if ok_results:
            v = ok_results[0]
            return (
                "ok",
                v.severity,
                v.reason,
                v.domain,
            )

        # No results at all — treat as ok
        return "ok", "", "", ""
