"""Drift detection via state comparison.

Compares previous violation state against new OPA
evaluation results to detect ok→alarm (new violation),
alarm→ok (resolution), or no-change transitions.
"""

import logging
from datetime import UTC, datetime

from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
    ViolationState,
)

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects state transitions between evaluations.

    Compares previous state from DynamoDB with fresh
    OPA evaluation results to classify the transition.

    Example:
        >>> detector = DriftDetector()
        >>> result = detector.detect(
        ...     previous=old_state,
        ...     current_status="alarm",
        ...     check_id="ec2_no_open_ssh",
        ...     resource_arn="arn:aws:ec2:...",
        ...     severity="critical",
        ...     trigger_event="AuthorizeSecurityGroupIngress",
        ... )
        >>> result.drift_type
        <DriftType.NEW_VIOLATION: 'new_violation'>
    """

    def detect(
        self,
        previous: ViolationState | None,
        current_status: str,
        check_id: str,
        resource_arn: str,
        severity: str = "",
        risk_score: int = 0,
        reason: str = "",
        domain: str = "",
        trigger_event: str = "",
        account_id: str = "",
        region: str = "us-east-1",
    ) -> DriftAlert:
        """Compare previous state with current result.

        Args:
            previous: Existing ViolationState from DB,
                or None if first time seeing this.
            current_status: New status from OPA eval
                (alarm/ok/error/skip).
            check_id: Policy check ID.
            resource_arn: AWS resource ARN.
            severity: Severity level string.
            risk_score: Composite risk score (0-100).
            reason: Human-readable reason.
            domain: Security domain.
            trigger_event: CloudTrail event name.
            account_id: AWS account ID.
            region: AWS region.

        Returns:
            DriftAlert with the detected transition.

        Example:
            >>> alert = detector.detect(
            ...     previous=None,
            ...     current_status="alarm",
            ...     check_id="s3_block_public_acls",
            ...     resource_arn="arn:aws:s3:::bucket",
            ... )
            >>> alert.drift_type
            <DriftType.FIRST_SEEN: 'first_seen'>
        """
        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        sev = _parse_severity(severity)

        if previous is None:
            return self._first_seen(
                current_status=current_status,
                check_id=check_id,
                resource_arn=resource_arn,
                severity=sev,
                risk_score=risk_score,
                reason=reason,
                trigger_event=trigger_event,
                account_id=account_id,
                region=region,
                timestamp=now,
            )

        prev_status = previous.status
        drift_type = _classify_transition(
            prev_status, current_status
        )

        logger.info(
            "Drift: %s -> %s (%s) for %s %s",
            prev_status,
            current_status,
            drift_type.value,
            check_id,
            resource_arn,
        )

        regression = previous.regression_count
        if drift_type == DriftType.NEW_VIOLATION:
            if previous.resolved_at:
                regression += 1

        return DriftAlert(
            drift_type=drift_type,
            check_id=check_id,
            resource_arn=resource_arn,
            previous_status=prev_status,
            current_status=current_status,
            severity=sev,
            risk_score=risk_score,
            trigger_event=trigger_event,
            timestamp=now,
            reason=_build_reason(
                drift_type,
                prev_status,
                current_status,
                reason,
            ),
            account_id=account_id,
            region=region,
        )

    def _first_seen(
        self,
        current_status: str,
        check_id: str,
        resource_arn: str,
        severity: AlertSeverity,
        risk_score: int,
        reason: str,
        trigger_event: str,
        account_id: str,
        region: str,
        timestamp: str,
    ) -> DriftAlert:
        """Handle first time a resource is evaluated.

        Args:
            current_status: Initial status.
            check_id: Policy check ID.
            resource_arn: AWS resource ARN.
            severity: Alert severity.
            risk_score: Risk score.
            reason: Reason string.
            trigger_event: Triggering event.
            account_id: AWS account ID.
            region: AWS region.
            timestamp: ISO timestamp.

        Returns:
            DriftAlert with FIRST_SEEN type.
        """
        logger.info(
            "First seen: %s %s -> %s",
            check_id,
            resource_arn,
            current_status,
        )

        return DriftAlert(
            drift_type=DriftType.FIRST_SEEN,
            check_id=check_id,
            resource_arn=resource_arn,
            previous_status="",
            current_status=current_status,
            severity=severity,
            risk_score=risk_score,
            trigger_event=trigger_event,
            timestamp=timestamp,
            reason=reason or (
                f"First evaluation: {current_status}"
            ),
            account_id=account_id,
            region=region,
        )

    def build_updated_state(
        self,
        previous: ViolationState | None,
        alert: DriftAlert,
        domain: str = "",
        compliance: dict | None = None,
        remediation_id: str = "",
    ) -> ViolationState:
        """Build a ViolationState to persist after drift.

        Merges previous state with new drift alert data
        to produce the record to write to DynamoDB.

        Args:
            previous: Existing state or None.
            alert: DriftAlert from detect().
            domain: Security domain.
            compliance: Compliance framework mappings.
            remediation_id: Remediation template ID.

        Returns:
            ViolationState ready for put_state().

        Example:
            >>> state = detector.build_updated_state(
            ...     previous=old_state,
            ...     alert=drift_alert,
            ...     domain="network",
            ... )
        """
        pk = f"{alert.account_id}#{alert.region}"
        sk = (
            f"{alert.check_id}#{alert.resource_arn}"
        )
        now = alert.timestamp

        if previous is None:
            return ViolationState(
                pk=pk,
                sk=sk,
                check_id=alert.check_id,
                status=alert.current_status,
                previous_status="",
                severity=alert.severity.value,
                risk_score=alert.risk_score,
                domain=domain,
                resource_arn=alert.resource_arn,
                reason=alert.reason,
                compliance=compliance or {},
                remediation_id=remediation_id,
                first_detected=now,
                last_evaluated=now,
                resolved_at=(
                    now
                    if alert.current_status == "ok"
                    else None
                ),
                regression_count=0,
                status_history=[
                    {
                        "status": alert.current_status,
                        "timestamp": now,
                    }
                ],
            )

        regression = previous.regression_count
        if (
            alert.drift_type
            == DriftType.NEW_VIOLATION
            and previous.resolved_at
        ):
            regression += 1

        resolved_at = previous.resolved_at
        if alert.current_status == "ok":
            resolved_at = now
        elif alert.current_status == "alarm":
            resolved_at = None

        # Build status_history: copy previous and
        # append on actual state transitions only
        history = list(previous.status_history)
        if alert.drift_type != DriftType.NO_CHANGE:
            history.append(
                {
                    "status": alert.current_status,
                    "timestamp": now,
                }
            )

        return ViolationState(
            pk=pk,
            sk=sk,
            check_id=alert.check_id,
            status=alert.current_status,
            previous_status=previous.status,
            severity=alert.severity.value,
            risk_score=alert.risk_score,
            domain=domain or previous.domain,
            resource_arn=alert.resource_arn,
            reason=alert.reason,
            compliance=(
                compliance
                or previous.compliance
            ),
            remediation_id=(
                remediation_id
                or previous.remediation_id
            ),
            first_detected=(
                previous.first_detected or now
            ),
            last_evaluated=now,
            resolved_at=resolved_at,
            regression_count=regression,
            status_history=history,
        )


def _classify_transition(
    previous: str, current: str
) -> DriftType:
    """Classify a status transition.

    Args:
        previous: Previous status string.
        current: Current status string.

    Returns:
        DriftType enum value.

    Example:
        >>> _classify_transition("ok", "alarm")
        <DriftType.NEW_VIOLATION: 'new_violation'>
        >>> _classify_transition("alarm", "ok")
        <DriftType.RESOLUTION: 'resolution'>
        >>> _classify_transition("alarm", "alarm")
        <DriftType.NO_CHANGE: 'no_change'>
    """
    if previous == current:
        return DriftType.NO_CHANGE
    if current == "alarm":
        return DriftType.NEW_VIOLATION
    if previous == "alarm" and current == "ok":
        return DriftType.RESOLUTION
    return DriftType.NO_CHANGE


def _parse_severity(
    severity: str,
) -> AlertSeverity:
    """Parse a severity string to enum.

    Args:
        severity: Severity string.

    Returns:
        AlertSeverity enum, defaults to MEDIUM.

    Example:
        >>> _parse_severity("critical")
        <AlertSeverity.CRITICAL: 'critical'>
        >>> _parse_severity("unknown")
        <AlertSeverity.MEDIUM: 'medium'>
    """
    try:
        return AlertSeverity(severity.lower())
    except (ValueError, AttributeError):
        return AlertSeverity.MEDIUM


def _build_reason(
    drift_type: DriftType,
    prev_status: str,
    curr_status: str,
    reason: str,
) -> str:
    """Build a human-readable drift reason.

    Args:
        drift_type: The classified transition.
        prev_status: Previous status.
        curr_status: Current status.
        reason: Original reason from OPA eval.

    Returns:
        Formatted reason string.

    Example:
        >>> _build_reason(
        ...     DriftType.NEW_VIOLATION,
        ...     "ok", "alarm",
        ...     "Port 22 open to 0.0.0.0/0",
        ... )
        'DRIFT: ok -> alarm. Port 22 open to 0.0.0.0/0'
    """
    if drift_type == DriftType.NEW_VIOLATION:
        prefix = (
            f"DRIFT: {prev_status} -> {curr_status}"
        )
    elif drift_type == DriftType.RESOLUTION:
        prefix = (
            f"RESOLVED: {prev_status} -> "
            f"{curr_status}"
        )
    else:
        prefix = f"Status: {curr_status}"

    if reason:
        return f"{prefix}. {reason}"
    return prefix
