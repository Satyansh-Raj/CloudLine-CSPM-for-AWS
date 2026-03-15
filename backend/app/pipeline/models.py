"""Data models for the real-time detection pipeline.

Defines CloudTrail event, drift alert, event mapping,
and violation state structures.
"""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class DriftType(str, Enum):
    """Type of state transition detected."""

    NEW_VIOLATION = "new_violation"
    RESOLUTION = "resolution"
    NO_CHANGE = "no_change"
    FIRST_SEEN = "first_seen"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CloudTrailEvent(BaseModel):
    """Parsed CloudTrail event from EventBridge.

    Attributes:
        event_name: AWS API action name.
        event_source: AWS service source.
        event_time: When the event occurred.
        aws_region: Region where event happened.
        account_id: AWS account ID.
        resource_id: Extracted resource identifier.
        resource_arn: Full ARN if available.
        actor_arn: ARN of the IAM entity.
        actor_type: Type of actor (IAMUser, Role).
        source_ip: IP address of the caller.
        user_agent: User agent string.
        request_params: Raw request parameters.
        response_elements: Raw response elements.

    Example:
        >>> event = CloudTrailEvent(
        ...     event_name="CreateBucket",
        ...     event_source="s3.amazonaws.com",
        ...     event_time="2026-02-27T12:00:00Z",
        ...     aws_region="us-east-1",
        ...     account_id="123456789012",
        ...     resource_id="my-bucket",
        ... )
        >>> event.event_name
        'CreateBucket'
    """

    event_name: str
    event_source: str
    event_time: str
    aws_region: str = "us-east-1"
    account_id: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    actor_arn: str = ""
    actor_type: str = ""
    source_ip: str = ""
    user_agent: str = ""
    request_params: dict = Field(
        default_factory=dict
    )
    response_elements: dict = Field(
        default_factory=dict
    )


class EventMapping(BaseModel):
    """Maps a CloudTrail event to its collector and policies.

    Attributes:
        collector: Name of the collector module.
        policies: List of Rego policy package names.

    Example:
        >>> mapping = EventMapping(
        ...     collector="s3",
        ...     policies=["data_protection.s3"],
        ... )
        >>> mapping.collector
        's3'
    """

    collector: str
    policies: list[str]


class DriftAlert(BaseModel):
    """Alert generated when a state transition is detected.

    Attributes:
        drift_type: Type of drift (new_violation/resolution).
        check_id: The policy check ID.
        resource_arn: AWS resource ARN.
        previous_status: Status before this evaluation.
        current_status: Status after this evaluation.
        severity: Alert severity level.
        risk_score: Composite risk score (0-100).
        trigger_event: CloudTrail event that caused this.
        timestamp: When the drift was detected.
        reason: Human-readable drift description.
        account_id: AWS account ID.
        region: AWS region.

    Example:
        >>> alert = DriftAlert(
        ...     drift_type=DriftType.NEW_VIOLATION,
        ...     check_id="ec2_05",
        ...     resource_arn="arn:aws:ec2:...",
        ...     previous_status="ok",
        ...     current_status="alarm",
        ...     severity=AlertSeverity.CRITICAL,
        ...     trigger_event="AuthorizeSecurityGroupIngress",
        ... )
    """

    drift_type: DriftType
    check_id: str
    resource_arn: str = ""
    previous_status: str = ""
    current_status: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    risk_score: int = 0
    trigger_event: str = ""
    timestamp: str = Field(
        default_factory=lambda: (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    )
    reason: str = ""
    account_id: str = ""
    region: str = "us-east-1"


class ViolationState(BaseModel):
    """DynamoDB violation state record.

    Attributes:
        pk: Partition key ({account_id}#{region}).
        sk: Sort key ({check_id}#{resource_arn}).
        check_id: Policy check identifier.
        status: Current status (alarm/ok/error/skip).
        previous_status: Status before last evaluation.
        severity: Severity level.
        risk_score: Composite risk score (0-100).
        domain: Security domain.
        resource_arn: Full AWS ARN.
        reason: Human-readable violation reason.
        compliance: Framework mappings.
        remediation_id: Remediation template ID.
        first_detected: ISO 8601 timestamp.
        last_evaluated: ISO 8601 timestamp.
        resolved_at: Null if open, timestamp if resolved.
        regression_count: Times violation recurred.
        ttl: TTL for resolved items (epoch seconds).

    Example:
        >>> state = ViolationState(
        ...     pk="123456789012#us-east-1",
        ...     sk="ec2_05#arn:aws:ec2:...",
        ...     check_id="ec2_05",
        ...     status="alarm",
        ...     severity="critical",
        ... )
    """

    pk: str
    sk: str
    check_id: str
    status: str = "ok"
    previous_status: str = ""
    severity: str = ""
    risk_score: int = 0
    domain: str = ""
    resource_arn: str = ""
    reason: str = ""
    compliance: dict = Field(default_factory=dict)
    remediation_id: str = ""
    first_detected: str = ""
    last_evaluated: str = ""
    resolved_at: str | None = None
    regression_count: int = 0
    ttl: int | None = None
