"""Maps CloudTrail event names to collectors and policies.

Each CloudTrail API event is mapped to the collector that
can fetch the affected resource and the Rego policy packages
that should be re-evaluated.

Policy strings are OPA package paths (after the ``aws.``
prefix) — e.g. ``data_protection.s3`` resolves to
``data.aws.data_protection.s3.violations``.
"""

import logging

from app.pipeline.models import EventMapping

logger = logging.getLogger(__name__)

EVENT_POLICY_MAP: dict[str, dict] = {
    # --- S3 events ---
    "CreateBucket": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "PutBucketPublicAccessBlock": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "PutBucketPolicy": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "PutBucketEncryption": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "DeleteBucketEncryption": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "DeleteBucket": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "DeleteBucketPolicy": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    "DeletePublicAccessBlock": {
        "collector": "s3",
        "policies": [
            "data_protection.s3",
        ],
    },
    # --- Security Group events ---
    "AuthorizeSecurityGroupIngress": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
            "cross_resource.capital_one",
        ],
    },
    "RevokeSecurityGroupIngress": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
        ],
    },
    "CreateSecurityGroup": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
        ],
    },
    "DeleteSecurityGroup": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
        ],
    },
    # --- IAM events ---
    "CreateUser": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "CreateAccessKey": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "DeleteAccessKey": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "DeleteUser": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "AttachRolePolicy": {
        "collector": "iam",
        "policies": [
            "identity.iam",
            "cross_resource.capital_one",
        ],
    },
    "UpdateAccountPasswordPolicy": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "DetachRolePolicy": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    "DeleteRolePolicy": {
        "collector": "iam",
        "policies": [
            "identity.iam",
        ],
    },
    # --- EC2 events ---
    "RunInstances": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
            "cross_resource.capital_one",
        ],
    },
    "ModifyInstanceMetadataOptions": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
            "cross_resource.capital_one",
        ],
    },
    "TerminateInstances": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
        ],
    },
    "ModifyInstanceAttribute": {
        "collector": "ec2",
        "policies": [
            "compute.ec2",
        ],
    },
    # --- CloudTrail events ---
    "StartLogging": {
        "collector": "logging",
        "policies": [
            "logging_monitoring.cloudtrail",
        ],
    },
    "CreateTrail": {
        "collector": "logging",
        "policies": [
            "logging_monitoring.cloudtrail",
        ],
    },
    "StopLogging": {
        "collector": "logging",
        "policies": [
            "logging_monitoring.cloudtrail",
        ],
    },
    "DeleteTrail": {
        "collector": "logging",
        "policies": [
            "logging_monitoring.cloudtrail",
        ],
    },
    # --- RDS events ---
    "CreateDBInstance": {
        "collector": "rds",
        "policies": [
            "data_protection.database",
        ],
    },
    "ModifyDBInstance": {
        "collector": "rds",
        "policies": [
            "data_protection.database",
        ],
    },
    "DeleteDBInstance": {
        "collector": "rds",
        "policies": [
            "data_protection.database",
        ],
    },
    # --- Lambda events ---
    "CreateFunction20150331": {
        "collector": "lambda",
        "policies": [
            "compute.serverless",
        ],
    },
    "DeleteFunction20150331": {
        "collector": "lambda",
        "policies": [
            "compute.serverless",
        ],
    },
    "UpdateFunctionConfiguration20150331v2": {
        "collector": "lambda",
        "policies": [
            "compute.serverless",
        ],
    },
    # --- EBS events ---
    "CreateVolume": {
        "collector": "ec2",
        "policies": [
            "data_protection.storage",
        ],
    },
    "DeleteVolume": {
        "collector": "ec2",
        "policies": [
            "data_protection.storage",
        ],
    },
    # --- VPC Flow Logs ---
    "CreateFlowLogs": {
        "collector": "vpc",
        "policies": [
            "network.vpc",
        ],
    },
    "DeleteFlowLogs": {
        "collector": "vpc",
        "policies": [
            "network.vpc",
        ],
    },
    # --- GuardDuty events ---
    "CreateDetector": {
        "collector": "logging",
        "policies": [
            "detection.aws_security",
        ],
    },
    "DeleteDetector": {
        "collector": "logging",
        "policies": [
            "detection.aws_security",
        ],
    },
}

# Reverse lookup: collector -> list of event names
COLLECTOR_EVENTS: dict[str, list[str]] = {}
for _evt, _mapping in EVENT_POLICY_MAP.items():
    _collector = _mapping["collector"]
    if _collector not in COLLECTOR_EVENTS:
        COLLECTOR_EVENTS[_collector] = []
    COLLECTOR_EVENTS[_collector].append(_evt)


def get_event_mapping(
    event_name: str,
) -> EventMapping | None:
    """Look up collector and policies for an event.

    Args:
        event_name: CloudTrail API event name,
            e.g. "CreateBucket".

    Returns:
        EventMapping with collector and policies,
        or None if event is not tracked.

    Example:
        >>> m = get_event_mapping("CreateBucket")
        >>> m.collector
        's3'
        >>> "data_protection.s3" in m.policies
        True
    """
    raw = EVENT_POLICY_MAP.get(event_name)
    if raw is None:
        logger.debug(
            "Untracked event: %s", event_name
        )
        return None
    return EventMapping(
        collector=raw["collector"],
        policies=raw["policies"],
    )


def is_tracked_event(event_name: str) -> bool:
    """Check if an event name is tracked.

    Args:
        event_name: CloudTrail API event name.

    Returns:
        True if the event is in EVENT_POLICY_MAP.

    Example:
        >>> is_tracked_event("CreateBucket")
        True
        >>> is_tracked_event("DescribeBuckets")
        False
    """
    return event_name in EVENT_POLICY_MAP


def get_tracked_events() -> list[str]:
    """Return all tracked event names.

    Returns:
        Sorted list of all CloudTrail event names
        in EVENT_POLICY_MAP.

    Example:
        >>> events = get_tracked_events()
        >>> "CreateBucket" in events
        True
    """
    return sorted(EVENT_POLICY_MAP.keys())


def get_events_for_collector(
    collector: str,
) -> list[str]:
    """Return event names handled by a collector.

    Args:
        collector: Collector module name
            (e.g. "s3", "iam").

    Returns:
        List of event names for that collector.

    Example:
        >>> evts = get_events_for_collector("s3")
        >>> "CreateBucket" in evts
        True
    """
    return COLLECTOR_EVENTS.get(collector, [])
