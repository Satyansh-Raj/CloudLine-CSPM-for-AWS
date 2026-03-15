"""Parse raw CloudTrail events into typed models.

Extracts service, resource_id, event_name, timestamp,
and actor from CloudTrail JSON delivered via EventBridge.
"""

import logging

from app.pipeline.models import CloudTrailEvent

logger = logging.getLogger(__name__)

# Maps event source domains to short service names
SOURCE_SERVICE_MAP: dict[str, str] = {
    "s3.amazonaws.com": "s3",
    "ec2.amazonaws.com": "ec2",
    "iam.amazonaws.com": "iam",
    "rds.amazonaws.com": "rds",
    "lambda.amazonaws.com": "lambda",
    "cloudtrail.amazonaws.com": "cloudtrail",
    "guardduty.amazonaws.com": "guardduty",
    "elasticloadbalancing.amazonaws.com": "elb",
    "kms.amazonaws.com": "kms",
}


def parse_cloudtrail_event(
    raw: dict,
) -> CloudTrailEvent | None:
    """Parse a raw CloudTrail/EventBridge event.

    Handles both direct CloudTrail format and the
    EventBridge wrapper format (detail field).

    Args:
        raw: Raw JSON dict from CloudTrail or
             EventBridge event payload.

    Returns:
        CloudTrailEvent model, or None if the event
        is malformed or missing required fields.

    Example:
        >>> event = parse_cloudtrail_event({
        ...     "detail": {
        ...         "eventName": "CreateBucket",
        ...         "eventSource": "s3.amazonaws.com",
        ...         "eventTime": "2026-02-27T12:00:00Z",
        ...         "awsRegion": "us-east-1",
        ...         "userIdentity": {
        ...             "accountId": "123456789012",
        ...             "arn": "arn:aws:iam::root",
        ...             "type": "IAMUser",
        ...         },
        ...         "requestParameters": {
        ...             "bucketName": "my-bucket",
        ...         },
        ...     }
        ... })
        >>> event.event_name
        'CreateBucket'
    """
    detail = raw.get("detail", raw)

    event_name = detail.get("eventName")
    event_source = detail.get("eventSource")
    event_time = detail.get("eventTime")

    if not event_name or not event_source:
        logger.warning(
            "Missing eventName or eventSource "
            "in CloudTrail event"
        )
        return None

    if not event_time:
        logger.warning(
            "Missing eventTime for event: %s",
            event_name,
        )
        return None

    identity = detail.get("userIdentity", {})
    request_params = detail.get(
        "requestParameters"
    ) or {}
    response_elements = detail.get(
        "responseElements"
    ) or {}

    resource_id = _extract_resource_id(
        event_name, request_params, response_elements
    )

    return CloudTrailEvent(
        event_name=event_name,
        event_source=event_source,
        event_time=event_time,
        aws_region=detail.get(
            "awsRegion", "us-east-1"
        ),
        account_id=identity.get("accountId", ""),
        resource_id=resource_id,
        resource_arn=_extract_resource_arn(
            response_elements, request_params
        ),
        actor_arn=identity.get("arn", ""),
        actor_type=identity.get("type", ""),
        source_ip=detail.get(
            "sourceIPAddress", ""
        ),
        user_agent=detail.get("userAgent", ""),
        request_params=request_params,
        response_elements=response_elements,
    )


def _extract_resource_id(
    event_name: str,
    request_params: dict,
    response_elements: dict,
) -> str:
    """Extract the primary resource ID from event data.

    Args:
        event_name: CloudTrail API action name.
        request_params: Request parameters dict.
        response_elements: Response elements dict.

    Returns:
        Resource identifier string, or empty string.

    Example:
        >>> _extract_resource_id(
        ...     "CreateBucket",
        ...     {"bucketName": "my-bucket"},
        ...     {},
        ... )
        'my-bucket'
    """
    extractors = {
        # S3
        "CreateBucket": lambda r, _: r.get(
            "bucketName", ""
        ),
        "PutBucketPublicAccessBlock": lambda r, _: (
            r.get("bucketName", "")
        ),
        "PutBucketPolicy": lambda r, _: r.get(
            "bucketName", ""
        ),
        "PutBucketEncryption": lambda r, _: r.get(
            "bucketName", ""
        ),
        "DeleteBucketEncryption": lambda r, _: (
            r.get("bucketName", "")
        ),
        # Security Groups
        "AuthorizeSecurityGroupIngress": (
            lambda r, _: r.get("groupId", "")
        ),
        "RevokeSecurityGroupIngress": (
            lambda r, _: r.get("groupId", "")
        ),
        # IAM
        "CreateUser": lambda r, _: r.get(
            "userName", ""
        ),
        "CreateAccessKey": lambda r, _: r.get(
            "userName", ""
        ),
        "AttachRolePolicy": lambda r, _: r.get(
            "roleName", ""
        ),
        "UpdateAccountPasswordPolicy": (
            lambda _, __: "account-password-policy"
        ),
        # EC2
        "RunInstances": lambda _, resp: (
            _nested_instance_id(resp)
        ),
        "ModifyInstanceMetadataOptions": (
            lambda r, _: r.get("instanceId", "")
        ),
        # CloudTrail
        "StopLogging": lambda r, _: r.get(
            "name", ""
        ),
        "DeleteTrail": lambda r, _: r.get(
            "name", ""
        ),
        # RDS
        "CreateDBInstance": lambda r, _: r.get(
            "dBInstanceIdentifier", ""
        ),
        "ModifyDBInstance": lambda r, _: r.get(
            "dBInstanceIdentifier", ""
        ),
        # Lambda
        "CreateFunction20150331": lambda r, _: (
            r.get("functionName", "")
        ),
        # EBS
        "CreateVolume": lambda _, resp: (
            resp.get("volumeId", "")
        ),
        # GuardDuty
        "DeleteDetector": lambda r, _: r.get(
            "detectorId", ""
        ),
    }

    extractor = extractors.get(event_name)
    if extractor:
        return extractor(
            request_params, response_elements
        )

    logger.debug(
        "No resource extractor for: %s",
        event_name,
    )
    return ""


def _nested_instance_id(
    response_elements: dict,
) -> str:
    """Extract instance ID from RunInstances response.

    Args:
        response_elements: RunInstances response dict.

    Returns:
        First instance ID, or empty string.

    Example:
        >>> _nested_instance_id({
        ...     "instancesSet": {"items": [
        ...         {"instanceId": "i-12345"}
        ...     ]}
        ... })
        'i-12345'
    """
    instances_set = response_elements.get(
        "instancesSet", {}
    )
    items = instances_set.get("items", [])
    if items:
        return items[0].get("instanceId", "")
    return ""


def _extract_resource_arn(
    response_elements: dict,
    request_params: dict,
) -> str:
    """Extract resource ARN from event data.

    Args:
        response_elements: Response elements dict.
        request_params: Request parameters dict.

    Returns:
        Resource ARN if found, or empty string.

    Example:
        >>> _extract_resource_arn(
        ...     {"instancesSet": {"items": [{
        ...         "instanceId": "i-123"
        ...     }]}},
        ...     {"trailArn": "arn:aws:cloudtrail:..."},
        ... )
        'arn:aws:cloudtrail:...'
    """
    for key in ("arn", "trailArn", "functionArn"):
        val = request_params.get(key, "")
        if val:
            return val
        val = response_elements.get(key, "")
        if val:
            return val
    return ""


def get_service_from_source(
    event_source: str,
) -> str:
    """Map event source domain to short service name.

    Args:
        event_source: CloudTrail event source domain,
            e.g. "s3.amazonaws.com".

    Returns:
        Short service name, e.g. "s3".
        Falls back to prefix before ".amazonaws.com".

    Example:
        >>> get_service_from_source(
        ...     "s3.amazonaws.com"
        ... )
        's3'
    """
    if event_source in SOURCE_SERVICE_MAP:
        return SOURCE_SERVICE_MAP[event_source]
    return event_source.split(".")[0]
