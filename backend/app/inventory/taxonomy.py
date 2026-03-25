"""Resource taxonomy — maps resource_type to
(technology_category, service).

Used by the classifier to categorize each AWS resource
into the correct inventory bucket.
"""

# (technology_category, aws_service)
RESOURCE_TAXONOMY: dict[str, tuple[str, str]] = {
    "ec2_instance": ("compute", "ec2"),
    "s3_bucket": ("storage", "s3"),
    "rds_instance": ("database", "rds"),
    "lambda_function": ("serverless", "lambda"),
    "security_group": ("network", "ec2"),
    "ebs_volume": ("storage", "ec2"),
    "vpc": ("network", "vpc"),
    "kms_key": ("encryption", "kms"),
    "secret": ("encryption", "secretsmanager"),
    "iam_user": ("identity", "iam"),
    "cloudtrail": ("monitoring", "cloudtrail"),
    "guardduty": ("monitoring", "guardduty"),
    "cloudwatch_alarm": ("monitoring", "cloudwatch"),
}

_DEFAULT = ("other", "unknown")


def get_taxonomy(
    resource_type: str,
) -> tuple[str, str]:
    """Look up (category, service) for a type.

    Returns ('other', 'unknown') for unrecognised types.
    """
    return RESOURCE_TAXONOMY.get(
        resource_type, _DEFAULT
    )
