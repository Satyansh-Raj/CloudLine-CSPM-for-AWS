"""Resource taxonomy — maps resource_type to
(technology_category, service).

Used by the classifier to categorize each AWS resource
into the correct inventory bucket.
"""

# (technology_category, aws_service)
RESOURCE_TAXONOMY: dict[str, tuple[str, str]] = {
    # Storage (blue)
    "s3_bucket": ("storage", "s3"),
    "ebs_volume": ("storage", "ec2"),
    # Compute (orange)
    "ec2_instance": ("compute", "ec2"),
    "auto_scaling_group": ("compute", "ec2"),
    # Database (purple)
    "rds_instance": ("database", "rds"),
    "aurora_cluster": ("database", "rds"),
    "dynamodb_table": ("database", "dynamodb"),
    # Network (cyan)
    "vpc": ("network", "vpc"),
    "subnet": ("network", "vpc"),
    "internet_gateway": ("network", "vpc"),
    "nat_gateway": ("network", "vpc"),
    "load_balancer": ("network", "elb"),
    "cloudfront_distribution": ("network", "cloudfront"),
    "route53_hosted_zone": ("network", "route53"),
    "security_group": ("network", "ec2"),
    "network_acl": ("network", "vpc"),
    "network_firewall": ("network", "vpc"),
    "waf_web_acl": ("network", "waf"),
    # Identity (yellow)
    "iam_user": ("identity", "iam"),
    "iam_group": ("identity", "iam"),
    "iam_role": ("identity", "iam"),
    "iam_policy": ("identity", "iam"),
    # Serverless (emerald)
    "lambda_function": ("serverless", "lambda"),
    "api_gateway": ("serverless", "apigateway"),
    # Encryption (pink)
    "kms_key": ("encryption", "kms"),
    "secret": ("encryption", "secretsmanager"),
    # Monitoring (indigo)
    "cloudtrail": ("monitoring", "cloudtrail"),
    "guardduty": ("monitoring", "guardduty"),
    "cloudwatch_alarm": ("monitoring", "cloudwatch"),
    # Backup (teal)
    "ebs_snapshot": ("backup", "ec2"),
    "rds_snapshot": ("backup", "rds"),
    # Containers (slate)
    "ecr_repository": ("containers", "ecr"),
    "ecs_cluster": ("containers", "ecs"),
    "ecs_task_definition": ("containers", "ecs"),
    "eks_cluster": ("containers", "eks"),
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
