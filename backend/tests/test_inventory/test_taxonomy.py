"""Tests for resource taxonomy mapping."""

import pytest

from app.inventory.taxonomy import (
    RESOURCE_TAXONOMY,
    get_taxonomy,
)


class TestResourceTaxonomy:
    """Verify all resource types map correctly."""

    def test_ec2_instance(self):
        cat, svc = RESOURCE_TAXONOMY["ec2_instance"]
        assert cat == "compute"
        assert svc == "ec2"

    def test_s3_bucket(self):
        cat, svc = RESOURCE_TAXONOMY["s3_bucket"]
        assert cat == "storage"
        assert svc == "s3"

    def test_rds_instance(self):
        cat, svc = RESOURCE_TAXONOMY["rds_instance"]
        assert cat == "database"
        assert svc == "rds"

    def test_lambda_function(self):
        cat, svc = RESOURCE_TAXONOMY["lambda_function"]
        assert cat == "serverless"
        assert svc == "lambda"

    def test_security_group(self):
        cat, svc = RESOURCE_TAXONOMY["security_group"]
        assert cat == "network"
        assert svc == "ec2"

    def test_ebs_volume(self):
        cat, svc = RESOURCE_TAXONOMY["ebs_volume"]
        assert cat == "storage"
        assert svc == "ec2"

    def test_vpc(self):
        cat, svc = RESOURCE_TAXONOMY["vpc"]
        assert cat == "network"
        assert svc == "vpc"

    def test_kms_key(self):
        cat, svc = RESOURCE_TAXONOMY["kms_key"]
        assert cat == "encryption"
        assert svc == "kms"

    def test_secret(self):
        cat, svc = RESOURCE_TAXONOMY["secret"]
        assert cat == "encryption"
        assert svc == "secretsmanager"

    def test_iam_user(self):
        cat, svc = RESOURCE_TAXONOMY["iam_user"]
        assert cat == "identity"
        assert svc == "iam"

    def test_cloudtrail(self):
        cat, svc = RESOURCE_TAXONOMY["cloudtrail"]
        assert cat == "monitoring"
        assert svc == "cloudtrail"

    def test_guardduty(self):
        cat, svc = RESOURCE_TAXONOMY["guardduty"]
        assert cat == "monitoring"
        assert svc == "guardduty"

    def test_cloudwatch_alarm(self):
        cat, svc = RESOURCE_TAXONOMY["cloudwatch_alarm"]
        assert cat == "monitoring"
        assert svc == "cloudwatch"

    # ── New resource types ─────────────────────────

    # Compute
    def test_auto_scaling_group(self):
        cat, svc = RESOURCE_TAXONOMY["auto_scaling_group"]
        assert cat == "compute"
        assert svc == "ec2"

    # Database
    def test_aurora_cluster(self):
        cat, svc = RESOURCE_TAXONOMY["aurora_cluster"]
        assert cat == "database"
        assert svc == "rds"

    def test_dynamodb_table(self):
        cat, svc = RESOURCE_TAXONOMY["dynamodb_table"]
        assert cat == "database"
        assert svc == "dynamodb"

    # Network
    def test_subnet(self):
        cat, svc = RESOURCE_TAXONOMY["subnet"]
        assert cat == "network"
        assert svc == "vpc"

    def test_internet_gateway(self):
        cat, svc = RESOURCE_TAXONOMY["internet_gateway"]
        assert cat == "network"
        assert svc == "vpc"

    def test_nat_gateway(self):
        cat, svc = RESOURCE_TAXONOMY["nat_gateway"]
        assert cat == "network"
        assert svc == "vpc"

    def test_load_balancer(self):
        cat, svc = RESOURCE_TAXONOMY["load_balancer"]
        assert cat == "network"
        assert svc == "elb"

    def test_cloudfront_distribution(self):
        cat, svc = RESOURCE_TAXONOMY[
            "cloudfront_distribution"
        ]
        assert cat == "network"
        assert svc == "cloudfront"

    def test_route53_hosted_zone(self):
        cat, svc = RESOURCE_TAXONOMY[
            "route53_hosted_zone"
        ]
        assert cat == "network"
        assert svc == "route53"

    def test_network_acl(self):
        cat, svc = RESOURCE_TAXONOMY["network_acl"]
        assert cat == "network"
        assert svc == "vpc"

    def test_network_firewall(self):
        cat, svc = RESOURCE_TAXONOMY["network_firewall"]
        assert cat == "network"
        assert svc == "vpc"

    def test_waf_web_acl(self):
        cat, svc = RESOURCE_TAXONOMY["waf_web_acl"]
        assert cat == "network"
        assert svc == "waf"

    # Identity
    def test_iam_group(self):
        cat, svc = RESOURCE_TAXONOMY["iam_group"]
        assert cat == "identity"
        assert svc == "iam"

    def test_iam_role(self):
        cat, svc = RESOURCE_TAXONOMY["iam_role"]
        assert cat == "identity"
        assert svc == "iam"

    def test_iam_policy(self):
        cat, svc = RESOURCE_TAXONOMY["iam_policy"]
        assert cat == "identity"
        assert svc == "iam"

    # Serverless
    def test_api_gateway(self):
        cat, svc = RESOURCE_TAXONOMY["api_gateway"]
        assert cat == "serverless"
        assert svc == "apigateway"

    # Backup
    def test_ebs_snapshot(self):
        cat, svc = RESOURCE_TAXONOMY["ebs_snapshot"]
        assert cat == "backup"
        assert svc == "ec2"

    def test_rds_snapshot(self):
        cat, svc = RESOURCE_TAXONOMY["rds_snapshot"]
        assert cat == "backup"
        assert svc == "rds"

    # Containers
    def test_ecr_repository(self):
        cat, svc = RESOURCE_TAXONOMY["ecr_repository"]
        assert cat == "containers"
        assert svc == "ecr"

    def test_ecs_cluster(self):
        cat, svc = RESOURCE_TAXONOMY["ecs_cluster"]
        assert cat == "containers"
        assert svc == "ecs"

    def test_ecs_task_definition(self):
        cat, svc = RESOURCE_TAXONOMY[
            "ecs_task_definition"
        ]
        assert cat == "containers"
        assert svc == "ecs"

    def test_eks_cluster(self):
        cat, svc = RESOURCE_TAXONOMY["eks_cluster"]
        assert cat == "containers"
        assert svc == "eks"


class TestGetTaxonomy:
    """Test the get_taxonomy() lookup helper."""

    def test_known_type(self):
        cat, svc = get_taxonomy("ec2_instance")
        assert cat == "compute"
        assert svc == "ec2"

    def test_unknown_type_returns_default(self):
        cat, svc = get_taxonomy("unknown_thing")
        assert cat == "other"
        assert svc == "unknown"

    def test_all_entries_are_two_tuples(self):
        for key, val in RESOURCE_TAXONOMY.items():
            assert len(val) == 2, (
                f"{key} should map to (category, service)"
            )

    def test_taxonomy_has_35_entries(self):
        assert len(RESOURCE_TAXONOMY) == 35
